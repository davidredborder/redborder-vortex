use crate::config::{ConfigValue, PluginBlock};
use crate::event::Event;
use crate::filters::Filter;
use crate::state::StateStore;
use anyhow::{anyhow, Context, Result};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyModule, PyString, PyTuple};
use serde_json::{Map, Number, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static MODULE_COUNTER: AtomicUsize = AtomicUsize::new(1);

fn json_to_py(py: Python<'_>, val: &Value) -> PyResult<PyObject> {
    match val {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_py(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Ok(py.None())
            }
        }
        Value::String(s) => Ok(s.into_py(py)),
        Value::Array(arr) => {
            let mut items = Vec::with_capacity(arr.len());
            for item in arr {
                items.push(json_to_py(py, item)?);
            }
            Ok(PyList::new_bound(py, items).into_py(py))
        }
        Value::Object(map) => {
            let dict = PyDict::new_bound(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

fn py_to_json(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if obj.is_instance_of::<PyBool>() {
        return Ok(Value::Bool(obj.extract::<bool>()?));
    }
    if obj.is_instance_of::<PyInt>() {
        if let Ok(i) = obj.extract::<i64>() {
            return Ok(Value::Number(i.into()));
        }
        if let Ok(u) = obj.extract::<u64>() {
            return Ok(Value::Number(u.into()));
        }
    }
    if obj.is_instance_of::<PyFloat>() {
        let f = obj.extract::<f64>()?;
        return Ok(Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null));
    }
    if obj.is_instance_of::<PyString>() {
        return Ok(Value::String(obj.extract::<String>()?));
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = Map::new();
        for (k, v) in dict.iter() {
            let key_str = k.str()?.to_str()?.to_string();
            map.insert(key_str, py_to_json(&v)?);
        }
        return Ok(Value::Object(map));
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        let mut vec = Vec::with_capacity(list.len());
        for item in list.iter() {
            vec.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(vec));
    }
    if let Ok(tuple) = obj.downcast::<PyTuple>() {
        let mut vec = Vec::with_capacity(tuple.len());
        for item in tuple.iter() {
            vec.push(py_to_json(&item)?);
        }
        return Ok(Value::Array(vec));
    }

    Ok(Value::String(obj.str()?.to_str()?.to_string()))
}

#[pyclass]
#[derive(Debug, Clone)]
pub struct PyEvent {
    inner: Event,
}

impl PyEvent {
    pub fn new(event: Event) -> Self {
        Self { inner: event }
    }

    pub fn into_inner(self) -> Event {
        self.inner
    }

    pub fn inner(&self) -> &Event {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut Event {
        &mut self.inner
    }
}

#[pymethods]
impl PyEvent {
    #[pyo3(signature = (path, default=None))]
    pub fn get(&self, py: Python<'_>, path: &str, default: Option<PyObject>) -> PyResult<PyObject> {
        match self.inner.get(path) {
            Some(v) if !v.is_null() => json_to_py(py, v),
            _ => Ok(default.unwrap_or_else(|| py.None())),
        }
    }

    pub fn set(&mut self, _py: Python<'_>, path: &str, val: Bound<'_, PyAny>) -> PyResult<()> {
        let json_val = py_to_json(&val)?;
        self.inner.set(path, json_val);
        Ok(())
    }

    pub fn remove(&mut self, py: Python<'_>, path: &str) -> PyResult<PyObject> {
        match self.inner.remove(path) {
            Some(v) => json_to_py(py, &v),
            None => Ok(py.None()),
        }
    }

    pub fn tag(&mut self, tag_name: &str) {
        self.inner.tag(tag_name);
    }

    pub fn cancel(&mut self) {
        self.inner.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = PyDict::new_bound(py);
        for (k, v) in self.inner.as_map() {
            dict.set_item(k, json_to_py(py, v)?)?;
        }
        Ok(dict.into_py(py))
    }

    pub fn __getitem__(&self, py: Python<'_>, path: &str) -> PyResult<PyObject> {
        self.get(py, path, None)
    }

    pub fn __setitem__(
        &mut self,
        py: Python<'_>,
        path: &str,
        val: Bound<'_, PyAny>,
    ) -> PyResult<()> {
        self.set(py, path, val)
    }

    pub fn __contains__(&self, path: &str) -> bool {
        self.inner.contains(path)
    }
}

#[pyclass]
pub struct PyStateStore {
    ptr: Option<*const StateStore>,
}

// Safety: `PyStateStore` is only active while `Filter::process` holds the GIL,
// and its pointer is cleared before `process` returns.
unsafe impl Send for PyStateStore {}
unsafe impl Sync for PyStateStore {}

impl PyStateStore {
    fn from_ref(state: &StateStore) -> Self {
        Self {
            ptr: Some(state as *const StateStore),
        }
    }

    fn clear(&mut self) {
        self.ptr = None;
    }

    fn state(&self) -> PyResult<&StateStore> {
        let raw = self.ptr.ok_or_else(|| {
            PyRuntimeError::new_err("StateStore reference is no longer active outside process()")
        })?;
        Ok(unsafe { &*raw })
    }
}

#[pymethods]
impl PyStateStore {
    pub fn get_record(&self, py: Python<'_>, store: &str, key: &str) -> PyResult<PyObject> {
        let state = self.state()?;
        match state.get_record(store, key) {
            Some(map) => json_to_py(py, &Value::Object(map)),
            None => Ok(py.None()),
        }
    }

    pub fn put_record(
        &self,
        _py: Python<'_>,
        store: &str,
        key: &str,
        val: Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let state = self.state()?;
        let json_val = py_to_json(&val)?;
        let Value::Object(map) = json_val else {
            return Err(PyRuntimeError::new_err(
                "put_record expects a dict value for record fields",
            ));
        };
        state
            .put_record(store, key, map)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn get_kv(&self, key: &str) -> PyResult<Option<String>> {
        let state = self.state()?;
        state
            .get_kv(key)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[pyo3(signature = (key, val, ttl_secs=None))]
    pub fn set_kv(&self, key: &str, val: &str, ttl_secs: Option<u64>) -> PyResult<()> {
        let state = self.state()?;
        state
            .set_kv(key, val, ttl_secs)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn enrich(&self, event: &mut PyEvent) -> PyResult<()> {
        let state = self.state()?;
        state.enrich(event.inner_mut());
        Ok(())
    }

    #[pyo3(signature = (counter_store, datasource, delta=1))]
    pub fn increment_counter(
        &self,
        counter_store: &str,
        datasource: &str,
        delta: i64,
    ) -> PyResult<i64> {
        let state = self.state()?;
        state
            .increment_counter(counter_store, datasource, delta)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn get_counter(&self, counter_store: &str, datasource: &str) -> PyResult<i64> {
        let state = self.state()?;
        Ok(state.get_counter(counter_store, datasource))
    }
}

const PYTHON_PRELUDE: &str = r#"
from datetime import datetime, timezone

def _rb_to_i(val):
    if val is None:
        return 0
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        s = val.strip()
        try:
            return int(float(s))
        except ValueError:
            pass
        try:
            iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            return 0
    return 0
"#;

fn resolve_plugin_file(module_or_path: &str) -> Result<PathBuf> {
    let direct = Path::new(module_or_path);
    if direct.exists() && direct.is_file() {
        return Ok(direct.to_path_buf());
    }

    let clean_name = module_or_path.trim_end_matches(".py");
    let rel_candidate = PathBuf::from("plugins").join(format!("{}.py", clean_name));
    if rel_candidate.exists() {
        return Ok(rel_candidate);
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_candidate = manifest_dir
        .join("plugins")
        .join(format!("{}.py", clean_name));
    if manifest_candidate.exists() {
        return Ok(manifest_candidate);
    }

    let manifest_direct = manifest_dir.join(module_or_path);
    if manifest_direct.exists() {
        return Ok(manifest_direct);
    }

    let share_candidate = PathBuf::from("/usr/share/redborder-vortex/plugins")
        .join(format!("{}.py", clean_name));
    if share_candidate.exists() {
        return Ok(share_candidate);
    }

    Err(anyhow!(
        "Could not locate Python plugin module or file '{}'",
        module_or_path
    ))
}

fn load_isolated_py_module<'py>(py: Python<'py>, module_or_path: &str) -> Result<Bound<'py, PyModule>> {
    let file_path = resolve_plugin_file(module_or_path)?;
    let source = fs::read_to_string(&file_path)
        .with_context(|| format!("Failed to read Python plugin {:?}", file_path))?;
    let stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("rb_plugin");
    let unique_name = format!(
        "rb_plugin_{}_{}",
        stem,
        MODULE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let file_str = file_path.to_string_lossy();
    let module = PyModule::from_code_bound(py, &source, file_str.as_ref(), &unique_name)
        .map_err(|e| anyhow!("Failed to compile Python module {:?}: {}", file_path, e))?;
    Ok(module)
}

enum PythonFilterKind {
    Inline {
        globals: Py<PyDict>,
        code: String,
    },
    Module {
        module: Py<PyModule>,
        function_name: String,
        second_arg_is_config: bool,
        takes_two_args: bool,
        config_obj: PyObject,
    },
}

pub struct PythonFilter {
    kind: PythonFilterKind,
}

impl PythonFilter {
    pub fn from_plugin_block(block: &PluginBlock) -> Result<Self> {
        let config_map = block.get_setting("config").and_then(|v| match v {
            ConfigValue::Map(_) => match v.to_json_value() {
                Value::Object(m) => Some(m),
                _ => None,
            },
            _ => None,
        });

        if let Some(module_or_path) = block.get_str("module").or_else(|| block.get_str("path")) {
            let func = block.get_str("function");
            return Self::new_module(module_or_path, func, config_map);
        }

        let init = block.get_str("init");
        let code = block
            .get_str("code")
            .ok_or_else(|| anyhow!("python filter requires either 'module'/'path' or 'code'"))?;
        Self::new_inline(init, code)
    }

    pub fn new_inline(init: Option<&str>, code: &str) -> Result<Self> {
        let globals = Python::with_gil(|py| -> Result<Py<PyDict>> {
            let dict = PyDict::new_bound(py);
            let builtins = PyModule::import_bound(py, "builtins")
                .map_err(|e| anyhow!("Failed to import Python builtins: {}", e))?;
            dict.set_item("__builtins__", builtins)
                .map_err(|e| anyhow!("Failed to set __builtins__: {}", e))?;

            py.run_bound(PYTHON_PRELUDE, Some(&dict), Some(&dict))
                .map_err(|e| anyhow!("Failed to run Python prelude: {}", e))?;

            if let Some(init_src) = init {
                let dedented = dedent_block(init_src);
                py.run_bound(&dedented, Some(&dict), Some(&dict))
                    .map_err(|e| anyhow!("Failed to run Python init block: {}", e))?;
            }

            Ok(dict.unbind())
        })?;

        let dedented_code = dedent_block(code);

        Ok(Self {
            kind: PythonFilterKind::Inline {
                globals,
                code: dedented_code,
            },
        })
    }

    pub fn new_module(
        module_or_path: &str,
        function: Option<&str>,
        config: Option<Map<String, Value>>,
    ) -> Result<Self> {
        let function_name = function.unwrap_or("filter").to_string();

        Python::with_gil(|py| {
            let module = load_isolated_py_module(py, module_or_path)?;
            let cfg_val = Value::Object(config.unwrap_or_default());
            let config_obj = json_to_py(py, &cfg_val)
                .map_err(|e| anyhow!("Failed to convert config to PyObject: {}", e))?;

            if let Ok(reg_fn) = module.getattr("register") {
                if reg_fn.is_callable() {
                    reg_fn
                        .call1((config_obj.bind(py),))
                        .map_err(|e| anyhow!("Python register(config) failed: {}", e))?;
                }
            }

            let func = module.getattr(function_name.as_str()).map_err(|e| {
                anyhow!(
                    "Python module '{}' has no function '{}': {}",
                    module_or_path,
                    function_name,
                    e
                )
            })?;

            // Inspect parameter names to decide whether the 2nd argument is `config` or `state`
            let inspect = PyModule::import_bound(py, "inspect")
                .map_err(|e| anyhow!("Failed to import inspect: {}", e))?;
            let sig = inspect
                .call_method1("signature", (&func,))
                .map_err(|e| anyhow!("Failed to inspect signature: {}", e))?;
            let params_dict = sig
                .getattr("parameters")
                .map_err(|e| anyhow!("Failed to read signature.parameters: {}", e))?;
            let param_names: Vec<String> = params_dict
                .call_method0("keys")
                .and_then(|k| k.extract::<Vec<String>>())
                .unwrap_or_default();

            let takes_two_args = param_names.len() >= 2;
            let second_arg_is_config = param_names
                .get(1)
                .map(|name| {
                    name == "config"
                        || name == "cfg"
                        || name.contains("config")
                        || name.contains("nodes")
                        || name.contains("homenets")
                        || name.contains("fields")
                })
                .unwrap_or(false);

            Ok(Self {
                kind: PythonFilterKind::Module {
                    module: module.unbind(),
                    function_name,
                    second_arg_is_config,
                    takes_two_args,
                    config_obj,
                },
            })
        })
    }
}

impl Filter for PythonFilter {
    fn process(&self, event: Event, state: &StateStore) -> Result<Vec<Event>> {
        Python::with_gil(|py| {
            let py_event = Bound::new(py, PyEvent::new(event))
                .map_err(|e| anyhow!("Failed to allocate PyEvent: {}", e))?;
            let py_state = Bound::new(py, PyStateStore::from_ref(state))
                .map_err(|e| anyhow!("Failed to allocate PyStateStore: {}", e))?;

            let exec_res: Result<()> = match &self.kind {
                PythonFilterKind::Inline { globals, code } => {
                    let g = globals.bind(py);
                    g.set_item("event", &py_event)
                        .map_err(|e| anyhow!("Failed to bind event: {}", e))?;
                    g.set_item("state", &py_state)
                        .map_err(|e| anyhow!("Failed to bind state: {}", e))?;

                    let run_res = py
                        .run_bound(code, Some(g), Some(g))
                        .map_err(|e| anyhow!("Inline Python filter execution error: {}", e));

                    let _ = g.del_item("event");
                    let _ = g.del_item("state");
                    run_res
                }
                PythonFilterKind::Module {
                    module,
                    function_name,
                    second_arg_is_config,
                    takes_two_args,
                    config_obj,
                } => {
                    let m = module.bind(py);
                    let func = m
                        .getattr(function_name.as_str())
                        .map_err(|e| anyhow!("Missing Python function '{}': {}", function_name, e))?;

                    let call_res = if *second_arg_is_config {
                        func.call1((&py_event, config_obj.bind(py)))
                    } else if *takes_two_args {
                        func.call1((&py_event, &py_state))
                    } else {
                        func.call1((&py_event,))
                    };

                    call_res
                        .map(|_| ())
                        .map_err(|e| anyhow!("Python module '{}' error: {}", function_name, e))
                }
            };

            // Always invalidate the scoped StateStore pointer before returning
            py_state.borrow_mut().clear();
            exec_res?;

            let final_event = py_event.borrow().inner().clone();
            if final_event.is_cancelled() {
                Ok(Vec::new())
            } else {
                Ok(vec![final_event])
            }
        })
    }
}

fn dedent_block(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let min_indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);

    lines
        .into_iter()
        .map(|l| {
            if l.len() >= min_indent {
                &l[min_indent..]
            } else {
                l.trim_start()
            }
        })
        .collect::<Vec<&str>>()
        .join("\n")
}

pub struct RubyCompatFilter {
    inner: PythonFilter,
}

impl RubyCompatFilter {
    pub fn from_plugin_block(block: &PluginBlock) -> Result<Self> {
        let init = block.get_str("init");
        let code = block
            .get_str("code")
            .ok_or_else(|| anyhow!("ruby filter block requires 'code' setting"))?;
        Self::new(init, code)
    }

    pub fn new(init: Option<&str>, code: &str) -> Result<Self> {
        let py_init = init.map(translate_ruby_to_python);
        let py_code = translate_ruby_to_python(code);
        let inner = PythonFilter::new_inline(py_init.as_deref(), &py_code)?;
        Ok(Self { inner })
    }
}

impl Filter for RubyCompatFilter {
    fn process(&self, event: Event, state: &StateStore) -> Result<Vec<Event>> {
        self.inner.process(event, state)
    }
}



fn translate_ruby_to_python(ruby_src: &str) -> String {
    let dedented = dedent_block(ruby_src);
    let mut out = Vec::new();
    let mut indent_level: usize = 0;

    for raw_line in dedented.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("require ") {
            continue;
        }
        if trimmed == "end" {
            indent_level = indent_level.saturating_sub(1);
            continue;
        }
        if trimmed == "else" {
            indent_level = indent_level.saturating_sub(1);
            out.push(format!("{}else:", "    ".repeat(indent_level)));
            indent_level += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("elsif ") {
            indent_level = indent_level.saturating_sub(1);
            let cond = translate_ruby_expr(rest);
            out.push(format!("{}elif {}:", "    ".repeat(indent_level), cond));
            indent_level += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("if ") {
            let cond = translate_ruby_expr(rest);
            out.push(format!("{}if {}:", "    ".repeat(indent_level), cond));
            indent_level += 1;
            continue;
        }

        let stmt = translate_ruby_expr(trimmed);
        out.push(format!("{}{}", "    ".repeat(indent_level), stmt));
    }

    out.join("\n")
}

fn translate_ruby_expr(expr: &str) -> String {
    let mut s = expr
        .replace('$', "")
        .replace("=>", ":")
        .replace("&&", " and ")
        .replace("||", " or ")
        .replace("nil", "None")
        .replace("true", "True")
        .replace("false", "False")
        .replace("event.cancel", "event.cancel()")
        .replace("event.cancel()()", "event.cancel()");

    // Handle `<receiver>.to_i`
    while let Some(idx) = s.find(".to_i") {
        let before = &s[..idx];
        let after = &s[idx + 5..];
        s = format!("_rb_to_i({}){}", before, after);
    }

    s
}
