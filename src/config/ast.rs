use crate::event::Event;
use serde_json::{Number, Value};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PipelineConfig {
    pub inputs: Vec<PluginBlock>,
    pub filters: Vec<Statement>,
    pub outputs: Vec<Statement>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Statement {
    Plugin(PluginBlock),
    Conditional(ConditionalBlock),
}

#[derive(Debug, Clone, PartialEq)]
pub struct PluginBlock {
    pub name: String,
    pub settings: Vec<(String, ConfigValue)>,
}

impl PluginBlock {
    pub fn get_setting(&self, key: &str) -> Option<&ConfigValue> {
        self.settings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get_setting(key).and_then(|v| v.as_str())
    }

    pub fn get_string_list(&self, key: &str) -> Option<Vec<String>> {
        match self.get_setting(key)? {
            ConfigValue::Array(items) => {
                let mut res = Vec::with_capacity(items.len());
                for item in items {
                    res.push(item.as_str()?.to_string());
                }
                Some(res)
            }
            v => v.as_str().map(|s| vec![s.to_string()]),
        }
    }

    pub fn get_map(&self, key: &str) -> Option<Vec<(String, ConfigValue)>> {
        match self.get_setting(key)? {
            ConfigValue::Map(entries) => Some(entries.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    String(String),
    Number(f64),
    Integer(i64),
    Bool(bool),
    Identifier(String),
    Array(Vec<ConfigValue>),
    Map(Vec<(String, ConfigValue)>),
}

impl ConfigValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConfigValue::String(s) | ConfigValue::Identifier(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ConfigValue::Integer(n) => Some(*n),
            ConfigValue::Number(f) => Some(*f as i64),
            ConfigValue::String(s) | ConfigValue::Identifier(s) => s.parse::<i64>().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            ConfigValue::Number(f) => Some(*f),
            ConfigValue::Integer(n) => Some(*n as f64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConfigValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn to_json_value(&self) -> Value {
        match self {
            ConfigValue::String(s) | ConfigValue::Identifier(s) => Value::String(s.clone()),
            ConfigValue::Integer(i) => Value::Number((*i).into()),
            ConfigValue::Number(f) => Number::from_f64(*f)
                .map(Value::Number)
                .unwrap_or(Value::Null),
            ConfigValue::Bool(b) => Value::Bool(*b),
            ConfigValue::Array(items) => {
                Value::Array(items.iter().map(|v| v.to_json_value()).collect())
            }
            ConfigValue::Map(entries) => {
                let mut map = serde_json::Map::new();
                for (k, v) in entries {
                    map.insert(k.clone(), v.to_json_value());
                }
                Value::Object(map)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConditionalBlock {
    pub branches: Vec<(Expr, Vec<Statement>)>,
    pub else_branch: Option<Vec<Statement>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    FieldExists(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Compare {
        left: Operand,
        op: CompareOp,
        right: Operand,
    },
    In {
        needle: Operand,
        haystack: Operand,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    NotEq,
    Lt,
    Lte,
    Gt,
    Gte,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    Field(String),
    Literal(ConfigValue),
}

fn resolve_operand(op: &Operand, event: &Event) -> Option<Value> {
    match op {
        Operand::Field(path) => event.get(path).cloned().filter(|v| !v.is_null()),
        Operand::Literal(cfg) => Some(cfg.to_json_value()),
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(na), Value::Number(nb)) => {
            if let (Some(ia), Some(ib)) = (na.as_i64(), nb.as_i64()) {
                ia == ib
            } else if let (Some(fa), Some(fb)) = (na.as_f64(), nb.as_f64()) {
                fa == fb
            } else {
                false
            }
        }
        (Value::String(sa), Value::String(sb)) => sa == sb,
        (Value::Bool(ba), Value::Bool(bb)) => ba == bb,
        (Value::Array(aa), Value::Array(ab)) => {
            aa.len() == ab.len() && aa.iter().zip(ab.iter()).all(|(x, y)| values_equal(x, y))
        }
        (Value::Object(oa), Value::Object(ob)) => oa == ob,
        (Value::Null, Value::Null) => true,
        _ => false,
    }
}

fn compare_values(left: Option<Value>, op: CompareOp, right: Option<Value>) -> bool {
    match (left, right) {
        (None, None) => matches!(op, CompareOp::Eq | CompareOp::Lte | CompareOp::Gte),
        (None, Some(_)) | (Some(_), None) => matches!(op, CompareOp::NotEq),
        (Some(l), Some(r)) => match op {
            CompareOp::Eq => values_equal(&l, &r),
            CompareOp::NotEq => !values_equal(&l, &r),
            CompareOp::Lt | CompareOp::Lte | CompareOp::Gt | CompareOp::Gte => match (&l, &r) {
                (Value::Number(nl), Value::Number(nr)) => {
                    if let (Some(fl), Some(fr)) = (nl.as_f64(), nr.as_f64()) {
                        match op {
                            CompareOp::Lt => fl < fr,
                            CompareOp::Lte => fl <= fr,
                            CompareOp::Gt => fl > fr,
                            CompareOp::Gte => fl >= fr,
                            _ => unreachable!(),
                        }
                    } else {
                        false
                    }
                }
                (Value::String(sl), Value::String(sr)) => match op {
                    CompareOp::Lt => sl < sr,
                    CompareOp::Lte => sl <= sr,
                    CompareOp::Gt => sl > sr,
                    CompareOp::Gte => sl >= sr,
                    _ => unreachable!(),
                },
                _ => false,
            },
        },
    }
}

pub fn eval_expr(expr: &Expr, event: &Event) -> bool {
    match expr {
        Expr::FieldExists(path) => match event.get(path) {
            None | Some(Value::Null) | Some(Value::Bool(false)) => false,
            Some(Value::String(s)) => !s.is_empty(),
            Some(_) => true,
        },
        Expr::Not(inner) => !eval_expr(inner, event),
        Expr::And(a, b) => eval_expr(a, event) && eval_expr(b, event),
        Expr::Or(a, b) => eval_expr(a, event) || eval_expr(b, event),
        Expr::Compare { left, op, right } => {
            let l = resolve_operand(left, event);
            let r = resolve_operand(right, event);
            compare_values(l, *op, r)
        }
        Expr::In { needle, haystack } => {
            let Some(needle_val) = resolve_operand(needle, event) else {
                return false;
            };
            let Some(haystack_val) = resolve_operand(haystack, event) else {
                return false;
            };
            match haystack_val {
                Value::Array(items) => items.iter().any(|item| values_equal(&needle_val, item)),
                Value::String(s) => {
                    if let Some(needle_str) = needle_val.as_str() {
                        s.contains(needle_str)
                    } else {
                        false
                    }
                }
                _ => false,
            }
        }
    }
}
