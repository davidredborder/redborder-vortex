use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    #[serde(flatten)]
    data: Map<String, Value>,
    #[serde(skip)]
    cancelled: bool,
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

struct StripMetadataMap<'a>(&'a Map<String, Value>);

impl<'a> Serialize for StripMetadataMap<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let count = self.0.len().saturating_sub(1);
        let mut map = serializer.serialize_map(Some(count))?;
        for (k, v) in self.0.iter() {
            if k != "@metadata" {
                map.serialize_entry(k, v)?;
            }
        }
        map.end()
    }
}

fn parse_path(path: &str) -> Vec<&str> {
    let trimmed = path.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let mut segments = Vec::new();
        let mut rest = trimmed;
        while let Some( after_open) = rest.strip_prefix('[') {
            if let Some(close_idx) = after_open.find(']') {
                segments.push(&after_open[..close_idx]);
                rest = &after_open[close_idx + 1..];
            } else {
                break;
            }
        }
        if rest.is_empty() && !segments.is_empty() {
            return segments;
        }
    }
    vec![path]
}

impl Event {
    pub fn new() -> Self {
        let mut data = Map::new();
        data.insert(
            "@timestamp".to_string(),
            Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
        );
        data.insert("@version".to_string(), Value::String("1".to_string()));
        Self {
            data,
            cancelled: false,
        }
    }

    pub fn from_json_str(s: &str) -> anyhow::Result<Self> {
        let data: Map<String, Value> = serde_json::from_str(s)?;
        Ok(Self::from_map(data))
    }

    pub fn from_map(map: Map<String, Value>) -> Self {
        Self {
            data: map,
            cancelled: false,
        }
    }

    pub fn to_json_string(&self) -> anyhow::Result<String> {
        if self.data.contains_key("@metadata") {
            Ok(serde_json::to_string(&StripMetadataMap(&self.data))?)
        } else {
            Ok(serde_json::to_string(&self.data)?)
        }
    }

    pub fn as_map(&self) -> &Map<String, Value> {
        &self.data
    }

    pub fn as_map_mut(&mut self) -> &mut Map<String, Value> {
        &mut self.data
    }

    pub fn into_map(self) -> Map<String, Value> {
        self.data
    }

    pub fn get(&self, path: &str) -> Option<&Value> {
        let segments = parse_path(path);
        let (first, tail) = segments.split_first()?;
        let mut current = self.data.get(*first)?;
        for seg in tail {
            if let Some(obj) = current.as_object() {
                current = obj.get(*seg)?;
            } else {
                let arr = current.as_array()?;
                let idx = seg.parse::<usize>().ok()?;
                current = arr.get(idx)?;
            }
        }
        Some(current)
    }

    pub fn get_str(&self, path: &str) -> Option<String> {
        let val = self.get(path)?;
        match val {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn get_i64(&self, path: &str) -> Option<i64> {
        let val = self.get(path)?;
        match val {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn set(&mut self, path: &str, value: impl Into<Value>) {
        let val = value.into();
        let segments = parse_path(path);
        if segments.is_empty() {
            return;
        }
        if segments.len() == 1 {
            self.data.insert(segments[0].to_string(), val);
            return;
        }

        let first = segments[0];
        let entry = self
            .data
            .entry(first.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }

        let mut current = entry;
        for seg in &segments[1..segments.len() - 1] {
            let obj = current.as_object_mut().expect("Guaranteed to be an Object");
            let next = obj
                .entry((*seg).to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if !next.is_object() {
                *next = Value::Object(Map::new());
            }
            current = next;
        }

        if let Some(last) = segments.last() {
            if let Some(obj) = current.as_object_mut() {
                obj.insert((*last).to_string(), val);
            }
        }
    }

    pub fn remove(&mut self, path: &str) -> Option<Value> {
        let segments = parse_path(path);
        if segments.is_empty() {
            return None;
        }
        if segments.len() == 1 {
            return self.data.remove(segments[0]);
        }

        let mut current = self.data.get_mut(segments[0])?;
        for seg in &segments[1..segments.len() - 1] {
            current = current.as_object_mut()?.get_mut(*seg)?;
        }
        let last = segments.last()?;
        current.as_object_mut()?.remove(*last)
    }

    pub fn contains(&self, path: &str) -> bool {
        matches!(self.get(path), Some(v) if !v.is_null())
    }

    pub fn interpolate(&self, template: &str) -> String {
        let mut out = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(start) = rest.find("%{") {
            out.push_str(&rest[..start]);
            let after_start = &rest[start + 2..];
            if let Some(end) = after_start.find('}') {
                let field_path = &after_start[..end];
                if let Some(val_str) = self.get_str(field_path) {
                    out.push_str(&val_str);
                }
                rest = &after_start[end + 1..];
            } else {
                out.push_str(&rest[start..]);
                return out;
            }
        }
        out.push_str(rest);
        out
    }

    pub fn tag(&mut self, tag_name: &str) {
        let tags_entry = self
            .data
            .entry("tags".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if !tags_entry.is_array() {
            *tags_entry = Value::Array(Vec::new());
        }
        if let Some(arr) = tags_entry.as_array_mut() {
            if !arr.iter().any(|v| v.as_str() == Some(tag_name)) {
                arr.push(json!(tag_name));
            }
        }
    }

    pub fn has_tag(&self, tag_name: &str) -> bool {
        self.data
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some(tag_name)))
            .unwrap_or(false)
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    pub fn clone_with_overrides(
        &self,
        overrides: Map<String, Value>,
        removed_keys: &[&str],
    ) -> Event {
        let mut cloned = self.clone();
        for key in removed_keys {
            cloned.remove(key);
        }
        for (k, v) in overrides {
            cloned.set(&k, v);
        }
        cloned
    }
}
