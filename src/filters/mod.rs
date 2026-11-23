pub mod builtin;
pub mod python;
pub mod redborder;

use crate::config::ast::PluginBlock;
use crate::event::Event;
use crate::state::StateStore;
use serde_json::{Map, Value};

pub trait Filter: Send + Sync {
    fn process(&self, event: Event, state: &StateStore) -> anyhow::Result<Vec<Event>>;
}

pub struct NoopFilter;

impl Filter for NoopFilter {
    fn process(&self, event: Event, _state: &StateStore) -> anyhow::Result<Vec<Event>> {
        Ok(vec![event])
    }
}

fn plugin_settings_to_map(block: &PluginBlock) -> Map<String, Value> {
    let mut map = Map::new();
    for (k, v) in &block.settings {
        map.insert(k.clone(), v.to_json_value());
    }
    map
}

pub fn create_filter(block: &PluginBlock) -> anyhow::Result<Box<dyn Filter>> {
    if let Some(f) = builtin::from_plugin_block(block)? {
        return Ok(f);
    }
    if let Some(f) = redborder::from_plugin_block(block)? {
        return Ok(f);
    }
    match block.name.as_str() {
        "python" => Ok(Box::new(python::PythonFilter::from_plugin_block(block)?)),
        "ruby" => Ok(Box::new(python::RubyCompatFilter::from_plugin_block(block)?)),
        "yara" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "malware",
                Some("yara_scan"),
                Some(cfg),
            )?))
        }
        "clamscan" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "malware",
                Some("clamscan_scan"),
                Some(cfg),
            )?))
        }
        "virustotal" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "malware",
                Some("virustotal_scan"),
                Some(cfg),
            )?))
        }
        "metadefender" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "malware",
                Some("metadefender_scan"),
                Some(cfg),
            )?))
        }
        "aerospike-malware-score" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "malware",
                Some("aerospike_malware_score"),
                Some(cfg),
            )?))
        }
        "s3-upload-malware-results" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "malware",
                Some("s3_upload_malware_results"),
                Some(cfg),
            )?))
        }
        "ips" => {
            let cfg = plugin_settings_to_map(block);
            Ok(Box::new(python::PythonFilter::new_module(
                "ips",
                Some("ips_filter"),
                Some(cfg),
            )?))
        }
        _ => Ok(Box::new(NoopFilter)),
    }
}
