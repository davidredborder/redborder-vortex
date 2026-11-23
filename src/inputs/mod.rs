pub mod file;
pub mod kafka;
pub mod rbwindow;

use crate::config::ast::{ConfigValue, PluginBlock};
pub use file::{FileConsumer, FileInputConfig};
pub use kafka::{borrowed_message_to_event, KafkaConsumerConfig};
pub use rbwindow::{RbwindowConfig, RbwindowRunner};

#[derive(Debug, Clone, PartialEq)]
pub enum InputSpec {
    Kafka {
        topics: Vec<String>,
        bootstrap_servers: String,
        codec: String,
        group_id: String,
        decorate_events: bool,
    },
    File(FileInputConfig),
    Rbwindow(RbwindowConfig),
    Pipeline {
        address: String,
    },
    Exec {
        command: String,
        schedule: Option<String>,
    },
    Other {
        name: String,
    },
}

impl InputSpec {
    pub fn from_plugin_block(block: &PluginBlock, pipeline_id: &str) -> anyhow::Result<Self> {
        match block.name.as_str() {
            "kafka" => {
                let topics = block
                    .get_string_list("topics")
                    .or_else(|| block.get_string_list("topic_id"))
                    .unwrap_or_default();
                let bootstrap_servers = block
                    .get_str("bootstrap_servers")
                    .unwrap_or("localhost:9092")
                    .to_string();
                let codec = block.get_str("codec").unwrap_or("json").to_string();
                let group_id = block
                    .get_str("group_id")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("redborder-vortex-{}", pipeline_id));
                let decorate_events = block
                    .get_setting("decorate_events")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                Ok(Self::Kafka {
                    topics,
                    bootstrap_servers,
                    codec,
                    group_id,
                    decorate_events,
                })
            }
            "file" => {
                let path = block.get_string_list("path").unwrap_or_default();
                let mode = block.get_str("mode").unwrap_or("tail").to_string();
                let sincedb_path = block.get_str("sincedb_path").map(std::path::PathBuf::from);
                let file_completed_action = block.get_str("file_completed_action").map(|s| s.to_string());
                let file_completed_log_path = block
                    .get_str("file_completed_log_path")
                    .map(std::path::PathBuf::from);
                Ok(Self::File(FileInputConfig {
                    path,
                    mode,
                    sincedb_path,
                    file_completed_action,
                    file_completed_log_path,
                }))
            }
            "rbwindow" => Ok(Self::Rbwindow(RbwindowConfig::from_plugin_block(block))),
            "pipeline" => {
                let address = block
                    .get_str("address")
                    .unwrap_or(pipeline_id)
                    .to_string();
                Ok(Self::Pipeline { address })
            }
            "exec" => {
                let command = block.get_str("command").unwrap_or("").to_string();
                let schedule = block.get_setting("schedule").and_then(|v| match v {
                    ConfigValue::String(s) | ConfigValue::Identifier(s) => Some(s.clone()),
                    ConfigValue::Map(entries) => entries
                        .iter()
                        .find(|(k, _)| k == "cron")
                        .and_then(|(_, val)| val.as_str().map(|s| s.to_string())),
                    _ => None,
                });
                Ok(Self::Exec { command, schedule })
            }
            other => Ok(Self::Other {
                name: other.to_string(),
            }),
        }
    }
}
