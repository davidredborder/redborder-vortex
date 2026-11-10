use crate::config::ast::PluginBlock;
use crate::event::Event;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{BorrowedMessage, Headers, Message};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct KafkaConsumerConfig {
    pub bootstrap_servers: String,
    pub group_id: String,
    pub topics: Vec<String>,
    pub codec: String,
    pub decorate_events: bool,
    pub auto_offset_reset: String,
    pub session_timeout_ms: String,
}

impl KafkaConsumerConfig {
    pub fn from_plugin_block(block: &PluginBlock, pipeline_id: &str) -> Self {
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
        let auto_offset_reset = block
            .get_str("auto_offset_reset")
            .unwrap_or("latest")
            .to_string();

        Self {
            bootstrap_servers,
            group_id,
            topics,
            codec,
            decorate_events,
            auto_offset_reset,
            session_timeout_ms: "45000".to_string(),
        }
    }

    pub fn to_client_config(&self) -> ClientConfig {
        let mut config = ClientConfig::new();
        config
            .set("bootstrap.servers", &self.bootstrap_servers)
            .set("group.id", &self.group_id)
            .set("enable.auto.commit", "true")
            .set("auto.commit.interval.ms", "5000")
            .set("auto.offset.reset", &self.auto_offset_reset)
            .set("session.timeout.ms", &self.session_timeout_ms)
            .set("max.poll.interval.ms", "300000");
        config
    }

    pub fn create_consumer(&self) -> anyhow::Result<StreamConsumer> {
        let consumer: StreamConsumer = self.to_client_config().create()?;
        let topic_refs: Vec<&str> = self.topics.iter().map(|s| s.as_str()).collect();
        if !topic_refs.is_empty() {
            consumer.subscribe(&topic_refs)?;
        }
        Ok(consumer)
    }
}

pub fn borrowed_message_to_event(
    msg: &BorrowedMessage,
    decorate: bool,
) -> anyhow::Result<Event> {
    let payload = msg.payload().unwrap_or(b"{}");
    let mut event = match serde_json::from_slice::<Value>(payload) {
        Ok(Value::Object(map)) => Event::from_map(map),
        Ok(other) => {
            let mut ev = Event::new();
            ev.set("message", other);
            ev
        }
        Err(_) => {
            let mut ev = Event::new();
            let text = String::from_utf8_lossy(payload).to_string();
            ev.set("message", text);
            ev
        }
    };

    if decorate {
        event.set("[@metadata][kafka][topic]", msg.topic());
        event.set("[@metadata][kafka][partition]", msg.partition() as i64);
        event.set("[@metadata][kafka][offset]", msg.offset());
        if let Some(key) = msg.key() {
            event.set(
                "[@metadata][kafka][key]",
                String::from_utf8_lossy(key).to_string(),
            );
        }
        if let Some(ts) = msg.timestamp().to_millis() {
            event.set("[@metadata][kafka][timestamp]", ts);
        }
        if let Some(headers) = msg.headers() {
            for i in 0..headers.count() {
                let header = headers.get(i);
                let key = header.key;
                if let Some(val) = header.value {
                    let path = format!("[@metadata][kafka][headers][{}]", key);
                    event.set(&path, String::from_utf8_lossy(val).to_string());
                }
            }
        }
    }

    Ok(event)
}
