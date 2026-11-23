use crate::config::ast::PluginBlock;
use crate::event::Event;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

pub fn default_auto_key_topics() -> Vec<String> {
    if let Ok(env_val) = std::env::var("VORTEX_KAFKA_AUTO_KEY_MAC_TOPICS") {
        let topics: Vec<String> = env_val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !topics.is_empty() {
            return topics;
        }
    }
    vec!["rb_location".to_string(), "rb_mobility".to_string()]
}

#[derive(Debug, Clone)]
pub struct KafkaProducerConfig {
    pub bootstrap_servers: String,
    pub topic_id: String,
    pub codec: String,
    pub client_id: Option<String>,
    pub message_key: Option<String>,
    pub auto_key_field: Option<String>,
    pub auto_key_topics: Vec<String>,
}

impl KafkaProducerConfig {
    pub fn from_plugin_block(block: &PluginBlock) -> Self {
        let topic_id = block
            .get_str("topic_id")
            .or_else(|| block.get_str("topic"))
            .unwrap_or("default_topic")
            .to_string();
        let bootstrap_servers = block
            .get_str("bootstrap_servers")
            .unwrap_or("localhost:9092")
            .to_string();
        let codec = block.get_str("codec").unwrap_or("json").to_string();
        let client_id = block.get_str("client_id").map(|s| s.to_string());
        let message_key = block
            .get_str("message_key")
            .or_else(|| block.get_str("key"))
            .map(|s| s.to_string());
        let auto_key_topics = block
            .get_string_list("auto_key_topics")
            .unwrap_or_else(default_auto_key_topics);
        let auto_key_field = block
            .get_str("auto_key_field")
            .map(|s| s.to_string());

        Self {
            bootstrap_servers,
            topic_id,
            codec,
            client_id,
            message_key,
            auto_key_field,
            auto_key_topics,
        }
    }

    pub fn determine_message_key(&self, event: &Event) -> Option<String> {
        if let Some(ref template) = self.message_key {
            let interpolated = event.interpolate(template);
            if !interpolated.is_empty() {
                return Some(interpolated);
            }
        }

        if let Some(k) = event
            .get("[@metadata][_id]")
            .or_else(|| event.get("[@metadata][kafka_key]"))
            .or_else(|| event.get("[@metadata][kafka][key]"))
            .and_then(|v| v.as_str().map(|s| s.to_string()))
        {
            return Some(k);
        }

        // Automatic fallback for configured topics (default: rb_location, rb_mobility)
        if self.auto_key_topics.iter().any(|t| t == &self.topic_id) {
            let field = self.auto_key_field.as_deref().unwrap_or("client_mac");
            if let Some(val) = event.get_str(field) {
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }

        None
    }

    pub fn to_client_config(&self) -> ClientConfig {
        let mut config = ClientConfig::new();
        config
            .set("bootstrap.servers", &self.bootstrap_servers)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.messages", "100000")
            .set("queue.buffering.max.ms", "20")
            .set("compression.type", "lz4");
        if let Some(cid) = &self.client_id {
            config.set("client.id", cid);
        }
        config
    }

    pub fn create_producer(&self) -> anyhow::Result<FutureProducer> {
        let producer: FutureProducer = self.to_client_config().create()?;
        Ok(producer)
    }
}

#[derive(Clone)]
pub struct LiveKafkaProducer {
    pub config: KafkaProducerConfig,
    pub producer: FutureProducer,
}

impl LiveKafkaProducer {
    pub fn new(config: KafkaProducerConfig) -> anyhow::Result<Self> {
        let producer = config.create_producer()?;
        Ok(Self { config, producer })
    }

    pub async fn emit(&self, event: &Event) -> anyhow::Result<()> {
        let payload = event.to_json_string()?;
        let mut record = FutureRecord::to(&self.config.topic_id).payload(&payload);

        let key_str = self.config.determine_message_key(event);
        if let Some(ref k) = key_str {
            record = record.key(k);
        }

        match self.producer.send(record, Duration::from_secs(5)).await {
            Ok(_) => Ok(()),
            Err((e, _)) => Err(anyhow::anyhow!("Kafka delivery error: {}", e)),
        }
    }
}
