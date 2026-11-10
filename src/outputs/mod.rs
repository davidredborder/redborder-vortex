pub mod kafka;

use crate::config::ast::PluginBlock;
use crate::event::Event;
pub use kafka::{KafkaProducerConfig, LiveKafkaProducer};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct KafkaOutput {
    pub topic_id: String,
    pub bootstrap_servers: String,
    pub codec: String,
    pub message_key: Option<String>,
    pub auto_key_field: Option<String>,
    pub auto_key_topics: Vec<String>,
    pub emitted: Arc<Mutex<Vec<Event>>>,
    pub live_producer: Option<Arc<LiveKafkaProducer>>,
}

impl std::fmt::Debug for KafkaOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaOutput")
            .field("topic_id", &self.topic_id)
            .field("bootstrap_servers", &self.bootstrap_servers)
            .field("codec", &self.codec)
            .field("message_key", &self.message_key)
            .field("auto_key_field", &self.auto_key_field)
            .field("auto_key_topics", &self.auto_key_topics)
            .finish()
    }
}

impl KafkaOutput {
    pub fn new(
        topic_id: impl Into<String>,
        bootstrap_servers: impl Into<String>,
        codec: impl Into<String>,
    ) -> Self {
        Self {
            topic_id: topic_id.into(),
            bootstrap_servers: bootstrap_servers.into(),
            codec: codec.into(),
            message_key: None,
            auto_key_field: None,
            auto_key_topics: kafka::default_auto_key_topics(),
            emitted: Arc::new(Mutex::new(Vec::new())),
            live_producer: None,
        }
    }

    pub fn attach_live_producer(&mut self, producer: Arc<LiveKafkaProducer>) {
        self.live_producer = Some(producer);
    }

    pub fn from_plugin_block(block: &PluginBlock) -> anyhow::Result<Self> {
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
        let message_key = block
            .get_str("message_key")
            .or_else(|| block.get_str("key"))
            .map(|s| s.to_string());
        let auto_key_field = block
            .get_str("auto_key_field")
            .map(|s| s.to_string());
        let auto_key_topics = block
            .get_string_list("auto_key_topics")
            .unwrap_or_else(kafka::default_auto_key_topics);

        let mut out = Self::new(topic_id, bootstrap_servers, codec);
        out.message_key = message_key;
        out.auto_key_field = auto_key_field;
        out.auto_key_topics = auto_key_topics;
        Ok(out)
    }

    pub fn emit(&self, event: Event) -> anyhow::Result<()> {
        if let Some(ref live) = self.live_producer {
            let lp = live.clone();
            let ev = event.clone();
            tokio::spawn(async move {
                if let Err(e) = lp.emit(&ev).await {
                    eprintln!("Error sending Kafka message: {:#}", e);
                }
            });
        }
        if let Ok(mut guard) = self.emitted.lock() {
            // Keep bounded buffer in case of huge benchmark runs while preserving recent events
            if guard.len() < 10_000 {
                guard.push(event);
            }
        }
        Ok(())
    }

    pub fn emitted_events(&self) -> Vec<Event> {
        self.emitted
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct PipelineOutput {
    pub send_to: Vec<String>,
    pub live_senders: Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<Event>>>>,
}

impl std::fmt::Debug for PipelineOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineOutput")
            .field("send_to", &self.send_to)
            .finish()
    }
}

impl PipelineOutput {
    pub fn new(send_to: Vec<String>) -> Self {
        Self {
            send_to,
            live_senders: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn attach_sender(&mut self, sender: tokio::sync::mpsc::UnboundedSender<Event>) {
        if let Ok(mut guard) = self.live_senders.lock() {
            guard.push(sender);
        }
    }

    pub fn from_plugin_block(block: &PluginBlock) -> anyhow::Result<Self> {
        let send_to = block
            .get_string_list("send_to")
            .unwrap_or_else(|| {
                block
                    .get_str("send_to")
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default()
            });
        Ok(Self::new(send_to))
    }

    pub fn emit(&self, event: &Event) -> anyhow::Result<()> {
        if let Ok(guard) = self.live_senders.lock() {
            for sender in guard.iter() {
                if let Err(e) = sender.send(event.clone()) {
                    eprintln!("Warning: Failed to deliver event to downstream pipeline: {}", e);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct StdoutOutput {
    pub codec: String,
}

impl StdoutOutput {
    pub fn from_plugin_block(block: &PluginBlock) -> anyhow::Result<Self> {
        let codec = block.get_str("codec").unwrap_or("json").to_string();
        Ok(Self { codec })
    }

    pub fn serialize_event(&self, event: &Event) -> anyhow::Result<String> {
        event.to_json_string()
    }
}

#[derive(Debug, Clone)]
pub enum OutputSink {
    Kafka(KafkaOutput),
    Stdout(StdoutOutput),
    Pipeline(PipelineOutput),
    Other(String),
}

impl OutputSink {
    pub fn from_plugin_block(block: &PluginBlock) -> anyhow::Result<Self> {
        match block.name.as_str() {
            "kafka" => Ok(Self::Kafka(KafkaOutput::from_plugin_block(block)?)),
            "stdout" => Ok(Self::Stdout(StdoutOutput::from_plugin_block(block)?)),
            "pipeline" => Ok(Self::Pipeline(PipelineOutput::from_plugin_block(block)?)),
            other => Ok(Self::Other(other.to_string())),
        }
    }

    pub fn target_name(&self) -> &str {
        match self {
            Self::Kafka(k) => &k.topic_id,
            Self::Stdout(_) => "stdout",
            Self::Pipeline(_) => "pipeline",
            Self::Other(n) => n,
        }
    }

    pub fn emit(&self, event: &Event) -> anyhow::Result<()> {
        match self {
            Self::Kafka(k) => k.emit(event.clone()),
            Self::Stdout(s) => {
                let _ = s.serialize_event(event)?;
                Ok(())
            }
            Self::Pipeline(p) => p.emit(event),
            Self::Other(_) => Ok(()),
        }
    }
}
