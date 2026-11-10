use anyhow::Context;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DaemonConfig {
    #[serde(rename = "path.settings")]
    pub path_settings: Option<String>,
    #[serde(rename = "pipelines.yml")]
    pub pipelines_yml: Option<String>,
    #[serde(rename = "ipc.socket")]
    pub ipc_socket: Option<String>,
    #[serde(rename = "redis.url")]
    pub redis_url: Option<String>,
    #[serde(rename = "redis.password")]
    pub redis_password: Option<String>,
    #[serde(rename = "plugins.dir")]
    pub plugins_dir: Option<String>,

    #[serde(rename = "postgres.host")]
    pub postgres_host: Option<String>,
    #[serde(rename = "postgres.port")]
    pub postgres_port: Option<u16>,
    #[serde(rename = "postgres.database")]
    pub postgres_database: Option<String>,
    #[serde(rename = "postgres.user")]
    pub postgres_user: Option<String>,
    #[serde(rename = "postgres.password")]
    pub postgres_password: Option<String>,

    #[serde(rename = "kafka.auto_key_mac_topics")]
    pub kafka_auto_key_mac_topics: Option<Vec<String>>,

    #[serde(rename = "nmsp.triangulation")]
    pub nmsp_triangulation: Option<bool>,
    #[serde(rename = "nmsp.triangulation_min_aps")]
    pub nmsp_triangulation_min_aps: Option<usize>,
}

impl DaemonConfig {
    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read daemon config from {:?}", path))?;
        if path.extension().is_some_and(|ext| ext == "json") {
            let cfg: Self = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse JSON config from {:?}", path))?;
            Ok(cfg)
        } else {
            let cfg: Self = serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse YAML config from {:?}", path))?;
            Ok(cfg)
        }
    }

    pub fn full_redis_url(&self) -> Option<String> {
        let raw_url = self.redis_url.as_ref()?;
        let password_candidate = self
            .redis_password
            .as_deref()
            .filter(|p| !p.is_empty())
            .map(|s| s.to_string())
            .or_else(|| std::env::var("REDIS_PASSWORD").ok().filter(|p| !p.is_empty()));
        if let Some(ref pass) = password_candidate {
            if !raw_url.contains('@') {
                let encoded_pass = percent_encode_password(pass);
                if let Some(stripped) = raw_url.strip_prefix("redis://") {
                    return Some(format!("redis://:{}@{}", encoded_pass, stripped));
                } else if let Some(stripped) = raw_url.strip_prefix("rediss://") {
                    return Some(format!("rediss://:{}@{}", encoded_pass, stripped));
                }
            }
        }
        Some(raw_url.clone())
    }

    pub fn merge(&mut self, other: DaemonConfig) {
        if other.path_settings.is_some() {
            self.path_settings = other.path_settings;
        }
        if other.pipelines_yml.is_some() {
            self.pipelines_yml = other.pipelines_yml;
        }
        if other.ipc_socket.is_some() {
            self.ipc_socket = other.ipc_socket;
        }
        if other.redis_url.is_some() {
            self.redis_url = other.redis_url;
            if other.redis_password.is_none() {
                self.redis_password = None;
            }
        }
        if other.redis_password.is_some() {
            self.redis_password = other.redis_password;
        }
        if other.plugins_dir.is_some() {
            self.plugins_dir = other.plugins_dir;
        }
        if other.postgres_host.is_some() {
            self.postgres_host = other.postgres_host;
            if other.postgres_password.is_none() {
                self.postgres_password = None;
            }
        }
        if other.postgres_port.is_some() {
            self.postgres_port = other.postgres_port;
        }
        if other.postgres_database.is_some() {
            self.postgres_database = other.postgres_database;
        }
        if other.postgres_user.is_some() {
            self.postgres_user = other.postgres_user;
        }
        if other.postgres_password.is_some() {
            self.postgres_password = other.postgres_password;
        }
        if other.kafka_auto_key_mac_topics.is_some() {
            self.kafka_auto_key_mac_topics = other.kafka_auto_key_mac_topics;
        }
        if other.nmsp_triangulation.is_some() {
            self.nmsp_triangulation = other.nmsp_triangulation;
        }
        if other.nmsp_triangulation_min_aps.is_some() {
            self.nmsp_triangulation_min_aps = other.nmsp_triangulation_min_aps;
        }
    }

    pub fn resolve(settings_dir: &Path, system_config_dir: &Path) -> Option<Self> {
        // If an explicit config file was passed (-c /path/to/custom.yml), use it directly
        // without inheriting or merging system cluster configuration.
        if settings_dir.is_file() {
            return DaemonConfig::load_from_file(settings_dir).ok();
        }

        let mut base_cfg = [
            system_config_dir.join("config.yml"),
            system_config_dir.join("vortex.yml"),
        ]
        .iter()
        .find_map(|p| {
            if p.exists() {
                DaemonConfig::load_from_file(p).ok()
            } else {
                None
            }
        });

        let custom_cfg = [
            settings_dir.join("vortex.yml"),
            settings_dir.join("config.yml"),
            settings_dir.join("logstash.yml"),
        ]
        .iter()
        .find_map(|p| {
            if p.exists() {
                DaemonConfig::load_from_file(p).ok()
            } else {
                None
            }
        });

        match (base_cfg.as_mut(), custom_cfg) {
            (Some(base), Some(custom)) => {
                base.merge(custom);
                base_cfg
            }
            (Some(_), None) => base_cfg,
            (None, Some(custom)) => Some(custom),
            (None, None) => None,
        }
    }
}

fn percent_encode_password(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(b as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", b));
            }
        }
    }
    encoded
}
