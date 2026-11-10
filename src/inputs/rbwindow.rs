use crate::config::ast::{ConfigValue, PluginBlock};
use crate::event::Event;
use crate::state::{
    StateStore, COUNTER_STORE, LOC_PSQL_STORE, SCRAMBLES_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use chrono::Utc;

pub const RBWINDOW_LOCK_KEY: &str = "rb:lock:rbwindow";

#[derive(Debug, Clone, PartialEq)]
pub struct RbwindowConfig {
    pub schedule: Option<String>,
    pub database_name: String,
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub memcached_server: String,
}

impl Default for RbwindowConfig {
    fn default() -> Self {
        Self {
            schedule: Some("0 * * * *".to_string()),
            database_name: "redborder".to_string(),
            user: "redborder".to_string(),
            password: String::new(),
            host: "127.0.0.1".to_string(),
            port: 5432,
            memcached_server: "127.0.0.1:11211".to_string(),
        }
    }
}

impl RbwindowConfig {
    pub fn from_plugin_block(block: &PluginBlock) -> Self {
        let mut cfg = Self::default();
        if let Some(sched) = block.get_setting("schedule") {
            match sched {
                ConfigValue::String(s) | ConfigValue::Identifier(s) => {
                    cfg.schedule = Some(s.clone());
                }
                ConfigValue::Map(entries) => {
                    if let Some((_, v)) = entries.iter().find(|(k, _)| k == "cron") {
                        if let Some(s) = v.as_str() {
                            cfg.schedule = Some(s.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        if let Some(db) = block.get_str("database_name") {
            cfg.database_name = db.to_string();
        }
        if let Some(user) = block.get_str("user") {
            cfg.user = user.to_string();
        }
        if let Some(pw) = block.get_str("password") {
            cfg.password = pw.to_string();
        }
        if let Some(host) = block.get_str("host") {
            cfg.host = host.to_string();
        }
        if let Some(port) = block.get_setting("port").and_then(|v| v.as_i64()) {
            cfg.port = port as u16;
        }
        if let Some(mc) = block.get_str("memcached_server") {
            cfg.memcached_server = mc.to_string();
        }
        cfg
    }
}

#[derive(Debug, Clone)]
pub struct RbwindowRunner {
    pub config: RbwindowConfig,
}

impl RbwindowRunner {
    pub fn new(config: RbwindowConfig) -> Self {
        Self { config }
    }

    pub fn from_plugin_block(block: &PluginBlock) -> Self {
        Self::new(RbwindowConfig::from_plugin_block(block))
    }

    pub fn try_acquire_leader_lock(
        state: &StateStore,
        node_name: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<bool> {
        state.acquire_or_renew_leader_lock(RBWINDOW_LOCK_KEY, node_name, ttl_secs)
    }

    pub fn run_tick(&self, state: &StateStore, node_name: &str) -> anyhow::Result<Vec<Event>> {
        if !Self::try_acquire_leader_lock(state, node_name, 60)? {
            return Ok(Vec::new());
        }

        // Increment rbwindow tick counter
        let ticks = state.increment_counter(COUNTER_STORE, "rbwindow_ticks", 1)?;

        // Ensure all PSQL/scramble stores are synchronized across backend periodically (every 5 min or tick 1)
        if ticks == 1 || (ticks > 0 && ticks % 5 == 0) {
            for store_name in [
                WLC_PSQL_STORE,
                SENSOR_PSQL_STORE,
                LOC_PSQL_STORE,
                SCRAMBLES_STORE,
            ] {
                let existing = state.get_store(store_name);
                state.replace_store(store_name, existing)?;
            }
        }

        // Evict expired records from dynamic stores with TTL
        if let Err(e) = state.evict_all_expired() {
            eprintln!("Warning: rbwindow error during expired store eviction: {}", e);
        }

        let now = Utc::now().timestamp();
        let mut ev = Event::new();
        ev.set("type", "monitor");
        ev.set("monitor", "rbwindow");
        ev.set("sensor_name", node_name);
        ev.set("timestamp", now);
        ev.set("rbwindow_ticks", ticks);

        Ok(vec![ev])
    }
}
