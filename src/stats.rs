use crate::inputs::rbwindow::RBWINDOW_LOCK_KEY;
use crate::state::{
    StateStore, DWELL_STORE, HISTORICAL_SUFFIX, LOCATION_STORE, LOC_PSQL_STORE, MOBILITY_STORE,
    NMSP_STORE_INFO, NMSP_STORE_MEASURE, RADIUS_STORE, SCRAMBLES_STORE, SENSOR_PSQL_STORE,
    WLC_PSQL_STORE,
};
use chrono::Utc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

pub const CLUSTER_NODES_KV_KEY: &str = "rb:cluster:nodes";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStatus {
    pub id: String,
    pub workers: usize,
    pub input_topics: Vec<String>,
    pub consumer_group: String,
    pub events_in: u64,
    pub events_out: u64,
    pub events_dropped: u64,
    pub errors: u64,
    pub last_run_timestamp: i64,
    pub last_run_duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VortexStats {
    pub uptime_seconds: u64,
    pub node_name: String,
    pub is_rbwindow_leader: bool,
    pub total_workers: usize,
    pub active_workers: usize,
    pub events_received: u64,
    pub events_emitted: u64,
    pub events_dropped: u64,
    pub events_failed: u64,
    pub state_stores: BTreeMap<String, usize>,
    pub pipelines: Vec<PipelineStatus>,
    pub cluster_nodes: Vec<String>,
}

struct PipelineCounters {
    workers: usize,
    input_topics: Vec<String>,
    consumer_group: String,
    events_in: AtomicU64,
    events_out: AtomicU64,
    events_dropped: AtomicU64,
    errors: AtomicU64,
    last_run_timestamp: AtomicI64,
    last_run_duration_us: AtomicU64,
}

pub struct StatsRegistry {
    pub node_name: String,
    started_at: Instant,
    events_received: AtomicU64,
    events_emitted: AtomicU64,
    events_dropped: AtomicU64,
    events_failed: AtomicU64,
    pipelines: DashMap<String, PipelineCounters>,
}

impl StatsRegistry {
    pub fn new(node_name: impl Into<String>) -> Self {
        Self {
            node_name: node_name.into(),
            started_at: Instant::now(),
            events_received: AtomicU64::new(0),
            events_emitted: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            events_failed: AtomicU64::new(0),
            pipelines: DashMap::new(),
        }
    }

    pub fn register_pipeline(
        &self,
        id: &str,
        workers: usize,
        input_topics: Vec<String>,
        consumer_group: String,
    ) {
        self.pipelines.insert(
            id.to_string(),
            PipelineCounters {
                workers,
                input_topics,
                consumer_group,
                events_in: AtomicU64::new(0),
                events_out: AtomicU64::new(0),
                events_dropped: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                last_run_timestamp: AtomicI64::new(0),
                last_run_duration_us: AtomicU64::new(0),
            },
        );
    }

    pub fn update_or_register_pipeline(
        &self,
        id: &str,
        workers: usize,
        input_topics: Vec<String>,
        consumer_group: String,
    ) {
        if let Some(mut existing) = self.pipelines.get_mut(id) {
            existing.workers = workers;
            existing.input_topics = input_topics;
            existing.consumer_group = consumer_group;
        } else {
            self.register_pipeline(id, workers, input_topics, consumer_group);
        }
    }

    pub fn retain_pipelines(&self, active_ids: &[String]) {
        self.pipelines.retain(|id, _| active_ids.iter().any(|act| act == id));
    }

    pub fn record_pipeline_run(
        &self,
        id: &str,
        events_in: u64,
        events_out: u64,
        events_dropped: u64,
        errors: u64,
        duration_us: u64,
    ) {
        self.events_received.fetch_add(events_in, Ordering::Relaxed);
        self.events_emitted.fetch_add(events_out, Ordering::Relaxed);
        self.events_dropped
            .fetch_add(events_dropped, Ordering::Relaxed);
        self.events_failed.fetch_add(errors, Ordering::Relaxed);

        let now = Utc::now().timestamp();
        if let Some(entry) = self.pipelines.get(id) {
            entry.events_in.fetch_add(events_in, Ordering::Relaxed);
            entry.events_out.fetch_add(events_out, Ordering::Relaxed);
            entry
                .events_dropped
                .fetch_add(events_dropped, Ordering::Relaxed);
            entry.errors.fetch_add(errors, Ordering::Relaxed);
            entry.last_run_timestamp.store(now, Ordering::Relaxed);
            entry
                .last_run_duration_us
                .store(duration_us, Ordering::Relaxed);
        }
    }

    pub fn get_stats(&self, state: &StateStore) -> VortexStats {
        let uptime_seconds = self.started_at.elapsed().as_secs();
        let is_rbwindow_leader = state
            .get_kv(RBWINDOW_LOCK_KEY)
            .ok()
            .flatten()
            .map(|holder| holder == self.node_name)
            .unwrap_or(false);

        let mut pipelines_list: Vec<PipelineStatus> = self
            .pipelines
            .iter()
            .map(|entry| {
                let c = entry.value();
                PipelineStatus {
                    id: entry.key().clone(),
                    workers: c.workers,
                    input_topics: c.input_topics.clone(),
                    consumer_group: c.consumer_group.clone(),
                    events_in: c.events_in.load(Ordering::Relaxed),
                    events_out: c.events_out.load(Ordering::Relaxed),
                    events_dropped: c.events_dropped.load(Ordering::Relaxed),
                    errors: c.errors.load(Ordering::Relaxed),
                    last_run_timestamp: c.last_run_timestamp.load(Ordering::Relaxed),
                    last_run_duration_us: c.last_run_duration_us.load(Ordering::Relaxed),
                }
            })
            .collect();
        pipelines_list.sort_by(|a, b| a.id.cmp(&b.id));

        let total_workers: usize = pipelines_list.iter().map(|p| p.workers).sum();
        let active_workers = total_workers;

        let mut state_stores = BTreeMap::new();
        let base_stores = [
            WLC_PSQL_STORE,
            SENSOR_PSQL_STORE,
            LOC_PSQL_STORE,
            NMSP_STORE_MEASURE,
            NMSP_STORE_INFO,
            RADIUS_STORE,
            LOCATION_STORE,
            DWELL_STORE,
            SCRAMBLES_STORE,
            MOBILITY_STORE,
        ];
        for s in base_stores {
            state_stores.insert(s.to_string(), state.get_store(s).len());
        }
        for s in [
            MOBILITY_STORE,
            LOCATION_STORE,
            NMSP_STORE_MEASURE,
            NMSP_STORE_INFO,
            RADIUS_STORE,
        ] {
            let hist = format!("{}{}", s, HISTORICAL_SUFFIX);
            let len = state.get_store(&hist).len();
            if len > 0 {
                state_stores.insert(hist, len);
            }
        }

        let mut cluster_nodes: Vec<String> = state
            .get_kv(CLUSTER_NODES_KV_KEY)
            .ok()
            .flatten()
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        if !cluster_nodes.contains(&self.node_name) {
            cluster_nodes.push(self.node_name.clone());
        }
        cluster_nodes.sort();
        cluster_nodes.dedup();

        VortexStats {
            uptime_seconds,
            node_name: self.node_name.clone(),
            is_rbwindow_leader,
            total_workers,
            active_workers,
            events_received: self.events_received.load(Ordering::Relaxed),
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            events_failed: self.events_failed.load(Ordering::Relaxed),
            state_stores,
            pipelines: pipelines_list,
            cluster_nodes,
        }
    }

    pub fn reset_stats(&self) {
        self.events_received.store(0, Ordering::Relaxed);
        self.events_emitted.store(0, Ordering::Relaxed);
        self.events_dropped.store(0, Ordering::Relaxed);
        self.events_failed.store(0, Ordering::Relaxed);

        for entry in self.pipelines.iter() {
            let c = entry.value();
            c.events_in.store(0, Ordering::Relaxed);
            c.events_out.store(0, Ordering::Relaxed);
            c.events_dropped.store(0, Ordering::Relaxed);
            c.errors.store(0, Ordering::Relaxed);
            c.last_run_timestamp.store(0, Ordering::Relaxed);
            c.last_run_duration_us.store(0, Ordering::Relaxed);
        }
    }
}
