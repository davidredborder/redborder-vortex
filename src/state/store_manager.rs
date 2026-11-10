use crate::event::Event;
use crate::state::redis_backend::ClusterBackend;
use crate::state::{
    COUNTER_STORE, DEVICE_IP_PSQL_STORE, DEVICE_MAC_PSQL_STORE, DWELL_STORE, FLOWS_NUMBER,
    HISTORICAL_SUFFIX, LOCATION_STORE, LOC_PSQL_STORE, MOBILITY_STORE, NMSP_STORE_INFO,
    NMSP_STORE_MEASURE, RADIUS_STORE, SCRAMBLES_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use dashmap::DashMap;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

const ENRICH_STORES: [&str; 7] = [
    WLC_PSQL_STORE,
    SENSOR_PSQL_STORE,
    NMSP_STORE_MEASURE,
    NMSP_STORE_INFO,
    RADIUS_STORE,
    LOCATION_STORE,
    DWELL_STORE,
];

const DAILY_ROTATE_STORES: [&str; 5] = [
    MOBILITY_STORE,
    LOCATION_STORE,
    NMSP_STORE_MEASURE,
    NMSP_STORE_INFO,
    RADIUS_STORE,
];

pub const DYNAMIC_TTL_STORES: [&str; 6] = [
    MOBILITY_STORE,
    DWELL_STORE,
    LOCATION_STORE,
    NMSP_STORE_MEASURE,
    NMSP_STORE_INFO,
    RADIUS_STORE,
];

pub struct StateStore {
    stores: DashMap<String, DashMap<String, Map<String, Value>>>,
    ttls: DashMap<String, DashMap<String, f64>>,
    counters: DashMap<String, DashMap<String, i64>>,
    kv: DashMap<String, String>,
    backend: Option<Arc<dyn ClusterBackend>>,
}

impl Default for StateStore {
    fn default() -> Self {
        Self::new_standalone()
    }
}

impl StateStore {
    pub fn new_standalone() -> Self {
        Self {
            stores: DashMap::new(),
            ttls: DashMap::new(),
            counters: DashMap::new(),
            kv: DashMap::new(),
            backend: None,
        }
    }

    pub fn with_backend(backend: Arc<dyn ClusterBackend>) -> Self {
        Self {
            stores: DashMap::new(),
            ttls: DashMap::new(),
            counters: DashMap::new(),
            kv: DashMap::new(),
            backend: Some(backend),
        }
    }

    pub fn new_with_redis(redis_url: &str) -> anyhow::Result<Self> {
        let backend = Arc::new(crate::state::RedisClusterBackend::new(redis_url)?);
        Ok(Self::with_backend(backend))
    }

    pub fn put_record(
        &self,
        store_name: &str,
        record_key: &str,
        value: Map<String, Value>,
    ) -> anyhow::Result<()> {
        let ttl_secs = if DYNAMIC_TTL_STORES.contains(&store_name) {
            Some(86400)
        } else {
            None
        };
        self.put_record_with_ttl(store_name, record_key, value, ttl_secs)
    }

    pub fn put_record_with_ttl(
        &self,
        store_name: &str,
        record_key: &str,
        value: Map<String, Value>,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        if let Some(backend) = &self.backend {
            backend.hset_record_with_ttl(store_name, record_key, &value, ttl_secs)?;
        }
        let store = self
            .stores
            .entry(store_name.to_string())
            .or_default();
        store.insert(record_key.to_string(), value);
        if let Some(ttl) = ttl_secs {
            let expire_at = chrono::Utc::now().timestamp() as f64 + ttl as f64;
            let tstore = self.ttls.entry(store_name.to_string()).or_default();
            tstore.insert(record_key.to_string(), expire_at);
        }
        Ok(())
    }

    pub fn put_record_local(
        &self,
        store_name: &str,
        record_key: &str,
        value: Map<String, Value>,
    ) {
        let store = self
            .stores
            .entry(store_name.to_string())
            .or_default();
        store.insert(record_key.to_string(), value);
    }

    pub fn remove_record_local(&self, store_name: &str, record_key: &str) {
        if let Some(store) = self.stores.get(store_name) {
            store.remove(record_key);
        }
        if let Some(tstore) = self.ttls.get(store_name) {
            tstore.remove(record_key);
        }
    }

    pub fn replace_store_local(
        &self,
        store_name: &str,
        records: HashMap<String, Map<String, Value>>,
    ) {
        let new_map = DashMap::new();
        for (k, v) in records {
            new_map.insert(k, v);
        }
        self.stores.insert(store_name.to_string(), new_map);
    }

    pub fn get_record(&self, store_name: &str, record_key: &str) -> Option<Map<String, Value>> {
        self.stores
            .get(store_name)
            .and_then(|s| s.get(record_key).map(|v| v.value().clone()))
    }

    pub fn get_record_with_historical(
        &self,
        store_name: &str,
        record_key: &str,
    ) -> Option<Map<String, Value>> {
        self.get_record(store_name, record_key).or_else(|| {
            let hist_store = format!("{}{}", store_name, HISTORICAL_SUFFIX);
            self.get_record(&hist_store, record_key)
        })
    }

    pub fn replace_store(
        &self,
        store_name: &str,
        records: HashMap<String, Map<String, Value>>,
    ) -> anyhow::Result<()> {
        if let Some(backend) = &self.backend {
            backend.replace_store(store_name, &records)?;
        }
        self.replace_store_local(store_name, records);
        Ok(())
    }

    pub fn get_store(&self, store_name: &str) -> HashMap<String, Map<String, Value>> {
        let mut out = HashMap::new();
        if let Some(store) = self.stores.get(store_name) {
            for entry in store.iter() {
                out.insert(entry.key().clone(), entry.value().clone());
            }
        }
        out
    }

    pub fn sync_store_from_backend(&self, store_name: &str) -> anyhow::Result<()> {
        let Some(backend) = &self.backend else {
            return Ok(());
        };
        let remote = backend.hgetall_store(store_name)?;
        self.replace_store_local(store_name, remote);
        Ok(())
    }

    pub fn sync_from_backend(&self) -> anyhow::Result<()> {
        let Some(backend) = &self.backend else {
            return Ok(());
        };

        let base_stores = [
            WLC_PSQL_STORE,
            SENSOR_PSQL_STORE,
            DEVICE_IP_PSQL_STORE,
            DEVICE_MAC_PSQL_STORE,
            LOC_PSQL_STORE,
            NMSP_STORE_MEASURE,
            NMSP_STORE_INFO,
            RADIUS_STORE,
            LOCATION_STORE,
            SCRAMBLES_STORE,
            MOBILITY_STORE,
        ];

        let mut all_store_names: Vec<String> = base_stores.iter().map(|s| s.to_string()).collect();
        for s in DAILY_ROTATE_STORES {
            all_store_names.push(format!("{}{}", s, HISTORICAL_SUFFIX));
        }

        for store_name in all_store_names {
            self.sync_store_from_backend(&store_name)?;
        }

        for counter_store in [COUNTER_STORE, FLOWS_NUMBER] {
            let remote_counters = backend.hget_counters(counter_store)?;
            let local_counters = DashMap::new();
            for (k, v) in remote_counters {
                local_counters.insert(k, v);
            }
            self.counters
                .insert(counter_store.to_string(), local_counters);
        }

        Ok(())
    }

    pub fn evict_expired_records(&self, store_name: &str) -> anyhow::Result<Vec<String>> {
        let evicted = if let Some(backend) = &self.backend {
            backend.evict_expired(store_name)?
        } else {
            let now = chrono::Utc::now().timestamp() as f64;
            let candidates: Vec<String> = if let Some(tstore) = self.ttls.get(store_name) {
                tstore
                    .iter()
                    .filter(|entry| *entry.value() <= now)
                    .map(|entry| entry.key().clone())
                    .collect()
            } else {
                Vec::new()
            };

            let mut expired = Vec::new();
            if let Some(tstore) = self.ttls.get(store_name) {
                for k in candidates {
                    if tstore.remove_if(&k, |_k, exp| *exp <= now).is_some() {
                        expired.push(k);
                    }
                }
            }
            if let Some(store) = self.stores.get(store_name) {
                for k in &expired {
                    store.remove(k);
                }
            }
            expired
        };
        for key in &evicted {
            self.remove_record_local(store_name, key);
        }
        Ok(evicted)
    }

    pub fn evict_all_expired(&self) -> anyhow::Result<()> {
        for store_name in DYNAMIC_TTL_STORES {
            if let Err(e) = self.evict_expired_records(store_name) {
                eprintln!(
                    "Warning: failed to evict expired records from {}: {}",
                    store_name, e
                );
            }
        }
        Ok(())
    }

    pub fn rotate_daily_stores(&self) -> anyhow::Result<()> {
        for store_name in DAILY_ROTATE_STORES {
            let current_records = if let Some(backend) = &self.backend {
                backend.hgetall_store(store_name)?
            } else {
                self.get_store(store_name)
            };

            let hist_name = format!("{}{}", store_name, HISTORICAL_SUFFIX);
            self.replace_store(&hist_name, current_records)?;
            self.replace_store(store_name, HashMap::new())?;
        }
        Ok(())
    }

    pub fn increment_counter(
        &self,
        counter_store: &str,
        datasource: &str,
        delta: i64,
    ) -> anyhow::Result<i64> {
        let new_val = if let Some(backend) = &self.backend {
            backend.hincrby_counter(counter_store, datasource, delta)?
        } else {
            let cstore = self
                .counters
                .entry(counter_store.to_string())
                .or_default();
            let mut entry = cstore.entry(datasource.to_string()).or_insert(0);
            *entry += delta;
            *entry
        };

        if self.backend.is_some() {
            let cstore = self
                .counters
                .entry(counter_store.to_string())
                .or_default();
            cstore.insert(datasource.to_string(), new_val);
        }

        Ok(new_val)
    }

    pub fn get_counter(&self, counter_store: &str, datasource: &str) -> i64 {
        self.counters
            .get(counter_store)
            .and_then(|c| c.get(datasource).map(|v| *v.value()))
            .unwrap_or(0)
    }

    pub fn get_all_counters(&self, counter_store: &str) -> HashMap<String, i64> {
        let mut out = HashMap::new();
        if let Some(cstore) = self.counters.get(counter_store) {
            for entry in cstore.iter() {
                out.insert(entry.key().clone(), *entry.value());
            }
        }
        out
    }

    pub fn get_kv(&self, key: &str) -> anyhow::Result<Option<String>> {
        if let Some(val) = self.kv.get(key) {
            return Ok(Some(val.value().clone()));
        }
        if let Some(backend) = &self.backend {
            if let Some(remote_val) = backend.get_kv(key)? {
                self.kv.insert(key.to_string(), remote_val.clone());
                return Ok(Some(remote_val));
            }
        }
        Ok(None)
    }

    pub fn set_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()> {
        if let Some(backend) = &self.backend {
            backend.set_kv(key, value, ttl_secs)?;
        }
        self.kv.insert(key.to_string(), value.to_string());
        Ok(())
    }

    pub fn set_kv_nx(&self, key: &str, value: &str, ttl_secs: u64) -> anyhow::Result<bool> {
        if let Some(backend) = &self.backend {
            let acquired = backend.set_kv_nx(key, value, ttl_secs)?;
            if acquired {
                self.kv.insert(key.to_string(), value.to_string());
            }
            return Ok(acquired);
        }
        use dashmap::mapref::entry::Entry;
        match self.kv.entry(key.to_string()) {
            Entry::Vacant(e) => {
                e.insert(value.to_string());
                Ok(true)
            }
            Entry::Occupied(_) => Ok(false),
        }
    }

    pub fn acquire_or_renew_leader_lock(
        &self,
        key: &str,
        node_name: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<bool> {
        if let Some(backend) = &self.backend {
            return backend.acquire_or_renew_leader_lock(key, node_name, ttl_secs);
        }
        let now = chrono::Utc::now().timestamp() as f64;
        let expire_at = now + ttl_secs as f64;
        use dashmap::mapref::entry::Entry;
        match self.kv.entry(key.to_string()) {
            Entry::Vacant(e) => {
                e.insert(node_name.to_string());
                let tstore = self.ttls.entry("__kv__".to_string()).or_default();
                tstore.insert(key.to_string(), expire_at);
                Ok(true)
            }
            Entry::Occupied(mut e) => {
                let is_expired = self
                    .ttls
                    .get("__kv__")
                    .and_then(|t| t.get(key).map(|exp| *exp <= now))
                    .unwrap_or(false);
                if e.get() == node_name || is_expired {
                    e.insert(node_name.to_string());
                    let tstore = self.ttls.entry("__kv__".to_string()).or_default();
                    tstore.insert(key.to_string(), expire_at);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    pub fn get_raw_kv(&self, key: &str) -> anyhow::Result<Option<String>> {
        if let Some(backend) = &self.backend {
            return backend.get_raw_kv(key);
        }
        Ok(self.kv.get(key).map(|v| v.value().clone()))
    }

    pub fn set_raw_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()> {
        if let Some(backend) = &self.backend {
            backend.set_raw_kv(key, value, ttl_secs)?;
        } else {
            self.kv.insert(key.to_string(), value.to_string());
        }
        Ok(())
    }

    fn get_store_keys(store_name: &str) -> &'static [&'static str] {
        match store_name {
            WLC_PSQL_STORE => &["wireless_station"],
            SENSOR_PSQL_STORE => &["sensor_uuid"],
            _ => &["client_mac", "namespace_uuid"],
        }
    }

    fn must_overwrite(store_name: &str) -> bool {
        !matches!(
            store_name,
            WLC_PSQL_STORE | SENSOR_PSQL_STORE | NMSP_STORE_MEASURE | NMSP_STORE_INFO
        )
    }

    fn has_historical_fallback(store_name: &str) -> bool {
        matches!(
            store_name,
            NMSP_STORE_MEASURE
                | NMSP_STORE_INFO
                | RADIUS_STORE
                | LOCATION_STORE
                | MOBILITY_STORE
        )
    }

    pub fn enrich(&self, event: &mut Event) {
        for store_name in ENRICH_STORES {
            let key_fields = Self::get_store_keys(store_name);
            let Some(primary_key_field) = key_fields.first() else {
                continue;
            };
            let Some(primary_val) = event.get_str(primary_key_field) else {
                continue;
            };
            if primary_val.is_empty() {
                continue;
            }
            let mut merge_key = primary_val;
            for field in &key_fields[1..] {
                if let Some(val) = event.get_str(field) {
                    merge_key.push_str(&val);
                }
            }

            let record = self.get_record(store_name, &merge_key).or_else(|| {
                if Self::has_historical_fallback(store_name) {
                    let hist_store = format!("{}{}", store_name, HISTORICAL_SUFFIX);
                    self.get_record(&hist_store, &merge_key)
                } else {
                    None
                }
            });

            let Some(enrichment) = record else {
                continue;
            };

            if store_name == WLC_PSQL_STORE || store_name == SENSOR_PSQL_STORE {
                let event_ns = event.get_str("namespace_uuid").unwrap_or_default();
                let store_ns = enrichment
                    .get("namespace_uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if !event_ns.is_empty() && !store_ns.is_empty() && event_ns != store_ns {
                    continue;
                }
            }

            let overwrite = Self::must_overwrite(store_name);
            for (k, v) in enrichment {
                if v.is_null() || v.is_object() {
                    continue;
                }
                // SENSOR_PSQL_STORE device attributes must NOT be automatically injected by
                // generic state.enrich() because device attribution must be handled by
                // device_enrichment filter (dual-mode: endpoint asset vs sensor).
                if store_name == SENSOR_PSQL_STORE
                    && (k == "device_id" || k == "device_name" || k == "device_role")
                {
                    continue;
                }
                if overwrite || !event.contains(&k) {
                    event.set(&k, v);
                }
            }
        }
    }
}
