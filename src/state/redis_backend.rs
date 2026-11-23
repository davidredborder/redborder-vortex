use dashmap::DashMap;
use redis::Commands;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub const PUBSUB_CHANNEL: &str = "rb:pubsub:updates";

pub trait ClusterBackend: Send + Sync {
    fn hset_record(
        &self,
        store_name: &str,
        record_key: &str,
        value: &Map<String, Value>,
    ) -> anyhow::Result<()>;

    fn hset_record_with_ttl(
        &self,
        store_name: &str,
        record_key: &str,
        value: &Map<String, Value>,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()>;

    fn evict_expired(&self, store_name: &str) -> anyhow::Result<Vec<String>>;

    fn hgetall_store(
        &self,
        store_name: &str,
    ) -> anyhow::Result<HashMap<String, Map<String, Value>>>;

    fn replace_store(
        &self,
        store_name: &str,
        records: &HashMap<String, Map<String, Value>>,
    ) -> anyhow::Result<()>;

    fn hincrby_counter(
        &self,
        counter_store: &str,
        datasource: &str,
        delta: i64,
    ) -> anyhow::Result<i64>;

    fn hget_counters(&self, counter_store: &str) -> anyhow::Result<HashMap<String, i64>>;

    fn get_kv(&self, key: &str) -> anyhow::Result<Option<String>>;

    fn set_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()>;

    fn set_kv_nx(&self, key: &str, value: &str, ttl_secs: u64) -> anyhow::Result<bool>;

    fn acquire_or_renew_leader_lock(
        &self,
        key: &str,
        node_name: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<bool>;

    fn get_raw_kv(&self, key: &str) -> anyhow::Result<Option<String>>;

    fn set_raw_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()>;
}

struct RedisConnectionPool {
    client: redis::Client,
    pool: std::sync::Mutex<Vec<redis::Connection>>,
    max_size: usize,
}

impl RedisConnectionPool {
    fn new(client: redis::Client, max_size: usize) -> Self {
        Self {
            client,
            pool: std::sync::Mutex::new(Vec::with_capacity(max_size)),
            max_size,
        }
    }

    fn acquire(&self) -> anyhow::Result<redis::Connection> {
        let conn_opt = {
            let mut guard = self
                .pool
                .lock()
                .map_err(|e| anyhow::anyhow!("Redis pool mutex poisoned: {}", e))?;
            guard.pop()
        };
        match conn_opt {
            Some(c) => Ok(c),
            None => {
                let c = self.client.get_connection()?;
                Ok(c)
            }
        }
    }

    fn release(&self, conn: redis::Connection) {
        if let Ok(mut guard) = self.pool.lock() {
            if guard.len() < self.max_size {
                guard.push(conn);
            }
        }
    }
}

pub struct RedisClusterBackend {
    client: redis::Client,
    pool: RedisConnectionPool,
}

impl RedisClusterBackend {
    pub fn new(redis_url: &str) -> anyhow::Result<Self> {
        let client = redis::Client::open(redis_url)?;
        // Verify connectivity and credentials eagerly
        let mut conn = client.get_connection()?;
        let () = redis::cmd("PING").query(&mut conn)?;
        let pool = RedisConnectionPool::new(client.clone(), 32);
        pool.release(conn);
        Ok(Self { client, pool })
    }

    pub fn client(&self) -> redis::Client {
        self.client.clone()
    }

    fn with_conn<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce(&mut redis::Connection) -> anyhow::Result<T>,
    {
        let mut conn = self.pool.acquire()?;
        let res = f(&mut conn);
        match res {
            Ok(val) => {
                self.pool.release(conn);
                Ok(val)
            }
            Err(e) => {
                // On error, do not return potentially broken connection to pool
                Err(e)
            }
        }
    }

    fn store_key(store_name: &str) -> String {
        format!("rb:store:{}", store_name)
    }

    fn ttl_key(store_name: &str) -> String {
        format!("rb:ttl:{}", store_name)
    }

    fn counter_key(counter_store: &str) -> String {
        format!("rb:counters:{}", counter_store)
    }

    fn kv_key(key: &str) -> String {
        format!("rb:kv:{}", key)
    }
}

impl ClusterBackend for RedisClusterBackend {
    fn hset_record(
        &self,
        store_name: &str,
        record_key: &str,
        value: &Map<String, Value>,
    ) -> anyhow::Result<()> {
        self.hset_record_with_ttl(store_name, record_key, value, None)
    }

    fn hset_record_with_ttl(
        &self,
        store_name: &str,
        record_key: &str,
        value: &Map<String, Value>,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        let rkey = Self::store_key(store_name);
        let serialized = serde_json::to_string(value)?;

        self.with_conn(|conn| {
            if let Some(ttl) = ttl_secs {
                let expire_at = chrono::Utc::now().timestamp() as f64 + ttl as f64;
                let ttl_k = Self::ttl_key(store_name);
                let mut pipe = redis::pipe();
                pipe.atomic();
                pipe.hset(&rkey, record_key, &serialized);
                pipe.zadd(&ttl_k, record_key, expire_at);
                let () = pipe.query(conn)?;
            } else {
                let _: () = conn.hset(&rkey, record_key, &serialized)?;
            }

            let notification = json!({
                "op": "hset",
                "store": store_name,
                "key": record_key,
                "data": value,
            })
            .to_string();
            let _: () = conn.publish(PUBSUB_CHANNEL, notification)?;
            Ok(())
        })
    }

    fn evict_expired(&self, store_name: &str) -> anyhow::Result<Vec<String>> {
        let now = chrono::Utc::now().timestamp() as f64;
        let ttl_k = Self::ttl_key(store_name);
        let store_k = Self::store_key(store_name);

        self.with_conn(|conn| {
            // Run atomic Lua eviction to prevent race conditions if a key's TTL was renewed concurrently
            let script = redis::Script::new(
                r#"
                local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ARGV[1], 'LIMIT', 0, 1000)
                local evicted = {}
                for _, key in ipairs(expired) do
                    local score = tonumber(redis.call('ZSCORE', KEYS[2], key))
                    if score and score <= tonumber(ARGV[1]) then
                        redis.call('HDEL', KEYS[1], key)
                        redis.call('ZREM', KEYS[2], key)
                        table.insert(evicted, key)
                    end
                end
                return evicted
                "#,
            );
            let expired: Vec<String> = script.key(&store_k).key(&ttl_k).arg(now).invoke(conn)?;

            if !expired.is_empty() {
                let notification = json!({
                    "op": "evict",
                    "store": store_name,
                    "keys": expired,
                })
                .to_string();
                let _: () = conn.publish(PUBSUB_CHANNEL, notification)?;
            }
            Ok(expired)
        })
    }

    fn hgetall_store(
        &self,
        store_name: &str,
    ) -> anyhow::Result<HashMap<String, Map<String, Value>>> {
        let rkey = Self::store_key(store_name);
        self.with_conn(|conn| {
            let raw: HashMap<String, String> = conn.hgetall(&rkey)?;
            let mut out = HashMap::with_capacity(raw.len());
            for (k, v) in raw {
                if let Ok(parsed) = serde_json::from_str::<Map<String, Value>>(&v) {
                    out.insert(k, parsed);
                }
            }
            Ok(out)
        })
    }

    fn replace_store(
        &self,
        store_name: &str,
        records: &HashMap<String, Map<String, Value>>,
    ) -> anyhow::Result<()> {
        let rkey = Self::store_key(store_name);
        self.with_conn(|conn| {
            let mut pipe = redis::pipe();
            pipe.atomic();
            pipe.del(&rkey);
            for (k, v) in records {
                let serialized = serde_json::to_string(v)?;
                pipe.hset(&rkey, k, serialized);
            }
            let () = pipe.query(conn)?;
            let notification = json!({
                "op": "replace",
                "store": store_name,
            })
            .to_string();
            let _: () = conn.publish(PUBSUB_CHANNEL, notification)?;
            Ok(())
        })
    }

    fn hincrby_counter(
        &self,
        counter_store: &str,
        datasource: &str,
        delta: i64,
    ) -> anyhow::Result<i64> {
        let rkey = Self::counter_key(counter_store);
        self.with_conn(|conn| {
            let new_val: i64 = conn.hincr(&rkey, datasource, delta)?;
            Ok(new_val)
        })
    }

    fn hget_counters(&self, counter_store: &str) -> anyhow::Result<HashMap<String, i64>> {
        let rkey = Self::counter_key(counter_store);
        self.with_conn(|conn| {
            let raw: HashMap<String, i64> = conn.hgetall(&rkey)?;
            Ok(raw)
        })
    }

    fn get_kv(&self, key: &str) -> anyhow::Result<Option<String>> {
        let rkey = Self::kv_key(key);
        self.with_conn(|conn| {
            let val: Option<String> = conn.get(&rkey)?;
            Ok(val)
        })
    }

    fn set_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()> {
        let rkey = Self::kv_key(key);
        self.with_conn(|conn| {
            if let Some(ttl) = ttl_secs {
                let _: () = conn.set_ex(&rkey, value, ttl)?;
            } else {
                let _: () = conn.set(&rkey, value)?;
            }
            Ok(())
        })
    }

    fn set_kv_nx(&self, key: &str, value: &str, ttl_secs: u64) -> anyhow::Result<bool> {
        let rkey = Self::kv_key(key);
        self.with_conn(|conn| {
            let res: Option<String> = redis::cmd("SET")
                .arg(&rkey)
                .arg(value)
                .arg("NX")
                .arg("EX")
                .arg(ttl_secs)
                .query(conn)?;
            Ok(res.is_some())
        })
    }

    fn acquire_or_renew_leader_lock(
        &self,
        key: &str,
        node_name: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<bool> {
        let rkey = Self::kv_key(key);
        self.with_conn(|conn| {
            let script = redis::Script::new(
                r#"
                local current = redis.call('get', KEYS[1])
                if current == false or current == ARGV[1] then
                    redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[2])
                    return 1
                else
                    return 0
                end
                "#,
            );
            let res: i64 = script.key(&rkey).arg(node_name).arg(ttl_secs).invoke(conn)?;
            Ok(res == 1)
        })
    }

    fn get_raw_kv(&self, key: &str) -> anyhow::Result<Option<String>> {
        self.with_conn(|conn| {
            let val: Option<String> = conn.get(key)?;
            Ok(val)
        })
    }

    fn set_raw_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()> {
        self.with_conn(|conn| {
            if let Some(ttl) = ttl_secs {
                let _: () = conn.set_ex(key, value, ttl)?;
            } else {
                let _: () = conn.set(key, value)?;
            }
            Ok(())
        })
    }
}

type StorePartition = DashMap<String, Map<String, Value>>;
type StoreCluster = Arc<DashMap<String, StorePartition>>;

#[derive(Clone, Default)]
pub struct InMemoryClusterBackend {
    stores: StoreCluster,
    ttls: Arc<DashMap<String, DashMap<String, f64>>>,
    counters: Arc<DashMap<String, DashMap<String, i64>>>,
    kv: Arc<DashMap<String, String>>,
    kv_ttls: Arc<DashMap<String, f64>>,
}

impl InMemoryClusterBackend {
    pub fn new() -> Self {
        Self {
            stores: Arc::new(DashMap::new()),
            ttls: Arc::new(DashMap::new()),
            counters: Arc::new(DashMap::new()),
            kv: Arc::new(DashMap::new()),
            kv_ttls: Arc::new(DashMap::new()),
        }
    }
}

impl ClusterBackend for InMemoryClusterBackend {
    fn hset_record(
        &self,
        store_name: &str,
        record_key: &str,
        value: &Map<String, Value>,
    ) -> anyhow::Result<()> {
        self.hset_record_with_ttl(store_name, record_key, value, None)
    }

    fn hset_record_with_ttl(
        &self,
        store_name: &str,
        record_key: &str,
        value: &Map<String, Value>,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        let store = self
            .stores
            .entry(store_name.to_string())
            .or_default();
        store.insert(record_key.to_string(), value.clone());
        if let Some(ttl) = ttl_secs {
            let expire_at = chrono::Utc::now().timestamp() as f64 + ttl as f64;
            let tstore = self.ttls.entry(store_name.to_string()).or_default();
            tstore.insert(record_key.to_string(), expire_at);
        }
        Ok(())
    }

    fn evict_expired(&self, store_name: &str) -> anyhow::Result<Vec<String>> {
        let now = chrono::Utc::now().timestamp() as f64;
        let mut expired = Vec::new();
        if let Some(tstore) = self.ttls.get(store_name) {
            let candidates: Vec<String> = tstore
                .iter()
                .filter(|entry| *entry.value() <= now)
                .map(|entry| entry.key().clone())
                .collect();

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
        Ok(expired)
    }

    fn hgetall_store(
        &self,
        store_name: &str,
    ) -> anyhow::Result<HashMap<String, Map<String, Value>>> {
        let mut out = HashMap::new();
        if let Some(store) = self.stores.get(store_name) {
            for entry in store.iter() {
                out.insert(entry.key().clone(), entry.value().clone());
            }
        }
        Ok(out)
    }

    fn replace_store(
        &self,
        store_name: &str,
        records: &HashMap<String, Map<String, Value>>,
    ) -> anyhow::Result<()> {
        let new_map = DashMap::new();
        for (k, v) in records {
            new_map.insert(k.clone(), v.clone());
        }
        self.stores.insert(store_name.to_string(), new_map);
        Ok(())
    }

    fn hincrby_counter(
        &self,
        counter_store: &str,
        datasource: &str,
        delta: i64,
    ) -> anyhow::Result<i64> {
        let cstore = self
            .counters
            .entry(counter_store.to_string())
            .or_default();
        let mut entry = cstore.entry(datasource.to_string()).or_insert(0);
        *entry += delta;
        Ok(*entry)
    }

    fn hget_counters(&self, counter_store: &str) -> anyhow::Result<HashMap<String, i64>> {
        let mut out = HashMap::new();
        if let Some(cstore) = self.counters.get(counter_store) {
            for entry in cstore.iter() {
                out.insert(entry.key().clone(), *entry.value());
            }
        }
        Ok(out)
    }

    fn get_kv(&self, key: &str) -> anyhow::Result<Option<String>> {
        let now = chrono::Utc::now().timestamp() as f64;
        if let Some(exp) = self.kv_ttls.get(key) {
            if *exp <= now {
                self.kv.remove(key);
                self.kv_ttls.remove(key);
                return Ok(None);
            }
        }
        Ok(self.kv.get(key).map(|v| v.value().clone()))
    }

    fn set_kv(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> anyhow::Result<()> {
        self.kv.insert(key.to_string(), value.to_string());
        if let Some(ttl) = ttl_secs {
            let expire_at = chrono::Utc::now().timestamp() as f64 + ttl as f64;
            self.kv_ttls.insert(key.to_string(), expire_at);
        } else {
            self.kv_ttls.remove(key);
        }
        Ok(())
    }

    fn set_kv_nx(&self, key: &str, value: &str, ttl_secs: u64) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp() as f64;
        let expire_at = now + ttl_secs as f64;
        use dashmap::mapref::entry::Entry;
        match self.kv.entry(key.to_string()) {
            Entry::Vacant(e) => {
                e.insert(value.to_string());
                self.kv_ttls.insert(key.to_string(), expire_at);
                Ok(true)
            }
            Entry::Occupied(mut e) => {
                let is_expired = self.kv_ttls.get(key).map(|exp| *exp <= now).unwrap_or(false);
                if is_expired {
                    e.insert(value.to_string());
                    self.kv_ttls.insert(key.to_string(), expire_at);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn acquire_or_renew_leader_lock(
        &self,
        key: &str,
        node_name: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<bool> {
        let now = chrono::Utc::now().timestamp() as f64;
        let expire_at = now + ttl_secs as f64;
        use dashmap::mapref::entry::Entry;
        match self.kv.entry(key.to_string()) {
            Entry::Vacant(e) => {
                e.insert(node_name.to_string());
                self.kv_ttls.insert(key.to_string(), expire_at);
                Ok(true)
            }
            Entry::Occupied(mut e) => {
                let is_expired = self.kv_ttls.get(key).map(|exp| *exp <= now).unwrap_or(false);
                if e.get() == node_name || is_expired {
                    e.insert(node_name.to_string());
                    self.kv_ttls.insert(key.to_string(), expire_at);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    fn get_raw_kv(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self.kv.get(key).map(|v| v.value().clone()))
    }

    fn set_raw_kv(&self, key: &str, value: &str, _ttl_secs: Option<u64>) -> anyhow::Result<()> {
        self.kv.insert(key.to_string(), value.to_string());
        Ok(())
    }
}

fn is_valid_store_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn process_pubsub_payload(state: &crate::state::StateStore, payload: &str) {
    let val: Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Warning: invalid pubsub JSON payload: {} ({})", e, payload);
            return;
        }
    };
    let op = val.get("op").and_then(|v| v.as_str());
    let store = val.get("store").and_then(|v| v.as_str());
    match (op, store) {
        (Some("hset"), Some(s)) if is_valid_store_name(s) => {
            if let (Some(key), Some(data)) = (
                val.get("key").and_then(|v| v.as_str()),
                val.get("data").and_then(|v| v.as_object()),
            ) {
                state.put_record_local(s, key, data.clone());
            }
        }
        (Some("replace"), Some(s)) if is_valid_store_name(s) => {
            if let Err(e) = state.sync_store_from_backend(s) {
                eprintln!("Warning: failed to sync store '{}' from backend: {}", s, e);
            }
        }
        (Some("evict"), Some(s)) if is_valid_store_name(s) => {
            if let Some(keys) = val.get("keys").and_then(|v| v.as_array()) {
                for k in keys {
                    if let Some(key_str) = k.as_str() {
                        state.remove_record_local(s, key_str);
                    }
                }
            }
        }
        _ => {
            eprintln!(
                "Warning: ignored unrecognized or invalid pubsub message: {}",
                payload
            );
        }
    }
}

pub fn spawn_redis_pubsub_task(
    client: redis::Client,
    state: Arc<crate::state::StateStore>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::task::spawn_blocking(move || {
        while !*shutdown_rx.borrow() {
            let mut conn = match client.get_connection() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "Failed to connect to Redis for pubsub sync: {}. Retrying in 2s...",
                        e
                    );
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    continue;
                }
            };
            let _ = conn.set_read_timeout(Some(std::time::Duration::from_millis(500)));

            let mut pubsub = conn.as_pubsub();
            if let Err(e) = pubsub.subscribe(PUBSUB_CHANNEL) {
                eprintln!(
                    "Failed to subscribe to {}: {}. Retrying in 2s...",
                    PUBSUB_CHANNEL, e
                );
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }

            while !*shutdown_rx.borrow() {
                match pubsub.get_message() {
                    Ok(msg) => {
                        let payload: String = match msg.get_payload() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        process_pubsub_payload(&state, &payload);
                    }
                    Err(ref e) if e.is_timeout() => {
                        continue;
                    }
                    Err(e) => {
                        eprintln!("Redis pubsub disconnected ({}). Reconnecting...", e);
                        std::thread::sleep(std::time::Duration::from_secs(1));
                        break;
                    }
                }
            }
        }
    });
}
