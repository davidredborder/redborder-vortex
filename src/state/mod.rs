pub mod postgres_sync;
pub mod redis_backend;
pub mod store_manager;

pub use postgres_sync::{spawn_postgres_sync_task, PostgresSyncConfig};
pub use redis_backend::{
    process_pubsub_payload, spawn_redis_pubsub_task, ClusterBackend, InMemoryClusterBackend,
    RedisClusterBackend, PUBSUB_CHANNEL,
};
pub use store_manager::StateStore;

pub const WLC_PSQL_STORE: &str = "wlc-psql";
pub const SENSOR_PSQL_STORE: &str = "sensor-psql";
pub const DEVICE_IP_PSQL_STORE: &str = "device-ip-psql";
pub const DEVICE_MAC_PSQL_STORE: &str = "device-mac-psql";
pub const LOC_PSQL_STORE: &str = "location-psql";
pub const NMSP_STORE_MEASURE: &str = "nmsp-measure";
pub const NMSP_STORE_INFO: &str = "nmsp-info";
pub const RADIUS_STORE: &str = "radius";
pub const LOCATION_STORE: &str = "location";
pub const DWELL_STORE: &str = "dwell";
pub const SCRAMBLES_STORE: &str = "scrambles";
pub const MOBILITY_STORE: &str = "mobility";
pub const COUNTER_STORE: &str = "counterStore";
pub const FLOWS_NUMBER: &str = "flowsNumber";
pub const HISTORICAL_SUFFIX: &str = "-historical";
