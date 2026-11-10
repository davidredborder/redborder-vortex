use crate::state::{
    StateStore, DEVICE_IP_PSQL_STORE, DEVICE_MAC_PSQL_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio_postgres::NoTls;

#[derive(Debug, Clone)]
pub struct PostgresSyncConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

impl PostgresSyncConfig {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            user: user.into(),
            password: password.into(),
        }
    }

    pub async fn sync(&self, state: &StateStore) -> anyhow::Result<usize> {
        let conn_str = format!(
            "host={} port={} dbname={} user={} password={}",
            self.host, self.port, self.database, self.user, self.password
        );

        let (client, connection) = tokio_postgres::connect(&conn_str, NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("PostgreSQL connection worker error: {}", e);
            }
        });

        let mut total_synced = 0usize;

        // 1. Sync sensors with linked devices
        let sensors_query = r#"
            SELECT DISTINCT ON (sensors.id)
                sensors.id,
                sensors.name,
                sensors.uuid,
                sensors.ip,
                devices.id AS device_id,
                devices.name AS device_name,
                device_roles.name AS device_role,
                namespaces.uuid::text AS namespace_uuid
            FROM sensors
            LEFT JOIN device_links ON device_links.sensor_id = sensors.id
            LEFT JOIN devices ON device_links.device_id = devices.id
            LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
            WHERE sensors.is_deleted = false
            ORDER BY sensors.id, device_links.id ASC
        "#;

        let sensor_rows_res = client.query(sensors_query, &[]).await;
        let sensor_rows = match sensor_rows_res {
            Ok(rows) => Ok(rows),
            Err(e) => {
                eprintln!(
                    "Warning: Detailed sensors/devices join query failed, falling back to basic sensors: {}",
                    e
                );
                client
                    .query(
                        "SELECT id, name, uuid, ip FROM sensors WHERE is_deleted = false",
                        &[],
                    )
                    .await
            }
        };

        match sensor_rows {
            Ok(rows) => {
                for row in rows {
                    let id_val: Option<i64> = row
                        .try_get::<_, i64>(0)
                        .ok()
                        .or_else(|| row.try_get::<_, i32>(0).ok().map(|v| v as i64));
                    let name: Option<String> = row.try_get(1).ok();
                    let uuid: Option<String> = row.try_get(2).ok();
                    let ip: Option<String> = row.try_get(3).ok();

                    let mut rec = Map::new();
                    if let Some(ref n) = name {
                        rec.insert("sensor_name".to_string(), json!(n));
                        rec.insert("name".to_string(), json!(n));
                    }
                    if let Some(ref u) = uuid {
                        rec.insert("sensor_uuid".to_string(), json!(u));
                    }
                    if let Some(ref addr) = ip {
                        rec.insert("ip".to_string(), json!(addr));
                    }
                    if let Some(id) = id_val {
                        rec.insert("id".to_string(), json!(id));
                    }
                    if let Ok(Some(ns)) = row.try_get::<_, Option<String>>("namespace_uuid") {
                        if !ns.is_empty() {
                            rec.insert("namespace_uuid".to_string(), json!(ns));
                        }
                    }

                    // Linked device attributes (if present from join query)
                    let dev_id_opt: Option<i64> = row
                        .try_get::<_, i64>("device_id")
                        .ok()
                        .or_else(|| row.try_get::<_, i32>("device_id").ok().map(|v| v as i64));
                    if let Some(dev_id) = dev_id_opt {
                        rec.insert("device_id".to_string(), json!(dev_id.to_string()));
                    }
                    if let Ok(Some(dev_name)) = row.try_get::<_, Option<String>>("device_name") {
                        if !dev_name.is_empty() {
                            rec.insert("device_name".to_string(), json!(dev_name));
                        }
                    }
                    if let Ok(Some(dev_role)) = row.try_get::<_, Option<String>>("device_role") {
                        if !dev_role.is_empty() {
                            rec.insert("device_role".to_string(), json!(dev_role));
                        }
                    }

                    // If device attributes were missing (e.g. fallback query without join),
                    // preserve existing device fields from state cache if available.
                    if dev_id_opt.is_none() {
                        let cached = uuid
                            .as_deref()
                            .and_then(|u| state.get_record(SENSOR_PSQL_STORE, u))
                            .or_else(|| {
                                id_val
                                    .map(|id| id.to_string())
                                    .and_then(|id_str| state.get_record(SENSOR_PSQL_STORE, &id_str))
                            });
                        if let Some(cached_rec) = cached {
                            for key in &["device_id", "device_name", "device_role"] {
                                if let Some(val) = cached_rec.get(*key) {
                                    rec.insert(key.to_string(), val.clone());
                                }
                            }
                        }
                    }

                    if let Some(ref u) = uuid {
                        if !u.is_empty() {
                            let _ = state.put_record(SENSOR_PSQL_STORE, u, rec.clone());
                            total_synced += 1;
                        }
                    }
                    if let Some(id) = id_val {
                        let _ = state.put_record(SENSOR_PSQL_STORE, &id.to_string(), rec);
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to query sensors table: {}", e);
            }
        }

        // 2. Sync access points (WLC) with full nested-set hierarchy and zones
        let hierarchical_query = r#"
            SELECT DISTINCT ON (access_points.mac_address)
                access_points.mac_address,
                access_points.name AS ap_name,
                access_points.ip_address,
                access_points.enrichment,
                access_points.latitude,
                access_points.longitude,
                zones.name AS zone,
                zones.id::text AS zone_uuid,
                floors.name AS floor,
                floors.uuid::text AS floor_uuid,
                buildings.name AS building,
                buildings.uuid::text AS building_uuid,
                campuses.name AS campus,
                campuses.uuid::text AS campus_uuid,
                deployments.name AS deployment,
                deployments.uuid::text AS deployment_uuid,
                namespaces.name AS namespace,
                namespaces.uuid::text AS namespace_uuid,
                markets.name AS market,
                markets.uuid::text AS market_uuid,
                organizations.name AS organization,
                organizations.uuid::text AS organization_uuid,
                service_providers.name AS service_provider,
                service_providers.uuid::text AS service_provider_uuid
            FROM access_points
            LEFT JOIN sensors ON (access_points.sensor_id = sensors.id)
            LEFT JOIN access_points_zones AS zones_ids ON access_points.id = zones_ids.access_point_id
            LEFT JOIN zones ON zones_ids.zone_id = zones.id
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=101) AS floors ON floors.lft <= sensors.lft AND floors.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=5) AS buildings ON buildings.lft <= sensors.lft AND buildings.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=4) AS campuses ON campuses.lft <= sensors.lft AND campuses.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=7) AS deployments ON deployments.lft <= sensors.lft AND deployments.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=3) AS markets ON markets.lft <= sensors.lft AND markets.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=2) AS organizations ON organizations.lft <= sensors.lft AND organizations.rgt >= sensors.rgt
            LEFT JOIN (SELECT * FROM sensors WHERE domain_type=6) AS service_providers ON service_providers.lft <= sensors.lft AND service_providers.rgt >= sensors.rgt
            ORDER BY access_points.mac_address, access_points.id
        "#;

        match client.query(hierarchical_query, &[]).await {
            Ok(rows) => {
                for row in rows {
                    let mac: Option<String> = row.try_get("mac_address").ok();
                    let ap_name: Option<String> = row.try_get("ap_name").ok();
                    let ip: Option<String> = row.try_get("ip_address").ok();
                    let enrichment: Option<String> = row.try_get("enrichment").ok();

                    let latitude: Option<f64> = row
                        .try_get::<_, Option<f64>>("latitude")
                        .ok()
                        .flatten()
                        .or_else(|| {
                            row.try_get::<_, Option<String>>("latitude")
                                .ok()
                                .flatten()
                                .and_then(|s| s.parse::<f64>().ok())
                        });

                    let longitude: Option<f64> = row
                        .try_get::<_, Option<f64>>("longitude")
                        .ok()
                        .flatten()
                        .or_else(|| {
                            row.try_get::<_, Option<String>>("longitude")
                                .ok()
                                .flatten()
                                .and_then(|s| s.parse::<f64>().ok())
                        });

                    let mut rec = Map::new();
                    if let Some(ref n) = ap_name {
                        rec.insert("ap_name".to_string(), json!(n));
                        rec.insert("name".to_string(), json!(n));
                    }
                    if let Some(ref addr) = ip {
                        rec.insert("ip".to_string(), json!(addr));
                    }
                    if let (Some(lat), Some(lon)) = (latitude, longitude) {
                        rec.insert("latitude".to_string(), json!(lat));
                        rec.insert("longitude".to_string(), json!(lon));
                        rec.insert(
                            "client_latlong".to_string(),
                            json!(format!("{:.6},{:.6}", lat, lon)),
                        );
                    }

                    // Hierarchy dimensions
                    for col in &[
                        "zone",
                        "zone_uuid",
                        "floor",
                        "floor_uuid",
                        "building",
                        "building_uuid",
                        "campus",
                        "campus_uuid",
                        "deployment",
                        "deployment_uuid",
                        "namespace",
                        "namespace_uuid",
                        "market",
                        "market_uuid",
                        "organization",
                        "organization_uuid",
                        "service_provider",
                        "service_provider_uuid",
                    ] {
                        if let Ok(Some(val)) = row.try_get::<_, Option<String>>(col) {
                            if !val.is_empty() {
                                rec.insert(col.to_string(), json!(val));
                            }
                        }
                    }

                    // Merge enrichment JSON if present
                    if let Some(ref enrich_raw) = enrichment {
                        if let Ok(Value::Object(enrich_map)) =
                            serde_json::from_str::<Value>(enrich_raw)
                        {
                            for (k, v) in enrich_map {
                                rec.insert(k, v);
                            }
                        }
                    }

                    if let Some(ref m) = mac {
                        let normalized = m.to_lowercase().replace('-', ":");
                        if !normalized.is_empty() {
                            rec.insert("mac".to_string(), json!(normalized));
                            let _ = state.put_record(WLC_PSQL_STORE, &normalized, rec.clone());
                            total_synced += 1;
                        }
                    }
                }
            }
            Err(e) => {
                // Table schema or sensors joins might not be available in mock DBs; fall back to basic query
                eprintln!(
                    "Warning: Hierarchical AP query failed, falling back to basic AP query: {}",
                    e
                );
                if let Ok(rows) = client
                    .query(
                        "SELECT id, name, mac_address, ip_address FROM access_points",
                        &[],
                    )
                    .await
                {
                    for row in rows {
                        let name: Option<String> = row.try_get(1).ok();
                        let mac: Option<String> = row.try_get(2).ok();
                        let ip: Option<String> = row.try_get(3).ok();

                        let mut rec = Map::new();
                        if let Some(ref n) = name {
                            rec.insert("ap_name".to_string(), json!(n));
                            rec.insert("name".to_string(), json!(n));
                        }
                        if let Some(ref addr) = ip {
                            rec.insert("ip".to_string(), json!(addr));
                        }

                        if let Some(ref m) = mac {
                            let normalized = m.to_lowercase().replace('-', ":");
                            if !normalized.is_empty() {
                                rec.insert("mac".to_string(), json!(normalized));
                                let _ = state.put_record(WLC_PSQL_STORE, &normalized, rec.clone());
                                total_synced += 1;
                            }
                        }
                    }
                }
            }
        }

        // 3. Sync device IPs from ipam_ip_addresses
        let device_ips_query = r#"
            SELECT DISTINCT ON (ip, COALESCE(namespace_uuid, ''))
                device_id,
                device_name,
                device_role,
                ip,
                namespace_uuid
            FROM (
                SELECT
                    devices.id AS device_id,
                    devices.name AS device_name,
                    device_roles.name AS device_role,
                    split_part(ipam_ip_addresses.address::text, '/', 1) AS ip,
                    namespaces.uuid::text AS namespace_uuid,
                    1 AS priority
                FROM ipam_ip_addresses
                JOIN devices ON (ipam_ip_addresses.parent_object_type = 'Device' AND ipam_ip_addresses.parent_object_id = devices.id)
                LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
                LEFT JOIN sensors ON sensors.id = devices.sensor_id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
                UNION ALL
                SELECT
                    devices.id AS device_id,
                    devices.name AS device_name,
                    device_roles.name AS device_role,
                    split_part(ipam_ip_addresses.address::text, '/', 1) AS ip,
                    namespaces.uuid::text AS namespace_uuid,
                    2 AS priority
                FROM ipam_ip_addresses
                JOIN interfaces ON (ipam_ip_addresses.parent_object_type = 'Interface' AND ipam_ip_addresses.parent_object_id = interfaces.id)
                JOIN devices ON interfaces.device_id = devices.id
                LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
                LEFT JOIN sensors ON sensors.id = devices.sensor_id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
                UNION ALL
                SELECT
                    devices.id AS device_id,
                    devices.name AS device_name,
                    device_roles.name AS device_role,
                    split_part(ipam_ip_addresses.address::text, '/', 1) AS ip,
                    namespaces.uuid::text AS namespace_uuid,
                    3 AS priority
                FROM ipam_ip_addresses
                JOIN devices ON (ipam_ip_addresses.parent_object_type IS NULL AND ipam_ip_addresses.sensor_id IS NOT NULL AND ipam_ip_addresses.sensor_id = devices.sensor_id)
                LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
                LEFT JOIN sensors ON sensors.id = devices.sensor_id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
                UNION ALL
                SELECT
                    devices.id AS device_id,
                    devices.name AS device_name,
                    device_roles.name AS device_role,
                    split_part(sensors.ip::text, '/', 1) AS ip,
                    namespaces.uuid::text AS namespace_uuid,
                    4 AS priority
                FROM sensors
                JOIN device_links ON device_links.sensor_id = sensors.id
                JOIN devices ON device_links.device_id = devices.id
                LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
                WHERE sensors.is_deleted = false AND sensors.ip IS NOT NULL AND sensors.ip != ''
                UNION ALL
                SELECT
                    devices.id AS device_id,
                    devices.name AS device_name,
                    device_roles.name AS device_role,
                    split_part(sensors.ip::text, '/', 1) AS ip,
                    namespaces.uuid::text AS namespace_uuid,
                    5 AS priority
                FROM sensors
                JOIN devices ON devices.sensor_id = sensors.id
                LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
                WHERE sensors.is_deleted = false AND sensors.ip IS NOT NULL AND sensors.ip != ''
            ) sub
            ORDER BY ip, COALESCE(namespace_uuid, ''), priority ASC
        "#;

        match client.query(device_ips_query, &[]).await {
            Ok(rows) => {
                for row in rows {
                    let ip: Option<String> = row.try_get("ip").ok();
                    let dev_id_opt: Option<i64> = row
                        .try_get::<_, i64>("device_id")
                        .ok()
                        .or_else(|| row.try_get::<_, i32>("device_id").ok().map(|v| v as i64));
                    let dev_name: Option<String> = row.try_get("device_name").ok();
                    let dev_role: Option<String> = row.try_get("device_role").ok();
                    let ns_opt: Option<String> = row.try_get::<_, Option<String>>("namespace_uuid").ok().flatten();

                    if let Some(ip_addr) = ip {
                        let clean_ip = ip_addr.trim();
                        if !clean_ip.is_empty() {
                            let mut rec = Map::new();
                            if let Some(id) = dev_id_opt {
                                rec.insert("device_id".to_string(), json!(id.to_string()));
                            }
                            if let Some(ref n) = dev_name {
                                if !n.is_empty() {
                                    rec.insert("device_name".to_string(), json!(n));
                                }
                            }
                            if let Some(ref r) = dev_role {
                                if !r.is_empty() {
                                    rec.insert("device_role".to_string(), json!(r));
                                }
                            }
                            if let Some(ref ns) = ns_opt {
                                if !ns.is_empty() {
                                    rec.insert("namespace_uuid".to_string(), json!(ns));
                                    let ns_key = format!("{}:{}", ns, clean_ip);
                                    let _ = state.put_record(DEVICE_IP_PSQL_STORE, &ns_key, rec);
                                    total_synced += 1;
                                    continue;
                                }
                            }
                            let _ = state.put_record(DEVICE_IP_PSQL_STORE, clean_ip, rec);
                            total_synced += 1;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to query device IPs: {}", e);
            }
        }

        // 4. Sync device MACs from macaddresses and interfaces / virtual interfaces
        let device_macs_query = r#"
            SELECT DISTINCT ON (mac, COALESCE(namespace_uuid, ''))
                device_id,
                device_name,
                device_role,
                mac,
                namespace_uuid
            FROM (
                SELECT
                    devices.id AS device_id,
                    devices.name AS device_name,
                    device_roles.name AS device_role,
                    macaddresses.mac_address AS mac,
                    namespaces.uuid::text AS namespace_uuid,
                    1 AS priority
                FROM macaddresses
                JOIN interfaces ON interfaces.macaddress_id = macaddresses.id
                JOIN devices ON interfaces.device_id = devices.id
                LEFT JOIN device_roles ON devices.device_role_id = device_roles.id
                LEFT JOIN sensors ON sensors.id = devices.sensor_id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
                UNION ALL
                SELECT
                    virtual_machines.id AS device_id,
                    virtual_machines.name AS device_name,
                    device_roles.name AS device_role,
                    macaddresses.mac_address AS mac,
                    namespaces.uuid::text AS namespace_uuid,
                    2 AS priority
                FROM macaddresses
                JOIN virtual_interfaces ON virtual_interfaces.macaddress_id = macaddresses.id
                JOIN virtual_machines ON virtual_interfaces.virtual_machine_id = virtual_machines.id
                LEFT JOIN device_roles ON virtual_machines.device_role_id = device_roles.id
                LEFT JOIN sensors ON sensors.id = virtual_machines.sensor_id
                LEFT JOIN (SELECT * FROM sensors WHERE domain_type=8) AS namespaces ON namespaces.lft <= sensors.lft AND namespaces.rgt >= sensors.rgt
            ) sub
            ORDER BY mac, COALESCE(namespace_uuid, ''), priority ASC
        "#;

        match client.query(device_macs_query, &[]).await {
            Ok(rows) => {
                for row in rows {
                    let mac: Option<String> = row.try_get("mac").ok();
                    let dev_id_opt: Option<i64> = row
                        .try_get::<_, i64>("device_id")
                        .ok()
                        .or_else(|| row.try_get::<_, i32>("device_id").ok().map(|v| v as i64));
                    let dev_name: Option<String> = row.try_get("device_name").ok();
                    let dev_role: Option<String> = row.try_get("device_role").ok();
                    let ns_opt: Option<String> = row.try_get::<_, Option<String>>("namespace_uuid").ok().flatten();

                    if let Some(raw_mac) = mac {
                        let norm = raw_mac.to_lowercase().replace('-', ":");
                        if !norm.is_empty() && norm != "00:00:00:00:00:00" {
                            let mut rec = Map::new();
                            if let Some(id) = dev_id_opt {
                                rec.insert("device_id".to_string(), json!(id.to_string()));
                            }
                            if let Some(ref n) = dev_name {
                                if !n.is_empty() {
                                    rec.insert("device_name".to_string(), json!(n));
                                }
                            }
                            if let Some(ref r) = dev_role {
                                if !r.is_empty() {
                                    rec.insert("device_role".to_string(), json!(r));
                                }
                            }
                            if let Some(ref ns) = ns_opt {
                                if !ns.is_empty() {
                                    rec.insert("namespace_uuid".to_string(), json!(ns));
                                    let ns_key = format!("{}:{}", ns, norm);
                                    let _ = state.put_record(DEVICE_MAC_PSQL_STORE, &ns_key, rec);
                                    total_synced += 1;
                                    continue;
                                }
                            }
                            let _ = state.put_record(DEVICE_MAC_PSQL_STORE, &norm, rec);
                            total_synced += 1;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to query device MACs: {}", e);
            }
        }

        Ok(total_synced)
    }
}

pub fn spawn_postgres_sync_task(
    config: PostgresSyncConfig,
    state: Arc<StateStore>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Initial sync on startup
        match config.sync(&state).await {
            Ok(count) => {
                println!(
                    "PostgreSQL initial metadata sync completed ({} records loaded)",
                    count
                );
            }
            Err(e) => {
                eprintln!(
                    "Warning: PostgreSQL metadata sync failed (will retry in background): {}",
                    e
                );
            }
        }

        // Periodic 5-minute background refresh
        let interval = Duration::from_secs(300);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tokio::time::sleep(interval) => {
                    if let Err(e) = config.sync(&state).await {
                        eprintln!("PostgreSQL periodic metadata sync error: {}", e);
                    }
                }
            }
        }
    })
}
