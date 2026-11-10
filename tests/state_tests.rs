use redborder_vortex::event::Event;
use redborder_vortex::state::{
    process_pubsub_payload, ClusterBackend, InMemoryClusterBackend, StateStore, COUNTER_STORE,
    DWELL_STORE, FLOWS_NUMBER, HISTORICAL_SUFFIX, LOCATION_STORE, MOBILITY_STORE, NMSP_STORE_INFO,
    NMSP_STORE_MEASURE, RADIUS_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use serde_json::{json, Map, Value};
use std::sync::Arc;

fn make_map(val: Value) -> Map<String, Value> {
    val.as_object().unwrap().clone()
}

#[test]
fn test_enrich_priority_and_overwrite_rules() {
    let store = StateStore::new_standalone();

    // 1. WLC_PSQL_STORE (must_overwrite = false, key = ["wireless_station"])
    store
        .put_record(
            WLC_PSQL_STORE,
            "aa:bb:cc:00:11:22",
            make_map(json!({
                "building": "HQ-WLC",
                "floor": "Floor-1",
                "existing_field": "from_wlc",
                "null_field": null,
                "nested_hash": { "ignore": "me" }
            })),
        )
        .unwrap();

    // 2. SENSOR_PSQL_STORE (must_overwrite = false, key = ["sensor_uuid"])
    store
        .put_record(
            SENSOR_PSQL_STORE,
            "sensor-001",
            make_map(json!({
                "sensor_name": "Sensor-North",
                "building": "HQ-Sensor" // Should NOT overwrite HQ-WLC from wlc-psql
            })),
        )
        .unwrap();

    // 3. NMSP_STORE_MEASURE (must_overwrite = false, key = ["client_mac", "namespace_uuid"])
    store
        .put_record(
            NMSP_STORE_MEASURE,
            "11:22:33:44:55:66ns-100",
            make_map(json!({
                "rssi": -58,
                "floor": "Floor-NMSP" // Should NOT overwrite Floor-1
            })),
        )
        .unwrap();

    // 4. RADIUS_STORE (must_overwrite = true, key = ["client_mac", "namespace_uuid"])
    store
        .put_record(
            RADIUS_STORE,
            "11:22:33:44:55:66ns-100",
            make_map(json!({
                "client_id": "alice",
                "floor": "Floor-Radius" // SHOULD overwrite Floor-1 because must_overwrite=true
            })),
        )
        .unwrap();

    // 5. LOCATION_STORE (must_overwrite = true, key = ["client_mac", "namespace_uuid"])
    store
        .put_record(
            LOCATION_STORE,
            "11:22:33:44:55:66ns-100",
            make_map(json!({
                "zone": "Zone-A",
                "floor": "Floor-Location" // Overwrites Floor-Radius since location runs after radius
            })),
        )
        .unwrap();

    // 6. DWELL_STORE (must_overwrite = true, key = ["client_mac", "namespace_uuid"])
    store
        .put_record(
            DWELL_STORE,
            "11:22:33:44:55:66ns-100",
            make_map(json!({
                "dwell_time": 420
            })),
        )
        .unwrap();

    let mut event = Event::from_map(make_map(json!({
        "wireless_station": "aa:bb:cc:00:11:22",
        "sensor_uuid": "sensor-001",
        "client_mac": "11:22:33:44:55:66",
        "namespace_uuid": "ns-100",
        "existing_field": "original_value"
    })));

    store.enrich(&mut event);

    // WLC did not overwrite existing_field
    assert_eq!(
        event.get_str("existing_field").as_deref(),
        Some("original_value")
    );
    // WLC set building, Sensor did not overwrite it
    assert_eq!(event.get_str("building").as_deref(), Some("HQ-WLC"));
    // Sensor set sensor_name
    assert_eq!(
        event.get_str("sensor_name").as_deref(),
        Some("Sensor-North")
    );
    // NMSP set rssi
    assert_eq!(event.get("rssi"), Some(&json!(-58)));
    // Radius set client_id
    assert_eq!(event.get_str("client_id").as_deref(), Some("alice"));
    // Location overwrote floor and set zone
    assert_eq!(event.get_str("floor").as_deref(), Some("Floor-Location"));
    assert_eq!(event.get_str("zone").as_deref(), Some("Zone-A"));
    // Dwell set dwell_time
    assert_eq!(event.get("dwell_time"), Some(&json!(420)));
    // Null and nested hashes were ignored
    assert!(!event.contains("null_field"));
    assert!(!event.contains("nested_hash"));
}

#[test]
fn test_enrich_wlc_and_sensor_namespace_check() {
    let store = StateStore::new_standalone();

    store
        .put_record(
            WLC_PSQL_STORE,
            "ap-mac-1",
            make_map(json!({
                "namespace_uuid": "ns-correct",
                "campus": "Campus-A"
            })),
        )
        .unwrap();

    store
        .put_record(
            SENSOR_PSQL_STORE,
            "sensor-1",
            make_map(json!({
                "namespace_uuid": "ns-other",
                "sensor_role": "ids"
            })),
        )
        .unwrap();

    // Event has namespace_uuid = "ns-correct": matches WLC, mismatches SENSOR
    let mut event = Event::from_map(make_map(json!({
        "wireless_station": "ap-mac-1",
        "sensor_uuid": "sensor-1",
        "namespace_uuid": "ns-correct"
    })));

    store.enrich(&mut event);

    assert_eq!(event.get_str("campus").as_deref(), Some("Campus-A"));
    assert_eq!(event.get("sensor_role"), None);
}

#[test]
fn test_enrich_historical_fallback() {
    let store = StateStore::new_standalone();

    let hist_radius = format!("{}{}", RADIUS_STORE, HISTORICAL_SUFFIX);
    store
        .put_record(
            &hist_radius,
            "aa:bb:cc:dd:ee:ffns-1",
            make_map(json!({
                "client_id": "bob_from_yesterday"
            })),
        )
        .unwrap();

    let mut event = Event::from_map(make_map(json!({
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "namespace_uuid": "ns-1"
    })));

    store.enrich(&mut event);

    assert_eq!(
        event.get_str("client_id").as_deref(),
        Some("bob_from_yesterday")
    );
}

#[test]
fn test_multi_node_concurrent_writes_no_lost_updates() {
    let shared_cluster = Arc::new(InMemoryClusterBackend::new());
    let node1 = StateStore::with_backend(shared_cluster.clone());
    let node2 = StateStore::with_backend(shared_cluster.clone());

    // Node 1 writes Client A to radius
    node1
        .put_record(
            RADIUS_STORE,
            "client-a-ns1",
            make_map(json!({"client_id": "alice", "dot1x_user": "alice@corp"})),
        )
        .unwrap();

    // Node 2 writes Client B to radius concurrently without having synced Client A first
    node2
        .put_record(
            RADIUS_STORE,
            "client-b-ns1",
            make_map(json!({"client_id": "bob", "dot1x_user": "bob@corp"})),
        )
        .unwrap();

    // Both nodes sync from the shared cluster backend
    node1.sync_from_backend().unwrap();
    node2.sync_from_backend().unwrap();

    // Both Client A and Client B must be present on both nodes (no whole-blob overwrite!)
    let n1_a = node1.get_record(RADIUS_STORE, "client-a-ns1").unwrap();
    let n1_b = node1.get_record(RADIUS_STORE, "client-b-ns1").unwrap();
    let n2_a = node2.get_record(RADIUS_STORE, "client-a-ns1").unwrap();
    let n2_b = node2.get_record(RADIUS_STORE, "client-b-ns1").unwrap();

    assert_eq!(n1_a.get("client_id"), Some(&json!("alice")));
    assert_eq!(n1_b.get("client_id"), Some(&json!("bob")));
    assert_eq!(n2_a.get("client_id"), Some(&json!("alice")));
    assert_eq!(n2_b.get("client_id"), Some(&json!("bob")));
}

#[test]
fn test_multi_node_atomic_counters() {
    let shared_cluster = Arc::new(InMemoryClusterBackend::new());
    let node1 = StateStore::with_backend(shared_cluster.clone());
    let node2 = StateStore::with_backend(shared_cluster.clone());

    node1
        .increment_counter(COUNTER_STORE, "rb_flow", 15)
        .unwrap();
    let total = node2
        .increment_counter(COUNTER_STORE, "rb_flow", 27)
        .unwrap();
    assert_eq!(total, 42);

    node1
        .increment_counter(FLOWS_NUMBER, "sensor-abc", 100)
        .unwrap();
    node2
        .increment_counter(FLOWS_NUMBER, "sensor-abc", 50)
        .unwrap();

    node1.sync_from_backend().unwrap();
    assert_eq!(node1.get_counter(COUNTER_STORE, "rb_flow"), 42);
    assert_eq!(node1.get_counter(FLOWS_NUMBER, "sensor-abc"), 150);
}

#[test]
fn test_rotate_daily_stores() {
    let shared_cluster = Arc::new(InMemoryClusterBackend::new());
    let store = StateStore::with_backend(shared_cluster);

    for store_name in [
        MOBILITY_STORE,
        LOCATION_STORE,
        NMSP_STORE_MEASURE,
        NMSP_STORE_INFO,
        RADIUS_STORE,
    ] {
        store
            .put_record(store_name, "k1", make_map(json!({"s": store_name})))
            .unwrap();
    }

    store.rotate_daily_stores().unwrap();

    for store_name in [
        MOBILITY_STORE,
        LOCATION_STORE,
        NMSP_STORE_MEASURE,
        NMSP_STORE_INFO,
        RADIUS_STORE,
    ] {
        assert!(
            store.get_record(store_name, "k1").is_none(),
            "current store {} should be cleared after daily rotation",
            store_name
        );
        let hist_name = format!("{}{}", store_name, HISTORICAL_SUFFIX);
        let hist_rec = store
            .get_record(&hist_name, "k1")
            .expect("historical store should contain rotated record");
        assert_eq!(hist_rec.get("s"), Some(&json!(store_name)));
    }
}

#[test]
fn test_local_record_update_and_sync_store_from_backend() {
    let shared_cluster = Arc::new(InMemoryClusterBackend::new());
    let node1 = StateStore::with_backend(shared_cluster.clone());
    let node2 = StateStore::with_backend(shared_cluster.clone());

    // Directly update local cache on node1 (simulating pub/sub delivery)
    node1.put_record_local(
        RADIUS_STORE,
        "live-session-1",
        make_map(json!({"username": "john_doe", "ip": "10.1.33.99"})),
    );
    assert_eq!(
        node1.get_record(RADIUS_STORE, "live-session-1").unwrap().get("username"),
        Some(&json!("john_doe"))
    );

    // Node 2 writes to shared cluster
    node2.put_record(
        RADIUS_STORE,
        "live-session-2",
        make_map(json!({"username": "jane_doe", "ip": "10.1.33.100"})),
    ).unwrap();

    // Node 1 selective single-store sync
    node1.sync_store_from_backend(RADIUS_STORE).unwrap();
    assert_eq!(
        node1.get_record(RADIUS_STORE, "live-session-2").unwrap().get("username"),
        Some(&json!("jane_doe"))
    );
}

#[test]
fn test_process_pubsub_payload_dispatch_and_security() {
    let shared_cluster = Arc::new(InMemoryClusterBackend::new());
    let node = StateStore::with_backend(shared_cluster.clone());

    // 1. Valid hset payload
    let hset_payload = json!({
        "op": "hset",
        "store": "radius",
        "key": "user@domain.com",
        "data": {
            "username": "user",
            "vlan": 100
        }
    })
    .to_string();

    process_pubsub_payload(&node, &hset_payload);
    let record = node.get_record("radius", "user@domain.com").expect("record should exist");
    assert_eq!(record.get("vlan"), Some(&json!(100)));

    // 2. Valid replace payload
    // Put record directly in backend
    shared_cluster
        .replace_store(
            "location",
            &std::collections::HashMap::from([(
                "ap-1".to_string(),
                make_map(json!({"campus": "Main", "building": "B1"})),
            )]),
        )
        .unwrap();

    let replace_payload = json!({
        "op": "replace",
        "store": "location"
    })
    .to_string();

    process_pubsub_payload(&node, &replace_payload);
    let ap_rec = node.get_record("location", "ap-1").expect("location store should be synced");
    assert_eq!(ap_rec.get("building"), Some(&json!("B1")));

    // 3. Security: invalid store name rejected (no panic, no write)
    let bad_payload = json!({
        "op": "hset",
        "store": "../../../etc/passwd",
        "key": "root",
        "data": {"pwn": true}
    })
    .to_string();
    process_pubsub_payload(&node, &bad_payload);
    assert!(node.get_record("../../../etc/passwd", "root").is_none());

    // 4. Invalid JSON / unknown op does not panic
    process_pubsub_payload(&node, "not-json");
    process_pubsub_payload(&node, r#"{"op": "drop_database", "store": "radius"}"#);
}

#[test]
fn test_ttl_eviction_and_pubsub_evict() {
    let shared_cluster = Arc::new(InMemoryClusterBackend::new());
    let node1 = StateStore::with_backend(shared_cluster.clone());
    let node2 = StateStore::with_backend(shared_cluster.clone());

    // Insert key with ttl_secs = 0 (immediately expired)
    node1
        .put_record_with_ttl(
            MOBILITY_STORE,
            "expired_mac",
            make_map(json!({"mac": "expired_mac", "dwell": 10})),
            Some(0),
        )
        .unwrap();

    // Insert key with 86400s ttl (still valid)
    node1
        .put_record(
            MOBILITY_STORE,
            "active_mac",
            make_map(json!({"mac": "active_mac", "dwell": 5})),
        )
        .unwrap();

    assert!(node1.get_record(MOBILITY_STORE, "expired_mac").is_some());
    assert!(node1.get_record(MOBILITY_STORE, "active_mac").is_some());

    // Evict expired records
    let evicted = node1.evict_expired_records(MOBILITY_STORE).unwrap();
    assert_eq!(evicted, vec!["expired_mac".to_string()]);

    // node1 local cache and backend should have evicted_mac removed, active_mac retained
    assert!(node1.get_record(MOBILITY_STORE, "expired_mac").is_none());
    assert!(node1.get_record(MOBILITY_STORE, "active_mac").is_some());

    // Pre-populate node2 local cache to verify pubsub eviction actively evicts it
    node2.put_record_local(
        MOBILITY_STORE,
        "expired_mac",
        make_map(json!({"mac": "expired_mac", "dwell": 10})),
    );
    assert!(node2.get_record(MOBILITY_STORE, "expired_mac").is_some());

    // Simulate pubsub eviction notification to node2
    let evict_payload = json!({
        "op": "evict",
        "store": MOBILITY_STORE,
        "keys": ["expired_mac"]
    })
    .to_string();
    process_pubsub_payload(&node2, &evict_payload);
    assert!(node2.get_record(MOBILITY_STORE, "expired_mac").is_none());
}

#[test]
fn test_standalone_ttl_eviction_and_dwell_store() {
    let standalone = StateStore::new_standalone();

    standalone
        .put_record_with_ttl(
            DWELL_STORE,
            "expired_dwell",
            make_map(json!({"mac": "expired_dwell", "dwell_time": 120})),
            Some(0),
        )
        .unwrap();

    standalone
        .put_record(
            DWELL_STORE,
            "active_dwell",
            make_map(json!({"mac": "active_dwell", "dwell_time": 30})),
        )
        .unwrap();

    assert!(standalone.get_record(DWELL_STORE, "expired_dwell").is_some());
    assert!(standalone.get_record(DWELL_STORE, "active_dwell").is_some());

    standalone.evict_all_expired().unwrap();

    assert!(standalone.get_record(DWELL_STORE, "expired_dwell").is_none());
    assert!(standalone.get_record(DWELL_STORE, "active_dwell").is_some());
}

#[test]
fn test_leader_lock_acquisition_renewal_and_failover() {
    let backend = Arc::new(InMemoryClusterBackend::new());
    let node1 = StateStore::with_backend(backend.clone());
    let node2 = StateStore::with_backend(backend.clone());

    // 1. Initial acquisition: node1 acquires leadership with 60s lease
    let won1 = node1.acquire_or_renew_leader_lock("leader:lock", "node1", 60).unwrap();
    assert!(won1, "Node 1 should successfully acquire vacant leader lock");

    // 2. Mutual exclusion: node2 attempts acquisition while node1 holds lease
    let won2 = node2.acquire_or_renew_leader_lock("leader:lock", "node2", 60).unwrap();
    assert!(!won2, "Node 2 must fail to acquire lock held by Node 1");

    // 3. Heartbeat renewal: node1 can renew its own lease
    let renewed1 = node1.acquire_or_renew_leader_lock("leader:lock", "node1", 60).unwrap();
    assert!(renewed1, "Node 1 should successfully renew its own active lease");

    // 4. Failover simulation: node1 crashes and its lease expires (ttl = 0)
    let _ = node1.acquire_or_renew_leader_lock("leader:lock", "node1", 0).unwrap();

    // 5. Automatic failover: node2 acquires expired lock
    let won_failover = node2.acquire_or_renew_leader_lock("leader:lock", "node2", 60).unwrap();
    assert!(won_failover, "Node 2 should take over leadership after lease expiry");

    // 6. Split-brain prevention: node1 resumes and attempts renewal, but fails
    let late_renewal = node1.acquire_or_renew_leader_lock("leader:lock", "node1", 60).unwrap();
    assert!(!late_renewal, "Node 1 must NOT be able to overwrite or renew lock lost to Node 2");
}

#[test]
fn test_mobility_store_historical_fallback() {
    let store = StateStore::new_standalone();
    let hist_name = format!("{}{}", MOBILITY_STORE, HISTORICAL_SUFFIX);

    // Place record only in historical store
    store
        .put_record_local(
            &hist_name,
            "client_123",
            make_map(json!({"mac": "client_123", "dwell": 50})),
        );

    // Mobility store should resolve it through historical fallback
    let record = store.get_record_with_historical(MOBILITY_STORE, "client_123");
    assert!(record.is_some(), "Should resolve record from mobility-historical");
    assert_eq!(record.unwrap().get("dwell").and_then(|v| v.as_i64()), Some(50));
}
