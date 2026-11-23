use redborder_vortex::config::ast::PluginBlock;
use redborder_vortex::config::{parse_logstash_conf, ConfigValue, PipelineEntry};
use redborder_vortex::engine::VortexEngine;
use redborder_vortex::event::Event;
use redborder_vortex::filters::create_filter;
use redborder_vortex::state::{
    StateStore, DEVICE_IP_PSQL_STORE, DEVICE_MAC_PSQL_STORE, RADIUS_STORE, SENSOR_PSQL_STORE,
};
use serde_json::json;
use std::sync::Arc;

#[test]
fn test_device_enrichment_filter_from_block() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![],
    };
    let filter = create_filter(&block).expect("Should create device_enrichment filter");

    let state = StateStore::new_standalone();
    let mut dev_rec = serde_json::Map::new();
    dev_rec.insert("device_id".to_string(), json!("42"));
    dev_rec.insert("device_name".to_string(), json!("edge-router-01"));
    dev_rec.insert("device_role".to_string(), json!("Core Router"));

    state
        .put_record(DEVICE_IP_PSQL_STORE, "192.168.1.50", dev_rec)
        .unwrap();

    let mut event = Event::new();
    event.set("sensor_uuid", "uuid-sensor-123");
    event.set("lan_ip", "192.168.1.50");

    let out = filter
        .process(event, &state)
        .expect("Filter process should succeed");
    assert_eq!(out.len(), 1);
    let enriched = &out[0];

    assert_eq!(
        enriched.get_str("sensor_uuid").as_deref(),
        Some("uuid-sensor-123")
    );
    assert_eq!(enriched.get_str("device_id").as_deref(), Some("42"));
    assert_eq!(
        enriched.get_str("device_name").as_deref(),
        Some("edge-router-01")
    );
    assert_eq!(
        enriched.get_str("device_role").as_deref(),
        Some("Core Router")
    );
    assert_eq!(enriched.get_str("lan_ip").as_deref(), Some("192.168.1.50"));
}

#[test]
fn test_device_enrichment_pipeline_ast_compilation() {
    let pipeline_conf = r#"
input {
  generator {
    count => 1
    message => '{"sensor_uuid": "sensor-uuid-99"}'
  }
}
filter {
  device_enrichment {
    mode => "sensor"
  }
}
output {
  null {}
}
"#;

    let parsed = parse_logstash_conf(pipeline_conf).expect("Pipeline should parse successfully");
    let state = Arc::new(StateStore::new_standalone());
    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("device_id".to_string(), json!("999"));
    sensor_rec.insert("device_name".to_string(), json!("switch-alpha"));
    sensor_rec.insert("device_role".to_string(), json!("Access Switch"));

    state
        .put_record(SENSOR_PSQL_STORE, "sensor-uuid-99", sensor_rec)
        .unwrap();

    let mut engine = VortexEngine::new(state.clone(), "test-node");
    engine
        .register_pipeline(
            PipelineEntry {
                id: "device-test".to_string(),
                path_config: "test.conf".to_string(),
                workers: 1,
            },
            &parsed,
        )
        .expect("Pipeline should register without error");

    let mut ev = Event::new();
    ev.set("sensor_uuid", "sensor-uuid-99");
    let processed = engine.process_pipeline_event("device-test", ev).unwrap();
    assert_eq!(processed.len(), 1);
    let out_ev = &processed[0].1;
    assert_eq!(out_ev.get_str("device_id").as_deref(), Some("999"));
    assert_eq!(
        out_ev.get_str("device_name").as_deref(),
        Some("switch-alpha")
    );
    assert_eq!(
        out_ev.get_str("device_role").as_deref(),
        Some("Access Switch")
    );
}

#[test]
fn test_device_enrichment_preserves_existing_fields_and_handles_missing_sensor() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("sensor".to_string())),
        ],
    };
    let filter = create_filter(&block).unwrap();

    let state = StateStore::new_standalone();
    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("device_id".to_string(), json!("500"));
    sensor_rec.insert("device_name".to_string(), json!("db-device"));
    sensor_rec.insert("device_role".to_string(), json!("Server"));

    state
        .put_record(SENSOR_PSQL_STORE, "uuid-sensor-found", sensor_rec)
        .unwrap();

    // 1. Event already has custom device_name: must NOT overwrite
    let mut ev_existing = Event::new();
    ev_existing.set("sensor_uuid", "uuid-sensor-found");
    ev_existing.set("device_name", "custom-override-name");

    let out1 = filter.process(ev_existing, &state).unwrap();
    assert_eq!(out1.len(), 1);
    assert_eq!(
        out1[0].get_str("device_name").as_deref(),
        Some("custom-override-name")
    );
    assert_eq!(out1[0].get_str("device_id").as_deref(), Some("500"));
    assert_eq!(out1[0].get_str("device_role").as_deref(), Some("Server"));

    // 2. Event has unknown sensor_uuid: remains unchanged without error
    let mut ev_unknown = Event::new();
    ev_unknown.set("sensor_uuid", "uuid-unknown");
    ev_unknown.set("msg", "hello");

    let out2 = filter.process(ev_unknown, &state).unwrap();
    assert_eq!(out2.len(), 1);
    assert_eq!(
        out2[0].get_str("sensor_uuid").as_deref(),
        Some("uuid-unknown")
    );
    assert_eq!(out2[0].get_str("device_id"), None);
    assert_eq!(out2[0].get_str("msg").as_deref(), Some("hello"));

    // 3. Event with no sensor_uuid at all: passes through cleanly
    let mut ev_no_uuid = Event::new();
    ev_no_uuid.set("foo", "bar");
    let out3 = filter.process(ev_no_uuid, &state).unwrap();
    assert_eq!(out3.len(), 1);
    assert_eq!(out3[0].get_str("foo").as_deref(), Some("bar"));
}

#[test]
fn test_device_enrichment_store_isolation_no_radius_or_location_pollution() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![],
    };
    let filter = create_filter(&block).unwrap();

    let state = StateStore::new_standalone();

    // Populate RADIUS_STORE with a client MAC record
    let mut radius_rec = serde_json::Map::new();
    radius_rec.insert("username".to_string(), json!("john_doe"));
    radius_rec.insert("device_id".to_string(), json!("radius-injected-id"));
    state
        .put_record(RADIUS_STORE, "aa:bb:cc:dd:ee:ff", radius_rec)
        .unwrap();

    // Event has client_mac matching RADIUS_STORE, but no sensor_uuid
    let mut ev = Event::new();
    ev.set("client_mac", "aa:bb:cc:dd:ee:ff");
    ev.set("status", "active");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    // Crucial check: device_enrichment MUST NOT trigger RADIUS or LOCATION enrichment
    assert_eq!(out[0].get_str("username"), None);
    assert_eq!(out[0].get_str("device_id"), None);
    assert_eq!(
        out[0].get_str("client_mac").as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
    assert_eq!(out[0].get_str("status").as_deref(), Some("active"));
}

#[test]
fn test_device_enrichment_endpoint_ip_resolution() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![],
    };
    let filter = create_filter(&block).unwrap();

    let state = StateStore::new_standalone();

    // Register NAS IP in DEVICE_IP_PSQL_STORE
    let mut nas_rec = serde_json::Map::new();
    nas_rec.insert("device_id".to_string(), json!("10"));
    nas_rec.insert("device_name".to_string(), json!("synology-nas"));
    nas_rec.insert("device_role".to_string(), json!("NAS"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "10.1.30.50", nas_rec)
        .unwrap();

    // NetFlow event with lan_ip matching NAS and sensor_uuid matching the transit router
    let mut ev = Event::new();
    ev.set("lan_ip", "10.1.30.50");
    ev.set("wan_ip", "216.58.206.10");
    ev.set("sensor_uuid", "router-sensor-uuid");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("10"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("synology-nas"));
    assert_eq!(out[0].get_str("device_role").as_deref(), Some("NAS"));
}

#[test]
fn test_device_enrichment_endpoint_mac_resolution_and_transit_mac_skipping() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![],
    };
    let filter = create_filter(&block).unwrap();

    let state = StateStore::new_standalone();

    // 0. Register router sensor in SENSOR_PSQL_STORE (device_id 1)
    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("device_id".to_string(), json!("1"));
    sensor_rec.insert("device_name".to_string(), json!("core-router"));
    sensor_rec.insert("sensor_name".to_string(), json!("core-router-sensor"));
    state
        .put_record(SENSOR_PSQL_STORE, "router-sensor-uuid", sensor_rec)
        .unwrap();

    // 1. Register printer MAC (Endpoint)
    let mut printer_rec = serde_json::Map::new();
    printer_rec.insert("device_id".to_string(), json!("25"));
    printer_rec.insert("device_name".to_string(), json!("office-printer"));
    printer_rec.insert("device_role".to_string(), json!("Printer"));
    state
        .put_record(DEVICE_MAC_PSQL_STORE, "00:11:22:33:44:55", printer_rec)
        .unwrap();

    // 2. Register router gateway MAC
    let mut router_mac_rec = serde_json::Map::new();
    router_mac_rec.insert("device_id".to_string(), json!("1"));
    router_mac_rec.insert("device_name".to_string(), json!("core-router"));
    router_mac_rec.insert("device_role".to_string(), json!("Router"));
    state
        .put_record(DEVICE_MAC_PSQL_STORE, "ec:ce:13:ae:35:b3", router_mac_rec)
        .unwrap();

    // Event A: client_mac is the printer -> matches printer!
    let mut ev_printer = Event::new();
    ev_printer.set("client_mac", "00:11:22:33:44:55");
    ev_printer.set("server_mac", "ec:ce:13:ae:35:b3"); // router gateway MAC
    let out_a = filter.process(ev_printer, &state).unwrap();
    assert_eq!(out_a.len(), 1);
    assert_eq!(out_a[0].get_str("device_id").as_deref(), Some("25"));
    assert_eq!(out_a[0].get_str("device_name").as_deref(), Some("office-printer"));

    // Event B: unmanaged guest client traffic forwarded through the router:
    // client_mac is unknown, server_mac is router transit MAC.
    // Transit MAC MUST be skipped, and because fallback_to_sensor is false, device_id remains None!
    let mut ev_unmanaged = Event::new();
    ev_unmanaged.set("client_mac", "aa:bb:cc:11:22:33");
    ev_unmanaged.set("server_mac", "ec:ce:13:ae:35:b3");
    ev_unmanaged.set("sensor_uuid", "router-sensor-uuid");
    let out_b = filter.process(ev_unmanaged, &state).unwrap();
    assert_eq!(out_b.len(), 1);
    assert_eq!(out_b[0].get_str("device_id"), None);
}

#[test]
fn test_device_enrichment_fallback_to_sensor_config() {
    // With fallback_to_sensor => true:
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(true)),
        ],
    };
    let filter = create_filter(&block).unwrap();

    let state = StateStore::new_standalone();
    let mut router_rec = serde_json::Map::new();
    router_rec.insert("device_id".to_string(), json!("1"));
    router_rec.insert("device_name".to_string(), json!("core-router"));
    router_rec.insert("device_role".to_string(), json!("Router"));
    state
        .put_record(SENSOR_PSQL_STORE, "router-sensor-uuid", router_rec)
        .unwrap();

    let mut ev = Event::new();
    ev.set("lan_ip", "192.168.1.99"); // unknown host
    ev.set("sensor_uuid", "router-sensor-uuid");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("1"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("core-router"));
}

#[test]
fn test_device_enrichment_sensor_mode_config() {
    // In vault and monitor pipelines: mode => "sensor"
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("sensor".to_string())),
        ],
    };
    let filter = create_filter(&block).unwrap();

    let state = StateStore::new_standalone();
    let mut srv_rec = serde_json::Map::new();
    srv_rec.insert("device_id".to_string(), json!("88"));
    srv_rec.insert("device_name".to_string(), json!("auth-vault-01"));
    srv_rec.insert("device_role".to_string(), json!("Server"));
    state
        .put_record(SENSOR_PSQL_STORE, "vault-sensor-uuid", srv_rec)
        .unwrap();

    let mut ev = Event::new();
    ev.set("sensor_uuid", "vault-sensor-uuid");
    ev.set("log_type", "sshd");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("88"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("auth-vault-01"));
}

#[test]
fn test_device_enrichment_auto_mode_recognizes_all_endpoint_fields() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("auto".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(false)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    let mut asset_rec = serde_json::Map::new();
    asset_rec.insert("device_id".to_string(), json!("777"));
    asset_rec.insert("device_name".to_string(), json!("db-cluster"));
    asset_rec.insert("device_role".to_string(), json!("Database"));

    state
        .put_record(DEVICE_IP_PSQL_STORE, "10.0.1.50", asset_rec.clone())
        .unwrap();

    // Event has src_ip only (not lan_ip) and sensor_uuid
    let mut ev_src = Event::new();
    ev_src.set("src_ip", "10.0.1.50");
    ev_src.set("sensor_uuid", "sensor-router-uuid");

    let out = filter.process(ev_src, &state).unwrap();
    assert_eq!(out.len(), 1);
    // In auto mode with src_ip present, it must NOT treat as sensor mode; must resolve endpoint asset
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("777"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("db-cluster"));
}

#[test]
fn test_device_enrichment_skip_transit_ip_resolution() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(false)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // 0. Exporter router sensor (device_id 1)
    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("device_id".to_string(), json!("1"));
    sensor_rec.insert("sensor_name".to_string(), json!("border-router-sensor"));
    state
        .put_record(SENSOR_PSQL_STORE, "router-sensor-uuid", sensor_rec)
        .unwrap();

    // 1. Exporter router IP
    let mut router_ip_rec = serde_json::Map::new();
    router_ip_rec.insert("device_id".to_string(), json!("1"));
    router_ip_rec.insert("device_name".to_string(), json!("border-router"));
    router_ip_rec.insert("device_role".to_string(), json!("Router"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "10.1.50.20", router_ip_rec)
        .unwrap();

    // 2. Client asset MAC
    let mut nas_mac_rec = serde_json::Map::new();
    nas_mac_rec.insert("device_id".to_string(), json!("42"));
    nas_mac_rec.insert("device_name".to_string(), json!("synology-nas"));
    nas_mac_rec.insert("device_role".to_string(), json!("Network Attached Storage"));
    state
        .put_record(DEVICE_MAC_PSQL_STORE, "00:11:32:aa:bb:cc", nas_mac_rec)
        .unwrap();

    // Event has sensor_uuid, router IP in wan_ip, and real NAS asset MAC in client_mac
    let mut ev = Event::new();
    ev.set("sensor_uuid", "router-sensor-uuid");
    ev.set("wan_ip", "10.1.50.20"); // router IP
    ev.set("client_mac", "00:11:32:aa:bb:cc"); // NAS MAC

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    // Must skip exporter router IP on wan_ip and resolve NAS by MAC!
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("42"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("synology-nas"));
    assert_eq!(out[0].get_str("device_role").as_deref(), Some("Network Attached Storage"));
}

#[test]
fn test_device_enrichment_namespace_isolation() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    let mut tenant_a_rec = serde_json::Map::new();
    tenant_a_rec.insert("device_id".to_string(), json!("101"));
    tenant_a_rec.insert("device_name".to_string(), json!("tenant-a-nas"));
    tenant_a_rec.insert("namespace_uuid".to_string(), json!("ns-tenant-a"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "192.168.1.100", tenant_a_rec)
        .unwrap();

    // Event from Tenant B with overlapping IP
    let mut ev_b = Event::new();
    ev_b.set("lan_ip", "192.168.1.100");
    ev_b.set("namespace_uuid", "ns-tenant-b");

    let out = filter.process(ev_b, &state).unwrap();
    assert_eq!(out.len(), 1);
    // Namespace mismatch must NOT enrich Tenant A's device onto Tenant B's event
    assert_eq!(out[0].get_str("device_id"), None);
}

#[test]
fn test_device_enrichment_overlapping_rfc1918_ips_across_namespaces() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // Tenant A device on 10.0.0.50
    let mut tenant_a_rec = serde_json::Map::new();
    tenant_a_rec.insert("device_id".to_string(), json!("101"));
    tenant_a_rec.insert("device_name".to_string(), json!("tenant-a-nas"));
    tenant_a_rec.insert("namespace_uuid".to_string(), json!("ns-tenant-a"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "ns-tenant-a:10.0.0.50", tenant_a_rec)
        .unwrap();

    // Tenant B device on overlapping 10.0.0.50
    let mut tenant_b_rec = serde_json::Map::new();
    tenant_b_rec.insert("device_id".to_string(), json!("202"));
    tenant_b_rec.insert("device_name".to_string(), json!("tenant-b-db"));
    tenant_b_rec.insert("namespace_uuid".to_string(), json!("ns-tenant-b"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "ns-tenant-b:10.0.0.50", tenant_b_rec)
        .unwrap();

    // Event from Tenant A
    let mut ev_a = Event::new();
    ev_a.set("lan_ip", "10.0.0.50");
    ev_a.set("namespace_uuid", "ns-tenant-a");
    let out_a = filter.process(ev_a, &state).unwrap();
    assert_eq!(out_a.len(), 1);
    assert_eq!(out_a[0].get_str("device_id").as_deref(), Some("101"));
    assert_eq!(out_a[0].get_str("device_name").as_deref(), Some("tenant-a-nas"));

    // Event from Tenant B
    let mut ev_b = Event::new();
    ev_b.set("lan_ip", "10.0.0.50");
    ev_b.set("namespace_uuid", "ns-tenant-b");
    let out_b = filter.process(ev_b, &state).unwrap();
    assert_eq!(out_b.len(), 1);
    assert_eq!(out_b[0].get_str("device_id").as_deref(), Some("202"));
    assert_eq!(out_b[0].get_str("device_name").as_deref(), Some("tenant-b-db"));
}

#[test]
fn test_device_enrichment_auto_mode_empty_blank_strings_falls_back_to_sensor() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("auto".to_string())),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("device_id".to_string(), json!("999"));
    sensor_rec.insert("device_name".to_string(), json!("vault-sensor-host"));
    sensor_rec.insert("device_role".to_string(), json!("Server"));
    state
        .put_record(SENSOR_PSQL_STORE, "vault-sensor-uuid", sensor_rec)
        .unwrap();

    // Event has empty/blank endpoint fields
    let mut ev = Event::new();
    ev.set("src_ip", "   ");
    ev.set("lan_ip", "");
    ev.set("sensor_uuid", "vault-sensor-uuid");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    // Auto mode should treat blank strings as absence of endpoint data and resolve sensor
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("999"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("vault-sensor-host"));
}

#[test]
fn test_state_enrich_does_not_pollute_device_id_before_device_enrichment() {
    let state = StateStore::new_standalone();

    // Sensor record in SENSOR_PSQL_STORE has sensor info AND linked router info
    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("sensor_name".to_string(), json!("border-router-sensor"));
    sensor_rec.insert("ip".to_string(), json!("10.1.50.20"));
    sensor_rec.insert("device_id".to_string(), json!("1")); // router device ID
    sensor_rec.insert("device_name".to_string(), json!("border-router"));
    sensor_rec.insert("device_role".to_string(), json!("Router"));

    state
        .put_record(SENSOR_PSQL_STORE, "sensor-router-uuid", sensor_rec)
        .unwrap();

    let mut event = Event::new();
    event.set("sensor_uuid", "sensor-router-uuid");

    // Generic state.enrich() runs (as in netflowenrich)
    state.enrich(&mut event);

    // Should enrich sensor_name and ip, but NOT device_id, device_name, device_role
    assert_eq!(event.get_str("sensor_name").as_deref(), Some("border-router-sensor"));
    assert_eq!(event.get_str("ip").as_deref(), Some("10.1.50.20"));
    assert_eq!(event.get_str("device_id"), None);
    assert_eq!(event.get_str("device_name"), None);
    assert_eq!(event.get_str("device_role"), None);
}

#[test]
fn test_strict_namespace_isolation_no_leak_between_tenants_and_global() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(true)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // 1. Tenant A asset: 10.0.0.1 on ns-a
    let mut tenant_a = serde_json::Map::new();
    tenant_a.insert("device_id".to_string(), json!("100"));
    tenant_a.insert("device_name".to_string(), json!("tenant-a-nas"));
    tenant_a.insert("namespace_uuid".to_string(), json!("ns-a"));
    state.put_record(DEVICE_IP_PSQL_STORE, "ns-a:10.0.0.1", tenant_a).unwrap();

    // 2. Global / Root asset: 10.0.0.2 (no namespace)
    let mut global_asset = serde_json::Map::new();
    global_asset.insert("device_id".to_string(), json!("200"));
    global_asset.insert("device_name".to_string(), json!("global-ntp-server"));
    state.put_record(DEVICE_IP_PSQL_STORE, "10.0.0.2", global_asset).unwrap();

    // Case 1: Event with namespace "ns-b" arrives with IP 10.0.0.1 (belongs to ns-a)
    let mut ev1 = Event::new();
    ev1.set("lan_ip", "10.0.0.1");
    ev1.set("namespace_uuid", "ns-b");
    let out1 = filter.process(ev1, &state).unwrap();
    assert_eq!(out1[0].get_str("device_id"), None, "Must not leak ns-a asset to ns-b");

    // Case 2: Event with namespace "ns-a" arrives with IP 10.0.0.2 (global asset)
    let mut ev2 = Event::new();
    ev2.set("lan_ip", "10.0.0.2");
    ev2.set("namespace_uuid", "ns-a");
    let out2 = filter.process(ev2, &state).unwrap();
    assert_eq!(out2[0].get_str("device_id"), None, "Must not leak global asset to tenant event without matching namespace");

    // Case 3: Event without namespace arrives with IP 10.0.0.1 (belongs to ns-a)
    let mut ev3 = Event::new();
    ev3.set("lan_ip", "10.0.0.1");
    let out3 = filter.process(ev3, &state).unwrap();
    assert_eq!(out3[0].get_str("device_id"), None, "Must not leak tenant asset to non-namespaced event");

    // Case 4: Event without namespace arrives with IP 10.0.0.2 (global asset)
    let mut ev4 = Event::new();
    ev4.set("lan_ip", "10.0.0.2");
    let out4 = filter.process(ev4, &state).unwrap();
    assert_eq!(out4[0].get_str("device_id").as_deref(), Some("200"), "Global event matches global asset");

    // Case 5: Sensor fallback with mismatched namespace must also be rejected
    let mut sensor_tenant_a = serde_json::Map::new();
    sensor_tenant_a.insert("device_id".to_string(), json!("300"));
    sensor_tenant_a.insert("device_name".to_string(), json!("sensor-router-a"));
    sensor_tenant_a.insert("namespace_uuid".to_string(), json!("ns-a"));
    state.put_record(SENSOR_PSQL_STORE, "sensor-uuid-a", sensor_tenant_a).unwrap();

    let mut ev5 = Event::new();
    ev5.set("lan_ip", "192.168.99.99"); // unknown endpoint IP
    ev5.set("sensor_uuid", "sensor-uuid-a");
    ev5.set("namespace_uuid", "ns-b"); // different tenant!
    let out5 = filter.process(ev5, &state).unwrap();
    assert_eq!(out5[0].get_str("device_id"), None, "Sensor fallback must reject mismatched namespace");
}

#[test]
fn test_device_enrichment_switch_or_router_as_lan_ip_enriches_device() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(false)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // Switch device with role Switch
    let mut switch_rec = serde_json::Map::new();
    switch_rec.insert("device_id".to_string(), json!("2"));
    switch_rec.insert("device_name".to_string(), json!("switch"));
    switch_rec.insert("device_role".to_string(), json!("Switch"));

    state
        .put_record(DEVICE_IP_PSQL_STORE, "10.1.50.30", switch_rec)
        .unwrap();

    // Netflow event where lan_ip is the switch itself
    let mut ev = Event::new();
    ev.set("lan_ip", "10.1.50.30");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("2"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("switch"));
    assert_eq!(out[0].get_str("device_role").as_deref(), Some("Switch"));
}

#[test]
fn test_device_enrichment_discovers_namespace_from_sensor_uuid_and_enriches_tenant_asset() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(false)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // 1. SENSOR_PSQL_STORE has sensor belonging to tenant namespace "ns-innovalia"
    let mut sensor_rec = serde_json::Map::new();
    sensor_rec.insert("sensor_name".to_string(), json!("border-router"));
    sensor_rec.insert("namespace_uuid".to_string(), json!("ns-innovalia"));
    state
        .put_record(SENSOR_PSQL_STORE, "sensor-router-uuid", sensor_rec)
        .unwrap();

    // 2. DEVICE_IP_PSQL_STORE has tenant asset on 10.1.50.30
    let mut switch_rec = serde_json::Map::new();
    switch_rec.insert("device_id".to_string(), json!("2"));
    switch_rec.insert("device_name".to_string(), json!("catalyst-switch"));
    switch_rec.insert("device_role".to_string(), json!("Switch"));
    switch_rec.insert("namespace_uuid".to_string(), json!("ns-innovalia"));

    state
        .put_record(DEVICE_IP_PSQL_STORE, "ns-innovalia:10.1.50.30", switch_rec)
        .unwrap();

    // 3. Incoming Netflow event from router lacks namespace_uuid initially
    let mut ev = Event::new();
    ev.set("sensor_uuid", "sensor-router-uuid");
    ev.set("lan_ip", "10.1.50.30");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("namespace_uuid").as_deref(), Some("ns-innovalia"));
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("2"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("catalyst-switch"));
}

#[test]
fn test_dynamic_roles_switch_and_pc_with_router_sensor() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(false)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // 1. Exporter Router Sensor (device_id 1)
    let mut router_sensor = serde_json::Map::new();
    router_sensor.insert("device_id".to_string(), json!("1"));
    router_sensor.insert("device_name".to_string(), json!("Core-Router"));
    router_sensor.insert("device_role".to_string(), json!("Router"));
    state
        .put_record(SENSOR_PSQL_STORE, "sensor-router-uuid", router_sensor)
        .unwrap();

    let mut router_mac = serde_json::Map::new();
    router_mac.insert("device_id".to_string(), json!("1"));
    router_mac.insert("device_name".to_string(), json!("Core-Router"));
    router_mac.insert("device_role".to_string(), json!("Router"));
    state
        .put_record(DEVICE_MAC_PSQL_STORE, "00:00:5e:00:01:01", router_mac)
        .unwrap();

    // 2. Switch (device_id 2, dynamic role "Custom Switch")
    let mut switch_rec = serde_json::Map::new();
    switch_rec.insert("device_id".to_string(), json!("2"));
    switch_rec.insert("device_name".to_string(), json!("switch"));
    switch_rec.insert("device_role".to_string(), json!("Custom Switch"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "10.1.50.30", switch_rec)
        .unwrap();

    // 3. DavidPC (device_id 3, dynamic role "Workstation")
    let mut pc_rec = serde_json::Map::new();
    pc_rec.insert("device_id".to_string(), json!("3"));
    pc_rec.insert("device_name".to_string(), json!("DavidPC"));
    pc_rec.insert("device_role".to_string(), json!("Workstation"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "10.1.33.158", pc_rec)
        .unwrap();

    // Flow A: DavidPC initiates traffic to Switch
    let mut ev_pc_to_sw = Event::new();
    ev_pc_to_sw.set("sensor_uuid", "sensor-router-uuid");
    ev_pc_to_sw.set("lan_ip", "10.1.33.158");
    ev_pc_to_sw.set("wan_ip", "10.1.50.30");
    let out_a = filter.process(ev_pc_to_sw, &state).unwrap();
    assert_eq!(out_a[0].get_str("device_id").as_deref(), Some("3"));
    assert_eq!(out_a[0].get_str("device_name").as_deref(), Some("DavidPC"));

    // Flow B: Switch initiates traffic (lan_ip = 10.1.50.30)
    let mut ev_sw = Event::new();
    ev_sw.set("sensor_uuid", "sensor-router-uuid");
    ev_sw.set("lan_ip", "10.1.50.30");
    ev_sw.set("wan_ip", "8.8.8.8");
    let out_b = filter.process(ev_sw, &state).unwrap();
    assert_eq!(out_b[0].get_str("device_id").as_deref(), Some("2"));
    assert_eq!(out_b[0].get_str("device_name").as_deref(), Some("switch"));
    assert_eq!(out_b[0].get_str("device_role").as_deref(), Some("Custom Switch"));

    // Flow C: Unmanaged guest traffic forwarded through router
    // client_mac unknown, server_mac is router MAC.
    // Must NOT attribute to router device 1!
    let mut ev_guest = Event::new();
    ev_guest.set("sensor_uuid", "sensor-router-uuid");
    ev_guest.set("lan_ip", "192.168.200.5");
    ev_guest.set("server_mac", "00:00:5e:00:01:01");
    let out_c = filter.process(ev_guest, &state).unwrap();
    assert_eq!(out_c[0].get_str("device_id"), None);
}

#[test]
fn test_device_enrichment_mac_takes_priority_over_ip_for_dhcp() {
    let block = PluginBlock {
        name: "device_enrichment".to_string(),
        settings: vec![
            ("mode".to_string(), ConfigValue::String("endpoint".to_string())),
            ("fallback_to_sensor".to_string(), ConfigValue::Bool(false)),
        ],
    };
    let filter = create_filter(&block).unwrap();
    let state = StateStore::new_standalone();

    // 1. Device A: Laptop (MAC registered, dynamic DHCP lease)
    let mut laptop = serde_json::Map::new();
    laptop.insert("device_id".to_string(), json!("10"));
    laptop.insert("device_name".to_string(), json!("Alice-Laptop"));
    laptop.insert("device_role".to_string(), json!("Laptop"));
    state
        .put_record(DEVICE_MAC_PSQL_STORE, "00:aa:bb:cc:dd:ee", laptop)
        .unwrap();

    // 2. Device B: Stale static desktop in IPAM on 192.168.1.50
    let mut desktop = serde_json::Map::new();
    desktop.insert("device_id".to_string(), json!("20"));
    desktop.insert("device_name".to_string(), json!("Bob-Old-Desktop"));
    desktop.insert("device_role".to_string(), json!("Workstation"));
    state
        .put_record(DEVICE_IP_PSQL_STORE, "192.168.1.50", desktop)
        .unwrap();

    // Event has both client_mac (Alice's Laptop hardware) and lan_ip (DHCP leased 192.168.1.50)
    let mut ev = Event::new();
    ev.set("client_mac", "00:aa:bb:cc:dd:ee");
    ev.set("lan_ip", "192.168.1.50");

    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    // Because MAC is unique in hardware and takes precedence under DHCP,
    // it MUST resolve to Alice-Laptop (10), not Bob-Old-Desktop (20)!
    assert_eq!(out[0].get_str("device_id").as_deref(), Some("10"));
    assert_eq!(out[0].get_str("device_name").as_deref(), Some("Alice-Laptop"));
}
