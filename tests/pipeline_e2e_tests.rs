use redborder_vortex::config::{parse_logstash_conf, PipelineEntry};
use redborder_vortex::engine::{CompiledPipeline, VortexEngine};
use redborder_vortex::event::Event;
use redborder_vortex::inputs::rbwindow::RbwindowRunner;
use redborder_vortex::ipc::{ query_ipc, start_ipc_server };
use redborder_vortex::state::{
    InMemoryClusterBackend, StateStore, COUNTER_STORE, LOCATION_STORE, MOBILITY_STORE,
    NMSP_STORE_MEASURE, RADIUS_STORE, SCRAMBLES_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use redborder_vortex::stats::VortexStats;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn write_all_12_pipelines(root: &Path) {
    let pipelines_dir = root.join("pipelines");
    let pipeline_ids = [
        "vault",
        "sflow",
        "netflow",
        "location",
        "nmsp",
        "radius",
        "mobility",
        "apstate",
        "rbwindow",
        "monitor",
        "druid-metrics",
        "malware",
    ];

    let mut yml = String::new();
    for id in &pipeline_ids {
        let dir = pipelines_dir.join(id);
        fs::create_dir_all(&dir).unwrap();
        yml.push_str(&format!(
            "- pipeline.id: {}\n  path.config: \"{}/{}\"/*.conf\n  pipeline.workers: 1\n",
            id,
            pipelines_dir.display(),
            id
        ));
    }
    // Rewrite clean YAML with proper quotes
    let mut clean_yml = String::new();
    for id in &pipeline_ids {
        let dir = pipelines_dir.join(id);
        clean_yml.push_str(&format!(
            "- pipeline.id: {}\n  path.config: \"{}/*.conf\"\n  pipeline.workers: 1\n",
            id,
            dir.display()
        ));
    }
    fs::write(root.join("pipelines.yml"), clean_yml).unwrap();

    // 1. netflow pipeline
    let netflow_dir = pipelines_dir.join("netflow");
    fs::write(
        netflow_dir.join("00_input.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_flow"]
    codec => json
  }
}
"#,
    )
    .unwrap();
    fs::write(
        netflow_dir.join("10_enrich.conf"),
        r#"
filter {
  macscrambling {}
  cidr {
    address => [ "%{src}" ]
    network => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]
    add_tag => [ "is_src_internal" ]
  }
  cidr {
    address => [ "%{dst}" ]
    network => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]
    add_tag => [ "is_dst_internal" ]
  }
  geoip {
    source => "dst"
    target => "geoip_dst"
    default_database_type => "City"
  }
  geoip {
    source => "dst"
    target => "geoip_dst"
    default_database_type => "ASN"
  }
  macvendorsenrich {}
}
"#,
    )
    .unwrap();
    fs::write(
        netflow_dir.join("85_discard_events.conf"),
        r#"
filter {
  if [discard_me] == "true" {
    drop {}
  }
}
"#,
    )
    .unwrap();
    fs::write(
        netflow_dir.join("90_splitflow.conf"),
        r#"
filter {
  netflowenrich {
    counter_store_counter => true
  }
}
"#,
    )
    .unwrap();
    fs::write(
        netflow_dir.join("91_rename.conf"),
        r#"
filter {
  if [geoip_dst][country_code2] {
    mutate {
      rename => {
        "[geoip_dst][country_code2]" => "dst_country_code"
        "[geoip_dst][as_org]" => "dst_as_name"
      }
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        netflow_dir.join("99_output.conf"),
        r#"
output {
  if ![sensor_uuid] or ![sensor_name] {
    kafka {
      bootstrap_servers => "kafka.service.consul:9092"
      topic_id => "rb_flow_post_discard"
      codec => json
    }
  } else {
    kafka {
      bootstrap_servers => "kafka.service.consul:9092"
      topic_id => "rb_flow_post"
      codec => json
    }
  }
}
"#,
    )
    .unwrap();

    // 2. sflow pipeline
    let sflow_dir = pipelines_dir.join("sflow");
    fs::write(
        sflow_dir.join("00_input.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["sflow_raw"]
    codec => json
  }
}
"#,
    )
    .unwrap();
    fs::write(
        sflow_dir.join("01_tagging.conf"),
        r#"
filter {
  cidr {
    address => [ "%{ip_src}" ]
    network => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]
    add_tag => [ "is_src_internal" ]
  }
}
"#,
    )
    .unwrap();
    fs::write(
        sflow_dir.join("02_normalization.conf"),
        r#"
filter {
  if "is_src_internal" in [tags] and !("is_dst_internal" in [tags]) {
    mutate {
      add_field => { "direction" => "upstream" }
    }
  } else if "is_dst_internal" in [tags] and !("is_src_internal" in [tags]) {
    mutate {
      add_field => { "direction" => "downstream" }
    }
  }
  mutate {
    rename => {
      "ip_src" => "src"
      "ip_dst" => "dst"
      "peer_ip_src" => "sensor_ip"
    }
    add_field => {
      "timestamp" => 1700000000
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        sflow_dir.join("03_enrichment.conf"),
        r#"
filter {
  mutate {
    add_field => {
      "sensor_name" => "sflow-sensor-01"
      "sensor_uuid" => "uuid-sflow-01"
      "index_partitions" => 2
      "index_replicas" => 1
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        sflow_dir.join("04_field_conversion.conf"),
        r#"
filter {
  mutate {
    convert => {
      "bytes" => "integer"
      "pkts" => "integer"
      "src_port" => "integer"
      "dst_port" => "integer"
      "ip_protocol" => "string"
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        sflow_dir.join("99_output.conf"),
        r#"
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_flow"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 3. vault pipeline
    let vault_dir = pipelines_dir.join("vault");
    fs::write(
        vault_dir.join("00_input.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_vault"]
    codec => json
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("01_generic.conf"),
        r#"
filter {
  fingerprint {
    source => "message"
    target => "fingerprint"
    key => "redborder-vault-key"
    method => "SHA256"
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("02_sshd.conf"),
        r#"
filter {
  if "sshd" in [app_name] {
    grok {
      match => { "message" => "%{SSHD_MESSAGE}" }
    }
    mutate {
      add_field => { "vault_service" => "sshd" }
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("03_iptables.conf"),
        r#"
filter {
  if "kernel" in [app_name] or "iptables" in [app_name] {
    grok {
      match => { "message" => "%{IPTABLES_MESSAGE}" }
    }
    mutate {
      add_field => { "vault_service" => "iptables" }
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("04_nginx.conf"),
        r#"
filter {
  if "nginx" in [app_name] {
    grok {
      match => { "message" => "%{NGINXACCESS}" }
    }
    mutate {
      add_field => { "vault_service" => "nginx" }
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("05_dnsmasq.conf"),
        r#"
filter {
  if "dnsmasq" in [app_name] {
    grok {
      match => { "message" => [ "%{DNSMASQ_QUERY}", "%{DNSMASQ_FORWARD}", "%{DNSMASQ_ACTION_IS}", "%{DHCPD}" ] }
    }
    mutate {
      add_field => { "vault_service" => "dnsmasq" }
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("07_addfields.conf"),
        r#"
filter {
  if [sshd_client_ip] {
    mutate {
      add_field => { "src" => "%{sshd_client_ip}" }
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("08_incident_enrichment.conf"),
        r#"
filter {
  incident_enrichment {
    incident_fields => ["src", "sshd_user"]
    source => "vault"
    field_scores => {
      "src" => 40
      "sshd_user" => 35
    }
  }
}
"#,
    )
    .unwrap();
    fs::write(
        vault_dir.join("99_output.conf"),
        r#"
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_vault_post"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 4. location pipeline
    let location_dir = pipelines_dir.join("location");
    fs::write(
        location_dir.join("00_location.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_location"]
    codec => json
  }
}
filter {
  location {}
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_location_post"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 5. nmsp pipeline
    let nmsp_dir = pipelines_dir.join("nmsp");
    fs::write(
        nmsp_dir.join("00_nmsp.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_nmsp"]
    codec => json
  }
}
filter {
  nmsp {}
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_nmsp_post"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 6. radius pipeline
    let radius_dir = pipelines_dir.join("radius");
    fs::write(
        radius_dir.join("00_radius.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_radius"]
    codec => json
  }
}
filter {
  radius {}
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_radius_post"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 7. mobility pipeline
    let mobility_dir = pipelines_dir.join("mobility");
    fs::write(
        mobility_dir.join("00_mobility.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_mobility"]
    codec => json
  }
}
filter {
  mobility {}
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_mobility_post"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 8. apstate pipeline
    let apstate_dir = pipelines_dir.join("apstate");
    fs::write(
        apstate_dir.join("00_apstate.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_state"]
    codec => json
  }
}
filter {
  apstate {
    counter_store_counter => true
  }
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_state_post"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 9. rbwindow pipeline
    let rbwindow_dir = pipelines_dir.join("rbwindow");
    fs::write(
        rbwindow_dir.join("00_rbwindow.conf"),
        r#"
input {
  rbwindow {
    schedule => "0 * * * *"
    database_name => "redborder"
    user => "redborder"
    host => "127.0.0.1"
    port => 5432
  }
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_monitor"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 10. monitor pipeline
    let monitor_dir = pipelines_dir.join("monitor");
    fs::write(
        monitor_dir.join("00_monitor.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_monitor_raw"]
    codec => json
  }
}
filter {
  mutate {
    add_field => { "type" => "monitor" }
  }
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_monitor"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 11. druid-metrics pipeline
    let druid_dir = pipelines_dir.join("druid-metrics");
    fs::write(
        druid_dir.join("00_druid_metrics.conf"),
        r#"
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_druid_metrics"]
    codec => json
  }
}
filter {
  druid_metrics {}
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_monitor"
    codec => json
  }
}
"#,
    )
    .unwrap();

    // 12. malware pipeline
    let malware_dir = pipelines_dir.join("malware");
    fs::write(
        malware_dir.join("00_malware.conf"),
        r#"
input {
  file {
    path => ["/var/spool/redborder/malware/*"]
    mode => "read"
  }
}
filter {
  yara {}
  aerospike-malware-score {}
  if [sha256] or [hash] {
    s3-upload-malware-results {
      bucket => "rb-malware"
    }
  }
  python {
    module => "malware"
    function => "clean_input_files"
  }
}
output {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topic_id => "rb_malware_post"
    codec => json
  }
}
"#,
    )
    .unwrap();
}

#[test]
fn test_compile_and_run_all_12_pipelines() {
    let temp_root = std::env::temp_dir().join(format!("rb_vortex_e2e_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();
    write_all_12_pipelines(&temp_root);

    let backend = Arc::new(InMemoryClusterBackend::new());
    let state = Arc::new(StateStore::with_backend(backend.clone()));

    // Seed StateStore for netflow/radius/location/apstate enrichment
    let mut sensor_rec = Map::new();
    sensor_rec.insert("sensor_name".to_string(), json!("sensor-main-01"));
    sensor_rec.insert("namespace_uuid".to_string(), json!("ns-100"));
    sensor_rec.insert("service_provider_uuid".to_string(), json!("sp-100"));
    state
        .put_record(SENSOR_PSQL_STORE, "uuid-sensor-01", sensor_rec)
        .unwrap();

    let mut wlc_rec = Map::new();
    wlc_rec.insert("building".to_string(), json!("Building-A"));
    wlc_rec.insert("campus".to_string(), json!("Campus-Main"));
    wlc_rec.insert("namespace_uuid".to_string(), json!("ns-100"));
    state
        .put_record(WLC_PSQL_STORE, "aa:bb:cc:00:11:22", wlc_rec)
        .unwrap();

    let mut scramble_rec = Map::new();
    scramble_rec.insert("mac_hashing_salt".to_string(), json!("secret_salt"));
    state
        .put_record(SCRAMBLES_STORE, "sp-100", scramble_rec)
        .unwrap();

    let engine = VortexEngine::from_settings_dir(&temp_root, state.clone(), "vortex-node-1")
        .expect("Should compile all 12 pipelines from settings dir");

    assert_eq!(engine.pipeline_ids().len(), 12);

    // 1. Test netflow pipeline:
    // Case A: Valid sensor_uuid + 90-second flow spanning a 60s boundary -> splits into 2 events routed to rb_flow_post
    let mut nf_ev = Event::new();
    nf_ev.set("src", "10.10.1.50");
    nf_ev.set("dst", "8.8.8.8");
    nf_ev.set("client_mac", "00:00:0c:12:34:56");
    nf_ev.set("sensor_uuid", "uuid-sensor-01");
    nf_ev.set("namespace_uuid", "ns-100");
    nf_ev.set("wireless_station", "aa:bb:cc:00:11:22");
    nf_ev.set("first_switched", 1700000010i64);
    nf_ev.set("timestamp", 1700000090i64);
    nf_ev.set("bytes", 800i64);
    nf_ev.set("pkts", 80i64);

    let nf_out = engine
        .process_pipeline_event("netflow", nf_ev)
        .expect("netflow should process");
    assert_eq!(nf_out.len(), 2, "80-second flow across minute boundary must split into 2 events");
    for (topic, ev) in &nf_out {
        assert_eq!(topic, "rb_flow_post");
        assert!(ev.has_tag("is_src_internal"));
        assert!(!ev.has_tag("is_dst_internal"));
        assert_eq!(ev.get("dst_country_code"), Some(&json!("US")));
        assert_eq!(ev.get("dst_as_name"), Some(&json!("GOOGLE")));
        assert_eq!(ev.get("client_mac_vendor"), Some(&json!("Cisco Systems, Inc")));
        assert_eq!(ev.get("building"), Some(&json!("Building-A")));
        assert_eq!(ev.get("sensor_name"), Some(&json!("sensor-main-01")));
    }

    // Case B: Missing sensor_uuid -> routed to rb_flow_post_discard
    let mut nf_missing_sensor = Event::new();
    nf_missing_sensor.set("src", "192.168.1.10");
    nf_missing_sensor.set("dst", "1.1.1.1");
    nf_missing_sensor.set("timestamp", 1700000050i64);
    nf_missing_sensor.set("bytes", 100i64);
    let nf_discard_out = engine
        .process_pipeline_event("netflow", nf_missing_sensor)
        .expect("netflow missing sensor should process");
    assert_eq!(nf_discard_out.len(), 1);
    assert_eq!(nf_discard_out[0].0, "rb_flow_post_discard");

    // Case C: Discarded by 85_discard_events
    let mut nf_drop = Event::new();
    nf_drop.set("discard_me", "true");
    let nf_dropped_out = engine
        .process_pipeline_event("netflow", nf_drop)
        .expect("netflow drop should process");
    assert!(nf_dropped_out.is_empty());

    // 2. Test sflow pipeline:
    let mut sf_ev = Event::new();
    sf_ev.set("@timestamp", "2023-11-14T22:13:20.000Z");
    sf_ev.set("peer_ip_src", "10.1.33.160");
    sf_ev.set("ip_src", "10.1.5.25");
    sf_ev.set("ip_dst", "8.8.4.4");
    sf_ev.set("bytes", "2048");
    sf_ev.set("pkts", "16");
    sf_ev.set("src_port", "51234");
    sf_ev.set("dst_port", "443");
    sf_ev.set("ip_protocol", 6);

    let sf_out = engine
        .process_pipeline_event("sflow", sf_ev)
        .expect("sflow should process");
    assert_eq!(sf_out.len(), 1);
    assert_eq!(sf_out[0].0, "rb_flow");
    let sf_res = &sf_out[0].1;
    assert!(sf_res.has_tag("is_src_internal"));
    assert_eq!(sf_res.get("direction"), Some(&json!("upstream")));
    assert_eq!(sf_res.get("src"), Some(&json!("10.1.5.25")));
    assert_eq!(sf_res.get("dst"), Some(&json!("8.8.4.4")));
    assert_eq!(sf_res.get("sensor_ip"), Some(&json!("10.1.33.160")));
    assert_eq!(sf_res.get("timestamp"), Some(&json!(1700000000)));
    assert_eq!(sf_res.get("sensor_name"), Some(&json!("sflow-sensor-01")));
    assert_eq!(sf_res.get("sensor_uuid"), Some(&json!("uuid-sflow-01")));
    assert_eq!(sf_res.get("bytes"), Some(&json!(2048)));
    assert_eq!(sf_res.get("pkts"), Some(&json!(16)));
    assert_eq!(sf_res.get("ip_protocol"), Some(&json!("6")));

    // 3. Test vault pipeline:
    let mut vault_ev = Event::new();
    vault_ev.set("app_name", "sshd");
    vault_ev.set(
        "message",
        "Accepted publickey for root from 192.168.10.55 port 54321 ssh2",
    );
    let vault_out = engine
        .process_pipeline_event("vault", vault_ev)
        .expect("vault should process");
    assert_eq!(vault_out.len(), 1);
    assert_eq!(vault_out[0].0, "rb_vault_post");
    let v_res = &vault_out[0].1;
    assert!(v_res.contains("fingerprint"));
    assert_eq!(v_res.get("vault_service"), Some(&json!("sshd")));
    assert_eq!(v_res.get("sshd_user"), Some(&json!("root")));
    assert_eq!(v_res.get("sshd_client_ip"), Some(&json!("192.168.10.55")));
    assert_eq!(v_res.get("src"), Some(&json!("192.168.10.55")));
    assert!(v_res.contains("incident_uuid"));
    assert_eq!(v_res.get("incident_score"), Some(&json!(75.0)));

    // 4. Test radius pipeline:
    let mut rad_ev = Event::new();
    rad_ev.set("Calling-Station-Id", "AA-BB-CC-11-22-33");
    rad_ev.set("Called-Station-Id", "AA-BB-CC-00-11-22:CorpWiFi");
    rad_ev.set("User-Name", "alice");
    rad_ev.set("Acct-Status-Type", "Start");
    rad_ev.set("namespace_uuid", "ns-100");
    let rad_out = engine
        .process_pipeline_event("radius", rad_ev)
        .expect("radius should process");
    assert_eq!(rad_out.len(), 1);
    assert_eq!(rad_out[0].0, "rb_radius_post");
    assert_eq!(rad_out[0].1.get("client_id"), Some(&json!("alice")));
    assert_eq!(rad_out[0].1.get("wireless_id"), Some(&json!("CorpWiFi")));
    assert!(state
        .get_record(RADIUS_STORE, "aa:bb:cc:11:22:33ns-100")
        .is_some());

    // 5. Test nmsp pipeline:
    let mut nmsp_ev = Event::new();
    nmsp_ev.set("type", "measure");
    nmsp_ev.set("client_mac", "aa:bb:cc:11:22:33");
    nmsp_ev.set("namespace_uuid", "ns-100");
    nmsp_ev.set("rssi", json!([-78, -58, -82]));
    nmsp_ev.set(
        "ap_mac",
        json!(["aa:bb:cc:00:11:01", "aa:bb:cc:00:11:22", "aa:bb:cc:00:11:03"]),
    );
    let nmsp_out = engine
        .process_pipeline_event("nmsp", nmsp_ev)
        .expect("nmsp should process");
    assert_eq!(nmsp_out.len(), 1);
    assert_eq!(nmsp_out[0].0, "rb_nmsp_post");
    assert_eq!(nmsp_out[0].1.get("client_rssi"), Some(&json!("excellent")));
    assert_eq!(nmsp_out[0].1.get("client_rssi_num"), Some(&json!(-58)));
    assert!(state
        .get_record(NMSP_STORE_MEASURE, "aa:bb:cc:11:22:33ns-100")
        .is_some());

    // 6. Test location pipeline:
    let mut loc_ev = Event::new();
    loc_ev.set("namespace_uuid", "ns-100");
    loc_ev.set(
        "StreamingNotification",
        json!({
            "location": {
                "macAddress": "aa:bb:cc:11:22:33",
                "MapInfo": {
                    "mapHierarchyString": "Campus-Main>Building-A>Floor-2>Zone-East"
                },
                "GeoCoordinate": {
                    "latitude": 37.3891,
                    "longitude": -5.9845
                },
                "dot11Status": "ASSOCIATED"
            }
        }),
    );
    let loc_out = engine
        .process_pipeline_event("location", loc_ev)
        .expect("location should process");
    assert_eq!(loc_out.len(), 1);
    assert_eq!(loc_out[0].0, "rb_location_post");
    assert_eq!(loc_out[0].1.get("floor"), Some(&json!("Floor-2")));
    assert_eq!(loc_out[0].1.get("zone"), Some(&json!("Zone-East")));
    assert!(state
        .get_record(LOCATION_STORE, "aa:bb:cc:11:22:33ns-100")
        .is_some());

    // 7. Test mobility pipeline:
    let mut mob_ev1 = Event::new();
    mob_ev1.set("client_mac", "aa:bb:cc:11:22:33");
    mob_ev1.set("namespace_uuid", "ns-100");
    mob_ev1.set("zone", "Zone-East");
    mob_ev1.set("timestamp", 1000_i64);
    let mob_out1 = engine
        .process_pipeline_event("mobility", mob_ev1)
        .expect("mobility 1 should process");
    assert_eq!(mob_out1.len(), 0, "Unconsolidated first ping produces 0 events");

    let mut mob_ev2 = Event::new();
    mob_ev2.set("client_mac", "aa:bb:cc:11:22:33");
    mob_ev2.set("namespace_uuid", "ns-100");
    mob_ev2.set("zone", "Zone-East");
    mob_ev2.set("timestamp", 1180_i64);
    let mob_out2 = engine
        .process_pipeline_event("mobility", mob_ev2)
        .expect("mobility 2 should process");
    assert!(!mob_out2.is_empty(), "Consolidation produces events");
    assert_eq!(mob_out2[0].0, "rb_mobility_post");
    let zone_ev = mob_out2
        .iter()
        .find(|e| e.1.get_str("type").as_deref() == Some("zone"))
        .expect("Must emit zone event");
    assert_eq!(zone_ev.1.get_str("old").as_deref(), Some("outside"));
    assert_eq!(zone_ev.1.get_str("new").as_deref(), Some("Zone-East"));
    assert_eq!(zone_ev.1.get_i64("transition"), Some(1));
    assert!(state
        .get_record(MOBILITY_STORE, "aa:bb:cc:11:22:33ns-100")
        .is_some());

    // 8. Test apstate pipeline:
    let mut ap_ev = Event::new();
    ap_ev.set("wireless_station", "aa:bb:cc:00:11:22");
    ap_ev.set("namespace_uuid", "ns-100");
    let ap_out = engine
        .process_pipeline_event("apstate", ap_ev)
        .expect("apstate should process");
    assert_eq!(ap_out.len(), 1);
    assert_eq!(ap_out[0].0, "rb_state_post");
    assert_eq!(ap_out[0].1.get("building"), Some(&json!("Building-A")));
    assert!(state.get_counter(COUNTER_STORE, "rb_state") >= 1);

    // 9. Test monitor pipeline:
    let mut mon_ev = Event::new();
    mon_ev.set("monitor", "cpu");
    mon_ev.set("value", 42);
    let mon_out = engine
        .process_pipeline_event("monitor", mon_ev)
        .expect("monitor should process");
    assert_eq!(mon_out.len(), 1);
    assert_eq!(mon_out[0].0, "rb_monitor");
    assert_eq!(mon_out[0].1.get("type"), Some(&json!("monitor")));

    // 10. Test druid-metrics pipeline:
    let mut dm_ev = Event::new();
    dm_ev.set("service", "druid/historical");
    dm_ev.set("metric", "query/cpu/time");
    dm_ev.set("value", 2500.0);
    dm_ev.set("host", "druid01.redborder.cluster:8083");
    dm_ev.set("timestamp", "2023-11-14T22:13:20Z");
    let dm_out = engine
        .process_pipeline_event("druid-metrics", dm_ev)
        .expect("druid-metrics should process");
    assert_eq!(dm_out.len(), 1);
    assert_eq!(dm_out[0].0, "rb_monitor");
    assert_eq!(
        dm_out[0].1.get("monitor"),
        Some(&json!("historical_query_cpu_time"))
    );
    assert_eq!(dm_out[0].1.get("value"), Some(&json!(2.5)));
    assert_eq!(dm_out[0].1.get("sensor_name"), Some(&json!("druid01")));

    // 11. Test malware pipeline:
    let sample_file = temp_root.join("eicar.bin");
    let lock_file = temp_root.join("eicar.bin.lock");
    fs::write(
        &sample_file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();
    fs::write(&lock_file, b"lock").unwrap();

    let mut mal_ev = Event::new();
    mal_ev.set("file_path", sample_file.to_string_lossy().to_string());
    mal_ev.set("file_lock_path", lock_file.to_string_lossy().to_string());
    let mal_out = engine
        .process_pipeline_event("malware", mal_ev)
        .expect("malware should process");
    assert_eq!(mal_out.len(), 1);
    assert_eq!(mal_out[0].0, "rb_malware_post");
    assert_eq!(mal_out[0].1.get("malware_detected"), Some(&json!(true)));
    assert_eq!(mal_out[0].1.get("malware_score"), Some(&json!(75)));
    assert_eq!(mal_out[0].1.get("s3_uploaded"), Some(&json!(true)));
    assert!(!sample_file.exists(), "malware input file should be cleaned up");
    assert!(!lock_file.exists(), "malware lock file should be cleaned up");

    // 12. Test rbwindow pipeline and multi-node Redis leader lock:
    let rbwindow_events_node1 = engine
        .run_rbwindow_tick()
        .expect("Node 1 should acquire rbwindow lock and emit heartbeat");
    assert_eq!(rbwindow_events_node1.len(), 1);
    assert_eq!(rbwindow_events_node1[0].0, "rb_monitor");
    assert_eq!(
        rbwindow_events_node1[0].1.get("monitor"),
        Some(&json!("rbwindow"))
    );
    assert_eq!(
        rbwindow_events_node1[0].1.get("sensor_name"),
        Some(&json!("vortex-node-1"))
    );

    // Second node sharing the same cluster backend must see the lock held by vortex-node-1
    let state_node2 = Arc::new(StateStore::with_backend(backend));
    state_node2.sync_from_backend().unwrap();
    let can_acquire = RbwindowRunner::try_acquire_leader_lock(&state_node2, "vortex-node-2", 60)
        .expect("Lock check should succeed");
    assert!(
        !can_acquire,
        "Node 2 must not acquire lock while Node 1 holds it"
    );

    let engine_node2 =
        VortexEngine::from_settings_dir(&temp_root, state_node2, "vortex-node-2").unwrap();
    let rbwindow_events_node2 = engine_node2
        .run_rbwindow_tick()
        .expect("Node 2 tick should succeed as no-op");
    assert!(
        rbwindow_events_node2.is_empty(),
        "Non-leader node must skip duplicate rbwindow execution"
    );

    let _ = fs::remove_dir_all(&temp_root);
}

#[tokio::test]
async fn test_in_memory_pipeline_input_output_chaining() {
    let tmp_path = std::env::temp_dir().join(format!("vortex_pipe_chain_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp_path).unwrap();
    let root = &tmp_path;
    let pipelines_dir = root.join("pipelines");

    // 1. upstream pipeline 'sflow'
    let sflow_dir = pipelines_dir.join("sflow");
    fs::create_dir_all(&sflow_dir).unwrap();
    fs::write(
        sflow_dir.join("00_pipeline.conf"),
        r#"
        input {
          pipeline {
            address => "sflow-entry"
          }
        }
        filter {
          mutate {
            add_field => { "source_pipeline" => "sflow" }
          }
        }
        output {
          pipeline {
            send_to => ["netflow-ingress"]
          }
        }
        "#,
    ).unwrap();

    // 2. downstream pipeline 'netflow'
    let netflow_dir = pipelines_dir.join("netflow");
    fs::create_dir_all(&netflow_dir).unwrap();
    fs::write(
        netflow_dir.join("00_pipeline.conf"),
        r#"
        input {
          pipeline {
            address => "netflow-ingress"
          }
        }
        filter {
          mutate {
            add_field => { "enriched_by" => "netflow" }
          }
        }
        output {
          kafka {
            topic_id => "rb_flow_post"
            bootstrap_servers => "127.0.0.1:9092"
          }
        }
        "#,
    ).unwrap();

    let pipelines_yml = format!(
        "- pipeline.id: sflow\n  path.config: \"{}/*.conf\"\n  pipeline.workers: 1\n- pipeline.id: netflow\n  path.config: \"{}/*.conf\"\n  pipeline.workers: 1\n",
        sflow_dir.display(),
        netflow_dir.display()
    );
    fs::write(root.join("pipelines.yml"), pipelines_yml).unwrap();

    let state = Arc::new(StateStore::new_standalone());
    let mut engine = VortexEngine::from_pipelines_yml(
        &root.join("pipelines.yml"),
        Some(root),
        state.clone(),
        "test-node".to_string(),
    ).expect("Engine should compile both pipelines with pipeline in/out");

    engine.wire_pipeline_channels();
    let engine_arc = Arc::new(engine);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let worker_handles = VortexEngine::spawn_pipeline_workers(engine_arc.clone(), shutdown_rx);

    // Send an event into 'sflow'
    let sflow_sender = engine_arc.get_pipeline_sender("sflow-entry").expect("Should have sflow-entry sender");
    let mut ev = Event::new();
    ev.set("sflow_seq", 1001);
    sflow_sender.send(ev).unwrap();

    // Deterministically poll for chained event delivery across sflow -> netflow
    let netflow_pipeline = engine_arc.pipelines.get("netflow").unwrap();
    let kafka_sink = netflow_pipeline.outputs.iter().find_map(|o| match o {
        redborder_vortex::outputs::OutputSink::Kafka(k) => Some(k),
        _ => None,
    }).unwrap();

    let start = std::time::Instant::now();
    while kafka_sink.emitted_events().is_empty() && start.elapsed() < std::time::Duration::from_secs(2) {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }

    let emitted = kafka_sink.emitted_events();
    assert_eq!(emitted.len(), 1, "Should have received 1 chained event in netflow output");
    assert_eq!(emitted[0].get_str("source_pipeline"), Some("sflow".to_string()));
    assert_eq!(emitted[0].get_str("enriched_by"), Some("netflow".to_string()));
    assert_eq!(emitted[0].get("sflow_seq").and_then(|v| v.as_i64()), Some(1001));

    let _ = shutdown_tx.send(true);
    for h in worker_handles {
        let _ = h.await;
    }
    let _ = fs::remove_dir_all(&tmp_path);
}

#[test]
fn test_ipc_unix_socket_stats_status_and_reset() {

    let temp_dir = std::env::temp_dir().join(format!("rb_vortex_ipc_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let sock_path = temp_dir.join("redborder-vortex.sock");
    let sock_str = sock_path.to_string_lossy().to_string();

    let state = Arc::new(StateStore::new_standalone());
    let mut rec = Map::new();
    rec.insert("sensor_name".to_string(), json!("sensor-01"));
    state.put_record(SENSOR_PSQL_STORE, "s1", rec).unwrap();

    let mut engine = VortexEngine::new(state.clone(), "vortex-ipc-node");
    let conf = parse_logstash_conf(
        r#"
        input { kafka { topics => ["rb_flow"] } }
        filter { mutate { add_field => { "processed" => "true" } } }
        output { kafka { topic_id => "rb_flow_post" } }
        "#,
    )
    .unwrap();
    engine
        .register_pipeline(
            PipelineEntry {
                id: "netflow".to_string(),
                path_config: "/etc/logstash/pipelines/netflow/*.conf".to_string(),
                workers: 2,
            },
            &conf,
        )
        .unwrap();

    // Process 3 events
    for i in 0..3 {
        let mut ev = Event::new();
        ev.set("seq", i);
        let out = engine.process_pipeline_event("netflow", ev).unwrap();
        assert_eq!(out.len(), 1);
    }

    let handle = start_ipc_server(&sock_str, engine.stats.clone(), state.clone())
        .expect("Should start IPC server on Unix socket");

    // 1. Query "stats"
    let stats_json = query_ipc(&sock_str, "stats").expect("Should query stats over IPC");
    let parsed_stats: VortexStats =
        serde_json::from_str(&stats_json).expect("Should deserialize VortexStats");
    assert_eq!(parsed_stats.node_name, "vortex-ipc-node");
    assert_eq!(parsed_stats.events_received, 3);
    assert_eq!(parsed_stats.events_emitted, 3);
    assert_eq!(parsed_stats.total_workers, 2);
    assert_eq!(parsed_stats.pipelines.len(), 1);
    assert_eq!(parsed_stats.pipelines[0].id, "netflow");
    assert_eq!(parsed_stats.pipelines[0].events_in, 3);
    assert_eq!(parsed_stats.pipelines[0].events_out, 3);
    assert_eq!(parsed_stats.state_stores.get(SENSOR_PSQL_STORE), Some(&1));

    // 2. Query "status"
    let status_json = query_ipc(&sock_str, "status").expect("Should query status over IPC");
    let parsed_status: VortexStats = serde_json::from_str(&status_json).unwrap();
    assert_eq!(parsed_status.events_received, 3);

    // 3. Query "reset"
    let reset_resp = query_ipc(&sock_str, "reset").expect("Should query reset over IPC");
    let reset_val: Value = serde_json::from_str(&reset_resp).unwrap();
    assert_eq!(reset_val.get("status"), Some(&json!("ok")));

    // 4. Verify counters are 0 after reset
    let after_reset_json = query_ipc(&sock_str, "stats").unwrap();
    let after_reset: VortexStats = serde_json::from_str(&after_reset_json).unwrap();
    assert_eq!(after_reset.events_received, 0);
    assert_eq!(after_reset.events_emitted, 0);
    assert_eq!(after_reset.pipelines[0].events_in, 0);
    assert_eq!(after_reset.pipelines[0].events_out, 0);

    // 5. Unknown command
    let unknown_resp = query_ipc(&sock_str, "invalid_cmd").unwrap();
    let unknown_val: Value = serde_json::from_str(&unknown_resp).unwrap();
    assert_eq!(unknown_val.get("error"), Some(&json!("unknown command")));

    // 6. Verify socket file permissions (0666) and double-binding protection
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&sock_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o666);
    }
    assert!(
        start_ipc_server(&sock_str, engine.stats.clone(), state.clone()).is_err(),
        "Should reject double binding when active daemon is listening"
    );

    handle.shutdown();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_compiled_pipeline_direct() {
    let conf = parse_logstash_conf(
        r#"
        input { kafka { topics => ["rb_test"] } }
        filter { mutate { add_field => { "ok" => "yes" } } }
        output { kafka { topic_id => "rb_test_out" } }
        "#,
    )
    .unwrap();
    let entry = PipelineEntry {
        id: "test_pipe".to_string(),
        path_config: "inline".to_string(),
        workers: 1,
    };
    let compiled = CompiledPipeline::compile(entry, &conf).expect("Should compile pipeline");
    let state = StateStore::new_standalone();
    let stats = redborder_vortex::stats::StatsRegistry::new("node-test");
    let out = compiled
        .process_event(Event::new(), &state, &stats)
        .expect("Should process event");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "rb_test_out");
    assert_eq!(out[0].1.get("ok"), Some(&json!("yes")));
}
