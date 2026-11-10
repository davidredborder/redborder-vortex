use redborder_vortex::config::ast::Statement;
use redborder_vortex::config::parse_logstash_conf;
use redborder_vortex::event::Event;
use redborder_vortex::filters::create_filter;
use redborder_vortex::filters::redborder::{
    ApstateFilter, DruidMetricsFilter, IncidentEnrichmentFilter, LocationFilter,
    MacScramblingFilter, MacVendorsEnrichFilter, MobilityFilter, NetflowEnrichFilter, NmspFilter,
    RadiusFilter, ThreatIntelligenceFilter,
};
use redborder_vortex::filters::Filter;
use redborder_vortex::state::{
    StateStore, COUNTER_STORE, DWELL_STORE, LOCATION_STORE, MOBILITY_STORE, NMSP_STORE_INFO,
    NMSP_STORE_MEASURE, RADIUS_STORE, SCRAMBLES_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use serde_json::{json, Map};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[test]
fn test_mac_scrambling_filter() {
    let state = StateStore::new_standalone();
    let mut scramble_rec = Map::new();
    scramble_rec.insert("mac_hashing_salt".to_string(), json!("secret_salt_123"));
    state
        .put_record(SCRAMBLES_STORE, "sp-uuid-1", scramble_rec)
        .unwrap();

    let mut event = Event::new();
    event.set("service_provider_uuid", "sp-uuid-1");
    event.set("client_mac", "AA:BB:CC:DD:EE:FF");

    let filter = MacScramblingFilter::new();
    let out = filter.process(event, &state).unwrap();
    assert_eq!(out.len(), 1);

    let mut hasher = Sha256::new();
    hasher.update("fdah7usad782345@aa:bb:cc:dd:ee:ffsecret_salt_123".as_bytes());
    let digest = hasher.finalize();
    let expected_mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    );

    assert_eq!(
        out[0].get_str("client_mac").as_deref(),
        Some(expected_mac.as_str())
    );
}

#[test]
fn test_mac_vendors_enrich_filter() {
    let state = StateStore::new_standalone();
    let filter = MacVendorsEnrichFilter::default();

    let mut event = Event::new();
    event.set("client_mac", "00:00:0c:12:34:56");

    let out = filter.process(event, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].get_str("client_mac_vendor").as_deref(),
        Some("Cisco Systems, Inc")
    );

    // Does not overwrite existing client_mac_vendor
    let mut event2 = Event::new();
    event2.set("client_mac", "00:00:0c:12:34:56");
    event2.set("client_mac_vendor", "Existing Vendor");
    let out2 = filter.process(event2, &state).unwrap();
    assert_eq!(
        out2[0].get_str("client_mac_vendor").as_deref(),
        Some("Existing Vendor")
    );
}

#[test]
fn test_netflow_enrich_and_split_flow_180s() {
    let state = StateStore::new_standalone();

    // Populate sensor-psql enrichment record
    let mut sensor_rec = Map::new();
    sensor_rec.insert("sensor_name".to_string(), json!("branch-router-1"));
    sensor_rec.insert("organization_uuid".to_string(), json!("org-100"));
    state
        .put_record(SENSOR_PSQL_STORE, "sensor-uuid-1", sensor_rec)
        .unwrap();

    // 180-second flow spanning 3 exact 60-second minute slices: [1200 .. 1380]
    let mut event = Event::new();
    event.set("sensor_uuid", "sensor-uuid-1");
    event.set("namespace_uuid", "ns-1");
    event.set("first_switched", 1200_i64);
    event.set("timestamp", 1380_i64);
    event.set("bytes", 1000_i64);
    event.set("pkts", 100_i64);

    let filter = NetflowEnrichFilter::default();
    let out = filter.process(event, &state).unwrap();

    assert_eq!(out.len(), 3);

    // First slice retains duration = 180
    assert_eq!(out[0].get("duration"), Some(&json!(180)));
    assert_eq!(out[0].get("timestamp"), Some(&json!(1200)));
    assert!(out[0].get("first_switched").is_none());
    assert_eq!(
        out[0].get_str("sensor_name").as_deref(),
        Some("branch-router-1")
    );

    // Subsequent slices have duration removed
    assert!(out[1].get("duration").is_none());
    assert_eq!(out[1].get("timestamp"), Some(&json!(1260)));
    assert!(out[2].get("duration").is_none());
    assert_eq!(out[2].get("timestamp"), Some(&json!(1320)));

    let total_bytes: i64 = out
        .iter()
        .map(|e| e.get("bytes").unwrap().as_i64().unwrap())
        .sum();
    let total_pkts: i64 = out
        .iter()
        .map(|e| e.get("pkts").unwrap().as_i64().unwrap())
        .sum();

    assert_eq!(total_bytes, 1000);
    assert_eq!(total_pkts, 100);

    // Counter incremented by 3
    assert!(
        state.get_counter(COUNTER_STORE, "rb_flow") == 3
            || state.get_counter(COUNTER_STORE, "rb_flow_ns-1") == 3
    );
}

#[test]
fn test_radius_nmsp_location_apstate_mobility_filters() {
    let state = StateStore::new_standalone();

    // 1. RadiusFilter writes to RADIUS_STORE and enriches event
    let mut radius_event = Event::new();
    radius_event.set("Calling-Station-Id", "AA-BB-CC-11-22-33");
    radius_event.set("Called-Station-Id", "00-11-22-33-44-55:CorpWiFi");
    radius_event.set("Packet-Src-IP-Address", "10.0.0.1");
    radius_event.set("User-Name", "alice");
    radius_event.set("Operator-Name", "RedborderTel");
    radius_event.set("Acct-Status-Type", "Start");
    radius_event.set("namespace_uuid", "ns-1");

    let radius_filter = RadiusFilter::new();
    let r_out = radius_filter.process(radius_event, &state).unwrap();
    assert_eq!(r_out.len(), 1);
    assert_eq!(
        r_out[0].get_str("client_mac").as_deref(),
        Some("aa:bb:cc:11:22:33")
    );
    assert_eq!(r_out[0].get_str("client_id").as_deref(), Some("alice"));
    assert_eq!(
        r_out[0].get_str("wireless_station").as_deref(),
        Some("00:11:22:33:44:55")
    );
    assert_eq!(
        r_out[0].get_str("wireless_id").as_deref(),
        Some("CorpWiFi")
    );
    assert_eq!(
        r_out[0].get_str("client_accounting_type").as_deref(),
        Some("start")
    );
    assert!(state
        .get_record(RADIUS_STORE, "aa:bb:cc:11:22:33ns-1")
        .is_some());

    // 2. NmspFilter measure + info
    let mut nmsp_measure = Event::new();
    nmsp_measure.set("type", "measure");
    nmsp_measure.set("client_mac", "aa:bb:cc:11:22:33");
    nmsp_measure.set("namespace_uuid", "ns-1");
    nmsp_measure.set("rssi", json!([-82, -65, -75]));
    nmsp_measure.set(
        "ap_mac",
        json!(["00:11:22:00:00:01", "00:11:22:00:00:02", "00:11:22:00:00:03"]),
    );

    let nmsp_filter = NmspFilter::new();
    let nm_out = nmsp_filter.process(nmsp_measure, &state).unwrap();
    assert_eq!(nm_out.len(), 1);
    assert_eq!(nm_out[0].get_str("client_rssi").as_deref(), Some("good"));
    assert_eq!(nm_out[0].get_str("client_id").as_deref(), Some("alice"));
    assert!(state
        .get_record(NMSP_STORE_MEASURE, "aa:bb:cc:11:22:33ns-1")
        .is_some());

    let mut nmsp_info = Event::new();
    nmsp_info.set("type", "info");
    nmsp_info.set("client_mac", "aa:bb:cc:11:22:33");
    nmsp_info.set("namespace_uuid", "ns-1");
    nmsp_info.set("wireless_channel", 36);
    nmsp_info.set("dot11_protocol", "802.11ax");
    let ni_out = nmsp_filter.process(nmsp_info, &state).unwrap();
    assert_eq!(ni_out.len(), 1);
    assert!(state
        .get_record(NMSP_STORE_INFO, "aa:bb:cc:11:22:33ns-1")
        .is_some());

    // 3. LocationFilter (MSE StreamingNotification)
    let mut loc_event = Event::new();
    loc_event.set("namespace_uuid", "ns-1");
    loc_event.set(
        "StreamingNotification",
        json!({
            "location": {
                "macAddress": "AA:BB:CC:11:22:33",
                "dot11Status": "ASSOCIATED",
                "apMacAddress": "00:11:22:33:44:55",
                "ssId": "CorpWiFi",
                "MapInfo": {
                    "mapHierarchyString": "HQ>BuildingA>Floor2"
                },
                "GeoCoordinate": {
                    "latitude": 37.386051,
                    "longitude": -5.984459
                }
            }
        }),
    );

    let loc_filter = LocationFilter::new();
    let loc_out = loc_filter.process(loc_event, &state).unwrap();
    assert_eq!(loc_out.len(), 1);
    assert_eq!(loc_out[0].get_str("campus").as_deref(), Some("HQ"));
    assert_eq!(
        loc_out[0].get_str("building").as_deref(),
        Some("BuildingA")
    );
    assert_eq!(loc_out[0].get_str("floor").as_deref(), Some("Floor2"));
    assert_eq!(
        loc_out[0].get_str("client_latlong").as_deref(),
        Some("37.386051,-5.984459")
    );
    assert_eq!(loc_out[0].get_str("type").as_deref(), Some("mse"));
    assert!(state
        .get_record(LOCATION_STORE, "aa:bb:cc:11:22:33ns-1")
        .is_some());

    // 4. ApstateFilter
    let mut wlc_rec = Map::new();
    wlc_rec.insert("campus".to_string(), json!("HQ"));
    state
        .put_record(WLC_PSQL_STORE, "00:11:22:33:44:55", wlc_rec)
        .unwrap();

    let mut ap_event = Event::new();
    ap_event.set("wireless_station", "00:11:22:33:44:55");
    let ap_filter = ApstateFilter::default();
    let ap_out = ap_filter.process(ap_event, &state).unwrap();
    assert_eq!(ap_out.len(), 1);
    assert_eq!(ap_out[0].get_str("campus").as_deref(), Some("HQ"));

    // 5. MobilityFilter
    let mut mob_event = Event::new();
    mob_event.set("client_mac", "aa:bb:cc:11:22:33");
    mob_event.set("namespace_uuid", "ns-1");
    mob_event.set("zone", "ZoneA");
    mob_event.set("timestamp", 2000_i64);
    let mob_filter = MobilityFilter::new();
    let mob_out = mob_filter.process(mob_event, &state).unwrap();
    assert_eq!(mob_out.len(), 0, "First ping is unconsolidated");

    // Client consolidates after 180s (t = 2180)
    let mut mob_event2 = Event::new();
    mob_event2.set("client_mac", "aa:bb:cc:11:22:33");
    mob_event2.set("namespace_uuid", "ns-1");
    mob_event2.set("zone", "ZoneA");
    mob_event2.set("timestamp", 2180_i64);
    let mob_out2 = mob_filter.process(mob_event2, &state).unwrap();
    assert!(!mob_out2.is_empty(), "Consolidation emits events");
    assert_eq!(mob_out2[0].get_str("client_id").as_deref(), Some("alice"));
    assert!(
        state
            .get_record(MOBILITY_STORE, "aa:bb:cc:11:22:33ns-1")
            .is_some()
            || state
                .get_record(DWELL_STORE, "aa:bb:cc:11:22:33ns-1")
                .is_some()
    );
}

#[test]
fn test_druid_metrics_filter() {
    let state = StateStore::new_standalone();
    let filter = DruidMetricsFilter::new();

    // 1. Broker metric
    let mut broker_ev = Event::new();
    broker_ev.set("timestamp", "2023-05-01T12:00:00.000Z");
    broker_ev.set("service", "druid/broker");
    broker_ev.set("metric", "query/time");
    broker_ev.set("value", 42);
    broker_ev.set("host", "broker01.redborder.cluster:8082");
    broker_ev.set("version", "0.22.1");
    broker_ev.set("feed", "metrics");

    let b_out = filter.process(broker_ev, &state).unwrap();
    assert_eq!(b_out.len(), 1);
    assert_eq!(
        b_out[0].get_str("monitor").as_deref(),
        Some("broker_query_time")
    );
    assert_eq!(b_out[0].get_str("unit").as_deref(), Some("ms"));
    assert_eq!(b_out[0].get_str("sensor_name").as_deref(), Some("broker01"));
    assert_eq!(b_out[0].get_str("type").as_deref(), Some("system"));
    assert_eq!(b_out[0].get("timestamp"), Some(&json!(1682942400)));
    assert!(b_out[0].get("service").is_none());
    assert!(b_out[0].get("metric").is_none());

    // 2. Historical query/cpu/time divides value by 1000.0
    let mut hist_ev = Event::new();
    hist_ev.set("timestamp", "2023-05-01T12:00:00.000Z");
    hist_ev.set("service", "historical");
    hist_ev.set("metric", "query/cpu/time");
    hist_ev.set("value", 25000);
    hist_ev.set("host", "hist02.local:8083");

    let h_out = filter.process(hist_ev, &state).unwrap();
    assert_eq!(h_out.len(), 1);
    assert_eq!(
        h_out[0].get_str("monitor").as_deref(),
        Some("historical_query_cpu_time")
    );
    assert_eq!(h_out[0].get("value"), Some(&json!(25.0)));
    assert_eq!(h_out[0].get_str("sensor_name").as_deref(), Some("hist02"));

    // 3. Unknown metric is dropped
    let mut unknown_ev = Event::new();
    unknown_ev.set("timestamp", "2023-05-01T12:00:00.000Z");
    unknown_ev.set("service", "druid/broker");
    unknown_ev.set("metric", "unknown/metric/name");
    unknown_ev.set("value", 1);

    let u_out = filter.process(unknown_ev, &state).unwrap();
    assert!(u_out.is_empty());
}

#[test]
fn test_threat_intelligence_and_incident_enrichment_filters() {
    let state = StateStore::new_standalone();

    // Populate KV with clean and malicious indicators for policy 1
    state.set_kv("rbti:1:ip:c:1.1.1.1", "1", None).unwrap();
    state.set_kv("rbti:1:ip:m:185.220.101.1", "90", None).unwrap();
    state
        .set_kv("rbti:1:domain:m:evil.example.com", "70", None)
        .unwrap();

    let ti_filter = ThreatIntelligenceFilter::new("1", "CorpTI", "malware");
    let mut event = Event::new();
    event.set("src", "1.1.1.1");
    event.set("dst", "185.220.101.1");
    event.set("host", "evil.example.com");

    let out = ti_filter.process(event, &state).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("ti_policy_id").as_deref(), Some("1"));
    assert_eq!(out[0].get_str("ti_policy_name").as_deref(), Some("CorpTI"));
    assert_eq!(out[0].get_str("ti_category").as_deref(), Some("malware"));
    // Matched: 1.1.1.1 (0.0), 185.220.101.1 (90.0), evil.example.com (70.0) -> avg = 160 / 3 = 53.33...
    // Or if only malicious/all matched indicators are averaged, score > 0
    let avg_score = out[0]
        .get("ti_average_score")
        .and_then(|v| v.as_f64())
        .unwrap();
    assert!(avg_score > 0.0);
    assert!(out[0].get("ti_indicators").is_some());

    // IncidentEnrichmentFilter
    let mut scores = HashMap::new();
    scores.insert("dst".to_string(), 80.0);
    let inc_filter =
        IncidentEnrichmentFilter::new(vec!["src".to_string(), "dst".to_string()], "ips", scores);
    let inc_out = inc_filter.process(out[0].clone(), &state).unwrap();
    assert_eq!(inc_out.len(), 1);
    assert!(inc_out[0].get_str("incident_uuid").is_some());
}

#[test]
fn test_incident_enrichment_legacy_mem2incident_flow() {
    use redborder_vortex::config::parse_logstash_conf;
    use redborder_vortex::config::ast::Statement;

    let conf = r#"
    filter {
      incident_enrichment {
        incident_fields => ["src", "src_port", "dst", "dst_port"]
        source => "Intrusion"
        incidents_priority_filter => "high"
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("parse conf");
    let state = StateStore::new_standalone();

    if let Statement::Plugin(block) = &parsed.filters[0] {
        let filter = IncidentEnrichmentFilter::from_block(block);

        // 1. High priority new event -> creates incident in Redis and correlation keys
        let mut ev1 = Event::new();
        ev1.set("priority", "high");
        ev1.set("src", "192.168.1.10");
        ev1.set("src_port", "4444");
        ev1.set("msg", "ET TROJAN Badness");
        ev1.set("namespace_uuid", "ns-test-1");

        let out1 = filter.process(ev1, &state).unwrap();
        assert_eq!(out1.len(), 1);
        let uuid1 = out1[0].get_str("incident_uuid").expect("uuid1 present");

        // Verify Redis raw keys formatted for redborder-mem2incident
        let incident_raw = state
            .get_raw_kv(&format!("rbincident:ns-test-1:incident:{}", uuid1))
            .unwrap()
            .expect("incident raw json must exist in redis");
        let inc_json: serde_json::Value = serde_json::from_str(&incident_raw).unwrap();
        assert_eq!(inc_json["uuid"], uuid1);
        assert_eq!(inc_json["name"], "ET TROJAN Badness");
        assert_eq!(inc_json["priority"], "high");
        assert_eq!(inc_json["source"], "Intrusion");
        assert_eq!(inc_json["domain_uuid"], "ns-test-1");
        assert!(inc_json["first_event_at"].is_string());

        // Verify correlation keys
        assert_eq!(
            state.get_raw_kv("rbincident:ns-test-1:ip:192.168.1.10").unwrap(),
            Some(uuid1.clone())
        );
        assert_eq!(
            state.get_raw_kv("rbincident:ns-test-1:port:4444").unwrap(),
            Some(uuid1.clone())
        );

        // 2. Low priority event on same IP correlates to existing incident (score = 100 >= 100)
        let mut ev2 = Event::new();
        ev2.set("priority", "low");
        ev2.set("src", "192.168.1.10");
        ev2.set("namespace_uuid", "ns-test-1");

        let out2 = filter.process(ev2, &state).unwrap();
        assert_eq!(out2.len(), 1);
        assert_eq!(out2[0].get_str("incident_uuid").as_deref(), Some(uuid1.as_str()));

        // 3. Low priority event on unknown IP does NOT create incident
        let mut ev3 = Event::new();
        ev3.set("priority", "low");
        ev3.set("src", "10.0.0.99");
        ev3.set("namespace_uuid", "ns-test-1");

        let out3 = filter.process(ev3, &state).unwrap();
        assert_eq!(out3.len(), 1);
        assert!(out3[0].get_str("incident_uuid").is_none());

        // 4. Partner correlation: event with low-score match (port 4444 -> score 30 < 100)
        // and new IP (src 10.0.0.77) with high priority creates new incident and links relation key
        let mut ev4 = Event::new();
        ev4.set("priority", "high");
        ev4.set("src", "10.0.0.77");
        ev4.set("src_port", "4444");
        ev4.set("msg", "ET ATTACK Linked");
        ev4.set("namespace_uuid", "ns-test-1");

        let out4 = filter.process(ev4, &state).unwrap();
        assert_eq!(out4.len(), 1);
        let uuid2 = out4[0].get_str("incident_uuid").expect("uuid2 present");
        assert_ne!(uuid1, uuid2);

        // Verify relation key points from new incident to partner (format rbincident:relation:<uuid>)
        let relation = state
            .get_raw_kv(&format!("rbincident:relation:{}", uuid2))
            .unwrap();
        assert_eq!(relation, Some(uuid1));
    }
}

#[test]
fn test_threat_intelligence_indicators_mapping_netflow() {
    use redborder_vortex::config::parse_logstash_conf;
    use redborder_vortex::config::ast::Statement;

    let conf = r#"
    filter {
      threat_intelligence {
        policy_id => "1"
        policy_name => "netflow_policy"
        category => "reputation"
        indicators_mapping => {
          "lan_ip" => "ip"
          "wan_ip" => "ip"
          "host" => "domain"
        }
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("parse conf");
    let state = StateStore::new_standalone();

    state.set_kv("rbti:1:ip:m:192.168.1.50", "95", None).unwrap();
    state.set_kv("rbti:1:domain:m:c2.badguys.com", "88", None).unwrap();

    if let Statement::Plugin(block) = &parsed.filters[0] {
        let filter = ThreatIntelligenceFilter::from_block(block);
        assert_eq!(filter.indicator_fields.len(), 3);
        assert!(filter.indicator_fields.contains(&("lan_ip".to_string(), "ip".to_string())));
        assert!(filter.indicator_fields.contains(&("wan_ip".to_string(), "ip".to_string())));
        assert!(filter.indicator_fields.contains(&("host".to_string(), "domain".to_string())));

        let mut event = Event::new();
        event.set("lan_ip", "192.168.1.50");
        event.set("wan_ip", "8.8.8.8");
        event.set("host", "c2.badguys.com");

        let out = filter.process(event, &state).unwrap();
        assert_eq!(out.len(), 1);
        let score = out[0].get("ti_average_score").and_then(|v| v.as_f64()).unwrap();
        assert!(score > 0.0);
        let indicators = out[0].get("ti_indicators").and_then(|v| v.as_array()).unwrap();
        assert_eq!(indicators.len(), 2); // lan_ip and host
    }
}

#[test]
fn test_threat_intelligence_memcached_and_sensors_policies() {
    use redborder_vortex::config::parse_logstash_conf;
    use redborder_vortex::config::ast::Statement;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // 1. Spawn a mock Memcached server
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 512];
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let req = String::from_utf8_lossy(&buf[..n]);
                for line in req.lines() {
                    if line.starts_with("get ") {
                        let key = line.trim_start_matches("get ").trim();
                        if key == "rbti:1:ip:m:192.168.1.100" {
                            let resp = "VALUE rbti:1:ip:m:192.168.1.100 0 3\r\n1.0\r\nEND\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        } else if key == "rbti:1:ip:c:192.168.1.1" {
                            let resp = "VALUE rbti:1:ip:c:192.168.1.1 0 1\r\n1\r\nEND\r\n";
                            let _ = stream.write_all(resp.as_bytes());
                        } else {
                            let _ = stream.write_all(b"END\r\n");
                        }
                    }
                }
            }
        }
    });

    let conf = format!(
        r#"
    filter {{
      threat_intelligence {{
        memcached_servers => ["127.0.0.1:{}"]
        sensors_policies => {{
          "router" => {{
            "id" => 1
            "name" => "threath intelligence"
            "threshold_ip" => 50
            "threshold_domain" => 50
          }}
        }}
        indicators_mapping => {{
          "lan_ip" => "ip"
          "wan_ip" => "ip"
          "host" => "domain"
        }}
      }}
    }}
    "#,
        port
    );

    let parsed = parse_logstash_conf(&conf).expect("parse conf");
    let state = StateStore::new_standalone();

    // In Redis/StateStore, add a fallback indicator for domain
    state
        .set_kv("rbti:1:domain:m:malicious-fallback.com", "0.9", None)
        .unwrap();

    if let Statement::Plugin(block) = &parsed.filters[0] {
        let filter = ThreatIntelligenceFilter::from_block(block);
        assert_eq!(filter.memcached_servers, vec![format!("127.0.0.1:{}", port)]);
        assert!(filter.sensors_policies.contains_key("router"));

        // Event from sensor "router"
        let mut event = Event::new();
        event.set("sensor_name", "router");
        event.set("lan_ip", "192.168.1.100"); // Malicious in Memcached
        event.set("wan_ip", "192.168.1.1"); // Clean in Memcached
        event.set("host", "malicious-fallback.com"); // Malicious in Redis fallback

        let out = filter.process(event, &state).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].get_str("ti_category").as_deref(), Some("malicious"));
        assert_eq!(out[0].get_str("ti_policy_id").as_deref(), Some("1"));
        assert_eq!(
            out[0].get_str("ti_policy_name").as_deref(),
            Some("threath intelligence")
        );
        let indicators_str = out[0].get_str("ti_indicators").unwrap();
        assert!(indicators_str.contains("lan_ip"));
        assert!(indicators_str.contains("host"));
        assert!(!indicators_str.contains("wan_ip"));
    }
}

#[test]
fn test_threat_intelligence_circuit_breaker_and_edge_cases() {
    use redborder_vortex::config::parse_logstash_conf;
    use redborder_vortex::config::ast::Statement;

    // Point to an unreachable port to test circuit breaker
    let conf = r#"
    filter {
      threat_intelligence {
        memcached_servers => ["127.0.0.1:4"]
        sensors_policies => {
          "router" => {
            "id" => 1
            "name" => "threath intelligence"
            "threshold_ip" => 50.0
          }
        }
        indicators_mapping => {
          "lan_ip" => "ip"
        }
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("parse conf");
    let state = StateStore::new_standalone();

    // Populate Redis fallback
    state.set_kv("rbti:1:ip:m:10.10.10.10", "0.85", None).unwrap();

    if let Statement::Plugin(block) = &parsed.filters[0] {
        let filter = ThreatIntelligenceFilter::from_block(block);

        // 1. CRLF / whitespace injection safety (must return None without error or crash)
        assert!(filter.query_memcached("rbti:1:ip:m:bad key\r\n").is_none());
        assert!(filter.query_memcached("").is_none());

        // 2. Unmatched sensor returns event untouched (no random policy assignment)
        let mut unknown_event = Event::new();
        unknown_event.set("sensor_name", "unknown_switch");
        unknown_event.set("lan_ip", "10.10.10.10");
        let unk_out = filter.process(unknown_event, &state).unwrap();
        assert_eq!(unk_out.len(), 1);
        assert!(unk_out[0].get_str("ti_category").is_none());

        // 3. Matched sensor: Memcached is down, circuit breaker opens and falls back to Redis
        let mut event1 = Event::new();
        event1.set("sensor_name", "router");
        event1.set("lan_ip", "10.10.10.10");
        let out1 = filter.process(event1, &state).unwrap();
        assert_eq!(out1.len(), 1);
        assert_eq!(out1[0].get_str("ti_category").as_deref(), Some("malicious"));
        assert_eq!(out1[0].get("ti_average_score").and_then(|v| v.as_f64()), Some(85.0));

        // 4. Second event hits L1 cache / circuit breaker (fast, sub-millisecond)
        let mut event2 = Event::new();
        event2.set("sensor_name", "router");
        event2.set("lan_ip", "10.10.10.10");
        let t2 = std::time::Instant::now();
        let out2 = filter.process(event2, &state).unwrap();
        assert!(t2.elapsed() < std::time::Duration::from_millis(5));
        assert_eq!(out2[0].get_str("ti_category").as_deref(), Some("malicious"));
    }
}

#[test]
fn test_nmsp_dot11_status_probing_and_associated() {
    let state = StateStore::new_standalone();
    let nmsp_filter = NmspFilter::new();

    // 1. Unknown client sends measure -> dot11_status must be "PROBING"
    let mut measure1 = Event::new();
    measure1.set("type", "measure");
    measure1.set("client_mac", "66:75:3b:f5:59:b4");
    measure1.set("namespace_uuid", "ns-1");
    measure1.set("rssi", json!([-70]));
    measure1.set("ap_mac", json!(["dc:8c:37:3d:30:00"]));

    let out1 = nmsp_filter.process(measure1, &state).unwrap();
    assert_eq!(out1.len(), 1);
    assert_eq!(out1[0].get_str("dot11_status").as_deref(), Some("PROBING"));

    // 2. Client is registered in NMSP info as associated to an AP with recent last_seen
    let now = chrono::Utc::now().timestamp();
    let mut info = Event::new();
    info.set("type", "info");
    info.set("client_mac", "66:75:3b:f5:59:b4");
    info.set("namespace_uuid", "ns-1");
    info.set("wireless_station", "dc:8c:37:3d:30:00");
    info.set("wireless_channel", 36);
    info.set("dot11_protocol", "DOT11AC");
    info.set("last_seen", now);
    let _ = nmsp_filter.process(info, &state).unwrap();

    // 3. Next measure event for that client -> dot11_status must be "ASSOCIATED"
    let mut measure2 = Event::new();
    measure2.set("type", "measure");
    measure2.set("client_mac", "66:75:3b:f5:59:b4");
    measure2.set("namespace_uuid", "ns-1");
    measure2.set("rssi", json!([-65]));
    measure2.set("ap_mac", json!(["dc:8c:37:3d:30:00"]));

    let out2 = nmsp_filter.process(measure2, &state).unwrap();
    assert_eq!(out2.len(), 1);
    assert_eq!(out2[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));
}

#[test]
fn test_nmsp_real_wlc_payload_info_timestamp_and_measure_parity() {
    let state = StateStore::new_standalone();
    let nmsp_filter = NmspFilter::new();
    let mac = "60:a5:e2:6b:62:46";
    let ns = "3c69fcf0-96b7-4a35-9946-1d9eb0b8cb88";
    let store_key = format!("{}{}", mac, ns);

    // 1. Send real WLC info payload: only has "timestamp", no "last_seen" field
    let mut info = Event::new();
    info.set("type", "info");
    info.set("client_mac", mac);
    info.set("namespace_uuid", ns);
    info.set("timestamp", 1793705528_i64);
    info.set("wireless_station", "DC:8C:37:3D:30:00");
    info.set("wireless_id", "AVANTALIA");
    info.set("dot11_protocol", "DOT11AC");

    let info_out = nmsp_filter.process(info, &state).unwrap();
    assert_eq!(info_out.len(), 1);
    assert_eq!(info_out[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));

    // Verify NMSP_STORE_INFO received last_seen and dot11_status
    let cached_info = state.get_record(NMSP_STORE_INFO, &store_key).expect("cached info must exist");
    assert_eq!(cached_info.get("last_seen").and_then(|v| v.as_i64()), Some(1793705528));
    assert_eq!(cached_info.get("dot11_status").and_then(|v| v.as_str()), Some("ASSOCIATED"));
    assert_eq!(cached_info.get("wireless_station").and_then(|v| v.as_str()), Some("dc:8c:37:3d:30:00"));

    // 2. Measure event for associated client arriving with multiple APs (associated AP has RSSI -72, other has -60)
    let mut measure1 = Event::new();
    measure1.set("type", "measure");
    measure1.set("client_mac", mac);
    measure1.set("namespace_uuid", ns);
    measure1.set("timestamp", 1793705560_i64);
    measure1.set("ap_mac", json!(["c8:84:a1:c0:54:00", "dc:8c:37:3d:30:00"]));
    measure1.set("rssi", json!([-60, -72]));

    let m_out1 = nmsp_filter.process(measure1, &state).unwrap();
    assert_eq!(m_out1.len(), 1);
    assert_eq!(m_out1[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));
    assert_eq!(m_out1[0].get_str("wireless_station").as_deref(), Some("dc:8c:37:3d:30:00"));
    assert_eq!(m_out1[0].get_i64("client_rssi_num"), Some(-72));
    assert_eq!(m_out1[0].get_str("wireless_id").as_deref(), Some("AVANTALIA"));
    assert_eq!(m_out1[0].get_str("dot11_protocol").as_deref(), Some("DOT11AC"));

    // 3. Measure event where the associated AP did NOT report the client -> dropped (to_druid = nil)
    let mut measure_other_ap = Event::new();
    measure_other_ap.set("type", "measure");
    measure_other_ap.set("client_mac", mac);
    measure_other_ap.set("namespace_uuid", ns);
    measure_other_ap.set("timestamp", 1793705570_i64);
    measure_other_ap.set("ap_mac", json!(["c8:84:a1:c0:54:00"]));
    measure_other_ap.set("rssi", json!([-65]));

    let m_out_drop = nmsp_filter.process(measure_other_ap, &state).unwrap();
    assert!(m_out_drop.is_empty(), "measure without associated AP present must be dropped");

    // 4. Legacy Redis record fallback: info record has wireless_station but lacks last_seen
    let legacy_mac = "2e:fb:fe:c6:e3:0d";
    let legacy_key = format!("{}{}", legacy_mac, ns);
    let mut legacy_info = serde_json::Map::new();
    legacy_info.insert("wireless_station".to_string(), json!("c8:84:a1:c0:54:00"));
    legacy_info.insert("wireless_id".to_string(), json!("GUEST"));
    state.put_record(NMSP_STORE_INFO, &legacy_key, legacy_info).unwrap();

    let mut measure_legacy = Event::new();
    measure_legacy.set("type", "measure");
    measure_legacy.set("client_mac", legacy_mac);
    measure_legacy.set("namespace_uuid", ns);
    measure_legacy.set("timestamp", 1793705580_i64);
    measure_legacy.set("ap_mac", json!(["c8:84:a1:c0:54:00"]));
    measure_legacy.set("rssi", json!([-64]));

    let m_out_legacy = nmsp_filter.process(measure_legacy, &state).unwrap();
    assert_eq!(m_out_legacy.len(), 1);
    assert_eq!(m_out_legacy[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));

    // 5. Weak probe dropping: unknown client probing with RSSI < -80 is dropped
    let mut weak_probe = Event::new();
    weak_probe.set("type", "measure");
    weak_probe.set("client_mac", "11:22:33:44:55:66");
    weak_probe.set("namespace_uuid", ns);
    weak_probe.set("rssi", json!([-85]));
    weak_probe.set("ap_mac", json!(["c8:84:a1:c0:54:00"]));

    let weak_out = nmsp_filter.process(weak_probe, &state).unwrap();
    assert!(weak_out.is_empty(), "probing event with rssi < -80 must be dropped");
}

#[test]
fn test_mobility_configurable_timings() {
    let state = StateStore::new_standalone();
    let mut filter = MobilityFilter::new();
    // Fast 10-second consolidation for testing
    filter.consolidated_time = 10;

    let mut ev1 = Event::new();
    ev1.set("client_mac", "66:75:3b:f5:59:b4");
    ev1.set("namespace_uuid", "ns-1");
    ev1.set("zone_uuid", "zone_test");
    ev1.set("timestamp", 1000_i64);
    let out1 = filter.process(ev1, &state).unwrap();
    assert_eq!(out1.len(), 0, "Initial ping should debounce");

    // Event 2 at t=1060 (next minute boundary)
    let mut ev2 = Event::new();
    ev2.set("client_mac", "66:75:3b:f5:59:b4");
    ev2.set("namespace_uuid", "ns-1");
    ev2.set("zone_uuid", "zone_test");
    ev2.set("timestamp", 1060_i64);
    let out2 = filter.process(ev2, &state).unwrap();
    assert!(!out2.is_empty(), "Should consolidate after configured 10s");
    let transition_ev = out2.iter().find(|e| e.get_i64("transition") == Some(1)).expect("Must emit transition event");
    assert_eq!(transition_ev.get_str("old").as_deref(), Some("outside"));
    assert_eq!(transition_ev.get_str("new").as_deref(), Some("zone_test"));
}

#[test]
fn test_mobility_configurable_ttl_settings() {
    use redborder_vortex::config::parse_logstash_conf;

    let conf = r#"
    filter {
        mobility {
            visitor_ttl => 43200
            outside_ttl => 3600
            dwell_store_ttl => 5400
        }
    }
    "#;
    let ast = parse_logstash_conf(conf).expect("Must parse mobility config");
    let pb = match &ast.filters[0] {
        redborder_vortex::config::Statement::Plugin(b) => b,
        _ => panic!("Expected plugin block"),
    };
    let filter = MobilityFilter::from_block(pb);
    assert_eq!(filter.max_time_without_movement, 43200);
    assert_eq!(filter.probe_ttl, 3600);
    assert_eq!(filter.dwell_ttl, 5400);

    let state = StateStore::new_standalone();

    // 1. Outside probe device:
    let mut probe_ev = Event::new();
    probe_ev.set("client_mac", "aa:bb:cc:dd:ee:01");
    probe_ev.set("namespace_uuid", "ns-probe");
    probe_ev.set("timestamp", 1000);
    let _ = filter.process(probe_ev, &state).unwrap();

    assert!(state.get_record(MOBILITY_STORE, "aa:bb:cc:dd:ee:01ns-probe").is_some());
    // Dwell store must NOT be written for outside probes:
    assert!(state.get_record(DWELL_STORE, "aa:bb:cc:dd:ee:01ns-probe").is_none());

    // 2. Consolidated visitor device (e.g. at building & floor):
    let mut visitor_ev1 = Event::new();
    visitor_ev1.set("client_mac", "aa:bb:cc:dd:ee:02");
    visitor_ev1.set("namespace_uuid", "ns-visitor");
    visitor_ev1.set("building_uuid", "bldg-1");
    visitor_ev1.set("timestamp", 1000);
    let _ = filter.process(visitor_ev1, &state).unwrap();

    let mut visitor_ev2 = Event::new();
    visitor_ev2.set("client_mac", "aa:bb:cc:dd:ee:02");
    visitor_ev2.set("namespace_uuid", "ns-visitor");
    visitor_ev2.set("building_uuid", "bldg-1");
    visitor_ev2.set("timestamp", 1200); // 200s later (> 180s consolidation)
    let _ = filter.process(visitor_ev2, &state).unwrap();

    assert!(state.get_record(MOBILITY_STORE, "aa:bb:cc:dd:ee:02ns-visitor").is_some());
    // Dwell store IS written for consolidated visitor:
    assert!(state.get_record(DWELL_STORE, "aa:bb:cc:dd:ee:02ns-visitor").is_some());
}

#[test]
fn test_mobility_client_mac_vendor_enrichment() {
    let state = StateStore::new_standalone();
    let filter = MobilityFilter::new();

    // 1. Initial event with Cisco MAC (OUI 00000C -> Cisco Systems, Inc)
    let mut ev1 = Event::new();
    ev1.set("client_mac", "00:00:0c:11:22:33");
    ev1.set("namespace_uuid", "ns-vendor-test");
    ev1.set("building_uuid", "bldg-test");
    ev1.set("timestamp", 1000_i64);
    let _ = filter.process(ev1, &state).unwrap();

    // Consolidation ping at t = 1200
    let mut ev1_cons = Event::new();
    ev1_cons.set("client_mac", "00:00:0c:11:22:33");
    ev1_cons.set("namespace_uuid", "ns-vendor-test");
    ev1_cons.set("building_uuid", "bldg-test");
    ev1_cons.set("timestamp", 1200_i64);

    let out1 = filter.process(ev1_cons, &state).unwrap();
    assert!(!out1.is_empty());
    assert_eq!(
        out1[0].get_str("client_mac_vendor").as_deref(),
        Some("Cisco Systems, Inc")
    );
    assert_eq!(
        out1[0].get_str("mac_vendor").as_deref(),
        Some("Cisco Systems, Inc")
    );

    // 2. Event with upstream pre-existing client_mac_vendor:
    let mut ev2 = Event::new();
    ev2.set("client_mac", "11:22:33:44:55:66");
    ev2.set("client_mac_vendor", "Pre-Enriched Vendor");
    ev2.set("namespace_uuid", "ns-vendor-test");
    ev2.set("building_uuid", "bldg-test");
    ev2.set("timestamp", 1000_i64);
    let _ = filter.process(ev2, &state).unwrap();

    let mut ev2_cons = Event::new();
    ev2_cons.set("client_mac", "11:22:33:44:55:66");
    ev2_cons.set("client_mac_vendor", "Pre-Enriched Vendor");
    ev2_cons.set("namespace_uuid", "ns-vendor-test");
    ev2_cons.set("building_uuid", "bldg-test");
    ev2_cons.set("timestamp", 1200_i64);

    let out2 = filter.process(ev2_cons, &state).unwrap();
    assert!(!out2.is_empty());
    assert_eq!(
        out2[0].get_str("client_mac_vendor").as_deref(),
        Some("Pre-Enriched Vendor")
    );
    assert_eq!(
        out2[0].get_str("mac_vendor").as_deref(),
        Some("Pre-Enriched Vendor")
    );
}

#[test]
fn test_nmsp_and_mobility_client_profile_classification() {
    let state = StateStore::new_standalone();
    let nmsp_filter = NmspFilter::new();
    let mut mobility_filter = MobilityFilter::new();
    mobility_filter.consolidated_time = 10;

    // 1. Weak RSSI (-80 dBm) -> soft
    let mut ev_soft = Event::new();
    ev_soft.set("type", "measure");
    ev_soft.set("client_mac", "AA:BB:CC:11:22:01");
    ev_soft.set("namespace_uuid", "ns-1");
    ev_soft.set("rssi", json!([-80]));
    let out_soft = nmsp_filter.process(ev_soft, &state).unwrap();
    assert_eq!(out_soft[0].get_str("client_profile").as_deref(), Some("soft"));

    // 2. Medium RSSI (-70 dBm) -> medium
    let mut ev_med = Event::new();
    ev_med.set("type", "measure");
    ev_med.set("client_mac", "AA:BB:CC:11:22:02");
    ev_med.set("namespace_uuid", "ns-1");
    ev_med.set("rssi", json!([-70]));
    let out_med = nmsp_filter.process(ev_med, &state).unwrap();
    assert_eq!(out_med[0].get_str("client_profile").as_deref(), Some("medium"));

    // 3. Strong RSSI (-55 dBm) -> hard
    let mut ev_hard = Event::new();
    ev_hard.set("type", "measure");
    ev_hard.set("client_mac", "AA:BB:CC:11:22:03");
    ev_hard.set("namespace_uuid", "ns-1");
    ev_hard.set("rssi", json!([-55]));
    let out_hard = nmsp_filter.process(ev_hard, &state).unwrap();
    assert_eq!(out_hard[0].get_str("client_profile").as_deref(), Some("hard"));

    // 4. Zero RSSI (e.g. associated / default) -> hard
    let mut ev_zero = Event::new();
    ev_zero.set("type", "measure");
    ev_zero.set("client_mac", "AA:BB:CC:11:22:04");
    ev_zero.set("namespace_uuid", "ns-1");
    ev_zero.set("rssi", json!([0]));
    let out_zero = nmsp_filter.process(ev_zero, &state).unwrap();
    assert_eq!(out_zero[0].get_str("client_profile").as_deref(), Some("hard"));

    // 5. Measure event without RSSI field -> defaults to hard
    let mut ev_no_rssi = Event::new();
    ev_no_rssi.set("type", "measure");
    ev_no_rssi.set("client_mac", "AA:BB:CC:11:22:05");
    ev_no_rssi.set("namespace_uuid", "ns-1");
    let out_no_rssi = nmsp_filter.process(ev_no_rssi, &state).unwrap();
    assert_eq!(out_no_rssi[0].get_str("client_profile").as_deref(), Some("hard"));

    // 6. Mobility with inherited client_profile ("medium")
    let mut mob1 = Event::new();
    mob1.set("client_mac", "AA:BB:CC:11:22:02");
    mob1.set("namespace_uuid", "ns-1");
    mob1.set("zone_uuid", "zone_test");
    mob1.set("client_profile", "medium");
    mob1.set("timestamp", 1000_i64);
    let _ = mobility_filter.process(mob1, &state).unwrap();

    let mut mob2 = Event::new();
    mob2.set("client_mac", "AA:BB:CC:11:22:02");
    mob2.set("namespace_uuid", "ns-1");
    mob2.set("zone_uuid", "zone_test");
    mob2.set("client_profile", "medium");
    mob2.set("timestamp", 1060_i64);
    let out_mob = mobility_filter.process(mob2, &state).unwrap();
    assert!(!out_mob.is_empty());
    for e in &out_mob {
        assert_eq!(e.get_str("client_profile").as_deref(), Some("medium"));
    }

    // 5. Mobility without client_profile -> defaults to "hard"
    let mut def1 = Event::new();
    def1.set("client_mac", "AA:BB:CC:11:22:99");
    def1.set("namespace_uuid", "ns-1");
    def1.set("zone_uuid", "zone_test");
    def1.set("timestamp", 2000_i64);
    let _ = mobility_filter.process(def1, &state).unwrap();

    let mut def2 = Event::new();
    def2.set("client_mac", "AA:BB:CC:11:22:99");
    def2.set("namespace_uuid", "ns-1");
    def2.set("zone_uuid", "zone_test");
    def2.set("timestamp", 2060_i64);
    let out_def = mobility_filter.process(def2, &state).unwrap();
    assert!(!out_def.is_empty());
    for e in &out_def {
        assert_eq!(e.get_str("client_profile").as_deref(), Some("hard"));
    }
}

#[test]
fn test_nmsp_configurable_rssi_and_mobility_timer_aliases() {
    use redborder_vortex::config::ast::{ConfigValue, PluginBlock};

    let state = StateStore::new_standalone();

    // 1. MobilityFilter parsing timer aliases (consolidation_timer, expiration_timer, dwell_timer, repetitions_expiration_timer)
    let mob_block = PluginBlock {
        name: "mobility".to_string(),
        settings: vec![
            ("consolidation_timer".to_string(), ConfigValue::Integer(15)),
            ("expiration_timer".to_string(), ConfigValue::Integer(600)),
            ("dwell_timer".to_string(), ConfigValue::Integer(300)),
            ("repetitions_expiration_timer".to_string(), ConfigValue::Integer(3600)),
        ],
    };
    let mob_filter = MobilityFilter::from_block(&mob_block);
    assert_eq!(mob_filter.consolidated_time, 15);
    assert_eq!(mob_filter.expired_time, 600);
    assert_eq!(mob_filter.max_dwell_time, 300);
    assert_eq!(mob_filter.expired_repetitions_time, 3600);

    // 2. NmspFilter with custom RSSI thresholds:
    //    custom soft_rssi = -80, custom medium_rssi = -70
    let nmsp_block = PluginBlock {
        name: "nmsp".to_string(),
        settings: vec![
            ("soft_rssi".to_string(), ConfigValue::Integer(-80)),
            ("medium_rssi".to_string(), ConfigValue::Integer(-70)),
        ],
    };
    let nmsp_filter = NmspFilter::from_block(&nmsp_block);
    assert_eq!(nmsp_filter.soft_rssi, -80);
    assert_eq!(nmsp_filter.medium_rssi, -70);

    // With soft_rssi = -80, an event with -78 dBm should now be "medium" (since > -80 and <= -70)
    // whereas with default (-75) it was "soft".
    let mut ev = Event::new();
    ev.set("type", "measure");
    ev.set("client_mac", "AA:BB:CC:11:22:88");
    ev.set("namespace_uuid", "ns-1");
    ev.set("rssi", json!([-78]));
    let out = nmsp_filter.process(ev, &state).unwrap();
    assert_eq!(out[0].get_str("client_profile").as_deref(), Some("medium"));
}

#[test]
fn test_nmsp_triangulation_weighted_centroid_and_floor_isolation() {
    use redborder_vortex::config::ast::{ConfigValue, PluginBlock};

    let state = StateStore::new_standalone();

    let ap1 = "11:11:11:11:11:11";
    let ap2 = "22:22:22:22:22:22";
    let ap3 = "33:33:33:33:33:33";

    // AP 1 on Floor A: (28.000000, -16.000000)
    let mut ap1_data = serde_json::Map::new();
    ap1_data.insert("mac".to_string(), json!(ap1));
    ap1_data.insert("latitude".to_string(), json!(28.000000));
    ap1_data.insert("longitude".to_string(), json!(-16.000000));
    ap1_data.insert("floor_uuid".to_string(), json!("floor-a"));
    state.put_record("wlc-psql", ap1, ap1_data).unwrap();

    // AP 2 on Floor A: (28.002000, -16.002000)
    let mut ap2_data = serde_json::Map::new();
    ap2_data.insert("mac".to_string(), json!(ap2));
    ap2_data.insert("latitude".to_string(), json!(28.002000));
    ap2_data.insert("longitude".to_string(), json!(-16.002000));
    ap2_data.insert("floor_uuid".to_string(), json!("floor-a"));
    state.put_record("wlc-psql", ap2, ap2_data).unwrap();

    // AP 3 on Floor B (different floor): (29.999999, -17.999999)
    let mut ap3_data = serde_json::Map::new();
    ap3_data.insert("mac".to_string(), json!(ap3));
    ap3_data.insert("latitude".to_string(), json!(29.999999));
    ap3_data.insert("longitude".to_string(), json!(-17.999999));
    ap3_data.insert("floor_uuid".to_string(), json!("floor-b"));
    state.put_record("wlc-psql", ap3, ap3_data).unwrap();

    // 1. By default, triangulation is disabled -> uses AP 1's exact coordinates
    let default_filter = NmspFilter::new();
    assert!(!default_filter.enable_triangulation);

    let mut ev_default = Event::new();
    ev_default.set("type", "measure");
    ev_default.set("client_mac", "aa:bb:cc:dd:ee:01");
    ev_default.set("namespace_uuid", "ns-1");
    ev_default.set("ap_mac", json!([ap1, ap2, ap3]));
    ev_default.set("rssi", json!([-60, -60, -50]));

    let out_def = default_filter.process(ev_default, &state).unwrap();
    assert_eq!(out_def.len(), 1);
    // When disabled, lat/long matches the strongest AP (ap3 or ap1)
    let latlong_def = out_def[0].get_str("client_latlong").unwrap();
    assert_ne!(latlong_def, "28.001000,-16.001000");

    // 2. Enable triangulation via PluginBlock
    let nmsp_block = PluginBlock {
        name: "nmsp".to_string(),
        settings: vec![
            ("triangulation".to_string(), ConfigValue::Bool(true)),
            ("triangulation_min_aps".to_string(), ConfigValue::Integer(2)),
        ],
    };
    let tri_filter = NmspFilter::from_block(&nmsp_block);
    assert!(tri_filter.enable_triangulation);
    assert_eq!(tri_filter.triangulation_min_aps, 2);

    // Two APs with equal RSSI (-50 dBm) on Floor A, plus AP 3 on Floor B with weaker signal (-70 dBm due to floor attenuation)
    // AP 3 on Floor B must be ignored because primary AP (ap1) is on Floor A!
    let mut ev_tri = Event::new();
    ev_tri.set("type", "measure");
    ev_tri.set("client_mac", "aa:bb:cc:dd:ee:02");
    ev_tri.set("namespace_uuid", "ns-1");
    ev_tri.set("ap_mac", json!([ap1, ap2, ap3]));
    ev_tri.set("rssi", json!([-50, -50, -70]));

    let out_tri = tri_filter.process(ev_tri, &state).unwrap();
    assert_eq!(out_tri.len(), 1);
    // Midpoint of (28.000000, -16.000000) and (28.002000, -16.002000) is (28.001000, -16.001000)
    assert_eq!(
        out_tri[0].get_str("client_latlong").as_deref(),
        Some("28.001000,-16.001000")
    );

    // 3. AP 1 much stronger (-50 dBm) than AP 2 (-70 dBm) -> pulls towards AP 1
    let mut ev_weighted = Event::new();
    ev_weighted.set("type", "measure");
    ev_weighted.set("client_mac", "aa:bb:cc:dd:ee:03");
    ev_weighted.set("namespace_uuid", "ns-1");
    ev_weighted.set("ap_mac", json!([ap1, ap2]));
    ev_weighted.set("rssi", json!([-50, -70]));

    let out_weighted = tri_filter.process(ev_weighted, &state).unwrap();
    let latlong_w = out_weighted[0].get_str("client_latlong").unwrap();
    let (lat_s, lon_s) = latlong_w.split_once(',').unwrap();
    let lat: f64 = lat_s.parse().unwrap();
    let lon: f64 = lon_s.parse().unwrap();
    // Lat should be very close to 28.000 (around 28.00018) rather than the midpoint 28.001
    assert!(lat > 28.000000 && lat < 28.000500, "lat was {}", lat);
    assert!(lon < -16.000000 && lon > -16.000500, "lon was {}", lon);

    // 4. Fallback when fewer than triangulation_min_aps (e.g. only 1 AP)
    let mut ev_single = Event::new();
    ev_single.set("type", "measure");
    ev_single.set("client_mac", "aa:bb:cc:dd:ee:04");
    ev_single.set("namespace_uuid", "ns-1");
    ev_single.set("ap_mac", json!([ap1]));
    ev_single.set("rssi", json!([-60]));

    let out_single = tri_filter.process(ev_single, &state).unwrap();
    assert_eq!(
        out_single[0].get_str("client_latlong").as_deref(),
        Some("28.000000,-16.000000")
    );

    // 5. Associated client on Floor A with AP 3 on Floor B reporting stronger RSSI (-40 vs -60):
    //    Primary floor remains Floor A because of active association to AP 1!
    let assoc_mac = "aa:bb:cc:dd:ee:05";
    let assoc_key = format!("{}{}", assoc_mac, "ns-1");
    let mut assoc_info = serde_json::Map::new();
    assoc_info.insert("wireless_station".to_string(), json!(ap1));
    assoc_info.insert("last_seen".to_string(), json!(chrono::Utc::now().timestamp()));
    assoc_info.insert("dot11_status".to_string(), json!("ASSOCIATED"));
    state.put_record(NMSP_STORE_INFO, &assoc_key, assoc_info).unwrap();

    let mut ev_assoc = Event::new();
    ev_assoc.set("type", "measure");
    ev_assoc.set("client_mac", assoc_mac);
    ev_assoc.set("namespace_uuid", "ns-1");
    ev_assoc.set("ap_mac", json!([ap1, ap2, ap3]));
    ev_assoc.set("rssi", json!([-60, -60, -40]));

    let out_assoc = tri_filter.process(ev_assoc, &state).unwrap();
    assert_eq!(out_assoc.len(), 1);
    assert_eq!(out_assoc[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));
    // Since Floor A has AP 1 (-60) and AP 2 (-60), midpoint is used
    assert_eq!(
        out_assoc[0].get_str("client_latlong").as_deref(),
        Some("28.001000,-16.001000")
    );

    // 6. Test block configuration parsing for triangulation
    let block = PluginBlock {
        name: "nmsp".to_string(),
        settings: vec![
            ("triangulation".to_string(), ConfigValue::Bool(true)),
            ("triangulation_min_aps".to_string(), ConfigValue::Integer(3)),
        ],
    };
    let block_filter = NmspFilter::from_block(&block);
    assert!(block_filter.enable_triangulation);
    assert_eq!(block_filter.triangulation_min_aps, 3);
}

#[tokio::test]
async fn test_nmsp_measure_without_namespace_uuid_preserves_associated() {
    let state = StateStore::new_standalone();
    let filter = NmspFilter::new();

    let client_mac = "7a:ee:1d:72:88:ba";
    let ns_uuid = "3c69fcf0-96b7-4a35-9946-1d9eb0b8cb88";
    let ap_mac = "dc:8c:37:3d:30:00";

    // Seed WLC_PSQL_STORE with AP metadata (including tenant namespace_uuid)
    let mut ap_rec = Map::new();
    ap_rec.insert("namespace_uuid".to_string(), json!(ns_uuid));
    ap_rec.insert("floor_uuid".to_string(), json!("floor-123"));
    state.put_record(WLC_PSQL_STORE, ap_mac, ap_rec).unwrap();

    // 1. WLC sends 5-minute info burst with namespace_uuid
    let mut info_ev = Event::new();
    info_ev.set("type", "info");
    info_ev.set("client_mac", client_mac);
    info_ev.set("namespace_uuid", ns_uuid);
    info_ev.set("wireless_station", ap_mac);
    info_ev.set("dot11_status", "ASSOCIATED");
    info_ev.set("timestamp", chrono::Utc::now().timestamp());

    let out_info = filter.process(info_ev, &state).unwrap();
    assert_eq!(out_info.len(), 1);
    assert_eq!(out_info[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));

    // 2. WLC sends continuous measure messages WITHOUT namespace_uuid
    let mut measure_ev = Event::new();
    measure_ev.set("type", "measure");
    measure_ev.set("client_mac", client_mac);
    // Explicitly NO namespace_uuid in event
    measure_ev.set("ap_mac", json!([ap_mac]));
    measure_ev.set("rssi", json!([-65]));
    measure_ev.set("timestamp", chrono::Utc::now().timestamp());

    let out_measure = filter.process(measure_ev, &state).unwrap();
    assert_eq!(out_measure.len(), 1);
    // Must remain ASSOCIATED, not demoted to PROBING!
    assert_eq!(
        out_measure[0].get_str("dot11_status").as_deref(),
        Some("ASSOCIATED"),
        "Client was falsely demoted to PROBING due to missing namespace_uuid in measure message!"
    );
    // Must backfill namespace_uuid from candidate AP in WLC_PSQL_STORE
    assert_eq!(
        out_measure[0].get_str("namespace_uuid").as_deref(),
        Some(ns_uuid)
    );

    // Verify NMSP_STORE_MEASURE is stored under the composite tenant key
    let expected_key = format!("{}{}", client_mac, ns_uuid);
    let measure_cache = state.get_record(NMSP_STORE_MEASURE, &expected_key);
    assert!(measure_cache.is_some(), "NMSP_STORE_MEASURE should be indexed by composite client_mac + namespace_uuid");
    // Verify bare client MAC was NOT used as a key in NMSP_STORE_MEASURE (prevents multi-tenant poisoning)
    assert!(state.get_record(NMSP_STORE_MEASURE, client_mac).is_none());
}

#[tokio::test]
async fn test_nmsp_measure_multi_tenant_candidate_ap_matches_associated_tenant() {
    let state = StateStore::new_standalone();
    let filter = NmspFilter::new();

    let client_mac = "00:aa:bb:cc:dd:ee";
    let tenant_a = "tenant-uuid-aaa";
    let tenant_b = "tenant-uuid-bbb";
    let ap1_tenant_a = "11:11:11:11:11:11";
    let ap2_tenant_b = "22:22:22:22:22:22";

    // AP1 belongs to Tenant A
    let mut ap1_rec = Map::new();
    ap1_rec.insert("namespace_uuid".to_string(), json!(tenant_a));
    state.put_record(WLC_PSQL_STORE, ap1_tenant_a, ap1_rec).unwrap();

    // AP2 belongs to Tenant B
    let mut ap2_rec = Map::new();
    ap2_rec.insert("namespace_uuid".to_string(), json!(tenant_b));
    state.put_record(WLC_PSQL_STORE, ap2_tenant_b, ap2_rec).unwrap();

    // Client is ASSOCIATED to Tenant B (via AP2)
    let mut info_ev = Event::new();
    info_ev.set("type", "info");
    info_ev.set("client_mac", client_mac);
    info_ev.set("namespace_uuid", tenant_b);
    info_ev.set("wireless_station", ap2_tenant_b);
    info_ev.set("dot11_status", "ASSOCIATED");
    info_ev.set("timestamp", chrono::Utc::now().timestamp());

    let out_info = filter.process(info_ev, &state).unwrap();
    assert_eq!(out_info[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));

    // Measure message arrives without namespace_uuid, and ap1 (Tenant A) is listed before ap2 (Tenant B)
    let mut measure_ev = Event::new();
    measure_ev.set("type", "measure");
    measure_ev.set("client_mac", client_mac);
    measure_ev.set("ap_mac", json!([ap1_tenant_a, ap2_tenant_b]));
    measure_ev.set("rssi", json!([-70, -60]));
    measure_ev.set("timestamp", chrono::Utc::now().timestamp());

    let out_measure = filter.process(measure_ev, &state).unwrap();
    assert_eq!(out_measure.len(), 1);
    // Must find the active association in Tenant B, NOT falsely bind to Tenant A and demote to PROBING!
    assert_eq!(out_measure[0].get_str("dot11_status").as_deref(), Some("ASSOCIATED"));
    assert_eq!(out_measure[0].get_str("namespace_uuid").as_deref(), Some(tenant_b));

    // Must be cached under Tenant B's composite key
    let key_b = format!("{}{}", client_mac, tenant_b);
    assert!(state.get_record(NMSP_STORE_MEASURE, &key_b).is_some());
    let key_a = format!("{}{}", client_mac, tenant_a);
    assert!(state.get_record(NMSP_STORE_MEASURE, &key_a).is_none());
}

#[tokio::test]
async fn test_nmsp_measure_array_alignment_with_malformed_entries() {
    let state = StateStore::new_standalone();
    let filter = NmspFilter::new();

    let client_mac = "7a:ee:1d:72:88:ba";
    let ap1 = "11:11:11:11:11:11";
    let ap2 = "22:22:22:22:22:22";

    let mut ap2_rec = Map::new();
    ap2_rec.insert("namespace_uuid".to_string(), json!("ns-2"));
    state.put_record(WLC_PSQL_STORE, ap2, ap2_rec).unwrap();

    let mut measure_ev = Event::new();
    measure_ev.set("type", "measure");
    measure_ev.set("client_mac", client_mac);
    // ap_mac has a null in the middle, rssi has 3 entries
    measure_ev.set("ap_mac", json!([ap1, null, ap2]));
    measure_ev.set("rssi", json!([-90, -40, -60]));
    measure_ev.set("timestamp", chrono::Utc::now().timestamp());

    let out = filter.process(measure_ev, &state).unwrap();
    assert_eq!(out.len(), 1);
    // ap2 (-60) is stronger than ap1 (-90), chosen_ap should be ap2
    assert_eq!(out[0].get_str("wireless_station").as_deref(), Some(ap2));
    assert_eq!(out[0].get_i64("client_rssi_num"), Some(-60));
}

#[test]
fn test_mobility_continuous_static_device_tracking() {
    let state = StateStore::new_standalone();
    let mut filter = MobilityFilter::new();
    filter.consolidated_time = 60; // 1 minute to consolidate
    filter.max_dwell_time = 3; // 3 minutes max dwell time before becoming static
    filter.expired_time = 1200; // 20 minutes inactivity expiration

    let mac = "aa:bb:cc:dd:ee:ff";
    let ns = "ns-static";

    // 1. Initial sighting at t = 1020 (minute 1020)
    let mut ev1 = Event::new();
    ev1.set("client_mac", mac);
    ev1.set("namespace_uuid", ns);
    ev1.set("zone_uuid", "zone-1");
    ev1.set("timestamp", 1020_i64);
    let out1 = filter.process(ev1, &state).unwrap();
    assert!(out1.is_empty(), "First ping should not consolidate yet");

    // 2. Consolidation at t = 1080 (60s later -> consolidates)
    let mut ev2 = Event::new();
    ev2.set("client_mac", mac);
    ev2.set("namespace_uuid", ns);
    ev2.set("zone_uuid", "zone-1");
    ev2.set("timestamp", 1080_i64);
    let out2 = filter.process(ev2, &state).unwrap();
    assert!(!out2.is_empty(), "Should consolidate at t=1080");
    for e in &out2 {
        assert_eq!(e.get_i64("static"), Some(0), "Initial consolidated events must have static=0");
    }

    // 3. Stationary updates across minutes t = 1140 (dwell=2), 1200 (dwell=3), 1260 (dwell=4), 1320 (dwell=5), 1380 (dwell=6)
    let mut ev3 = Event::new();
    ev3.set("client_mac", mac);
    ev3.set("namespace_uuid", ns);
    ev3.set("zone_uuid", "zone-1");
    ev3.set("timestamp", 1380_i64);
    let out3 = filter.process(ev3, &state).unwrap();
    // Should emit 5 events (for t = 1140, 1200, 1260, 1320, 1380 -> dwell_time = 2, 3, 4, 5, 6)
    assert_eq!(out3.len(), 5, "Must continue emitting events past max_dwell_time=3");

    let dwell_times: Vec<i64> = out3.iter().map(|e| e.get_i64("dwell_time").unwrap()).collect();
    assert_eq!(dwell_times, vec![2, 3, 4, 5, 6]);
    let statics: Vec<i64> = out3.iter().map(|e| e.get_i64("static").unwrap()).collect();
    assert_eq!(statics, vec![0, 0, 1, 1, 1]);

    // 4. Subsequent stationary update at t = 1440 (dwell=7) still emits with static=1
    let mut ev4 = Event::new();
    ev4.set("client_mac", mac);
    ev4.set("namespace_uuid", ns);
    ev4.set("zone_uuid", "zone-1");
    ev4.set("timestamp", 1440_i64);
    let out4 = filter.process(ev4, &state).unwrap();
    assert_eq!(out4.len(), 1);
    assert_eq!(out4[0].get_i64("dwell_time"), Some(7));
    assert_eq!(out4[0].get_i64("static"), Some(1));

    // 5. After inactivity > expired_time (e.g. t = 3000), move-to-outside event has static=1, and new session resets to static=0
    let mut ev5 = Event::new();
    ev5.set("client_mac", mac);
    ev5.set("namespace_uuid", ns);
    ev5.set("zone_uuid", "zone-1");
    ev5.set("timestamp", 3000_i64);
    let out5 = filter.process(ev5, &state).unwrap();
    assert_eq!(out5.len(), 1, "Expiration emits move_to_outside event");
    assert_eq!(out5[0].get_str("new").as_deref(), Some("outside"));
    assert_eq!(out5[0].get_i64("static"), Some(1));

    // Consolidate new session at t = 3060 -> static=0 again
    let mut ev6 = Event::new();
    ev6.set("client_mac", mac);
    ev6.set("namespace_uuid", ns);
    ev6.set("zone_uuid", "zone-1");
    ev6.set("timestamp", 3060_i64);
    let out6 = filter.process(ev6, &state).unwrap();
    assert!(!out6.is_empty());
    for e in &out6 {
        assert_eq!(e.get_i64("static"), Some(0), "New session after expiration must reset static=0");
    }
}

#[test]
fn test_intrusion_filter_enrichment_and_pipeline() {
    let state = StateStore::new_standalone();

    // Populate SENSOR_PSQL_STORE and RADIUS_STORE / LOCATION_STORE
    let mut sensor_rec = Map::new();
    sensor_rec.insert("sensor_name".to_string(), json!("ips-sensor-01"));
    sensor_rec.insert("organization".to_string(), json!("ACME Corp"));
    sensor_rec.insert("namespace_uuid".to_string(), json!("ns-intrusion-1"));
    state.put_record(SENSOR_PSQL_STORE, "sensor-uuid-99", sensor_rec).unwrap();

    let mut radius_rec = Map::new();
    radius_rec.insert("client_id".to_string(), json!("alice@acme.local"));
    state
        .put_record(RADIUS_STORE, "aa:11:22:33:44:55ns-intrusion-1", radius_rec)
        .unwrap();

    let mut loc_rec = Map::new();
    loc_rec.insert("building".to_string(), json!("HQ-Building"));
    state
        .put_record(LOCATION_STORE, "aa:11:22:33:44:55ns-intrusion-1", loc_rec)
        .unwrap();

    let conf = r#"
    filter {
      intrusion {}
      mutate {
        remove_field => ["@version", "@timestamp"]
      }
    }
    "#;
    let ast = parse_logstash_conf(conf).unwrap();
    let filters: Vec<Box<dyn Filter>> = ast
        .filters
        .iter()
        .filter_map(|s| match s {
            Statement::Plugin(b) => Some(create_filter(b).unwrap()),
            _ => None,
        })
        .collect();
    assert_eq!(filters.len(), 2);

    let mut ev = Event::new();
    ev.set("sensor_uuid", "sensor-uuid-99");
    ev.set("client_mac", "aa:11:22:33:44:55");
    ev.set("src", "10.0.0.50");
    ev.set("dst", "198.51.100.10");
    ev.set("sig_id", 2001219_i64);

    let mut events = vec![ev];
    for f in &filters {
        let mut next = Vec::new();
        for e in events {
            next.extend(f.process(e, &state).unwrap());
        }
        events = next;
    }

    assert_eq!(events.len(), 1);
    let enriched = &events[0];
    assert_eq!(enriched.get_str("sensor_name").as_deref(), Some("ips-sensor-01"));
    assert_eq!(enriched.get_str("organization").as_deref(), Some("ACME Corp"));
    assert_eq!(enriched.get_str("namespace_uuid").as_deref(), Some("ns-intrusion-1"));
    assert_eq!(enriched.get_str("client_id").as_deref(), Some("alice@acme.local"));
    assert_eq!(enriched.get_str("building").as_deref(), Some("HQ-Building"));
    assert!(!enriched.contains("@version"));
    assert!(!enriched.contains("@timestamp"));
}


