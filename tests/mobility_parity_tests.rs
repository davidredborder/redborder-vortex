use redborder_vortex::event::Event;
use redborder_vortex::filters::redborder::MobilityFilter;
use redborder_vortex::filters::Filter;
use redborder_vortex::state::StateStore;

#[test]
fn test_first_entry_and_consolidation() {
    let state = StateStore::new_standalone();
    let filter = MobilityFilter::new();

    // 1. Initial event at t = 1000 in Zone-A (0 seconds into zone)
    let mut ev1 = Event::new();
    ev1.set("client_mac", "AA:BB:CC:11:22:33");
    ev1.set("namespace_uuid", "ns-1");
    ev1.set("zone_uuid", "zone_a");
    ev1.set("timestamp", 1000_i64);
    ev1.set("sensor_uuid", "sensor-1");

    let out1 = filter.process(ev1, &state).unwrap();
    // In legacy Logstash, un-consolidated location updates are debounced and emit 0 events
    assert_eq!(out1.len(), 0, "Unconsolidated first ping should yield 0 events");

    // 2. Client stays in Zone-A for 180 seconds (consolidation threshold) -> t = 1180
    let mut ev2 = Event::new();
    ev2.set("client_mac", "AA:BB:CC:11:22:33");
    ev2.set("namespace_uuid", "ns-1");
    ev2.set("zone_uuid", "zone_a");
    ev2.set("timestamp", 1180_i64);
    ev2.set("sensor_uuid", "sensor-1");

    let out2 = filter.process(ev2, &state).unwrap();
    assert!(!out2.is_empty(), "Consolidation should emit events");

    // Verify first event is transition from outside
    let first = &out2[0];
    assert_eq!(first.get_str("client_mac").as_deref(), Some("aa:bb:cc:11:22:33"));
    assert_eq!(first.get_str("old").as_deref(), Some("outside"));
    assert_eq!(first.get_str("new").as_deref(), Some("zone_a"));
    assert_eq!(first.get_i64("transition"), Some(1));
    assert_eq!(first.get_i64("dwell_time"), Some(1));
    assert_eq!(first.get_str("type").as_deref(), Some("zone"));
    assert_eq!(first.get_str("zone_uuid").as_deref(), Some("zone_a"));
    assert_eq!(first.get_str("sensor_uuid").as_deref(), Some("sensor-1"));
    assert!(first.get_str("session").unwrap().contains("aa:bb:cc:11:22:33ns-1"));
}

#[test]
fn test_minute_dwell_time_expansion() {
    let state = StateStore::new_standalone();
    let filter = MobilityFilter::new();

    // Consolidate in Zone-A at t = 1180
    let mut ev1 = Event::new();
    ev1.set("client_mac", "AA:BB:CC:11:22:33");
    ev1.set("namespace_uuid", "ns-1");
    ev1.set("zone_uuid", "zone_a");
    ev1.set("timestamp", 1000_i64);
    let _ = filter.process(ev1, &state).unwrap();

    let mut ev2 = Event::new();
    ev2.set("client_mac", "AA:BB:CC:11:22:33");
    ev2.set("namespace_uuid", "ns-1");
    ev2.set("zone_uuid", "zone_a");
    ev2.set("timestamp", 1180_i64);
    let _ = filter.process(ev2, &state).unwrap();

    // Minute tick update at t = 1240 (1 min later, still in Zone-A)
    let mut ev3 = Event::new();
    ev3.set("client_mac", "AA:BB:CC:11:22:33");
    ev3.set("namespace_uuid", "ns-1");
    ev3.set("zone_uuid", "zone_a");
    ev3.set("timestamp", 1240_i64);

    let out3 = filter.process(ev3, &state).unwrap();
    assert_eq!(out3.len(), 1, "Should emit 1 dwell event for the minute tick");
    assert_eq!(out3[0].get_i64("transition"), Some(0), "Dwelling in place has transition=0");
    assert_eq!(out3[0].get_str("old").as_deref(), Some("zone_a"));
    assert_eq!(out3[0].get_str("new").as_deref(), Some("zone_a"));
    assert!(out3[0].get_i64("dwell_time").unwrap() >= 2);
}

#[test]
fn test_zone_roaming_transition() {
    let state = StateStore::new_standalone();
    let filter = MobilityFilter::new();

    // 1. Establish consolidated presence in Zone-A
    let mut ev1 = Event::new();
    ev1.set("client_mac", "AA:BB:CC:11:22:33");
    ev1.set("namespace_uuid", "ns-1");
    ev1.set("zone_uuid", "zone_a");
    ev1.set("timestamp", 1000_i64);
    let _ = filter.process(ev1, &state).unwrap();

    let mut ev2 = Event::new();
    ev2.set("client_mac", "AA:BB:CC:11:22:33");
    ev2.set("namespace_uuid", "ns-1");
    ev2.set("zone_uuid", "zone_a");
    ev2.set("timestamp", 1180_i64);
    let _ = filter.process(ev2, &state).unwrap();

    // 2. Client roams to Zone-B at t = 1300
    let mut ev3 = Event::new();
    ev3.set("client_mac", "AA:BB:CC:11:22:33");
    ev3.set("namespace_uuid", "ns-1");
    ev3.set("zone_uuid", "zone_b");
    ev3.set("timestamp", 1300_i64);
    let out3 = filter.process(ev3, &state).unwrap();
    // Not consolidated yet in Zone-B
    assert_eq!(out3.len(), 0);

    // 3. Client consolidates in Zone-B at t = 1480 (180s later)
    let mut ev4 = Event::new();
    ev4.set("client_mac", "AA:BB:CC:11:22:33");
    ev4.set("namespace_uuid", "ns-1");
    ev4.set("zone_uuid", "zone_b");
    ev4.set("timestamp", 1480_i64);

    let out4 = filter.process(ev4, &state).unwrap();
    assert!(!out4.is_empty());

    // Should contain transition event from Zone-A to Zone-B
    let transition_ev = out4.iter().find(|e| e.get_i64("transition") == Some(1)).expect("Must emit transition=1 event");
    assert_eq!(transition_ev.get_str("old").as_deref(), Some("zone_a"));
    assert_eq!(transition_ev.get_str("new").as_deref(), Some("zone_b"));
    assert_eq!(transition_ev.get_i64("dwell_time"), Some(1));
}

#[test]
fn test_session_expiration_to_outside() {
    let state = StateStore::new_standalone();
    let filter = MobilityFilter::new();

    // 1. Establish presence in Zone-A
    let mut ev1 = Event::new();
    ev1.set("client_mac", "AA:BB:CC:11:22:33");
    ev1.set("namespace_uuid", "ns-1");
    ev1.set("zone_uuid", "zone_a");
    ev1.set("timestamp", 1000_i64);
    let _ = filter.process(ev1, &state).unwrap();

    let mut ev2 = Event::new();
    ev2.set("client_mac", "AA:BB:CC:11:22:33");
    ev2.set("namespace_uuid", "ns-1");
    ev2.set("zone_uuid", "zone_a");
    ev2.set("timestamp", 1180_i64);
    let _ = filter.process(ev2, &state).unwrap();

    // 2. Client is seen again at t = 3000 (1820s later, exceeding expired_time of 1200s)
    let mut ev3 = Event::new();
    ev3.set("client_mac", "AA:BB:CC:11:22:33");
    ev3.set("namespace_uuid", "ns-1");
    ev3.set("zone_uuid", "zone_c");
    ev3.set("timestamp", 3000_i64);

    let out3 = filter.process(ev3, &state).unwrap();
    // Should emit move_to_outside event for previous session
    let outside_ev = out3.iter().find(|e| e.get_str("new").as_deref() == Some("outside")).expect("Must emit outside event");
    assert_eq!(outside_ev.get_str("old").as_deref(), Some("zone_a"));
    assert_eq!(outside_ev.get_i64("transition"), Some(1));
}

#[test]
fn test_mobility_full_hierarchy_enrichment_and_transition() {
    use redborder_vortex::state::WLC_PSQL_STORE;
    use serde_json::json;

    let state = StateStore::new_standalone();
    let filter = MobilityFilter::new();

    // Populate WLC store with AP1 (Floor 2, Zone 2)
    let mut ap1_data = serde_json::Map::new();
    ap1_data.insert("wireless_station".to_string(), json!("dc:8c:37:79:eb:e0"));
    ap1_data.insert("zone".to_string(), json!("Zone two"));
    ap1_data.insert("zone_uuid".to_string(), json!("uuid-zone-2"));
    ap1_data.insert("floor".to_string(), json!("Floor two"));
    ap1_data.insert("floor_uuid".to_string(), json!("uuid-floor-2"));
    ap1_data.insert("building".to_string(), json!("Edificio Principal"));
    ap1_data.insert("building_uuid".to_string(), json!("uuid-bldg-1"));
    ap1_data.insert("campus".to_string(), json!("Campus Central"));
    ap1_data.insert("campus_uuid".to_string(), json!("uuid-campus-1"));
    ap1_data.insert("organization".to_string(), json!("RedBorder Org"));
    ap1_data.insert("organization_uuid".to_string(), json!("uuid-org-1"));
    ap1_data.insert("client_latlong".to_string(), json!("37.38,-5.98"));
    state.put_record(WLC_PSQL_STORE, "dc:8c:37:79:eb:e0", ap1_data).unwrap();

    // Event 1 at t=1000 on AP1
    let mut ev1 = Event::new();
    ev1.set("client_mac", "66:75:3b:f5:59:b4");
    ev1.set("wireless_station", "dc:8c:37:79:eb:e0");
    ev1.set("namespace_uuid", "default");
    ev1.set("timestamp", 1000_i64);
    state.enrich(&mut ev1);

    assert_eq!(ev1.get_str("zone_uuid").as_deref(), Some("uuid-zone-2"));
    assert_eq!(ev1.get_str("floor").as_deref(), Some("Floor two"));
    assert_eq!(ev1.get_str("building").as_deref(), Some("Edificio Principal"));
    assert_eq!(ev1.get_str("campus").as_deref(), Some("Campus Central"));

    let _ = filter.process(ev1, &state).unwrap();

    // Event 2 at t=1180 consolidating in Zone 2
    let mut ev2 = Event::new();
    ev2.set("client_mac", "66:75:3b:f5:59:b4");
    ev2.set("wireless_station", "dc:8c:37:79:eb:e0");
    ev2.set("namespace_uuid", "default");
    ev2.set("timestamp", 1180_i64);
    state.enrich(&mut ev2);

    let out2 = filter.process(ev2, &state).unwrap();
    assert!(!out2.is_empty(), "Must emit consolidated events");

    // Must emit events for all 4 hierarchy levels: campus, building, floor, zone
    let campus_ev = out2.iter().find(|e| e.get_str("type").as_deref() == Some("campus")).expect("Must emit campus event");
    assert_eq!(campus_ev.get_str("old").as_deref(), Some("outside"));
    assert_eq!(campus_ev.get_str("new").as_deref(), Some("uuid-campus-1"));
    assert_eq!(campus_ev.get_str("campus").as_deref(), Some("Campus Central"));

    let bldg_ev = out2.iter().find(|e| e.get_str("type").as_deref() == Some("building")).expect("Must emit building event");
    assert_eq!(bldg_ev.get_str("old").as_deref(), Some("outside"));
    assert_eq!(bldg_ev.get_str("new").as_deref(), Some("uuid-bldg-1"));
    assert_eq!(bldg_ev.get_str("building").as_deref(), Some("Edificio Principal"));

    let floor_ev = out2.iter().find(|e| e.get_str("type").as_deref() == Some("floor")).expect("Must emit floor event");
    assert_eq!(floor_ev.get_str("old").as_deref(), Some("outside"));
    assert_eq!(floor_ev.get_str("new").as_deref(), Some("uuid-floor-2"));
    assert_eq!(floor_ev.get_str("floor").as_deref(), Some("Floor two"));

    let zone_ev = out2.iter().find(|e| e.get_str("type").as_deref() == Some("zone")).expect("Must emit zone event");
    assert_eq!(zone_ev.get_str("old").as_deref(), Some("outside"));
    assert_eq!(zone_ev.get_str("new").as_deref(), Some("uuid-zone-2"));
    assert_eq!(zone_ev.get_str("zone").as_deref(), Some("Zone two"));
    assert_eq!(zone_ev.get_str("floor").as_deref(), Some("Floor two"));
    assert_eq!(zone_ev.get_str("floor_uuid").as_deref(), Some("uuid-floor-2"));
    assert_eq!(zone_ev.get_str("building").as_deref(), Some("Edificio Principal"));
    assert_eq!(zone_ev.get_str("building_uuid").as_deref(), Some("uuid-bldg-1"));
    assert_eq!(zone_ev.get_str("campus").as_deref(), Some("Campus Central"));
    assert_eq!(zone_ev.get_str("campus_uuid").as_deref(), Some("uuid-campus-1"));
    assert_eq!(zone_ev.get_str("organization").as_deref(), Some("RedBorder Org"));
    assert_eq!(zone_ev.get_str("organization_uuid").as_deref(), Some("uuid-org-1"));
}

#[test]
fn test_continuous_dwell_time_past_24_minutes_without_reset() {
    use redborder_vortex::inputs::rbwindow::{RbwindowConfig, RbwindowRunner};

    let state = StateStore::new_standalone();
    let filter = MobilityFilter::default();
    let rbwindow = RbwindowRunner::new(RbwindowConfig::default());

    let client_mac = "aa:bb:cc:dd:ee:01";
    let campus_uuid = "campus-01";

    let mut last_dwell = 0;
    let mut transition_from_outside_count = 0;

    // Simulate 30 consecutive minutes of traffic (1 event per minute)
    for minute in 0..=30 {
        let t = 100_000 + minute * 60;

        // Run rbwindow tick once per minute
        let _ = rbwindow.run_tick(&state, "node-1").unwrap();

        let mut ev = Event::new();
        ev.set("client_mac", client_mac);
        ev.set("campus_uuid", campus_uuid);
        ev.set("timestamp", t);

        let out = filter.process(ev, &state).unwrap();
        for e in out {
            if e.get_str("type").as_deref() == Some("campus") {
                if e.get_str("old").as_deref() == Some("outside") {
                    transition_from_outside_count += 1;
                }
                if let Some(dwell) = e.get("dwell_time").and_then(|v| v.as_i64()) {
                    last_dwell = dwell;
                }
            }
        }
    }

    // Client should only transition from outside ONCE during initial consolidation
    assert_eq!(
        transition_from_outside_count, 1,
        "Client must only transition from outside once, never resetting at minute 24"
    );

    // Dwell time after 30 minutes must be at least 25+ minutes
    assert!(
        last_dwell >= 25,
        "Dwell time should smoothly progress past 24 minutes without resetting to 1 (got {})",
        last_dwell
    );
}
