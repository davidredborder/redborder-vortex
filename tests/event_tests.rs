use redborder_vortex::event::Event;
use serde_json::{json, Map, Value};

#[test]
fn test_new_event_defaults() {
    let event = Event::new();
    assert_eq!(event.get_str("@version").as_deref(), Some("1"));
    assert!(event.contains("@timestamp"));
    let ts = event.get_str("@timestamp").unwrap();
    assert!(ts.contains('T'));
    assert!(!event.is_cancelled());
}

#[test]
fn test_plain_and_bracketed_field_access() {
    let mut event = Event::new();

    // Plain field access
    event.set("lan_ip", "192.168.1.10");
    assert!(event.contains("lan_ip"));
    assert_eq!(event.get("lan_ip"), Some(&json!("192.168.1.10")));
    assert_eq!(event.get_str("lan_ip").as_deref(), Some("192.168.1.10"));

    // Single-level bracket path should map to top-level key
    event.set("[src_locality]", "private");
    assert!(event.contains("src_locality"));
    assert!(event.contains("[src_locality]"));
    assert_eq!(event.get_str("src_locality").as_deref(), Some("private"));
    assert_eq!(event.get_str("[src_locality]").as_deref(), Some("private"));

    // Multi-level bracket path creates nested objects
    event.set("[city_lan][country_code2]", "ES");
    event.set("[city_lan][region_name]", "Andalucia");
    assert!(event.contains("[city_lan][country_code2]"));
    assert_eq!(
        event.get_str("[city_lan][country_code2]").as_deref(),
        Some("ES")
    );
    assert_eq!(
        event.get_str("[city_lan][region_name]").as_deref(),
        Some("Andalucia")
    );
    assert_eq!(
        event.get("city_lan"),
        Some(&json!({
            "country_code2": "ES",
            "region_name": "Andalucia"
        }))
    );

    // Scalar numbers and booleans via get_str
    event.set("bytes", 1500);
    event.set("is_ipv6", false);
    assert_eq!(event.get_str("bytes").as_deref(), Some("1500"));
    assert_eq!(event.get_str("is_ipv6").as_deref(), Some("false"));

    // Null check for contains
    event.set("null_field", Value::Null);
    assert!(!event.contains("null_field"));

    // Remove nested and plain fields
    let removed_cc = event.remove("[city_lan][country_code2]");
    assert_eq!(removed_cc, Some(json!("ES")));
    assert!(!event.contains("[city_lan][country_code2]"));
    assert!(event.contains("[city_lan][region_name]"));

    let removed_loc = event.remove("[src_locality]");
    assert_eq!(removed_loc, Some(json!("private")));
    assert!(!event.contains("src_locality"));
}

#[test]
fn test_interpolation() {
    let mut event = Event::new();
    event.set("iptables_src_ip", "10.0.0.5");
    event.set("iptables_src_port", 443);
    event.set("[city_lan][country_code2]", "US");

    assert_eq!(
        event.interpolate("%{[city_lan][country_code2]}"),
        "US"
    );
    assert_eq!(
        event.interpolate("%{iptables_src_ip}:%{iptables_src_port}"),
        "10.0.0.5:443"
    );
    assert_eq!(
        event.interpolate("prefix-%{missing_field}-suffix"),
        "prefix--suffix"
    );
    assert_eq!(
        event.interpolate("no placeholders here"),
        "no placeholders here"
    );
}

#[test]
fn test_tags_management() {
    let mut event = Event::new();
    assert!(!event.has_tag("oversized_flow"));

    event.tag("oversized_flow");
    assert!(event.has_tag("oversized_flow"));

    // Idempotent duplicate tag addition
    event.tag("oversized_flow");
    event.tag("geoip_enriched");
    assert!(event.has_tag("geoip_enriched"));

    let tags = event.get("tags").and_then(|v| v.as_array()).unwrap();
    assert_eq!(tags.len(), 2);
    assert_eq!(tags[0], json!("oversized_flow"));
    assert_eq!(tags[1], json!("geoip_enriched"));
}

#[test]
fn test_cancel_lifecycle() {
    let mut event = Event::new();
    assert!(!event.is_cancelled());
    event.cancel();
    assert!(event.is_cancelled());
}

#[test]
fn test_clone_with_overrides_for_flow_splitting() {
    let mut base = Event::from_json_str(
        r#"{
            "src": "10.0.0.1",
            "dst": "8.8.8.8",
            "bytes": 1200,
            "pkts": 12,
            "first_switched": 1000,
            "last_switched": 1120
        }"#,
    )
    .unwrap();
    base.tag("flow");

    let mut overrides = Map::new();
    overrides.insert("bytes".to_string(), json!(600));
    overrides.insert("pkts".to_string(), json!(6));
    overrides.insert("timestamp".to_string(), json!(1000));

    let split_event = base.clone_with_overrides(
        overrides,
        &["first_switched", "last_switched"],
    );

    assert_eq!(split_event.get("bytes"), Some(&json!(600)));
    assert_eq!(split_event.get("pkts"), Some(&json!(6)));
    assert_eq!(split_event.get("timestamp"), Some(&json!(1000)));
    assert_eq!(split_event.get_str("src").as_deref(), Some("10.0.0.1"));
    assert!(!split_event.contains("first_switched"));
    assert!(!split_event.contains("last_switched"));
    assert!(split_event.has_tag("flow"));

    // Original event remains untouched
    assert_eq!(base.get("bytes"), Some(&json!(1200)));
    assert!(base.contains("first_switched"));
}

#[test]
fn test_json_roundtrip_and_map_conversions() {
    let raw = r#"{"sensor_name":"sensor-01","bytes":4096,"nested":{"key":"val"}}"#;
    let event = Event::from_json_str(raw).unwrap();
    assert_eq!(event.get_str("sensor_name").as_deref(), Some("sensor-01"));
    assert_eq!(event.get_str("[nested][key]").as_deref(), Some("val"));

    let serialized = event.to_json_string().unwrap();
    let roundtripped = Event::from_json_str(&serialized).unwrap();
    assert_eq!(event.as_map(), roundtripped.as_map());

    let map = roundtripped.into_map();
    let from_map = Event::from_map(map);
    assert_eq!(from_map.get("bytes"), Some(&json!(4096)));
}

#[test]
fn test_event_array_indexing_in_get() {
    let raw = r#"{
        "users": [
            {"name": "Alice", "id": 1},
            {"name": "Bob", "id": 2}
        ],
        "matrix": [
            [10, 20],
            [30, 40]
        ]
    }"#;
    let event = Event::from_json_str(raw).unwrap();

    assert_eq!(event.get_str("[users][0][name]").as_deref(), Some("Alice"));
    assert_eq!(event.get("[users][1][id]"), Some(&json!(2)));
    assert_eq!(event.get("[matrix][1][0]"), Some(&json!(30)));

    // Out of bounds and non-array return None safely
    assert!(event.get("[users][5][name]").is_none());
    assert!(event.get("[users][not_a_num][name]").is_none());
}

#[test]
fn test_metadata_excluded_from_json_serialization() {
    let mut event = Event::new();
    event.set("sensor_uuid", "uuid-1234");
    event.set("value", 42);
    event.set("[@metadata][kafka][topic]", "rb_druid_metrics");
    event.set("[@metadata][kafka][offset]", 100);
    event.set("[@metadata][kafka_key]", "partition-key-1");

    // Metadata is accessible internally within the pipeline
    assert_eq!(
        event.get_str("[@metadata][kafka][topic]").as_deref(),
        Some("rb_druid_metrics")
    );
    assert_eq!(event.get("[@metadata][kafka][offset]"), Some(&json!(100)));
    assert_eq!(
        event.get_str("[@metadata][kafka_key]").as_deref(),
        Some("partition-key-1")
    );

    // Serialization for output MUST NOT contain @metadata
    let json_str = event.to_json_string().unwrap();
    assert!(!json_str.contains("@metadata"));
    assert!(!json_str.contains("rb_druid_metrics"));
    assert!(!json_str.contains("partition-key-1"));

    // Regular fields must be preserved
    assert!(json_str.contains("\"sensor_uuid\":\"uuid-1234\""));
    assert!(json_str.contains("\"value\":42"));
}
