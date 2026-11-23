use redborder_vortex::config::ast::{ConfigValue, PluginBlock};
use redborder_vortex::inputs::kafka::KafkaConsumerConfig;
use redborder_vortex::outputs::kafka::KafkaProducerConfig;

#[test]
fn test_kafka_consumer_config_from_ast() {
    let block = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            (
                "topics".to_string(),
                ConfigValue::Array(vec![
                    ConfigValue::String("rb_flow".to_string()),
                    ConfigValue::String("rb_sflow".to_string()),
                ]),
            ),
            (
                "bootstrap_servers".to_string(),
                ConfigValue::String("10.1.33.160:9092".to_string()),
            ),
            (
                "group_id".to_string(),
                ConfigValue::String("vortex-netflow-group".to_string()),
            ),
            (
                "decorate_events".to_string(),
                ConfigValue::Bool(true),
            ),
        ],
    };

    let consumer_cfg = KafkaConsumerConfig::from_plugin_block(&block, "netflow");
    assert_eq!(consumer_cfg.topics, vec!["rb_flow", "rb_sflow"]);
    assert_eq!(consumer_cfg.bootstrap_servers, "10.1.33.160:9092");
    assert_eq!(consumer_cfg.group_id, "vortex-netflow-group");
    assert!(consumer_cfg.decorate_events);

    let client_config = consumer_cfg.to_client_config();
    assert_eq!(
        client_config.get("bootstrap.servers"),
        Some("10.1.33.160:9092")
    );
    assert_eq!(
        client_config.get("group.id"),
        Some("vortex-netflow-group")
    );
    assert_eq!(client_config.get("enable.auto.commit"), Some("true"));
}

#[test]
fn test_kafka_producer_config_from_ast() {
    let block = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            (
                "topic_id".to_string(),
                ConfigValue::String("rb_flow_post".to_string()),
            ),
            (
                "bootstrap_servers".to_string(),
                ConfigValue::String("10.1.33.160:9092".to_string()),
            ),
            (
                "client_id".to_string(),
                ConfigValue::String("vortex-producer-01".to_string()),
            ),
        ],
    };

    let prod_cfg = KafkaProducerConfig::from_plugin_block(&block);
    assert_eq!(prod_cfg.topic_id, "rb_flow_post");
    assert_eq!(prod_cfg.bootstrap_servers, "10.1.33.160:9092");
    assert_eq!(prod_cfg.client_id, Some("vortex-producer-01".to_string()));

    let client_config = prod_cfg.to_client_config();
    assert_eq!(
        client_config.get("bootstrap.servers"),
        Some("10.1.33.160:9092")
    );
    assert_eq!(client_config.get("client.id"), Some("vortex-producer-01"));
    assert_eq!(client_config.get("compression.type"), Some("lz4"));
}

#[test]
fn test_kafka_producer_message_key_and_auto_partitioning() {
    use redborder_vortex::event::Event;

    // 1. Explicit message_key interpolation
    let block_explicit = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            ("topic_id".to_string(), ConfigValue::String("rb_custom".to_string())),
            ("message_key".to_string(), ConfigValue::String("%{client_mac}".to_string())),
        ],
    };
    let cfg_explicit = KafkaProducerConfig::from_plugin_block(&block_explicit);
    assert_eq!(cfg_explicit.message_key, Some("%{client_mac}".to_string()));

    let mut ev1 = Event::new();
    ev1.set("client_mac", "aa:bb:cc:11:22:33");
    assert_eq!(
        cfg_explicit.determine_message_key(&ev1),
        Some("aa:bb:cc:11:22:33".to_string())
    );

    // 2. Auto-keying for rb_location intermediate topic (zero-config Chef support)
    let block_location = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            ("topic_id".to_string(), ConfigValue::String("rb_location".to_string())),
        ],
    };
    let cfg_location = KafkaProducerConfig::from_plugin_block(&block_location);
    assert_eq!(cfg_location.message_key, None);

    let mut ev_loc = Event::new();
    ev_loc.set("client_mac", "de:ad:be:ef:00:01");
    ev_loc.set("sensor_name", "ap-floor-1");
    assert_eq!(
        cfg_location.determine_message_key(&ev_loc),
        Some("de:ad:be:ef:00:01".to_string())
    );

    // 3. Auto-keying for rb_mobility intermediate topic
    let block_mobility = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            ("topic_id".to_string(), ConfigValue::String("rb_mobility".to_string())),
        ],
    };
    let cfg_mobility = KafkaProducerConfig::from_plugin_block(&block_mobility);
    assert_eq!(
        cfg_mobility.determine_message_key(&ev_loc),
        Some("de:ad:be:ef:00:01".to_string())
    );

    // 4. Other topics without message_key do NOT auto-key unless metadata present
    let block_flow = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            ("topic_id".to_string(), ConfigValue::String("rb_flow".to_string())),
        ],
    };
    let cfg_flow = KafkaProducerConfig::from_plugin_block(&block_flow);
    assert_eq!(cfg_flow.determine_message_key(&ev_loc), None);

    // 5. Metadata key override
    let mut ev_meta = Event::new();
    ev_meta.set("[@metadata][kafka_key]", "meta-key-123");
    assert_eq!(
        cfg_flow.determine_message_key(&ev_meta),
        Some("meta-key-123".to_string())
    );

    // 6. Configurable auto_key_topics and auto_key_field in plugin block (no hardcoding)
    let block_custom = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            ("topic_id".to_string(), ConfigValue::String("tenant_loc_stream".to_string())),
            (
                "auto_key_topics".to_string(),
                ConfigValue::Array(vec![
                    ConfigValue::String("tenant_loc_stream".to_string()),
                    ConfigValue::String("tenant_mob_stream".to_string()),
                ]),
            ),
            ("auto_key_field".to_string(), ConfigValue::String("device_mac".to_string())),
        ],
    };
    let cfg_custom = KafkaProducerConfig::from_plugin_block(&block_custom);
    assert_eq!(
        cfg_custom.auto_key_topics,
        vec!["tenant_loc_stream", "tenant_mob_stream"]
    );
    assert_eq!(cfg_custom.auto_key_field, Some("device_mac".to_string()));

    let mut ev_custom = Event::new();
    ev_custom.set("device_mac", "11:22:33:44:55:66");
    assert_eq!(
        cfg_custom.determine_message_key(&ev_custom),
        Some("11:22:33:44:55:66".to_string())
    );

    // 7. Environment variable override
    std::env::set_var("VORTEX_KAFKA_AUTO_KEY_MAC_TOPICS", "env_topic_1,env_topic_2");
    let block_env = PluginBlock {
        name: "kafka".to_string(),
        settings: vec![
            ("topic_id".to_string(), ConfigValue::String("env_topic_1".to_string())),
        ],
    };
    let cfg_env = KafkaProducerConfig::from_plugin_block(&block_env);
    assert_eq!(cfg_env.auto_key_topics, vec!["env_topic_1", "env_topic_2"]);
    let mut ev_env = Event::new();
    ev_env.set("client_mac", "ff:ee:dd:cc:bb:aa");
    assert_eq!(
        cfg_env.determine_message_key(&ev_env),
        Some("ff:ee:dd:cc:bb:aa".to_string())
    );
    std::env::remove_var("VORTEX_KAFKA_AUTO_KEY_MAC_TOPICS");
}
