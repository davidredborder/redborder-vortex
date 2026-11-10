use redborder_vortex::config::{
    eval_expr, load_pipeline_dir, load_pipelines_yml, parse_logstash_conf, parse_pipelines_yml,
    CompareOp, ConfigValue, Expr, Operand, Statement,
};
use redborder_vortex::event::Event;
use serde_json::json;
use std::fs;

const PIPELINES_YML_10_1_33_160: &str = r#"
- pipeline.id: netflow
  path.config: "/etc/logstash/pipelines/netflow/*.conf"
  pipeline.workers: 1
- pipeline.id: sflow
  path.config: "/etc/logstash/pipelines/sflow/*.conf"
  pipeline.workers: 1
- pipeline.id: vault
  path.config: "/etc/logstash/pipelines/vault/*.conf"
  pipeline.workers: 1
- pipeline.id: event
  path.config: "/etc/logstash/pipelines/event/*.conf"
  pipeline.workers: 1
- pipeline.id: monitor
  path.config: "/etc/logstash/pipelines/monitor/*.conf"
  pipeline.workers: 1
- pipeline.id: state
  path.config: "/etc/logstash/pipelines/state/*.conf"
  pipeline.workers: 1
- pipeline.id: scanner
  path.config: "/etc/logstash/pipelines/scanner/*.conf"
  pipeline.workers: 1
- pipeline.id: syslog
  path.config: "/etc/logstash/pipelines/syslog/*.conf"
  pipeline.workers: 1
- pipeline.id: malware
  path.config: "/etc/logstash/pipelines/malware/*.conf"
  pipeline.workers: 1
- pipeline.id: location
  path.config: "/etc/logstash/pipelines/location/*.conf"
  pipeline.workers: 1
- pipeline.id: traffic
  path.config: "/etc/logstash/pipelines/traffic/*.conf"
  pipeline.workers: 1
- pipeline.id: rbwindow
  path.config: "/etc/logstash/pipelines/rbwindow/*.conf"
  pipeline.workers: 1
"#;

#[test]
fn test_parse_pipelines_yml_all_12_pipelines() {
    let entries = parse_pipelines_yml(PIPELINES_YML_10_1_33_160).expect("Should parse pipelines.yml");
    assert_eq!(entries.len(), 12);

    let expected_ids = [
        "netflow", "sflow", "vault", "event", "monitor", "state", "scanner", "syslog", "malware",
        "location", "traffic", "rbwindow",
    ];
    for (entry, expected_id) in entries.iter().zip(expected_ids.iter()) {
        assert_eq!(entry.id, *expected_id);
        assert_eq!(
            entry.path_config,
            format!("/etc/logstash/pipelines/{}/*.conf", expected_id)
        );
        assert_eq!(entry.workers, 1);
    }

    // Also test default workers when omitted
    let minimal_yaml = r#"
- pipeline.id: custom
  path.config: "/etc/logstash/pipelines/custom/*.conf"
"#;
    let minimal_entries = parse_pipelines_yml(minimal_yaml).expect("Should parse minimal yaml");
    assert_eq!(minimal_entries.len(), 1);
    assert_eq!(minimal_entries[0].id, "custom");
    assert_eq!(minimal_entries[0].workers, 1);
}

#[test]
fn test_parse_netflow_and_sflow_multiline_ruby() {
    let conf = r#"
# Input kafka
input {
  kafka {
    bootstrap_servers => "kafka.service.consul:9092"
    topics => ["rb_flow"]
    codec => json
    consumer_threads => 1
    decorate_events => false
  }
}

filter {
  if ![tag] or [tag] == 0 {
    mutate {
      add_tag => [ "is_src_internal" ]
    }
  } else if [direction] == "downstream" {
    geoip {
      source => "src"
      target => "city_lan"
      fields => [COUNTRY_CODE2]
    }
  }

  ruby {
    init => '
      require "ipaddr"
      PRIVATE_NETS = [
        IPAddr.new("10.0.0.0/8"),
        IPAddr.new("172.16.0.0/12")
      ]
    '
    code => '
      pkt = event.get("pkts")
      if pkt
        event.set("pkts", pkt * 2)
      end
    '
  }
}

output {
  if [namespace_uuid] {
  } else {
    kafka {
      bootstrap_servers => "kafka.service.consul:9092"
      topic_id => "rb_flow_post"
      codec => json
    }
  }
}
"#;

    let parsed = parse_logstash_conf(conf).expect("Should parse netflow/sflow conf");
    assert_eq!(parsed.inputs.len(), 1);
    assert_eq!(parsed.inputs[0].name, "kafka");
    assert_eq!(
        parsed.inputs[0].get_str("bootstrap_servers"),
        Some("kafka.service.consul:9092")
    );
    assert_eq!(parsed.inputs[0].get_str("codec"), Some("json"));
    assert_eq!(
        parsed.inputs[0].get_string_list("topics"),
        Some(vec!["rb_flow".to_string()])
    );

    assert_eq!(parsed.filters.len(), 2);
    match &parsed.filters[0] {
        Statement::Conditional(cond) => {
            assert_eq!(cond.branches.len(), 2);
            assert!(cond.else_branch.is_none());
            // Check second branch geoip fields => [COUNTRY_CODE2]
            match &cond.branches[1].1[0] {
                Statement::Plugin(geoip) => {
                    assert_eq!(geoip.name, "geoip");
                    assert_eq!(
                        geoip.get_string_list("fields"),
                        Some(vec!["COUNTRY_CODE2".to_string()])
                    );
                }
                _ => panic!("Expected Plugin in else if branch"),
            }
        }
        _ => panic!("Expected conditional filter"),
    }

    match &parsed.filters[1] {
        Statement::Plugin(ruby) => {
            assert_eq!(ruby.name, "ruby");
            let init_code = ruby.get_str("init").expect("init string");
            assert!(init_code.contains("IPAddr.new(\"10.0.0.0/8\")"));
            let code = ruby.get_str("code").expect("code string");
            assert!(code.contains("event.set(\"pkts\", pkt * 2)"));
        }
        _ => panic!("Expected ruby plugin"),
    }

    assert_eq!(parsed.outputs.len(), 1);
    match &parsed.outputs[0] {
        Statement::Conditional(cond) => {
            assert_eq!(cond.branches.len(), 1);
            assert!(cond.branches[0].1.is_empty()); // empty if [namespace_uuid] { }
            let else_stmts = cond.else_branch.as_ref().expect("Should have else branch");
            assert_eq!(else_stmts.len(), 1);
        }
        _ => panic!("Expected conditional in output"),
    }
}

#[test]
fn test_parse_vault_multiple_add_field_and_in_expr() {
    let conf = r#"
filter {
  if "sshd" in [app_name] {
    mutate {
      add_field => { "action" => "login" }
      add_field => { "category" => "auth" "sub" => "ssh" }
      rename => { "[host][name]" => "hostname" "old_f" => "new_f" }
    }
  } elsif "nginx" in [app_name] {
    mutate {
      add_field => { "service" => "web" }
    }
  }
}
"#;

    let parsed = parse_logstash_conf(conf).expect("Should parse vault conf");
    assert_eq!(parsed.filters.len(), 1);
    match &parsed.filters[0] {
        Statement::Conditional(cond) => {
            assert_eq!(cond.branches.len(), 2);
            match &cond.branches[0].1[0] {
                Statement::Plugin(mutate) => {
                    assert_eq!(mutate.name, "mutate");
                    // Should preserve both duplicate `add_field` settings in order!
                    let add_fields: Vec<_> = mutate
                        .settings
                        .iter()
                        .filter(|(k, _)| k == "add_field")
                        .collect();
                    assert_eq!(add_fields.len(), 2);
                }
                _ => panic!("Expected mutate plugin"),
            }
        }
        _ => panic!("Expected conditional"),
    }
}

#[test]
fn test_parse_malware_hyphenated_plugins_and_multiple_filter_blocks() {
    let conf = r#"
filter {
  aerospike-malware-score {
    server => "127.0.0.1:3000"
    namespace => "malware"
  }
}

filter {
  if [hash] {
    s3-upload-malware-results {
      bucket => "rb-malware"
    }
  }
}
"#;

    let parsed = parse_logstash_conf(conf).expect("Should parse malware conf");
    assert_eq!(parsed.filters.len(), 2);
    match &parsed.filters[0] {
        Statement::Plugin(p) => {
            assert_eq!(p.name, "aerospike-malware-score");
            assert_eq!(p.get_str("server"), Some("127.0.0.1:3000"));
        }
        _ => panic!("Expected aerospike-malware-score plugin"),
    }
    match &parsed.filters[1] {
        Statement::Conditional(c) => match &c.branches[0].1[0] {
            Statement::Plugin(p) => {
                assert_eq!(p.name, "s3-upload-malware-results");
                assert_eq!(p.get_str("bucket"), Some("rb-malware"));
            }
            _ => panic!("Expected s3-upload-malware-results plugin"),
        },
        _ => panic!("Expected conditional"),
    }
}

#[test]
fn test_parse_rbwindow_schedule_and_combined_blocks() {
    let conf = r#"
input {
  exec {
    command => "echo hello"
    schedule => { cron => "*/1 * * * * UTC" }
  }
}
filter {
  fingerprint {
    method => SHA256
    key => yourenterprisekey
  }
}
output {
  stdout { codec => rubydebug }
}
"#;

    let parsed = parse_logstash_conf(conf).expect("Should parse rbwindow conf");
    assert_eq!(parsed.inputs.len(), 1);
    let exec_plugin = &parsed.inputs[0];
    assert_eq!(exec_plugin.name, "exec");
    let sched_map = exec_plugin.get_map("schedule").expect("schedule map");
    assert_eq!(sched_map.len(), 1);
    assert_eq!(sched_map[0].0, "cron");
    assert_eq!(sched_map[0].1.as_str(), Some("*/1 * * * * UTC"));

    assert_eq!(parsed.filters.len(), 1);
    match &parsed.filters[0] {
        Statement::Plugin(fp) => {
            assert_eq!(fp.name, "fingerprint");
            assert_eq!(fp.get_str("method"), Some("SHA256"));
            assert_eq!(fp.get_str("key"), Some("yourenterprisekey"));
        }
        _ => panic!("Expected fingerprint plugin"),
    }
}

#[test]
fn test_load_pipeline_dir_lexicographical_merge() {
    let temp_dir = std::env::temp_dir().join(format!("rb_vortex_test_dir_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    fs::write(
        temp_dir.join("00_input.conf"),
        r#"input { kafka { topics => ["t1"] } }"#,
    )
    .unwrap();
    fs::write(
        temp_dir.join("99_output.conf"),
        r#"output { kafka { topic_id => "out1" } }"#,
    )
    .unwrap();
    fs::write(
        temp_dir.join("01_filter.conf"),
        r#"filter { mutate { add_tag => ["step1"] } }"#,
    )
    .unwrap();
    fs::write(
        temp_dir.join("02_filter.conf"),
        r#"filter { mutate { add_tag => ["step2"] } }"#,
    )
    .unwrap();

    let yml_path = temp_dir.join("pipelines.yml");
    fs::write(&yml_path, PIPELINES_YML_10_1_33_160).unwrap();
    let loaded_yml = load_pipelines_yml(&yml_path).expect("Should load pipelines.yml from file");
    assert_eq!(loaded_yml.len(), 12);

    let cfg = load_pipeline_dir(&temp_dir).expect("Should load and merge pipeline dir");
    assert_eq!(cfg.inputs.len(), 1);
    assert_eq!(cfg.filters.len(), 2);
    assert_eq!(cfg.outputs.len(), 1);

    match (&cfg.filters[0], &cfg.filters[1]) {
        (Statement::Plugin(p1), Statement::Plugin(p2)) => {
            assert_eq!(p1.get_string_list("add_tag"), Some(vec!["step1".to_string()]));
            assert_eq!(p2.get_string_list("add_tag"), Some(vec!["step2".to_string()]));
        }
        _ => panic!("Expected two filter plugins in lexicographical order"),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_eval_expr_comprehensive() {
    let mut ev = Event::new();
    ev.set("app_name", "OpenSSH_8.2p1 sshd[1234]");
    ev.tag("is_src_internal");
    ev.set("sensor_uuid", "uuid-1");
    ev.set("[city_lan][country_code2]", "ES");
    ev.set("tag", 0);

    // 1. ![tag] or [tag] == 0
    let expr_tag = Expr::Or(
        Box::new(Expr::Not(Box::new(Expr::FieldExists("[tag]".to_string())))),
        Box::new(Expr::Compare {
            left: Operand::Field("[tag]".to_string()),
            op: CompareOp::Eq,
            right: Operand::Literal(ConfigValue::Integer(0)),
        }),
    );
    assert!(eval_expr(&expr_tag, &ev));

    ev.set("tag", 5);
    assert!(!eval_expr(&expr_tag, &ev));

    ev.remove("tag");
    assert!(eval_expr(&expr_tag, &ev));

    // 2. "is_src_internal" in [tags]
    let expr_in_tags = Expr::In {
        needle: Operand::Literal(ConfigValue::String("is_src_internal".to_string())),
        haystack: Operand::Field("[tags]".to_string()),
    };
    assert!(eval_expr(&expr_in_tags, &ev));

    let expr_not_in_tags = Expr::In {
        needle: Operand::Literal(ConfigValue::String("other_tag".to_string())),
        haystack: Operand::Field("[tags]".to_string()),
    };
    assert!(!eval_expr(&expr_not_in_tags, &ev));

    // 3. "sshd" in [app_name] (substring check)
    let expr_in_str = Expr::In {
        needle: Operand::Literal(ConfigValue::String("sshd".to_string())),
        haystack: Operand::Field("[app_name]".to_string()),
    };
    assert!(eval_expr(&expr_in_str, &ev));

    // 4. ![sensor_uuid] or ![sensor_name]
    let expr_missing_sensor = Expr::Or(
        Box::new(Expr::Not(Box::new(Expr::FieldExists(
            "[sensor_uuid]".to_string(),
        )))),
        Box::new(Expr::Not(Box::new(Expr::FieldExists(
            "[sensor_name]".to_string(),
        )))),
    );
    assert!(eval_expr(&expr_missing_sensor, &ev));
    ev.set("sensor_name", "sensor-01");
    assert!(!eval_expr(&expr_missing_sensor, &ev));

    // 5. [city_lan][country_code2]
    let expr_nested = Expr::FieldExists("[city_lan][country_code2]".to_string());
    assert!(eval_expr(&expr_nested, &ev));

    // Boolean false field should evaluate FieldExists to false in Logstash conditionals
    ev.set("bool_flag", json!(false));
    assert!(!eval_expr(
        &Expr::FieldExists("[bool_flag]".to_string()),
        &ev
    ));

    // Empty string field should evaluate FieldExists to false in Logstash conditionals
    ev.set("empty_str", json!(""));
    assert!(!eval_expr(
        &Expr::FieldExists("[empty_str]".to_string()),
        &ev
    ));
    ev.set("non_empty_str", json!("hello"));
    assert!(eval_expr(
        &Expr::FieldExists("[non_empty_str]".to_string()),
        &ev
    ));

    // Also verify parsing and evaluating parenthesized & nested expressions directly from .conf
    let conf_exprs = r#"
    filter {
      if (![sensor_uuid] or ![sensor_name]) and [city_lan][country_code2] {
        mutate { add_tag => ["matched"] }
      }
      if "is_src_internal" in [tags] {
        mutate { add_tag => ["internal"] }
      }
    }
    "#;
    let parsed = parse_logstash_conf(conf_exprs).expect("Should parse complex conditional expressions");
    if let Statement::Conditional(c1) = &parsed.filters[0] {
        assert!(!eval_expr(&c1.branches[0].0, &ev));
        ev.remove("sensor_name");
        assert!(eval_expr(&c1.branches[0].0, &ev));
    } else {
        panic!("Expected conditional");
    }
    if let Statement::Conditional(c2) = &parsed.filters[1] {
        assert!(eval_expr(&c2.branches[0].0, &ev));
    } else {
        panic!("Expected conditional");
    }
}

#[test]
fn test_parse_json_style_colon_separators_in_plugin_settings() {
    let conf = r#"
    filter {
      python {
        module => "sflow"
        function => "enrich_nodes"
        config => {
          "no_proxy_nodes" => {"10.10.1.4":{"sensor_name":"fortigate","sensor_uuid":"9f51b1a2-8500-40d7-ba49-7375ef534c31","index_partitions":5,"index_replicas":1},"10.1.50.20":{"sensor_name":"router","sensor_uuid":"1dcf3aef-786d-4408-823f-1280e5a0bef9","namespace":"NS","namespace_uuid":"360e7226-dda8-4ae1-b027-5a4136c9f4c7","organization":"ORG","organization_uuid":"be5b5adc-b54c-4698-98f4-ba84d1830661","service_provider":"SP","service_provider_uuid":"de3ff891-2bb1-4dad-bae4-4f47e5f106ec","index_partitions":5,"index_replicas":1},"10.1.33.155":{"sensor_name":"sflowD","sensor_uuid":"2d846fbf-63c8-4e72-a05d-7def6738fb1f","index_partitions":5,"index_replicas":1}},
          "proxy_nodes" => {}
        }
      }
    }
    "#;
    let parsed = parse_logstash_conf(conf).expect("Should parse JSON colon separators in map");
    assert_eq!(parsed.filters.len(), 1);
}
