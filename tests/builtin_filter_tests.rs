use redborder_vortex::config::{eval_expr, parse_logstash_conf, Statement};
use redborder_vortex::event::Event;
use redborder_vortex::filters::builtin::{
    from_plugin_block, CidrFilter, DropFilter, FingerprintFilter, GeoipFilter, GrokFilter,
    MutateFilter,
};
use redborder_vortex::filters::Filter;
use redborder_vortex::state::StateStore;
use serde_json::json;
use sha2::{Digest, Sha256};

fn execute_statements(
    statements: &[Statement],
    event: Event,
    state: &StateStore,
) -> Vec<Event> {
    let mut events = vec![event];
    for stmt in statements {
        let mut next_events = Vec::new();
        for ev in events {
            if ev.is_cancelled() {
                continue;
            }
            match stmt {
                Statement::Plugin(block) => {
                    if let Some(filter) =
                        from_plugin_block(block).expect("Should build builtin filter")
                    {
                        let out = filter.process(ev, state).expect("Filter execution succeeds");
                        next_events.extend(out);
                    } else {
                        next_events.push(ev);
                    }
                }
                Statement::Conditional(cond) => {
                    let mut matched = false;
                    for (expr, branch_stmts) in &cond.branches {
                        if eval_expr(expr, &ev) {
                            next_events.extend(execute_statements(branch_stmts, ev.clone(), state));
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        if let Some(else_stmts) = &cond.else_branch {
                            next_events.extend(execute_statements(else_stmts, ev, state));
                        } else {
                            next_events.push(ev);
                        }
                    }
                }
            }
        }
        events = next_events;
    }
    events
}

#[test]
fn test_mutate_filter_operations_and_ordering() {
    let conf = r#"
    filter {
      mutate {
        copy => { "orig_src" => "copied_src" }
        rename => { "old_name" => "new_name" }
        replace => { "status" => "status_for_%{new_name}" }
        add_field => { "step_field" => "first" }
        add_field => { "step_field" => "%{step_field}_second" "extra" => "val_%{copied_src}" }
        remove_field => [ "temp1", "temp2" ]
        convert => [ "l4_proto", "integer" ]
        convert => { "bytes_str" => "integer" "score_str" => "float" "flag_str" => "boolean" "num_to_str" => "string" }
        add_tag => [ "mutated_tag" ]
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("Should parse mutate conf");
    let Statement::Plugin(block) = &parsed.filters[0] else {
        panic!("Expected plugin block");
    };
    let filter = MutateFilter::from_config(block).expect("Should construct MutateFilter");
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("orig_src", "10.0.0.1");
    ev.set("old_name", "alice");
    ev.set("status", "initial");
    ev.set("temp1", "delete_me");
    ev.set("temp2", "delete_me_too");
    ev.set("l4_proto", "17");
    ev.set("bytes_str", "4096");
    ev.set("score_str", "9.75");
    ev.set("flag_str", "true");
    ev.set("num_to_str", 42);

    let out = filter.process(ev, &state).expect("Mutate process should succeed");
    assert_eq!(out.len(), 1);
    let res = &out[0];

    // copy
    assert_eq!(res.get_str("orig_src").as_deref(), Some("10.0.0.1"));
    assert_eq!(res.get_str("copied_src").as_deref(), Some("10.0.0.1"));

    // rename
    assert!(res.get("old_name").is_none());
    assert_eq!(res.get_str("new_name").as_deref(), Some("alice"));

    // replace with interpolation
    assert_eq!(res.get_str("status").as_deref(), Some("status_for_alice"));

    // multiple add_field in order
    assert_eq!(res.get_str("step_field").as_deref(), Some("first_second"));
    assert_eq!(res.get_str("extra").as_deref(), Some("val_10.0.0.1"));

    // remove_field
    assert!(res.get("temp1").is_none());
    assert!(res.get("temp2").is_none());

    // convert (both 2-element array ["l4_proto", "integer"] and map)
    assert_eq!(res.get("l4_proto"), Some(&json!(17)));
    assert_eq!(res.get("bytes_str"), Some(&json!(4096)));
    assert_eq!(res.get("score_str"), Some(&json!(9.75)));
    assert_eq!(res.get("flag_str"), Some(&json!(true)));
    assert_eq!(res.get("num_to_str"), Some(&json!("42")));

    // add_tag
    assert!(res.has_tag("mutated_tag"));
}

#[test]
fn test_cidr_filter_private_and_public_ips() {
    let conf = r#"
    filter {
      cidr {
        address => [ "%{lan_ip}" ]
        network => [ "0.0.0.0/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "255.255.255.255/32" ]
        add_field => { "[src_locality]" => "private" }
        add_tag => [ "is_src_internal" ]
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("Should parse cidr conf");
    let Statement::Plugin(block) = &parsed.filters[0] else {
        panic!("Expected plugin block");
    };
    let filter = CidrFilter::from_config(block).expect("Should construct CidrFilter");
    let state = StateStore::new_standalone();

    // Private RFC1918 IP: 10.1.33.160 -> matches
    let mut ev_priv = Event::new();
    ev_priv.set("lan_ip", "10.1.33.160");
    let out_priv = filter.process(ev_priv, &state).unwrap();
    assert_eq!(
        out_priv[0].get_str("[src_locality]").as_deref(),
        Some("private")
    );
    assert!(out_priv[0].has_tag("is_src_internal"));

    // Public IP: 8.8.8.8 -> ignored
    let mut ev_pub = Event::new();
    ev_pub.set("lan_ip", "8.8.8.8");
    let out_pub = filter.process(ev_pub, &state).unwrap();
    assert!(out_pub[0].get("[src_locality]").is_none());
    assert!(!out_pub[0].has_tag("is_src_internal"));
}

#[test]
fn test_geoip_filter_city_and_asn_netflow_geoenrich() {
    let conf = r#"
    filter {
      geoip {
        source => "wan_ip"
        default_database_type => "City"
        target => "city_wan"
        fields => [COUNTRY_CODE2]
      }
      if [city_wan][country_code2] {
        mutate {
          add_field => { "dst_country_code" => "%{[city_wan][country_code2]}" }
        }
      }
      mutate {
        remove_field => [ "city_wan" ]
      }

      geoip {
        source => "wan_ip"
        default_database_type => "ASN"
        target => "asn_wan"
        fields => [AUTONOMOUS_SYSTEM_ORGANIZATION]
      }
      if [asn_wan][as_org] {
        mutate {
          add_field => { "dst_as_name" => "%{[asn_wan][as_org]}" }
        }
      }
      mutate {
        remove_field => [ "asn_wan" ]
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("Should parse netflow 02_geoenrich conf");
    let state = StateStore::new_standalone();

    // Test direct GeoipFilter construction as well
    if let Statement::Plugin(first_block) = &parsed.filters[0] {
        let direct_geoip = GeoipFilter::from_config(first_block).unwrap();
        let mut ev_direct = Event::new();
        ev_direct.set("wan_ip", "8.8.8.8");
        let res_direct = direct_geoip.process(ev_direct, &state).unwrap();
        assert_eq!(
            res_direct[0]
                .get_str("[city_wan][country_code2]")
                .as_deref(),
            Some("US")
        );
    }

    // Full pipeline execution for 8.8.8.8
    let mut ev = Event::new();
    ev.set("wan_ip", "8.8.8.8");
    let out = execute_statements(&parsed.filters, ev, &state);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get_str("dst_country_code").as_deref(), Some("US"));
    assert_eq!(out[0].get_str("dst_as_name").as_deref(), Some("GOOGLE"));
    assert!(out[0].get("city_wan").is_none());
    assert!(out[0].get("asn_wan").is_none());

    // Private IP should not produce geoip enrichment
    let mut ev_priv = Event::new();
    ev_priv.set("wan_ip", "10.1.33.160");
    let out_priv = execute_statements(&parsed.filters, ev_priv, &state);
    assert!(out_priv[0].get("dst_country_code").is_none());
    assert!(out_priv[0].get("dst_as_name").is_none());
}

#[test]
fn test_geoip_filter_database_config_and_fallback() {
    let conf = r#"
    filter {
      geoip {
        source => "client_ip"
        database => "/etc/logstash/GeoLite2-City.mmdb"
        default_database_type => "City"
        target => "client_geo"
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("Should parse geoip with database");
    let state = StateStore::new_standalone();

    if let Statement::Plugin(first_block) = &parsed.filters[0] {
        let geoip = GeoipFilter::from_config(first_block).unwrap();
        assert_eq!(geoip.source, "client_ip");
        assert_eq!(geoip.database_path.as_deref(), Some("/etc/logstash/GeoLite2-City.mmdb"));
        assert_eq!(geoip.target, "client_geo");

        // When DB is missing, gracefully falls back
        let mut ev = Event::new();
        ev.set("client_ip", "1.1.1.1");
        let out = geoip.process(ev, &state).unwrap();
        assert_eq!(out[0].get_str("[client_geo][country_code2]").as_deref(), Some("AU"));

        // Non-public IPs (IPv4-mapped IPv6 and benchmarking network) are ignored
        let mut ev_mapped = Event::new();
        ev_mapped.set("client_ip", "::ffff:10.1.33.160");
        let out_mapped = geoip.process(ev_mapped, &state).unwrap();
        assert!(out_mapped[0].get("client_geo").is_none());

        let mut ev_bench = Event::new();
        ev_bench.set("client_ip", "198.18.0.1");
        let out_bench = geoip.process(ev_bench, &state).unwrap();
        assert!(out_bench[0].get("client_geo").is_none());
    }

    // Test fields filtering
    let conf_fields = r#"
    filter {
      geoip {
        source => "ip"
        default_database_type => "City"
        target => "geo"
        fields => [ "country_name" ]
      }
    }
    "#;
    let parsed_fields = parse_logstash_conf(conf_fields).unwrap();
    if let Statement::Plugin(block) = &parsed_fields.filters[0] {
        let geoip = GeoipFilter::from_config(block).unwrap();
        let mut ev = Event::new();
        ev.set("ip", "8.8.8.8");
        let out = geoip.process(ev, &state).unwrap();
        // country_code2 was not requested in fields, so it shouldn't be populated
        assert!(out[0].get("[geo][country_code2]").is_none());
    }
}

#[test]
fn test_grok_filter_vault_all_four_log_types() {
    let state = StateStore::new_standalone();

    // 1. sshd
    let sshd_conf = r#"
    filter {
      grok {
        patterns_dir => ["/etc/logstash/pipelines/vault/patterns"]
        match => { "message" => [ "%{SSHD_MESSAGE}" ] }
      }
    }
    "#;
    let parsed_sshd = parse_logstash_conf(sshd_conf).unwrap();
    let Statement::Plugin(sshd_block) = &parsed_sshd.filters[0] else {
        panic!("Expected grok block");
    };
    let sshd_grok = GrokFilter::from_config(sshd_block).expect("Should build sshd GrokFilter");

    let mut ev_sshd = Event::new();
    ev_sshd.set(
        "message",
        "Accepted publickey for root from 10.1.33.10 port 54322 ssh2",
    );
    let out_sshd = sshd_grok.process(ev_sshd, &state).unwrap();
    assert_eq!(out_sshd[0].get_str("sshd_result").as_deref(), Some("Accepted"));
    assert_eq!(
        out_sshd[0].get_str("sshd_auth_type").as_deref(),
        Some("publickey")
    );
    assert_eq!(out_sshd[0].get_str("sshd_user").as_deref(), Some("root"));
    assert_eq!(
        out_sshd[0].get_str("sshd_client_ip").as_deref(),
        Some("10.1.33.10")
    );
    assert_eq!(out_sshd[0].get_str("sshd_port").as_deref(), Some("54322"));
    assert_eq!(
        out_sshd[0].get_str("sshd_protocol").as_deref(),
        Some("ssh2")
    );

    // Also test a later alternative in SSHD_MESSAGE (e.g. SSHD_FAIL)
    let mut ev_sshd_fail = Event::new();
    ev_sshd_fail.set(
        "message",
        "Failed password for admin from 192.168.1.50 port 41111 ssh2",
    );
    let out_sshd_fail = sshd_grok.process(ev_sshd_fail, &state).unwrap();
    assert_eq!(
        out_sshd_fail[0].get_str("sshd_fail_msg").as_deref(),
        Some("Failed")
    );
    assert_eq!(
        out_sshd_fail[0].get_str("sshd_auth_type").as_deref(),
        Some("password")
    );
    assert_eq!(
        out_sshd_fail[0].get_str("sshd_invalid_user").as_deref(),
        Some("admin")
    );
    assert_eq!(
        out_sshd_fail[0].get_str("sshd_client_ip").as_deref(),
        Some("192.168.1.50")
    );

    // 2. iptables
    let iptables_conf = r#"
    filter {
      grok {
        patterns_dir => ["/etc/logstash/pipelines/vault/patterns"]
        match => { "message" => [ "%{IPTABLES_MESSAGE}" ] }
      }
    }
    "#;
    let parsed_ipt = parse_logstash_conf(iptables_conf).unwrap();
    let Statement::Plugin(ipt_block) = &parsed_ipt.filters[0] else {
        panic!("Expected grok block");
    };
    let ipt_grok = GrokFilter::from_config(ipt_block).expect("Should build iptables GrokFilter");

    let mut ev_ipt = Event::new();
    ev_ipt.set(
        "message",
        "DROP IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=10.1.33.25 DST=10.1.33.160 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=45678 DPT=22",
    );
    let out_ipt = ipt_grok.process(ev_ipt, &state).unwrap();
    assert_eq!(out_ipt[0].get_str("status").as_deref(), Some("DROP"));
    assert_eq!(
        out_ipt[0].get_str("iptables_in_device").as_deref(),
        Some("eth0")
    );
    assert_eq!(
        out_ipt[0].get_str("iptables_src_ip").as_deref(),
        Some("10.1.33.25")
    );
    assert_eq!(
        out_ipt[0].get_str("iptables_dst_ip").as_deref(),
        Some("10.1.33.160")
    );
    assert_eq!(
        out_ipt[0].get_str("iptables_protocol").as_deref(),
        Some("TCP")
    );
    assert_eq!(
        out_ipt[0].get_str("iptables_src_port").as_deref(),
        Some("45678")
    );
    assert_eq!(
        out_ipt[0].get_str("iptables_dst_port").as_deref(),
        Some("22")
    );

    // 3. nginx
    let nginx_conf = r#"
    filter {
      grok {
        patterns_dir => ["/etc/logstash/pipelines/vault/patterns"]
        match => { "message" => [ "%{NGINXACCESS}" ] }
      }
    }
    "#;
    let parsed_nginx = parse_logstash_conf(nginx_conf).unwrap();
    let Statement::Plugin(nginx_block) = &parsed_nginx.filters[0] else {
        panic!("Expected grok block");
    };
    let nginx_grok = GrokFilter::from_config(nginx_block).expect("Should build nginx GrokFilter");

    let mut ev_nginx = Event::new();
    ev_nginx.set(
        "message",
        r#"10.1.33.10 - admin [26/Oct/2026:12:00:00 +0000] "GET /api/v1/status HTTP/1.1" 200 512 "https://10.1.33.160/" "Mozilla/5.0""#,
    );
    let out_nginx = nginx_grok.process(ev_nginx, &state).unwrap();
    assert_eq!(
        out_nginx[0].get_str("remote_ip").as_deref(),
        Some("10.1.33.10")
    );
    assert_eq!(out_nginx[0].get_str("user_name").as_deref(), Some("admin"));
    assert_eq!(
        out_nginx[0].get_str("request_action").as_deref(),
        Some("GET")
    );
    assert_eq!(
        out_nginx[0].get_str("request").as_deref(),
        Some("/api/v1/status")
    );
    assert_eq!(
        out_nginx[0].get_str("http_version").as_deref(),
        Some("1.1")
    );
    assert_eq!(out_nginx[0].get_str("response").as_deref(), Some("200"));
    assert_eq!(out_nginx[0].get_str("bytes").as_deref(), Some("512"));

    // 4. dnsmasq & dnsmasq-dhcp (as configured in vault/05_dnsmasq_grok.conf)
    let dnsmasq_conf = r#"
    filter {
      if [app_name] == "dnsmasq-dhcp" {
        grok {
          patterns_dir => ["/etc/logstash/pipelines/vault/patterns"]
          match => { "message" => [ "%{DHCPD}" ] }
        }
      } else if [app_name] == "dnsmasq" {
        grok {
          patterns_dir => ["/etc/logstash/pipelines/vault/patterns"]
          match => {
            "message" => [
              "%{DNSMASQ_QUERY}",
              "%{DNSMASQ_FORWARD}",
              "%{DNSMASQ_ACTION_IS}"
            ]
          }
        }
      }
    }
    "#;
    let parsed_dns = parse_logstash_conf(dnsmasq_conf).unwrap();

    let mut ev_dhcp = Event::new();
    ev_dhcp.set("app_name", "dnsmasq-dhcp");
    ev_dhcp.set(
        "message",
        "DHCPACK(eth0) 10.1.33.199 00:1a:2b:3c:4d:5e client-host",
    );
    let out_dhcp = execute_statements(&parsed_dns.filters, ev_dhcp, &state);
    assert_eq!(
        out_dhcp[0].get_str("message_type").as_deref(),
        Some("DHCPACK")
    );
    assert_eq!(out_dhcp[0].get_str("interface").as_deref(), Some("eth0"));
    assert_eq!(
        out_dhcp[0].get_str("source_ip").as_deref(),
        Some("10.1.33.199")
    );
    assert_eq!(
        out_dhcp[0].get_str("source_mac").as_deref(),
        Some("00:1a:2b:3c:4d:5e")
    );
    assert_eq!(
        out_dhcp[0].get_str("source_hostname").as_deref(),
        Some("client-host")
    );

    let mut ev_query = Event::new();
    ev_query.set("app_name", "dnsmasq");
    ev_query.set("message", "query[A] consul.service.consul from 127.0.0.1");
    let out_query = execute_statements(&parsed_dns.filters, ev_query, &state);
    assert_eq!(out_query[0].get_str("action_dns").as_deref(), Some("query"));
    assert_eq!(out_query[0].get_str("action_opt").as_deref(), Some("A"));
    assert_eq!(
        out_query[0].get_str("target_ip").as_deref(),
        Some("consul.service.consul")
    );
    assert_eq!(
        out_query[0].get_str("source_ip").as_deref(),
        Some("127.0.0.1")
    );

    let mut ev_forward = Event::new();
    ev_forward.set("app_name", "dnsmasq");
    ev_forward.set("message", "forwarded consul.service.consul to 127.0.0.1");
    let out_forward = execute_statements(&parsed_dns.filters, ev_forward, &state);
    assert_eq!(
        out_forward[0].get_str("action_dns").as_deref(),
        Some("forwarded")
    );
    assert_eq!(
        out_forward[0].get_str("domain").as_deref(),
        Some("consul.service.consul")
    );
    assert_eq!(
        out_forward[0].get_str("ip_forward").as_deref(),
        Some("127.0.0.1")
    );

    let mut ev_reply = Event::new();
    ev_reply.set("app_name", "dnsmasq");
    ev_reply.set("message", "reply consul.service.consul is 10.1.33.160");
    let out_reply = execute_statements(&parsed_dns.filters, ev_reply, &state);
    assert_eq!(out_reply[0].get_str("action_dns").as_deref(), Some("reply"));
    assert_eq!(
        out_reply[0].get_str("target_dns").as_deref(),
        Some("consul.service.consul")
    );
    assert_eq!(
        out_reply[0].get_str("status_dns").as_deref(),
        Some("10.1.33.160")
    );
}

#[test]
fn test_fingerprint_and_drop_filters() {
    let conf = r#"
    filter {
      fingerprint {
        source => "raw-message"
        target => "fingerprint"
        key => yourenterprisekey
        method => SHA256
      }
      if [drop_me] {
        drop {}
      }
    }
    "#;

    let parsed = parse_logstash_conf(conf).expect("Should parse fingerprint + drop conf");
    let Statement::Plugin(fp_block) = &parsed.filters[0] else {
        panic!("Expected fingerprint block");
    };
    let fp_filter = FingerprintFilter::from_config(fp_block).unwrap();
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("raw-message", "vault syslog line 123");
    let out = fp_filter.process(ev, &state).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(b"vault syslog line 123yourenterprisekey");
    let expected_hex = hex::encode(hasher.finalize());
    assert_eq!(
        out[0].get_str("fingerprint").as_deref(),
        Some(expected_hex.as_str())
    );

    // Test DropFilter directly and via pipeline
    let drop_filter = DropFilter::default();
    let mut ev_drop = Event::new();
    let drop_res = drop_filter.process(ev_drop.clone(), &state).unwrap();
    assert!(drop_res.is_empty());

    ev_drop.set("drop_me", true);
    let pipeline_res = execute_statements(&parsed.filters, ev_drop, &state);
    assert!(pipeline_res.is_empty());
}

#[test]
fn test_grok_filter_dollar_brace_syntax() {
    let conf = r#"
    filter {
      grok {
        match => {
          "message" => "Received signal %{NUMBER:sshd_signal}; ${WORD:terminate_msg}."
        }
      }
    }
    "#;
    let parsed = parse_logstash_conf(conf).expect("Should parse conf");
    let Statement::Plugin(grok_block) = &parsed.filters[0] else {
        panic!("Expected grok block");
    };
    let grok_filter = GrokFilter::from_config(grok_block).unwrap();
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("message", "Received signal 15; Terminated.");
    let out = grok_filter.process(ev, &state).unwrap();
    assert_eq!(out[0].get_str("sshd_signal").as_deref(), Some("15"));
    assert_eq!(out[0].get_str("terminate_msg").as_deref(), Some("Terminated"));
}

#[test]
fn test_json_filter_target_and_root_merge() {
    let conf = r#"
    filter {
      json {
        source => [message]
        target => "message"
      }
      json {
        source => "extra"
      }
    }
    "#;
    let parsed = parse_logstash_conf(conf).expect("parse json filter conf");
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("message", r#"{"PowerSupplies": [{"Health": "OK"}], "Model": "ProLiant"}"#);
    ev.set("extra", r#"{"environment": "production", "rack_id": 42}"#);

    let out = execute_statements(&parsed.filters, ev, &state);
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].get_str("[message][Model]").as_deref(),
        Some("ProLiant")
    );
    assert_eq!(
        out[0].get_str("[message][PowerSupplies][0][Health]").as_deref(),
        Some("OK")
    );
    assert_eq!(out[0].get_str("environment").as_deref(), Some("production"));
    assert_eq!(out[0].get("rack_id"), Some(&json!(42)));

    // Failure case: malformed JSON
    let mut ev_bad = Event::new();
    ev_bad.set("message", "{bad json string");
    let out_bad = execute_statements(&parsed.filters, ev_bad, &state);
    assert!(out_bad[0].has_tag("_jsonparsefailure"));
}

#[test]
fn test_grok_filter_empty_pattern_no_panic() {
    let conf = r#"
    filter {
      grok {
        match => { "message" => "" }
      }
    }
    "#;
    let parsed = parse_logstash_conf(conf).expect("Should parse empty grok pattern");
    let Statement::Plugin(grok_block) = &parsed.filters[0] else {
        panic!("Expected grok block");
    };
    let grok_filter = GrokFilter::from_config(grok_block).unwrap();
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("message", "anything");
    let out = grok_filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
}
