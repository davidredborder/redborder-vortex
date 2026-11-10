use redborder_vortex::config::{parse_logstash_conf, Statement};
use redborder_vortex::event::Event;
use redborder_vortex::filters::python::{PythonFilter, RubyCompatFilter};
use redborder_vortex::filters::Filter;
use redborder_vortex::state::{StateStore, WLC_PSQL_STORE};
use serde_json::{json, Map};

fn extract_first_plugin(conf: &str) -> redborder_vortex::config::PluginBlock {
    let parsed = parse_logstash_conf(conf).expect("Failed to parse logstash conf");
    match parsed.filters.into_iter().next().expect("Expected filter") {
        Statement::Plugin(block) => block,
        _ => panic!("Expected plugin block"),
    }
}

#[test]
fn test_python_filter_inline_init_and_pyevent_methods() {
    let conf = r#"
    filter {
      python {
        init => "
multiplier = 3
prefix = 'rb_'
"
        code => "
val = event.get('pkts')
if val is not None:
    event.set('pkts', val * multiplier)
event.set('[nested][label]', prefix + str(event.get('sensor_name')))
event.remove('temp_field')
event.tag('processed_by_python')
snap = event.to_dict()
event.set('field_count_has_pkts', 'pkts' in snap)
"
      }
    }
    "#;

    let block = extract_first_plugin(conf);
    let filter = PythonFilter::from_plugin_block(&block).expect("Should build PythonFilter");
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("pkts", 10);
    ev.set("sensor_name", "probe01");
    ev.set("temp_field", "delete_me");

    let out = filter.process(ev, &state).expect("Should process event");
    assert_eq!(out.len(), 1);
    let res = &out[0];
    assert_eq!(res.get("pkts"), Some(&json!(30)));
    assert_eq!(res.get("[nested][label]"), Some(&json!("rb_probe01")));
    assert_eq!(res.get("temp_field"), None);
    assert!(res.has_tag("processed_by_python"));
    assert_eq!(res.get("field_count_has_pkts"), Some(&json!(true)));
}

#[test]
fn test_python_filter_cancel_event() {
    let filter = PythonFilter::new_inline(
        None,
        r#"
if event.get("drop_me") == True:
    event.cancel()
"#,
    )
    .expect("Should create inline PythonFilter");

    let state = StateStore::new_standalone();

    let mut drop_ev = Event::new();
    drop_ev.set("drop_me", true);
    let out = filter.process(drop_ev, &state).expect("Should process");
    assert!(out.is_empty(), "Cancelled event must return empty Vec");

    let mut keep_ev = Event::new();
    keep_ev.set("drop_me", false);
    let out2 = filter.process(keep_ev, &state).expect("Should process");
    assert_eq!(out2.len(), 1);
}

#[test]
fn test_python_filter_state_store_access_and_enrich() {
    let state = StateStore::new_standalone();
    let mut wlc_record = Map::new();
    wlc_record.insert("campus".to_string(), json!("NorthCampus"));
    wlc_record.insert("building".to_string(), json!("HQ"));
    state
        .put_record(WLC_PSQL_STORE, "aa:bb:cc:dd:ee:ff", wlc_record)
        .unwrap();

    let filter = PythonFilter::new_inline(
        None,
        r#"
# Read and write KV in StateStore
state.set_kv("last_seen_mac", event.get("wireless_station"))
kv_val = state.get_kv("last_seen_mac")
event.set("kv_echo", kv_val)

# Read and write a custom store record in StateStore
state.put_record("custom-store", "k1", {"score": 99, "status": "active"})
rec = state.get_record("custom-store", "k1")
if rec:
    event.set("custom_score", rec["score"])

# Trigger full StateStore enrichment (e.g. wlc-psql)
state.enrich(event)
"#,
    )
    .expect("Should create inline PythonFilter");

    let mut ev = Event::new();
    ev.set("wireless_station", "aa:bb:cc:dd:ee:ff");

    let out = filter.process(ev, &state).expect("Should process");
    assert_eq!(out.len(), 1);
    let res = &out[0];
    assert_eq!(res.get("kv_echo"), Some(&json!("aa:bb:cc:dd:ee:ff")));
    assert_eq!(res.get("custom_score"), Some(&json!(99)));
    assert_eq!(res.get("campus"), Some(&json!("NorthCampus")));
    assert_eq!(res.get("building"), Some(&json!("HQ")));
    assert_eq!(
        state.get_kv("last_seen_mac").unwrap(),
        Some("aa:bb:cc:dd:ee:ff".to_string())
    );
}

#[test]
fn test_python_filter_external_module_malware() {
    let state = StateStore::new_standalone();

    // Test malware pipeline functions from plugins/malware.py (yara_scan, aerospike_malware_score, s3_upload_malware_results)
    let yara_filter =
        PythonFilter::new_module("malware", Some("yara_scan"), None).expect("yara_scan module");
    let score_filter = PythonFilter::new_module("malware", Some("aerospike_malware_score"), None)
        .expect("aerospike_malware_score module");
    let s3_filter = PythonFilter::new_module("malware", Some("s3_upload_malware_results"), None)
        .expect("s3_upload_malware_results module");

    let mut mal_ev = Event::new();
    mal_ev.set(
        "payload",
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    );

    let step1 = yara_filter.process(mal_ev, &state).unwrap().remove(0);
    assert_eq!(step1.get("malware_detected"), Some(&json!(true)));
    assert_eq!(
        step1.get("yara_matches"),
        Some(&json!(["EICAR_Test_File"]))
    );

    let step2 = score_filter.process(step1, &state).unwrap().remove(0);
    assert_eq!(step2.get("malware_score"), Some(&json!(75)));

    let step3 = s3_filter.process(step2, &state).unwrap().remove(0);
    assert_eq!(step3.get("s3_uploaded"), Some(&json!(true)));
    assert_eq!(step3.get("s3_bucket"), Some(&json!("rb-malware")));
}

#[test]
fn test_malware_pipeline_legacy_parity_fields() {
    let state = StateStore::new_standalone();

    let yara_filter =
        PythonFilter::new_module("malware", Some("yara_scan"), None).expect("yara_scan module");
    let score_filter = PythonFilter::new_module("malware", Some("aerospike_malware_score"), None)
        .expect("aerospike_malware_score module");
    let _s3_filter = PythonFilter::new_module("malware", Some("s3_upload_malware_results"), None)
        .expect("s3_upload_malware_results module");

    let mut ev = Event::new();
    ev.set("payload", "powershell -enc test_attack");
    ev.set("path", "/usr/share/malware/sample_uuid.lock");

    // 1. Check YARA parity fields: yara map (Hits, yara_rules, Weight), loader, fb_yara
    let ev1 = yara_filter.process(ev, &state).unwrap().remove(0);
    assert_eq!(ev1.get("loader"), Some(&json!("yara")));
    assert_eq!(ev1.get("malware_detected"), Some(&json!(true)));
    assert!(ev1.get("sha256").is_some());
    assert!(ev1.get("fb_yara").is_some());
    let yara_dict = ev1.get("yara").expect("yara field should exist");
    assert!(yara_dict.get("Hits").is_some());
    assert!(yara_dict.get("yara_rules").is_some());
    assert!(yara_dict.get("Weight").is_some());

    // 2. Check Aerospike scoring
    let ev2 = score_filter.process(ev1, &state).unwrap().remove(0);
    let score = ev2.get("malware_score").unwrap().as_i64().unwrap();
    assert!(score > 0, "Malware score should be positive for detected threat");

    // 2b. Check Blacklist and Whitelist handling in Aerospike scoring
    let mut black_ev = Event::new();
    black_ev.set("sha256", "test_hash_black");
    black_ev.set("list_type", "black");
    let black_out = score_filter.process(black_ev, &state).unwrap().remove(0);
    assert_eq!(black_out.get("malware_score"), Some(&json!(100)));

    let mut white_ev = Event::new();
    white_ev.set("sha256", "test_hash_white");
    white_ev.set("list_type", "white");
    let white_out = score_filter.process(white_ev, &state).unwrap().remove(0);
    assert_eq!(white_out.get("malware_score"), Some(&json!(0)));

    // 3. Check S3 results path formatting and payload structure with output_dir
    let tmp_dir = std::env::temp_dir().join(format!("s3_test_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let mut s3_cfg = Map::new();
    s3_cfg.insert("output_dir".to_string(), json!(tmp_dir.to_string_lossy().to_string()));
    let s3_with_dir = PythonFilter::new_module("malware", Some("s3_upload_malware_results"), Some(s3_cfg))
        .expect("s3 filter with output_dir");

    let ev3 = s3_with_dir.process(ev2, &state).unwrap().remove(0);
    assert_eq!(ev3.get("s3_uploaded"), Some(&json!(true)));
    let s3_key = ev3.get("s3_key").unwrap().as_str().unwrap();
    assert!(s3_key.starts_with("mdata/resultData/realTime/"));
    assert!(s3_key.ends_with("/results.json"));

    // Verify written payload format is an array of results matching legacy
    let hash_str = ev3.get("sha256").unwrap().as_str().unwrap();
    let written_file = tmp_dir.join(format!("{}.json", hash_str));
    assert!(written_file.exists(), "Output JSON file must be written to output_dir");
    let content = std::fs::read_to_string(&written_file).unwrap();
    let parsed_json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(parsed_json.is_array(), "S3 result payload must be a JSON array of analyzer results");
    assert_eq!(parsed_json[0].get("loader"), Some(&json!("yara")));

    // 4. Verify multi-loader accumulation (clamscan + yara) without overwriting
    let mut clam_ev = Event::new();
    clam_ev.set("sha256", hash_str);
    clam_ev.set("loader", "clamscan");
    clam_ev.set("malware_score", 100);
    clam_ev.set("clamscan", json!({"Virus Family": "Eicar-Signature"}));
    let _ev_clam = s3_with_dir.process(clam_ev, &state).unwrap().remove(0);

    let content_after = std::fs::read_to_string(&written_file).unwrap();
    let parsed_multi: serde_json::Value = serde_json::from_str(&content_after).unwrap();
    assert!(parsed_multi.is_array());
    let arr = parsed_multi.as_array().unwrap();
    assert_eq!(arr.len(), 2, "Both yara and clamscan must be present in the multi-loader results array");
    let loaders: Vec<&str> = arr.iter().filter_map(|x| x.get("loader").and_then(|l| l.as_str())).collect();
    assert!(loaders.contains(&"yara"));
    assert!(loaders.contains(&"clamscan"));

    let _ = std::fs::remove_dir_all(tmp_dir);
}

#[test]
fn test_malware_all_legacy_loaders_clamscan_virustotal_metadefender() {
    use redborder_vortex::filters::create_filter;

    let state = StateStore::new_standalone();

    // Setup temporary clean and infected files on disk
    let tmp_dir = std::env::temp_dir().join(format!("malware_loader_test_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let clean_file = tmp_dir.join("clean.txt");
    std::fs::write(&clean_file, b"This is a benign clean file for testing.\n").unwrap();

    let infected_file = tmp_dir.join("eicar.com");
    std::fs::write(&infected_file, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").unwrap();

    // 1. Clamscan plugin creation & processing (clean vs infected)
    let clam_block = extract_first_plugin(r#"
filter {
  clamscan {
    file_field => "message"
  }
}
"#);
    let clam_filter = create_filter(&clam_block).expect("create_filter clamscan should succeed");

    // 1a. Clean file
    let mut clam_clean_ev = Event::new();
    clam_clean_ev.set("message", clean_file.to_string_lossy().to_string());
    let clam_clean_out = clam_filter.process(clam_clean_ev, &state).unwrap().remove(0);
    assert_eq!(clam_clean_out.get("loader"), Some(&json!("clamscan")));
    assert_eq!(clam_clean_out.get("fb_clamscan"), Some(&json!(0)));
    assert_eq!(
        clam_clean_out.get("clamscan").and_then(|c| c.get("Virus Family")),
        Some(&json!("Clean"))
    );
    assert!(clam_clean_out.get("clamscan_latency").is_some());

    // 1b. Infected file
    let mut clam_inf_ev = Event::new();
    clam_inf_ev.set("message", infected_file.to_string_lossy().to_string());
    let clam_inf_out = clam_filter.process(clam_inf_ev, &state).unwrap().remove(0);
    assert_eq!(clam_inf_out.get("loader"), Some(&json!("clamscan")));
    assert_eq!(clam_inf_out.get("fb_clamscan"), Some(&json!(100)));
    assert_eq!(
        clam_inf_out.get("clamscan").and_then(|c| c.get("Virus Family")),
        Some(&json!("Eicar-Test-Signature"))
    );

    // 2. Virustotal plugin with custom file_field and file hashing from disk
    let vt_block = extract_first_plugin(r#"
filter {
  virustotal {
    apikey => "test_mock_api_key"
    file_field => "sample_file"
  }
}
"#);
    let vt_filter = create_filter(&vt_block).expect("create_filter virustotal should succeed");

    let mut vt_ev = Event::new();
    vt_ev.set("sample_file", infected_file.to_string_lossy().to_string());
    let vt_out = vt_filter.process(vt_ev, &state).unwrap().remove(0);
    assert_eq!(vt_out.get("loader"), Some(&json!("virustotal")));
    assert_eq!(
        vt_out.get("sha256"),
        Some(&json!("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
    );
    assert_eq!(vt_out.get("fb_virustotal"), Some(&json!(92)));
    assert!(vt_out.get("virustotal").is_some());
    assert!(vt_out.get("virustotal_latency").is_some());

    // 3. MetaDefender plugin with file_field and file hashing from disk
    let md_block = extract_first_plugin(r#"
filter {
  metadefender {
    apikey => "test_mock_md_key"
    file_field => "message"
  }
}
"#);
    let md_filter = create_filter(&md_block).expect("create_filter metadefender should succeed");

    let mut md_ev = Event::new();
    md_ev.set("message", infected_file.to_string_lossy().to_string());
    let md_out = md_filter.process(md_ev, &state).unwrap().remove(0);
    assert_eq!(md_out.get("loader"), Some(&json!("metadefender")));
    assert_eq!(
        md_out.get("sha256"),
        Some(&json!("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
    );
    assert_eq!(md_out.get("fb_metadefender"), Some(&json!(95)));
    assert!(md_out.get("metadefender").is_some());

    // 4. Verify Aerospike scoring priority when event already has fb_yara = 0 and new loader is clamscan
    let score_filter = PythonFilter::new_module("malware", Some("aerospike_malware_score"), None)
        .expect("aerospike_malware_score module");
    let mut multi_ev = clam_inf_out;
    multi_ev.set("fb_yara", 0); // older yara scan was 0
    let multi_scored = score_filter.process(multi_ev, &state).unwrap().remove(0);
    assert_eq!(multi_scored.get("malware_score"), Some(&json!(100)));

    let _ = std::fs::remove_dir_all(tmp_dir);
}



#[test]
fn test_ruby_compat_general_inline_translation() {
    let conf = r#"
filter {
  ruby {
    init => '
      $scale_factor = 4
    '
    code => '
      pkt = event.get("pkts")
      if pkt
        event.set("pkts", pkt * $scale_factor)
        event.tag("scaled")
      end
      if event.get("should_drop") == true
        event.cancel
      end
    '
  }
}
"#;
    let block = extract_first_plugin(conf);
    let filter = RubyCompatFilter::from_plugin_block(&block).expect("Should build translated ruby");
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("pkts", 7);
    let out = filter.process(ev, &state).expect("Should process");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].get("pkts"), Some(&json!(28)));
    assert!(out[0].has_tag("scaled"));

    let mut drop_ev = Event::new();
    drop_ev.set("should_drop", true);
    let dropped = filter.process(drop_ev, &state).expect("Should process");
    assert!(dropped.is_empty());
}

#[test]
fn test_python_filter_generic_module_lifecycle() {
    let conf = r#"
    filter {
      python {
        module => "malware"
        function => "clean_input_files"
      }
    }
    "#;
    let block = extract_first_plugin(conf);
    let filter = PythonFilter::from_plugin_block(&block).expect("clean_input_files should load");
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("file_path", "/nonexistent/test/path");
    let out = filter.process(ev, &state).unwrap();
    assert_eq!(out.len(), 1);
}

#[test]
fn test_ips_filter_parsing_and_enrichment() {
    let conf = r#"
    filter {
      ips {
        reputation_servers => ["127.0.0.1:7777"]
      }
    }
    "#;
    let block = extract_first_plugin(conf);
    let filter = redborder_vortex::filters::create_filter(&block).expect("Should build ips filter");
    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("sha256", "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267");
    ev.set("file_hostname", "example.com");
    ev.set("file_uri", "/download/test.exe");
    ev.set("file_size", 2048);
    ev.set("src", "192.168.1.50");
    ev.set("dst", "10.0.0.1");

    let out = filter.process(ev, &state).expect("Should process");
    assert_eq!(out.len(), 1);
    let res = &out[0];
    assert_eq!(res.get("type"), Some(&json!("ips")));
    assert_eq!(res.get("url"), Some(&json!("http://example.com/download/test.exe")));
    assert_eq!(res.get("file_name"), Some(&json!("test.exe")));
    assert_eq!(res.get("file_size"), Some(&json!("1kB-1MB")));
    assert_eq!(res.get("application_id_name"), Some(&json!("http")));
    assert!(res.get("hash_score").is_some());

    // Without sha256, event should be cancelled/dropped
    let mut no_sha_ev = Event::new();
    no_sha_ev.set("file_hostname", "example.com");
    let dropped = filter.process(no_sha_ev, &state).expect("Should process");
    assert!(dropped.is_empty(), "Events without sha256 must be cancelled");
}

#[test]
fn test_ips_filter_incident_pipeline_integration() {
    let conf_ips = r#"
    filter {
      ips {
        reputation_servers => ["127.0.0.1:7777"]
      }
    }
    "#;
    let conf_enrich = r#"
    filter {
      python {
        module => "ips"
        function => "enrich_incident_scores"
        config => {
          "priority" => "critical"
        }
      }
    }
    "#;

    let b_ips = extract_first_plugin(conf_ips);
    let f_ips = redborder_vortex::filters::create_filter(&b_ips).unwrap();

    let b_enrich = extract_first_plugin(conf_enrich);
    let f_enrich = redborder_vortex::filters::create_filter(&b_enrich).unwrap();

    let state = StateStore::new_standalone();

    let mut ev = Event::new();
    ev.set("sha256", "mock_hash_for_test");
    ev.set("file_size", 500);

    let out1 = f_ips.process(ev, &state).unwrap();
    assert_eq!(out1.len(), 1);
    assert_eq!(out1[0].get("file_size"), Some(&json!("<1kB")));

    // Manually set a positive hash score to simulate an Aerospike hit
    let mut ev_scored = out1.into_iter().next().unwrap();
    ev_scored.set("hash_score", 85);

    let out2 = f_enrich.process(ev_scored, &state).unwrap();
    assert_eq!(out2.len(), 1);
    let final_ev = &out2[0];
    assert_eq!(final_ev.get("malware_score"), Some(&json!(85)));
    assert_eq!(final_ev.get("priority"), Some(&json!("critical")));
    assert!(final_ev.get("message").unwrap().as_str().unwrap().contains("Hash Score: 85"));
}

#[test]
fn test_pure_python_aerospike_wire_protocol_and_no_ruby() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    // 1. Verify no Ruby wrapper or Ruby subprocess calls remain in plugins/ips.py or plugins/malware.py
    let ips_src = std::fs::read_to_string("plugins/ips.py").expect("read plugins/ips.py");
    let malware_src = std::fs::read_to_string("plugins/malware.py").expect("read plugins/malware.py");
    assert!(
        !ips_src.contains("_find_ruby_wrapper") && !ips_src.contains("require 'aerospike'"),
        "plugins/ips.py must not use Ruby subprocesses"
    );
    assert!(
        !malware_src.contains("_find_ruby_wrapper")
            && !malware_src.contains("require 'aerospike'")
            && !malware_src.contains("require 'aws-sdk-s3'"),
        "plugins/malware.py must not use Ruby subprocesses"
    );

    // 2. Start a mock Aerospike binary protocol TCP server
    // Stores map of (namespace, set_name, digest_bytes) -> Vec<(bin_name, particle_type, raw_val_bytes)>
    type BinEntry = (String, u8, Vec<u8>);
    type RecordStore = std::collections::HashMap<(String, String, Vec<u8>), Vec<BinEntry>>;
    let store: Arc<Mutex<RecordStore>> = Arc::new(Mutex::new(std::collections::HashMap::new()));

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock aerospike");
    let addr = listener.local_addr().unwrap();
    let store_srv = Arc::clone(&store);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let store_conn = Arc::clone(&store_srv);
            std::thread::spawn(move || {
                let mut sock = stream;
                loop {
                    let mut hdr = [0u8; 30];
                    if sock.read_exact(&mut hdr).is_err() {
                        break;
                    }
                    let proto = u64::from_be_bytes(hdr[0..8].try_into().unwrap());
                    let msg_len = (proto & 0xFFFF_FFFF_FFFF) as usize;
                    let body_len = msg_len.saturating_sub(22);
                    let info1 = hdr[9];
                    let info2 = hdr[10];
                    let field_count = u16::from_be_bytes([hdr[26], hdr[27]]) as usize;
                    let op_count = u16::from_be_bytes([hdr[28], hdr[29]]) as usize;

                    let mut body = vec![0u8; body_len];
                    if body_len > 0 && sock.read_exact(&mut body).is_err() {
                        break;
                    }

                    let mut pos = 0;
                    let mut ns = String::new();
                    let mut set_name = String::new();
                    let mut digest = Vec::new();

                    for _ in 0..field_count {
                        let f_sz = u32::from_be_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;
                        let f_type = body[pos + 4];
                        let f_data = &body[pos + 5..pos + 4 + f_sz];
                        pos += 4 + f_sz;
                        match f_type {
                            0 => ns = String::from_utf8_lossy(f_data).to_string(),
                            1 => set_name = String::from_utf8_lossy(f_data).to_string(),
                            4 => digest = f_data.to_vec(),
                            _ => {}
                        }
                    }

                    let key = (ns, set_name, digest);
                    if (info2 & 0x01) != 0 {
                        // WRITE request
                        let mut db = store_conn.lock().unwrap();
                        let rec = db.entry(key).or_default();
                        for _ in 0..op_count {
                            let op_sz = u32::from_be_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;
                            let _op_type = body[pos + 4];
                            let p_type = body[pos + 5];
                            let name_len = body[pos + 7] as usize;
                            let name = String::from_utf8_lossy(&body[pos + 8..pos + 8 + name_len]).to_string();
                            let val_bytes = body[pos + 8 + name_len..pos + 4 + op_sz].to_vec();
                            pos += 4 + op_sz;
                            if let Some(existing) = rec.iter_mut().find(|b| b.0 == name) {
                                existing.1 = p_type;
                                existing.2 = val_bytes;
                            } else {
                                rec.push((name, p_type, val_bytes));
                            }
                        }
                        // 30-byte OK response (result_code = 0)
                        let mut resp = [0u8; 30];
                        let resp_proto: u64 = (2u64 << 56) | (3u64 << 48) | 22u64;
                        resp[0..8].copy_from_slice(&resp_proto.to_be_bytes());
                        resp[8] = 22;
                        resp[13] = 0;
                        let _ = sock.write_all(&resp);
                    } else if (info1 & 0x01) != 0 {
                        // READ request
                        let db = store_conn.lock().unwrap();
                        if let Some(bins) = db.get(&key) {
                            let mut ops_buf = Vec::new();
                            for (b_name, p_type, val_bytes) in bins {
                                let name_bytes = b_name.as_bytes();
                                let op_sz = (4 + name_bytes.len() + val_bytes.len()) as u32;
                                ops_buf.extend_from_slice(&op_sz.to_be_bytes());
                                ops_buf.push(1); // op_type
                                ops_buf.push(*p_type);
                                ops_buf.push(0);
                                ops_buf.push(name_bytes.len() as u8);
                                ops_buf.extend_from_slice(name_bytes);
                                ops_buf.extend_from_slice(val_bytes);
                            }
                            let total_after_proto = 22 + ops_buf.len();
                            let mut resp = vec![0u8; 30];
                            let resp_proto: u64 = (2u64 << 56) | (3u64 << 48) | (total_after_proto as u64);
                            resp[0..8].copy_from_slice(&resp_proto.to_be_bytes());
                            resp[8] = 22;
                            resp[13] = 0; // OK
                            let op_c = bins.len() as u16;
                            resp[28..30].copy_from_slice(&op_c.to_be_bytes());
                            resp.extend_from_slice(&ops_buf);
                            let _ = sock.write_all(&resp);
                        } else {
                            // KEY_NOT_FOUND_ERROR = 2
                            let mut resp = [0u8; 30];
                            let resp_proto: u64 = (2u64 << 56) | (3u64 << 48) | 22u64;
                            resp[0..8].copy_from_slice(&resp_proto.to_be_bytes());
                            resp[8] = 22;
                            resp[13] = 2;
                            let _ = sock.write_all(&resp);
                        }
                    }
                }
            });
        }
    });

    // 3. Exercise malware.aerospike_malware_score (writes to hashScores & controlFiles, reads back)
    let state = StateStore::new_standalone();
    let mut score_cfg = Map::new();
    score_cfg.insert("aerospike_server".to_string(), json!(addr.to_string()));
    let score_filter = PythonFilter::new_module(
        "malware",
        Some("aerospike_malware_score"),
        Some(score_cfg),
    )
    .expect("aerospike_malware_score filter");

    let test_sha = "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";
    let mut mal_ev = Event::new();
    mal_ev.set("sha256", test_sha);
    mal_ev.set("loader", "yara");
    mal_ev.set("fb_yara", 80);
    mal_ev.set("file_path", "/tmp/uuid_sample_1");
    mal_ev.set("@timestamp", "2026-11-07T08:00:00Z");

    let scored_ev = score_filter.process(mal_ev, &state).unwrap().remove(0);
    // Without weights.yml on disk, default weight is 0.1 -> 80 * 0.1 = 8
    assert_eq!(scored_ev.get("malware_score"), Some(&json!(8)));

    // Now test IPS filter reading back that same hashScore from our mock Aerospike server!
    let mut ips_cfg = Map::new();
    ips_cfg.insert("aerospike_server".to_string(), json!(addr.to_string()));
    let ips_filter =
        PythonFilter::new_module("ips", Some("ips_filter"), Some(ips_cfg)).expect("ips_filter");

    let mut ips_ev = Event::new();
    ips_ev.set("sha256", test_sha);
    ips_ev.set("file_hostname", "malware.example.org");
    ips_ev.set("file_uri", "/dropper.exe");
    ips_ev.set("src", "192.0.2.10");
    ips_ev.set("dst", "198.51.100.20");

    let ips_out = ips_filter.process(ips_ev, &state).unwrap().remove(0);
    assert_eq!(ips_out.get("hash_score"), Some(&json!(8)));
    assert_eq!(ips_out.get("hash_list_type"), Some(&json!("none")));

    // 4. Second loader (clamscan = 100) updates the same hash in Aerospike:
    // combines fb_yara (80 * 0.1 = 8) + fb_clamscan (100 * 0.1 = 10) -> global_score = 18
    // and appends second S3 path to controlFiles s3_uuids LIST bin
    let mut mal_ev2 = Event::new();
    mal_ev2.set("sha256", test_sha);
    mal_ev2.set("loader", "clamscan");
    mal_ev2.set("fb_clamscan", 100);
    mal_ev2.set("file_path", "/tmp/uuid_sample_2");
    mal_ev2.set("@timestamp", "2026-11-07T08:00:00Z");

    let scored_ev2 = score_filter.process(mal_ev2, &state).unwrap().remove(0);
    assert_eq!(scored_ev2.get("malware_score"), Some(&json!(18)));

    let db = store.lock().unwrap();
    let ctrl_entries: Vec<&Vec<BinEntry>> = db
        .iter()
        .filter(|((ns, set, _), _)| ns == "malware" && set == "controlFiles")
        .map(|(_, v)| v)
        .collect();
    assert_eq!(ctrl_entries.len(), 1, "controlFiles record should exist");
    let s3_uuids_bin = ctrl_entries[0]
        .iter()
        .find(|(name, _, _)| name == "s3_uuids")
        .expect("s3_uuids bin should exist");
    assert_eq!(s3_uuids_bin.1, 20, "s3_uuids bin must use ParticleType::LIST (20)");
    // MsgPack array header for 2 elements is 0x92
    assert_eq!(
        s3_uuids_bin.2[0], 0x92,
        "s3_uuids MsgPack list should contain 2 accumulated paths"
    );
}

#[test]
fn test_pure_python_minio_s3_sigv4_upload() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock s3");
    let addr = listener.local_addr().unwrap();

    let s3_objects: Arc<Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let seen_auth_headers: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let s3_srv = Arc::clone(&s3_objects);
    let auth_srv = Arc::clone(&seen_auth_headers);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut sock = stream;
            let mut buf = vec![0u8; 65536];
            let mut total = 0;
            let mut header_end = None;
            let mut content_len = 0usize;

            loop {
                match sock.read(&mut buf[total..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total += n;
                        if header_end.is_none() {
                            if let Some(idx) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                                let h_end = idx + 4;
                                header_end = Some(h_end);
                                let hdr_str = String::from_utf8_lossy(&buf[..h_end]);
                                for line in hdr_str.lines() {
                                    let lower = line.to_ascii_lowercase();
                                    if let Some(rest) = lower.strip_prefix("content-length:") {
                                        content_len = rest.trim().parse().unwrap_or(0);
                                    }
                                }
                            }
                        }
                        if let Some(h_end) = header_end {
                            if total >= h_end + content_len {
                                break;
                            }
                        }
                    }
                }
            }

            let Some(h_end) = header_end else { continue };
            let hdr_str = String::from_utf8_lossy(&buf[..h_end]).to_string();
            let body_str = String::from_utf8_lossy(&buf[h_end..h_end + content_len]).to_string();

            let mut lines = hdr_str.lines();
            let req_line = lines.next().unwrap_or("");
            let parts: Vec<&str> = req_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let method = parts[0];
            let path = parts[1].to_string();

            for line in lines {
                if line.to_ascii_lowercase().starts_with("authorization:") {
                    auth_srv.lock().unwrap().push(line.to_string());
                }
            }

            if method == "GET" {
                let objs = s3_srv.lock().unwrap();
                if let Some(existing) = objs.get(&path) {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        existing.len(),
                        existing
                    );
                    let _ = sock.write_all(resp.as_bytes());
                } else {
                    let err_xml = "<Error><Code>NoSuchKey</Code></Error>";
                    let resp = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        err_xml.len(),
                        err_xml
                    );
                    let _ = sock.write_all(resp.as_bytes());
                }
            } else if method == "PUT" {
                s3_srv.lock().unwrap().insert(path, body_str);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = sock.write_all(resp.as_bytes());
            }
        }
    });

    let state = StateStore::new_standalone();
    let mut s3_cfg = Map::new();
    s3_cfg.insert("endpoint".to_string(), json!(format!("http://{}", addr)));
    s3_cfg.insert("bucket".to_string(), json!("rb-malware"));
    s3_cfg.insert("access_key_id".to_string(), json!("TESTKEYID123"));
    s3_cfg.insert("secret_access_key".to_string(), json!("TESTSECRETKEY456"));

    let s3_filter = PythonFilter::new_module(
        "malware",
        Some("s3_upload_malware_results"),
        Some(s3_cfg),
    )
    .expect("s3_upload_malware_results filter");

    // 1. Upload YARA result
    let mut ev1 = Event::new();
    ev1.set("sha256", "abc123hash");
    ev1.set("loader", "yara");
    ev1.set("malware_score", 75);
    ev1.set("file_path", "/tmp/file_uuid_99");
    ev1.set("@timestamp", "2026-11-07T08:00:00Z");
    ev1.set("yara_matches", json!(["RuleA"]));

    let out1 = s3_filter.process(ev1, &state).unwrap().remove(0);
    assert_eq!(out1.get("s3_uploaded"), Some(&json!(true)));

    // 2. Upload ClamAV result to same object and verify multi-loader merge over HTTP S3
    let mut ev2 = Event::new();
    ev2.set("sha256", "abc123hash");
    ev2.set("loader", "clamscan");
    ev2.set("malware_score", 100);
    ev2.set("file_path", "/tmp/file_uuid_99");
    ev2.set("@timestamp", "2026-11-07T08:00:00Z");
    ev2.set("clamscan", json!({"Virus Family": "Eicar"}));

    let out2 = s3_filter.process(ev2, &state).unwrap().remove(0);
    assert_eq!(out2.get("s3_uploaded"), Some(&json!(true)));

    let auths = seen_auth_headers.lock().unwrap();
    assert!(
        auths.len() >= 4,
        "Expected at least 4 signed S3 requests (GET+PUT twice), got {}",
        auths.len()
    );
    for a in auths.iter() {
        assert!(
            a.contains("AWS4-HMAC-SHA256 Credential=TESTKEYID123/"),
            "Missing AWS4-HMAC-SHA256 signature in header: {}",
            a
        );
    }

    let objs = s3_objects.lock().unwrap();
    let expected_path = "/rb-malware/mdata/resultData/realTime/2026/11/07/08/file_uuid_99/results.json";
    let stored_json = objs.get(expected_path).expect("S3 object should be stored at path");
    let parsed: serde_json::Value = serde_json::from_str(stored_json).expect("Valid JSON in S3");
    let arr = parsed.as_array().expect("Array of loader results");
    assert_eq!(arr.len(), 2, "Both yara and clamscan results must be merged in S3");
}




