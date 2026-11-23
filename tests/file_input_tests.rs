use redborder_vortex::config::parse_logstash_conf;
use redborder_vortex::engine::VortexEngine;
use redborder_vortex::inputs::file::{FileConsumer, FileInputConfig};
use redborder_vortex::state::StateStore;
use redborder_vortex::stats::StatsRegistry;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

struct TempTestDir(PathBuf);
impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{}_{}", prefix, uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn test_file_input_wildcard_matching_and_event_generation() {
    let tmp = TempTestDir::new("file_test1");
    let lock_file = tmp.0.join("payload.lock");
    fs::write(&lock_file, "/path/to/extracted/sample.bin\n").unwrap();

    let pattern = format!("{}/*.lock", tmp.0.to_string_lossy());
    let sincedb = tmp.0.join("sincedb.log");
    let complete_log = tmp.0.join("complete.log");

    let cfg = FileInputConfig {
        path: vec![pattern],
        mode: "read".to_string(),
        sincedb_path: Some(sincedb.clone()),
        file_completed_action: Some("log".to_string()),
        file_completed_log_path: Some(complete_log.clone()),
    };

    let mut consumer = FileConsumer::new(cfg, "node1".to_string());

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("node1".to_string()));
    let mut engine = VortexEngine::new_with_stats(state, stats, "node1".to_string());

    let pipeline_conf = r#"
        input {
            file {
                path => "/dummy/*.lock"
            }
        }
        filter {
            mutate {
                copy => {
                    "message" => "file_path"
                    "path" => "file_lock_path"
                }
            }
        }
        output {
            stdout { codec => json }
        }
    "#;
    let parsed = parse_logstash_conf(pipeline_conf).unwrap();
    let entry = redborder_vortex::config::PipelineEntry {
        id: "test-file".to_string(),
        path_config: "".to_string(),
        workers: 1,
    };
    engine.register_pipeline(entry, &parsed).unwrap();

    let (events_count, _) = consumer.poll_and_process(&engine, "test-file").unwrap();
    assert_eq!(events_count, 1, "Should have processed 1 event from lock file");

    // Verify sincedb was written and contains the lock file path
    assert!(sincedb.exists(), "sincedb should exist");
    let sincedb_content = fs::read_to_string(&sincedb).unwrap();
    assert!(sincedb_content.contains(&lock_file.to_string_lossy().to_string()));

    // Verify complete log was written
    assert!(complete_log.exists(), "complete log should exist");
    let log_content = fs::read_to_string(&complete_log).unwrap();
    assert!(log_content.contains(&lock_file.to_string_lossy().to_string()));

    // Second poll should NOT reprocess the same file
    let (second_count, _) = consumer.poll_and_process(&engine, "test-file").unwrap();
    assert_eq!(second_count, 0, "Second poll should find no new events");
}

#[test]
fn test_file_input_completed_action_delete() {
    let tmp = TempTestDir::new("file_test2");
    let lock_file = tmp.0.join("task1.lock");
    fs::write(&lock_file, "task data line 1\ntask data line 2\n").unwrap();

    let pattern = format!("{}/*.lock", tmp.0.to_string_lossy());

    let cfg = FileInputConfig {
        path: vec![pattern],
        mode: "read".to_string(),
        sincedb_path: None,
        file_completed_action: Some("delete".to_string()),
        file_completed_log_path: None,
    };

    let mut consumer = FileConsumer::new(cfg, "node1".to_string());

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("node1".to_string()));
    let mut engine = VortexEngine::new_with_stats(state, stats, "node1".to_string());

    let pipeline_conf = r#"
        input { file { path => "/dummy/*.lock" } }
        output { stdout { codec => json } }
    "#;
    let parsed = parse_logstash_conf(pipeline_conf).unwrap();
    let entry = redborder_vortex::config::PipelineEntry {
        id: "test-delete".to_string(),
        path_config: "".to_string(),
        workers: 1,
    };
    engine.register_pipeline(entry, &parsed).unwrap();

    let (events_count, _) = consumer.poll_and_process(&engine, "test-delete").unwrap();
    assert_eq!(events_count, 2, "Should process 2 lines as 2 events");
    assert!(!lock_file.exists(), "File should be deleted after completion");
}

#[test]
fn test_file_input_end_to_end_malware_flow() {
    let tmp = TempTestDir::new("file_test3");
    let sample_file = tmp.0.join("suspicious.bin");
    fs::write(&sample_file, b"powershell -enc aQB3AHIA").unwrap();

    let lock_file = tmp.0.join("analysis.lock");
    fs::write(&lock_file, format!("{}\n", sample_file.to_string_lossy())).unwrap();

    let pattern = format!("{}/*.lock", tmp.0.to_string_lossy());

    let cfg = FileInputConfig {
        path: vec![pattern],
        mode: "read".to_string(),
        sincedb_path: None,
        file_completed_action: Some("log".to_string()),
        file_completed_log_path: Some(tmp.0.join("malware_done.log")),
    };

    let mut consumer = FileConsumer::new(cfg, "node1".to_string());

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("node1".to_string()));
    let mut engine = VortexEngine::new_with_stats(state, stats, "node1".to_string());

    let malware_conf = r#"
        input {
            file {
                path => "/dummy/*.lock"
            }
        }
        filter {
            mutate {
                copy => {
                    "message" => "file_path"
                    "path" => "file_lock_path"
                }
            }
            yara {
                file_field => "message"
            }
            aerospike-malware-score {
                loader_score_name => "fb_yara"
                loader_type => "fb"
            }
            s3-upload-malware-results {
                file_field => "message"
                loader => "yara"
            }
            python {
                module => "malware"
                function => "clean_input_files"
            }
        }
        output {
            stdout { codec => json }
        }
    "#;
    let parsed = parse_logstash_conf(malware_conf).unwrap();
    let entry = redborder_vortex::config::PipelineEntry {
        id: "malware-test".to_string(),
        path_config: "".to_string(),
        workers: 1,
    };
    engine.register_pipeline(entry, &parsed).unwrap();

    let (events_count, routed) = consumer.poll_and_process(&engine, "malware-test").unwrap();
    assert_eq!(events_count, 1);
    assert_eq!(routed.len(), 1);
    let output_event = &routed[0].1;
    assert_eq!(output_event.get("malware_detected"), Some(&json!(true)));
    assert_eq!(output_event.get("s3_uploaded"), Some(&json!(true)));

    // Verify clean_input_files removed both the target sample and the lock file
    assert!(!sample_file.exists(), "Sample file should be cleaned up by python clean_input_files");
    assert!(!lock_file.exists(), "Lock file should be cleaned up by python clean_input_files");
}

#[test]
fn test_file_input_relative_and_question_mark_wildcards() {
    let tmp = TempTestDir::new("file_test4");
    let f1 = tmp.0.join("sample_1.txt");
    let f2 = tmp.0.join("sample_2.txt");
    let f_other = tmp.0.join("sample_12.txt");
    fs::write(&f1, "msg1\n").unwrap();
    fs::write(&f2, "msg2\n").unwrap();
    fs::write(&f_other, "msg_other\n").unwrap();

    let pattern_q = format!("{}/sample_?.txt", tmp.0.to_string_lossy());
    let cfg = FileInputConfig {
        path: vec![pattern_q],
        mode: "read".to_string(),
        sincedb_path: None,
        file_completed_action: None,
        file_completed_log_path: None,
    };
    let consumer = FileConsumer::new(cfg, "node1".to_string());
    let matching = consumer.find_matching_files();
    assert_eq!(matching.len(), 2);
    assert!(matching.contains(&f1));
    assert!(matching.contains(&f2));
    assert!(!matching.contains(&f_other));
}

#[test]
fn test_file_input_nested_directory_wildcard() {
    let tmp = TempTestDir::new("file_nested");
    let sub1 = tmp.0.join("dir1");
    let sub2 = tmp.0.join("dir2");
    fs::create_dir_all(&sub1).unwrap();
    fs::create_dir_all(&sub2).unwrap();

    let f1 = sub1.join("task.lock");
    let f2 = sub2.join("task.lock");
    fs::write(&f1, "data1\n").unwrap();
    fs::write(&f2, "data2\n").unwrap();

    let pattern = format!("{}/*/*.lock", tmp.0.to_string_lossy());
    let cfg = FileInputConfig {
        path: vec![pattern],
        mode: "read".to_string(),
        sincedb_path: None,
        file_completed_action: None,
        file_completed_log_path: None,
    };
    let consumer = FileConsumer::new(cfg, "node1".to_string());
    let matching = consumer.find_matching_files();
    assert_eq!(matching.len(), 2);
    assert!(matching.contains(&f1));
    assert!(matching.contains(&f2));
}

#[test]
fn test_file_input_tail_mode_never_deletes() {
    let tmp = TempTestDir::new("file_tail");
    let log_file = tmp.0.join("app.log");
    fs::write(&log_file, "log line 1\n").unwrap();

    let pattern = format!("{}/app.log", tmp.0.to_string_lossy());
    let cfg = FileInputConfig {
        path: vec![pattern],
        mode: "tail".to_string(),
        sincedb_path: None,
        file_completed_action: None,
        file_completed_log_path: None,
    };
    let mut consumer = FileConsumer::new(cfg, "node1".to_string());

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("node1".to_string()));
    let mut engine = VortexEngine::new_with_stats(state, stats, "node1".to_string());

    let pipeline_conf = r#"
        input { file { path => "/dummy/app.log" } }
        output { stdout { codec => json } }
    "#;
    let parsed = parse_logstash_conf(pipeline_conf).unwrap();
    let entry = redborder_vortex::config::PipelineEntry {
        id: "tail-test".to_string(),
        path_config: "".to_string(),
        workers: 1,
    };
    engine.register_pipeline(entry, &parsed).unwrap();

    let (events_count, _) = consumer.poll_and_process(&engine, "tail-test").unwrap();
    assert_eq!(events_count, 1);
    assert!(log_file.exists(), "File must NOT be deleted in tail mode when no action is specified");
}

#[test]
fn test_file_input_corrupted_file_no_infinite_loop() {
    let tmp = TempTestDir::new("file_corrupted");
    let corrupt_file = tmp.0.join("corrupt.lock");
    // Write invalid UTF-8 sequence [0xFF, 0xFE, 0xFD]
    fs::write(&corrupt_file, &[0xFF, 0xFE, 0xFD, 0x0A]).unwrap();

    let pattern = format!("{}/corrupt.lock", tmp.0.to_string_lossy());
    let cfg = FileInputConfig {
        path: vec![pattern],
        mode: "read".to_string(),
        sincedb_path: None,
        file_completed_action: Some("log".to_string()),
        file_completed_log_path: None,
    };
    let mut consumer = FileConsumer::new(cfg, "node1".to_string());

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("node1".to_string()));
    let engine = VortexEngine::new_with_stats(state, stats, "node1".to_string());

    // Should return Ok without hanging indefinitely
    let res = consumer.poll_and_process(&engine, "dummy");
    assert!(res.is_ok());
}
