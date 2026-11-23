use redborder_vortex::engine::VortexEngine;
use redborder_vortex::ipc::{query_ipc, start_ipc_server_with_reload, ReloadRequest};
use redborder_vortex::state::StateStore;
use redborder_vortex::stats::StatsRegistry;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_engine_reload_preserves_state_and_stats() {
    let tmp = std::env::temp_dir().join(format!("vortex_reload_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp).unwrap();
    let root = &tmp;

    // 1. Initial configuration with 1 pipeline
    let p1_dir = root.join("pipelines").join("p1");
    fs::create_dir_all(&p1_dir).unwrap();
    fs::write(
        p1_dir.join("00_pipeline.conf"),
        r#"
        input { pipeline { address => "in-1" } }
        output { pipeline { send_to => ["out-1"] } }
        "#,
    )
    .unwrap();

    let pipelines_yml = root.join("pipelines.yml");
    fs::write(
        &pipelines_yml,
        format!(
            "- pipeline.id: p1\n  path.config: \"{}\"\n  pipeline.workers: 1\n",
            p1_dir.to_str().unwrap()
        ),
    )
    .unwrap();

    let state = Arc::new(StateStore::new_standalone());
    state.put_record("custom_store", "k1", serde_json::Map::new()).unwrap();

    let stats = Arc::new(StatsRegistry::new("test-node"));
    stats.register_pipeline("p1", 1, vec!["in-1".to_string()], "grp1".to_string());
    stats.record_pipeline_run("p1", 1, 1, 0, 0, 50);

    // Initial engine
    let engine1 = VortexEngine::from_settings_dir_with_stats(root, state.clone(), stats.clone(), "test-node").unwrap();
    assert_eq!(engine1.pipeline_ids(), vec!["p1"]);
    assert_eq!(stats.get_stats(&state).events_received, 1);

    // 2. Add second pipeline p2 to config
    let p2_dir = root.join("pipelines").join("p2");
    fs::create_dir_all(&p2_dir).unwrap();
    fs::write(
        p2_dir.join("00_pipeline.conf"),
        r#"
        input { pipeline { address => "in-2" } }
        output { pipeline { send_to => ["out-2"] } }
        "#,
    )
    .unwrap();

    fs::write(
        &pipelines_yml,
        format!(
            "- pipeline.id: p1\n  path.config: \"{}\"\n  pipeline.workers: 1\n- pipeline.id: p2\n  path.config: \"{}\"\n  pipeline.workers: 2\n",
            p1_dir.to_str().unwrap(),
            p2_dir.to_str().unwrap()
        ),
    )
    .unwrap();

    // Reload new engine using same state and stats
    let engine2 = VortexEngine::from_settings_dir_with_stats(root, state.clone(), stats.clone(), "test-node").unwrap();
    let mut ids = engine2.pipeline_ids();
    ids.sort();
    assert_eq!(ids, vec!["p1", "p2"]);

    // StateStore record must still be intact
    assert!(state.get_record("custom_store", "k1").is_some());
    // Stats cumulative count must still be preserved
    assert_eq!(stats.get_stats(&state).events_received, 1);

    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn test_engine_reload_atomic_failure_isolation() {
    let tmp = std::env::temp_dir().join(format!("vortex_reload_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp).unwrap();
    let root = &tmp;

    let p1_dir = root.join("pipelines").join("p1");
    fs::create_dir_all(&p1_dir).unwrap();
    fs::write(
        p1_dir.join("00_pipeline.conf"),
        r#"
        input { pipeline { address => "in-1" } }
        output { pipeline { send_to => ["out-1"] } }
        "#,
    )
    .unwrap();

    let pipelines_yml = root.join("pipelines.yml");
    fs::write(
        &pipelines_yml,
        format!(
            "- pipeline.id: p1\n  path.config: \"{}\"\n",
            p1_dir.to_str().unwrap()
        ),
    )
    .unwrap();

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("test-node"));

    let engine1 = VortexEngine::from_settings_dir_with_stats(root, state.clone(), stats.clone(), "test-node").unwrap();
    assert_eq!(engine1.pipeline_ids(), vec!["p1"]);

    // Corrupt configuration with syntax error
    fs::write(
        p1_dir.join("00_pipeline.conf"),
        r#"
        input { broken_syntax {{{{{
        "#,
    )
    .unwrap();

    // Reload attempt must fail
    let res = VortexEngine::from_settings_dir_with_stats(root, state.clone(), stats.clone(), "test-node");
    assert!(res.is_err(), "Corrupted config must return Err");

    // Original engine remains untouched
    assert_eq!(engine1.pipeline_ids(), vec!["p1"]);

    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ipc_reload_command_handling() {
    let tmp = std::env::temp_dir().join(format!("vortex_reload_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp).unwrap();
    let socket_path = tmp.join("vortex_reload.sock").to_str().unwrap().to_string();

    let state = Arc::new(StateStore::new_standalone());
    let stats = Arc::new(StatsRegistry::new("test-node"));

    let (reload_tx, mut reload_rx) = mpsc::unbounded_channel::<ReloadRequest>();

    let _ipc = start_ipc_server_with_reload(
        &socket_path,
        stats.clone(),
        state.clone(),
        Some(reload_tx),
    )
    .unwrap();

    // Spawn mock daemon loop to handle reload request
    tokio::spawn(async move {
        if let Some(req) = reload_rx.recv().await {
            let _ = req.responder.send(Ok("reloaded 3 pipelines".to_string()));
        }
    });

    // Small delay to ensure IPC server is bound
    tokio::time::sleep(Duration::from_millis(100)).await;

    let sp_clone = socket_path.clone();
    let response = tokio::task::spawn_blocking(move || query_ipc(&sp_clone, "reload"))
        .await
        .unwrap()
        .unwrap();
    let val: serde_json::Value = serde_json::from_str(&response).expect("Response must be valid JSON");
    assert_eq!(val["status"], "ok", "Response: {}", response);
    assert_eq!(val["message"], "reloaded 3 pipelines", "Response: {}", response);

    drop(_ipc);
    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn test_sighup_signal_live_reload() {
    let tmp = std::env::temp_dir().join(format!("vortex_sighup_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&tmp).unwrap();
    let socket_path = tmp.join("vortex_sighup.sock").to_str().unwrap().to_string();

    // 1. Initial config with 1 pipeline 'p1'
    let p1_dir = tmp.join("pipelines").join("p1");
    fs::create_dir_all(&p1_dir).unwrap();
    fs::write(
        p1_dir.join("00_pipeline.conf"),
        r#"
        input { pipeline { address => "in-1" } }
        output { pipeline { send_to => ["out-1"] } }
        "#,
    )
    .unwrap();

    let pipelines_yml = tmp.join("pipelines.yml");
    fs::write(
        &pipelines_yml,
        format!(
            "- pipeline.id: p1\n  path.config: \"{}\"\n",
            p1_dir.to_str().unwrap()
        ),
    )
    .unwrap();

    // Build path to target debug binary
    let bin_path = env!("CARGO_BIN_EXE_redborder-vortex");

    // Spawn daemon process
    let mut child = std::process::Command::new(bin_path)
        .arg("--path.settings")
        .arg(tmp.to_str().unwrap())
        .arg("--socket")
        .arg(&socket_path)
        .spawn()
        .expect("Failed to spawn redborder-vortex binary");

    let pid = child.id();

    // Wait up to 5 seconds for IPC socket to become ready
    let mut ready = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if query_ipc(&socket_path, "status").is_ok() {
            ready = true;
            break;
        }
    }
    assert!(ready, "Daemon IPC socket did not become ready");

    // Verify initial status has 1 pipeline
    let status_initial = query_ipc(&socket_path, "status").unwrap();
    assert!(status_initial.contains("\"id\": \"p1\""), "Initial: {}", status_initial);
    assert!(!status_initial.contains("\"id\": \"p2\""));

    // 2. Add second pipeline 'p2'
    let p2_dir = tmp.join("pipelines").join("p2");
    fs::create_dir_all(&p2_dir).unwrap();
    fs::write(
        p2_dir.join("00_pipeline.conf"),
        r#"
        input { pipeline { address => "in-2" } }
        output { pipeline { send_to => ["out-2"] } }
        "#,
    )
    .unwrap();

    fs::write(
        &pipelines_yml,
        format!(
            "- pipeline.id: p1\n  path.config: \"{}\"\n- pipeline.id: p2\n  path.config: \"{}\"\n",
            p1_dir.to_str().unwrap(),
            p2_dir.to_str().unwrap()
        ),
    )
    .unwrap();

    // Send SIGHUP to the running daemon
    let _ = std::process::Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status();

    // Wait up to 3 seconds for reload to complete
    let mut reloaded = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(status) = query_ipc(&socket_path, "status") {
            if status.contains("\"id\": \"p2\"") {
                reloaded = true;
                break;
            }
        }
    }
    assert!(reloaded, "Daemon did not reload pipeline p2 on SIGHUP");

    // Clean shutdown via SIGTERM
    let _ = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
    let _ = child.wait();

    let _ = fs::remove_dir_all(&tmp);
}
