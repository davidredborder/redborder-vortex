use redborder_vortex::config::{parse_logstash_conf, DaemonConfig, PipelineEntry};
use redborder_vortex::engine::VortexEngine;
use redborder_vortex::event::Event;
use redborder_vortex::ipc::{
    default_socket_path, query_ipc, start_ipc_server_with_reload, ReloadRequest, ReloadResponse,
};
use redborder_vortex::state::{
    spawn_postgres_sync_task, spawn_redis_pubsub_task, PostgresSyncConfig, StateStore,
    SCRAMBLES_STORE, SENSOR_PSQL_STORE, WLC_PSQL_STORE,
};
use redborder_vortex::stats::StatsRegistry;
use serde_json::{json, Map};
use std::env;
use std::path::Path;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");

async fn reload_pipeline_configuration(
    settings_dir: &str,
    state: &Arc<StateStore>,
    stats: &Arc<StatsRegistry>,
    node_name: &str,
    engine_arc: &mut Arc<VortexEngine>,
    kafka_shutdown_tx: &mut tokio::sync::watch::Sender<bool>,
    pipeline_shutdown_tx: &mut tokio::sync::watch::Sender<bool>,
    file_shutdown_tx: &mut tokio::sync::watch::Sender<bool>,
    kafka_handles: &mut Vec<tokio::task::JoinHandle<()>>,
    pipeline_handles: &mut Vec<tokio::task::JoinHandle<()>>,
    file_handles: &mut Vec<tokio::task::JoinHandle<()>>,
    rbwindow_task: &mut tokio::task::JoinHandle<()>,
    ipc_responder: Option<std::sync::mpsc::SyncSender<ReloadResponse>>,
) {
    let path = Path::new(settings_dir);
    let candidate_res = if path.is_file() {
        VortexEngine::from_pipelines_yml_with_stats(
            path,
            path.parent(),
            state.clone(),
            stats.clone(),
            node_name,
        )
    } else {
        VortexEngine::from_settings_dir_with_stats(path, state.clone(), stats.clone(), node_name)
    };

    match candidate_res {
        Ok(mut new_engine) => {
            println!(
                "Candidate configuration compiled successfully with {} pipelines. Transitioning workers...",
                new_engine.pipeline_ids().len()
            );

            // Phase 1a: Stop upstream Kafka & file ingestion workers first
            let _ = kafka_shutdown_tx.send(true);
            let old_kafka = std::mem::take(kafka_handles);
            for h in old_kafka {
                let _ = h.await;
            }

            let _ = file_shutdown_tx.send(true);
            let old_file = std::mem::take(file_handles);
            for h in old_file {
                let _ = h.await;
            }

            // Phase 1b: Signal downstream pipeline workers to drain all queued in-memory events
            let _ = pipeline_shutdown_tx.send(true);
            let old_pipe = std::mem::take(pipeline_handles);
            for h in old_pipe {
                let _ = h.await;
            }

            // Phase 1c: Abort and await previous rbwindow task
            rbwindow_task.abort();
            let _ = (&mut *rbwindow_task).await;

            // Phase 2: Wire up new engine
            new_engine.attach_live_producers();
            new_engine.wire_pipeline_channels();
            let new_arc = Arc::new(new_engine);
            *engine_arc = new_arc.clone();

            // Phase 3: Create fresh shutdown channels & spawn new workers
            let (new_k_tx, new_k_rx) = tokio::sync::watch::channel(false);
            let (new_p_tx, new_p_rx) = tokio::sync::watch::channel(false);
            let (new_f_tx, new_f_rx) = tokio::sync::watch::channel(false);
            *kafka_shutdown_tx = new_k_tx;
            *pipeline_shutdown_tx = new_p_tx;
            *file_shutdown_tx = new_f_tx;

            *kafka_handles =
                VortexEngine::spawn_kafka_workers(engine_arc.clone(), new_k_rx);
            *pipeline_handles =
                VortexEngine::spawn_pipeline_workers(engine_arc.clone(), new_p_rx);
            *file_handles =
                VortexEngine::spawn_file_workers(engine_arc.clone(), new_f_rx);

            let rb_engine = engine_arc.clone();
            *rbwindow_task = tokio::spawn(async move {
                loop {
                    let _ = rb_engine.run_rbwindow_tick();
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            });

            let msg = format!(
                "Configuration reload completed successfully ({} pipelines active)",
                engine_arc.pipeline_ids().len()
            );
            println!("{}", msg);
            if let Some(resp) = ipc_responder {
                let _ = resp.send(Ok(msg));
            }
        }
        Err(e) => {
            let err_msg = format!(
                "Configuration reload rejected: {:#}. Retaining existing running pipelines.",
                e
            );
            eprintln!("{}", err_msg);
            if let Some(resp) = ipc_responder {
                let _ = resp.send(Err(err_msg));
            }
        }
    }
}

fn print_help() {
    println!(
        "redborder-vortex {}
Drop-in Rust + PyO3 replacement for Logstash in redBorder NG

USAGE:
    redborder-vortex [OPTIONS]

OPTIONS:
    -c, --config <PATH>            Path to settings directory or config file
        --path.settings <DIR>      Path to Logstash settings directory (default: /etc/logstash)
        --config.test_and_exit     Validate pipelines.yml and all .conf files and exit
    -t, --status                   Query running daemon status/stats over IPC socket
    -r, --reset                    Reset daemon statistics counters over IPC socket
    -R, --reload                   Trigger configuration reload on running daemon over IPC socket
        --socket <PATH>            Override IPC socket path (default: /run/redborder-vortex/redborder-vortex.sock)
        --benchmark                Run 50,000-event throughput benchmark across netflow, sflow, and vault
    -v, --version                  Print version information
    -h, --help                     Print help information",
        VERSION
    );
}

fn detect_node_name() -> String {
    env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "redborder-vortex-node".to_string())
}

fn run_benchmark() -> anyhow::Result<()> {
    let state = Arc::new(StateStore::new_standalone());

    let mut sensor_rec = Map::new();
    sensor_rec.insert("sensor_name".to_string(), json!("sensor-bench-01"));
    sensor_rec.insert("namespace_uuid".to_string(), json!("ns-bench"));
    sensor_rec.insert("service_provider_uuid".to_string(), json!("sp-bench"));
    state.put_record(SENSOR_PSQL_STORE, "uuid-bench-01", sensor_rec)?;

    let mut wlc_rec = Map::new();
    wlc_rec.insert("building".to_string(), json!("HQ-Building"));
    wlc_rec.insert("campus".to_string(), json!("Main-Campus"));
    wlc_rec.insert("namespace_uuid".to_string(), json!("ns-bench"));
    state.put_record(WLC_PSQL_STORE, "aa:bb:cc:00:11:22", wlc_rec)?;

    let mut scramble_rec = Map::new();
    scramble_rec.insert("mac_hashing_salt".to_string(), json!("bench_salt"));
    state.put_record(SCRAMBLES_STORE, "sp-bench", scramble_rec)?;

    let mut engine = VortexEngine::new(state, detect_node_name());

    let netflow_conf = parse_logstash_conf(
        r#"
        input { kafka { topics => ["rb_flow"] } }
        filter {
          macscrambling {}
          cidr {
            address => [ "%{src}" ]
            network => [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ]
            add_tag => [ "is_src_internal" ]
          }
          geoip {
            source => "dst"
            target => "geoip_dst"
            default_database_type => "City"
          }
          macvendorsenrich {}
          netflowenrich { counter_store_counter => true }
        }
        output { kafka { topic_id => "rb_flow_post" } }
        "#,
    )?;
    engine.register_pipeline(
        PipelineEntry {
            id: "netflow".to_string(),
            path_config: "benchmark/netflow".to_string(),
            workers: 1,
        },
        &netflow_conf,
    )?;

    let sflow_conf = parse_logstash_conf(
        r#"
        input { kafka { topics => ["sflow_raw"] } }
        filter {
          cidr {
            address => [ "%{ip_src}" ]
            network => [ "10.0.0.0/8", "192.168.0.0/16" ]
            add_tag => [ "is_src_internal" ]
          }
          if "is_src_internal" in [tags] {
            mutate { add_field => { "direction" => "upstream" } }
          }
          mutate {
            rename => { "ip_src" => "src" "ip_dst" => "dst" }
            convert => { "bytes" => "integer" "pkts" => "integer" }
          }
        }
        output { kafka { topic_id => "rb_flow" } }
        "#,
    )?;
    engine.register_pipeline(
        PipelineEntry {
            id: "sflow".to_string(),
            path_config: "benchmark/sflow".to_string(),
            workers: 1,
        },
        &sflow_conf,
    )?;

    let vault_conf = parse_logstash_conf(
        r#"
        input { kafka { topics => ["rb_vault"] } }
        filter {
          fingerprint {
            source => "message"
            target => "fingerprint"
            key => "bench-key"
          }
          if "sshd" in [app_name] {
            grok { match => { "message" => "%{SSHD_MESSAGE}" } }
          }
          incident_enrichment {
            incident_fields => ["sshd_client_ip", "sshd_user"]
            source => "vault"
          }
        }
        output { kafka { topic_id => "rb_vault_post" } }
        "#,
    )?;
    engine.register_pipeline(
        PipelineEntry {
            id: "vault".to_string(),
            path_config: "benchmark/vault".to_string(),
            workers: 1,
        },
        &vault_conf,
    )?;

    let total_events: usize = 50_000;
    let start = Instant::now();

    for i in 0..total_events {
        match i % 3 {
            0 => {
                let mut ev = Event::new();
                ev.set("src", "10.1.2.3");
                ev.set("dst", "8.8.8.8");
                ev.set("client_mac", "00:00:0c:aa:bb:cc");
                ev.set("sensor_uuid", "uuid-bench-01");
                ev.set("namespace_uuid", "ns-bench");
                ev.set("wireless_station", "aa:bb:cc:00:11:22");
                ev.set("first_switched", 1700000010i64);
                ev.set("timestamp", 1700000040i64);
                ev.set("bytes", 1500i64);
                ev.set("pkts", 12i64);
                engine.process_pipeline_event("netflow", ev)?;
            }
            1 => {
                let mut ev = Event::new();
                ev.set("ip_src", "10.20.30.40");
                ev.set("ip_dst", "1.1.1.1");
                ev.set("bytes", "4096");
                ev.set("pkts", "32");
                engine.process_pipeline_event("sflow", ev)?;
            }
            _ => {
                let mut ev = Event::new();
                ev.set("app_name", "sshd");
                ev.set(
                    "message",
                    "Accepted publickey for admin from 10.10.10.5 port 42222 ssh2",
                );
                engine.process_pipeline_event("vault", ev)?;
            }
        }
    }

    let elapsed = start.elapsed();
    let secs = elapsed.as_secs_f64().max(1e-9);
    let eps = (total_events as f64) / secs;

    println!(
        "Benchmark completed: {} events processed in {:.3}s ({:.0} events/sec)",
        total_events, secs, eps
    );
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut settings_dir = "/etc/logstash".to_string();
    let mut custom_settings = false;
    let mut socket_path = default_socket_path();
    let mut custom_socket = false;
    let mut mode_status = false;
    let mut mode_reset = false;
    let mut mode_reload = false;
    let mut mode_test_and_exit = false;
    let mut mode_benchmark = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                process::exit(0);
            }
            "-v" | "--version" => {
                println!("redborder-vortex {}", VERSION);
                process::exit(0);
            }
            "-t" | "--status" => {
                mode_status = true;
            }
            "-r" | "--reset" => {
                mode_reset = true;
            }
            "-R" | "--reload" => {
                mode_reload = true;
            }
            "--config.test_and_exit" => {
                mode_test_and_exit = true;
            }
            "--benchmark" => {
                mode_benchmark = true;
            }
            "-c" | "--config" | "--path.settings" => {
                if i + 1 < args.len() {
                    settings_dir = args[i + 1].clone();
                    custom_settings = true;
                    i += 1;
                }
            }
            arg if arg.starts_with("--path.settings=") => {
                settings_dir = arg.trim_start_matches("--path.settings=").to_string();
                custom_settings = true;
            }
            "--socket" => {
                if i + 1 < args.len() {
                    socket_path = args[i + 1].clone();
                    custom_socket = true;
                    i += 1;
                }
            }
            arg if arg.starts_with("--socket=") => {
                socket_path = arg.trim_start_matches("--socket=").to_string();
                custom_socket = true;
            }
            _ => {}
        }
        i += 1;
    }

    // Attempt to load DaemonConfig early (CLI queries need socket path)
    // Merges base cluster settings (/etc/redborder-vortex/) with settings_dir overrides
    let daemon_config = DaemonConfig::resolve(
        Path::new(&settings_dir),
        Path::new("/etc/redborder-vortex"),
    );

    let node_name = detect_node_name();

    // If daemon_config overrides paths:
    if let Some(ref dc) = daemon_config {
        if !custom_socket {
            if let Some(ref sp) = dc.ipc_socket {
                socket_path = sp.clone();
            }
        }
        if let Some(ref ps) = dc.path_settings {
            if !custom_settings && !Path::new(&settings_dir).is_file() {
                settings_dir = ps.clone();
            }
        }
        if let Some(ref topics) = dc.kafka_auto_key_mac_topics {
            std::env::set_var("VORTEX_KAFKA_AUTO_KEY_MAC_TOPICS", topics.join(","));
        }
        if let Some(tri) = dc.nmsp_triangulation {
            std::env::set_var("VORTEX_NMSP_TRIANGULATION", if tri { "true" } else { "false" });
        }
        if let Some(min_aps) = dc.nmsp_triangulation_min_aps {
            std::env::set_var("VORTEX_NMSP_TRIANGULATION_MIN_APS", min_aps.to_string());
        }
    }

    if mode_status {
        match query_ipc(&socket_path, "stats") {
            Ok(resp) => {
                print!("{}", resp);
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error querying IPC socket {}: {}", socket_path, e);
                process::exit(1);
            }
        }
    }

    if mode_reset {
        match query_ipc(&socket_path, "reset") {
            Ok(resp) => {
                print!("{}", resp);
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error resetting stats via IPC socket {}: {}", socket_path, e);
                process::exit(1);
            }
        }
    }

    if mode_reload {
        match query_ipc(&socket_path, "reload") {
            Ok(resp) => {
                print!("{}", resp);
                let is_ok = serde_json::from_str::<serde_json::Value>(&resp)
                    .map(|v| v["status"] == "ok")
                    .unwrap_or(false);
                if is_ok {
                    process::exit(0);
                } else {
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error triggering reload via IPC socket {}: {}", socket_path, e);
                process::exit(1);
            }
        }
    }

    if mode_benchmark {
        if let Err(e) = run_benchmark() {
            eprintln!("Benchmark failed: {}", e);
            process::exit(1);
        }
        process::exit(0);
    }

    // Configure StateStore (Redis L2 if configured, else standalone)
    let (state, redis_client_opt) = if let Some(ref dc) = daemon_config {
        if let Some(redis_url) = dc.full_redis_url() {
            match StateStore::new_with_redis(&redis_url) {
                Ok(store) => {
                    println!("Connected to Redis cluster state backend");
                    if let Err(e) = store.sync_from_backend() {
                        eprintln!("Warning: Initial state sync from Redis failed: {}", e);
                    }
                    let client = redis::Client::open(redis_url.as_str()).ok();
                    (Arc::new(store), client)
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to connect to Redis at {}: {} (falling back to in-memory state)",
                        redis_url, e
                    );
                    (Arc::new(StateStore::new_standalone()), None)
                }
            }
        } else {
            (Arc::new(StateStore::new_standalone()), None)
        }
    } else {
        (Arc::new(StateStore::new_standalone()), None)
    };

    let path = Path::new(&settings_dir);
    let engine_res = if path.is_file() {
        VortexEngine::from_pipelines_yml(path, path.parent(), state.clone(), node_name.clone())
    } else {
        VortexEngine::from_settings_dir(path, state.clone(), node_name.clone())
    };

    match engine_res {
        Ok(mut engine) => {
            if mode_test_and_exit {
                println!(
                    "Configuration OK ({} pipelines compiled)",
                    engine.pipeline_ids().len()
                );
                process::exit(0);
            }
            engine.attach_live_producers();
            engine.wire_pipeline_channels();
            let mut engine_arc = Arc::new(engine);
            let stats = engine_arc.stats.clone();

            let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<ReloadRequest>();
            let _ipc_handle = match start_ipc_server_with_reload(
                &socket_path,
                stats.clone(),
                state.clone(),
                Some(reload_tx),
            ) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Failed to start IPC server at {}: {}", socket_path, e);
                    process::exit(1);
                }
            };

            // Daemon-level shutdown channel (for long-lived tasks: Postgres, Redis)
            let (daemon_shutdown_tx, daemon_shutdown_rx) = tokio::sync::watch::channel(false);

            // Staged worker shutdown channels (cycled on reload)
            let (mut kafka_shutdown_tx, kafka_shutdown_rx) = tokio::sync::watch::channel(false);
            let (mut pipeline_shutdown_tx, pipeline_shutdown_rx) = tokio::sync::watch::channel(false);
            let (mut file_shutdown_tx, file_shutdown_rx) = tokio::sync::watch::channel(false);
            let mut kafka_handles = VortexEngine::spawn_kafka_workers(
                engine_arc.clone(),
                kafka_shutdown_rx,
            );
            let mut pipeline_handles = VortexEngine::spawn_pipeline_workers(
                engine_arc.clone(),
                pipeline_shutdown_rx,
            );
            let mut file_handles = VortexEngine::spawn_file_workers(
                engine_arc.clone(),
                file_shutdown_rx,
            );

            // Launch PostgreSQL sync task if configured
            if let Some(ref dc) = daemon_config {
                if let (Some(ref host), Some(ref user), Some(ref db)) =
                    (&dc.postgres_host, &dc.postgres_user, &dc.postgres_database)
                {
                    let pg_pass = dc
                        .postgres_password
                        .clone()
                        .filter(|p| !p.is_empty())
                        .or_else(|| std::env::var("PGPASSWORD").ok())
                        .unwrap_or_default();
                    let pg_cfg = PostgresSyncConfig::new(
                        host,
                        dc.postgres_port.unwrap_or(5432),
                        db,
                        user,
                        pg_pass,
                    );
                    spawn_postgres_sync_task(pg_cfg, state.clone(), daemon_shutdown_rx.clone());
                }
            }

            // Launch Redis pub/sub real-time cross-node sync task if configured
            if let Some(client) = redis_client_opt {
                spawn_redis_pubsub_task(client, state.clone(), daemon_shutdown_rx.clone());
            }

            let rbwindow_engine = engine_arc.clone();
            let mut rbwindow_task = tokio::spawn(async move {
                loop {
                    let _ = rbwindow_engine.run_rbwindow_tick();
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            });

            // Signal handlers: SIGINT (Ctrl-C), SIGTERM, and SIGHUP
            let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("Failed to register SIGHUP handler");

            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        println!("Received SIGINT, initiating graceful shutdown...");
                        break;
                    }
                    _ = sigterm.recv() => {
                        println!("Received SIGTERM, initiating graceful shutdown...");
                        break;
                    }
                    _ = sighup.recv() => {
                        println!("Received SIGHUP, initiating configuration reload...");
                        reload_pipeline_configuration(
                            &settings_dir,
                            &state,
                            &stats,
                            &node_name,
                            &mut engine_arc,
                            &mut kafka_shutdown_tx,
                            &mut pipeline_shutdown_tx,
                            &mut file_shutdown_tx,
                            &mut kafka_handles,
                            &mut pipeline_handles,
                            &mut file_handles,
                            &mut rbwindow_task,
                            None,
                        ).await;
                    }
                    Some(req) = reload_rx.recv() => {
                        println!("Received IPC reload request, initiating configuration reload...");
                        reload_pipeline_configuration(
                            &settings_dir,
                            &state,
                            &stats,
                            &node_name,
                            &mut engine_arc,
                            &mut kafka_shutdown_tx,
                            &mut pipeline_shutdown_tx,
                            &mut file_shutdown_tx,
                            &mut kafka_handles,
                            &mut pipeline_handles,
                            &mut file_handles,
                            &mut rbwindow_task,
                            Some(req.responder),
                        ).await;
                    }
                }
            }

            let _ = daemon_shutdown_tx.send(true);
            let _ = kafka_shutdown_tx.send(true);
            let _ = pipeline_shutdown_tx.send(true);
            let _ = file_shutdown_tx.send(true);
            rbwindow_task.abort();
            let _ = rbwindow_task.await;
            for handle in kafka_handles {
                let _ = handle.await;
            }
            for handle in pipeline_handles {
                let _ = handle.await;
            }
            for handle in file_handles {
                let _ = handle.await;
            }
            println!("redborder-vortex shutdown completed.");
        }
        Err(e) => {
            eprintln!("Configuration error: {:#}", e);
            process::exit(1);
        }
    }
}
