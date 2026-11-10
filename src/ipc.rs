use crate::state::StateStore;
use crate::stats::StatsRegistry;
use anyhow::Context;
use serde_json::json;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub fn default_socket_path() -> String {
    let standard = "/run/redborder-vortex/redborder-vortex.sock";
    if Path::new(standard).exists() || Path::new("/run/redborder-vortex").is_dir() {
        return standard.to_string();
    }
    "/tmp/redborder-vortex.sock".to_string()
}

fn is_tcp_address(socket_path: &str) -> Option<&str> {
    if let Some(stripped) = socket_path.strip_prefix("tcp://") {
        return Some(stripped);
    }
    if !socket_path.starts_with('/') && !socket_path.starts_with('.') && socket_path.contains(':') {
        return Some(socket_path);
    }
    None
}

pub type ReloadResponse = Result<String, String>;

pub struct ReloadRequest {
    pub responder: std::sync::mpsc::SyncSender<ReloadResponse>,
}

fn handle_command(
    cmd: &str,
    stats: &StatsRegistry,
    state: &StateStore,
    reload_tx: Option<&tokio::sync::mpsc::UnboundedSender<ReloadRequest>>,
) -> String {
    let trimmed = cmd.trim();
    match trimmed {
        "" | "stats" | "status" => {
            let snap = stats.get_stats(state);
            let mut json = serde_json::to_string_pretty(&snap)
                .unwrap_or_else(|_| "{\"error\": \"serialization failed\"}".to_string());
            json.push('\n');
            json
        }
        "reset" => {
            stats.reset_stats();
            "{\"status\": \"ok\", \"message\": \"stats reset successfully\"}\n".to_string()
        }
        "reload" => {
            if let Some(tx) = reload_tx {
                let (resp_tx, resp_rx) = std::sync::mpsc::sync_channel(1);
                if tx.send(ReloadRequest { responder: resp_tx }).is_err() {
                    let mut s = serde_json::to_string(&json!({
                        "status": "error",
                        "message": "failed to deliver reload request to engine"
                    })).unwrap_or_default();
                    s.push('\n');
                    return s;
                }
                match resp_rx.recv_timeout(Duration::from_secs(30)) {
                    Ok(Ok(msg)) => {
                        let mut s = serde_json::to_string(&json!({
                            "status": "ok",
                            "message": msg
                        })).unwrap_or_default();
                        s.push('\n');
                        s
                    }
                    Ok(Err(err)) => {
                        let mut s = serde_json::to_string(&json!({
                            "status": "error",
                            "message": err
                        })).unwrap_or_default();
                        s.push('\n');
                        s
                    }
                    Err(e) => {
                        let mut s = serde_json::to_string(&json!({
                            "status": "error",
                            "message": format!("reload timed out or failed: {}", e)
                        })).unwrap_or_default();
                        s.push('\n');
                        s
                    }
                }
            } else {
                let mut s = serde_json::to_string(&json!({
                    "status": "error",
                    "message": "reload not supported on this instance"
                })).unwrap_or_default();
                s.push('\n');
                s
            }
        }
        _ => "{\"error\": \"unknown command\"}\n".to_string(),
    }
}

pub struct IpcServerHandle {
    stop_flag: Arc<AtomicBool>,
    socket_path: String,
    unix_path: Option<PathBuf>,
    join_handle: Option<JoinHandle<()>>,
}

impl IpcServerHandle {
    pub fn shutdown(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(tcp_addr) = is_tcp_address(&self.socket_path) {
            if let Ok(mut s) = TcpStream::connect(tcp_addr) {
                let _ = s.write_all(b"\n");
                let _ = s.flush();
            }
        } else {
            if let Ok(mut s) = UnixStream::connect(&self.socket_path) {
                let _ = s.write_all(b"\n");
                let _ = s.flush();
            }
        }
    }
}

impl Drop for IpcServerHandle {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
        if let Some(p) = &self.unix_path {
            let _ = fs::remove_file(p);
        }
    }
}

pub fn start_ipc_server(
    socket_path: &str,
    stats: Arc<StatsRegistry>,
    state: Arc<StateStore>,
) -> anyhow::Result<IpcServerHandle> {
    start_ipc_server_with_reload(socket_path, stats, state, None)
}

pub fn start_ipc_server_with_reload(
    socket_path: &str,
    stats: Arc<StatsRegistry>,
    state: Arc<StateStore>,
    reload_tx: Option<tokio::sync::mpsc::UnboundedSender<ReloadRequest>>,
) -> anyhow::Result<IpcServerHandle> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let path_str = socket_path.to_string();

    if let Some(tcp_addr) = is_tcp_address(socket_path) {
        let listener = TcpListener::bind(tcp_addr)
            .with_context(|| format!("Failed to bind TCP IPC socket at {}", tcp_addr))?;
        let reload_opt = reload_tx.clone();
        let jh = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(mut stream) = stream_res {
                    let stats = stats.clone();
                    let state = state.clone();
                    let reload_opt = reload_opt.clone();
                    let stop = stop_clone.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let line = {
                            let mut reader = BufReader::new(&stream);
                            let mut l = String::new();
                            let _ = reader.read_line(&mut l);
                            l
                        };
                        if !stop.load(Ordering::SeqCst) {
                            let resp = handle_command(&line, &stats, &state, reload_opt.as_ref());
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.flush();
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                    });
                }
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        Ok(IpcServerHandle {
            stop_flag,
            socket_path: path_str,
            unix_path: None,
            join_handle: Some(jh),
        })
    } else {
        let unix_path = PathBuf::from(socket_path);
        if let Some(parent) = unix_path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = fs::create_dir_all(parent);
            }
        }
        if unix_path.exists() {
            if UnixStream::connect(&unix_path).is_ok() {
                anyhow::bail!("Another redborder-vortex instance is already listening on {:?}", unix_path);
            }
            let _ = fs::remove_file(&unix_path);
        }
        let listener = UnixListener::bind(&unix_path)
            .with_context(|| format!("Failed to bind Unix IPC socket at {:?}", unix_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&unix_path, fs::Permissions::from_mode(0o666));
        }

        let reload_opt = reload_tx;
        let jh = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(mut stream) = stream_res {
                    let stats = stats.clone();
                    let state = state.clone();
                    let reload_opt = reload_opt.clone();
                    let stop = stop_clone.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let line = {
                            let mut reader = BufReader::new(&stream);
                            let mut l = String::new();
                            let _ = reader.read_line(&mut l);
                            l
                        };
                        if !stop.load(Ordering::SeqCst) {
                            let resp = handle_command(&line, &stats, &state, reload_opt.as_ref());
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.flush();
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                    });
                }
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        Ok(IpcServerHandle {
            stop_flag,
            socket_path: path_str,
            unix_path: Some(unix_path),
            join_handle: Some(jh),
        })
    }
}

pub fn query_ipc(socket_path: &str, cmd: &str) -> anyhow::Result<String> {
    let payload = format!("{}\n", cmd.trim());
    let timeout = if cmd.trim() == "reload" {
        Duration::from_secs(35)
    } else {
        Duration::from_secs(5)
    };
    if let Some(tcp_addr) = is_tcp_address(socket_path) {
        let mut stream = TcpStream::connect(tcp_addr)
            .with_context(|| format!("Failed to connect to TCP IPC socket {}", tcp_addr))?;
        let _ = stream.set_read_timeout(Some(timeout));
        stream.write_all(payload.as_bytes())?;
        stream.flush()?;
        let _ = stream.shutdown(Shutdown::Write);
        let mut out = String::new();
        stream.read_to_string(&mut out)?;
        Ok(out)
    } else {
        let mut stream = UnixStream::connect(socket_path)
            .with_context(|| format!("Failed to connect to Unix IPC socket {}", socket_path))?;
        let _ = stream.set_read_timeout(Some(timeout));
        stream.write_all(payload.as_bytes())?;
        stream.flush()?;
        let _ = stream.shutdown(Shutdown::Write);
        let mut out = String::new();
        stream.read_to_string(&mut out)?;
        Ok(out)
    }
}
