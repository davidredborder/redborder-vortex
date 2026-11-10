use crate::engine::VortexEngine;
use crate::event::Event;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct FileInputConfig {
    pub path: Vec<String>,
    pub mode: String,
    pub sincedb_path: Option<PathBuf>,
    pub file_completed_action: Option<String>,
    pub file_completed_log_path: Option<PathBuf>,
}

pub struct FileConsumer {
    config: FileInputConfig,
    node_name: String,
    processed_files: HashSet<PathBuf>,
}

impl FileConsumer {
    pub fn new(config: FileInputConfig, node_name: String) -> Self {
        let mut processed_files = HashSet::new();
        if let Some(ref sdb) = config.sincedb_path {
            if sdb.exists() {
                if let Ok(file) = fs::File::open(sdb) {
                    let reader = BufReader::new(file);
                    for line in reader.lines().map_while(Result::ok) {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            processed_files.insert(PathBuf::from(trimmed));
                        }
                    }
                }
            }
        }
        Self {
            config,
            node_name,
            processed_files,
        }
    }

    pub fn config(&self) -> &FileInputConfig {
        &self.config
    }

    /// Finds files matching the configured paths (including wildcard patterns).
    pub fn find_matching_files(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for pattern_str in &self.config.path {
            let p = Path::new(pattern_str);
            if pattern_str.contains('*') || pattern_str.contains('?') {
                found.extend(expand_glob(p));
            } else if p.is_file() {
                found.push(p.to_path_buf());
            }
        }
        found.sort();
        found.dedup();
        found
    }

    /// Polls for matching files, reads their lines as events, processes through engine, and updates completion/sincedb.
    pub fn poll_and_process(
        &mut self,
        engine: &VortexEngine,
        pipeline_id: &str,
    ) -> anyhow::Result<(usize, Vec<(String, Event)>)> {
        let matching = self.find_matching_files();
        let mut total_events = 0;
        let mut all_routed = Vec::new();

        for file_path in matching {
            if self.processed_files.contains(&file_path) {
                continue;
            }

            let file = match fs::File::open(&file_path) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let reader = BufReader::new(file);
            for line_res in reader.lines() {
                let line = match line_res {
                    Ok(l) => l,
                    Err(_) => break, // Stop reading on I/O or decode error to prevent infinite spinning
                };
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                let mut ev = Event::new();
                ev.set("message", trimmed.to_string());
                ev.set("path", file_path.to_string_lossy().to_string());
                ev.set("host", self.node_name.clone());

                let routed = engine.process_pipeline_event(pipeline_id, ev)?;
                all_routed.extend(routed);
                total_events += 1;
            }

            // Post-completion actions
            if let Some(ref log_path) = self.config.file_completed_log_path {
                if let Some(parent) = log_path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Ok(mut log_file) = OpenOptions::new().create(true).append(true).open(log_path) {
                    let now = chrono::Utc::now().to_rfc3339();
                    let _ = writeln!(log_file, "{} completed at {}", file_path.display(), now);
                }
            }

            // In Logstash, default completed action is "delete" in read mode, and "log" (never delete) in tail mode.
            let default_action = if self.config.mode == "read" { "delete" } else { "log" };
            let action = self.config.file_completed_action.as_deref().unwrap_or(default_action);
            if action == "delete" {
                let _ = fs::remove_file(&file_path);
            }

            self.processed_files.insert(file_path.clone());
            if let Some(ref sdb) = self.config.sincedb_path {
                if let Some(parent) = sdb.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Ok(mut sdb_file) = OpenOptions::new().create(true).append(true).open(sdb) {
                    let _ = writeln!(sdb_file, "{}", file_path.display());
                }
            }
        }

        Ok((total_events, all_routed))
    }
}

fn expand_glob(pattern: &Path) -> Vec<PathBuf> {
    let components: Vec<_> = pattern.components().collect();
    if components.is_empty() {
        return Vec::new();
    }

    let mut current_paths = Vec::new();
    let mut start_idx = 0;

    match components[0] {
        std::path::Component::RootDir => {
            current_paths.push(PathBuf::from("/"));
            start_idx = 1;
        }
        std::path::Component::Prefix(prefix) => {
            current_paths.push(PathBuf::from(prefix.as_os_str()));
            start_idx = 1;
        }
        std::path::Component::CurDir => {
            current_paths.push(PathBuf::from("."));
            start_idx = 1;
        }
        _ => {
            current_paths.push(PathBuf::from("."));
        }
    }

    for comp in &components[start_idx..] {
        let comp_str = match comp {
            std::path::Component::Normal(s) => s.to_string_lossy(),
            std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                let mut next_paths = Vec::new();
                for p in current_paths {
                    if let Some(parent) = p.parent() {
                        next_paths.push(parent.to_path_buf());
                    }
                }
                current_paths = next_paths;
                continue;
            }
            _ => continue,
        };

        let mut next_paths = Vec::new();
        if comp_str.contains('*') || comp_str.contains('?') {
            for dir in current_paths {
                if dir.is_dir() {
                    if let Ok(entries) = fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            if let Some(fname) = entry.file_name().to_str() {
                                if wildcard_match(&comp_str, fname) {
                                    next_paths.push(entry.path());
                                }
                            }
                        }
                    }
                }
            }
        } else {
            for dir in current_paths {
                let child = if dir == Path::new(".") {
                    PathBuf::from(comp_str.as_ref())
                } else {
                    dir.join(comp_str.as_ref())
                };
                if child.exists() {
                    next_paths.push(child);
                }
            }
        }
        current_paths = next_paths;
    }

    current_paths.into_iter().filter(|p| p.is_file()).collect()
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let mut regex_str = String::from("^");
    for c in pattern.chars() {
        match c {
            '*' => regex_str.push_str(".*"),
            '?' => regex_str.push('.'),
            '.' | '(' | ')' | '[' | ']' | '{' | '}' | '+' | '^' | '$' | '|' | '\\' => {
                regex_str.push('\\');
                regex_str.push(c);
            }
            other => regex_str.push(other),
        }
    }
    regex_str.push('$');
    regex::Regex::new(&regex_str)
        .map(|r| r.is_match(text))
        .unwrap_or(false)
}
