use crate::config::ast::{eval_expr, Expr, Statement};
use crate::config::{load_pipeline_dir, load_pipelines_yml, PipelineConfig, PipelineEntry};
use crate::event::Event;
use crate::filters::{create_filter, Filter};
use crate::inputs::file::FileConsumer;
use crate::inputs::kafka::{borrowed_message_to_event, KafkaConsumerConfig};
use crate::inputs::rbwindow::RbwindowRunner;
use crate::inputs::InputSpec;
use crate::outputs::kafka::{KafkaProducerConfig, LiveKafkaProducer};
use crate::outputs::OutputSink;
use crate::state::StateStore;
use crate::stats::{StatsRegistry, CLUSTER_NODES_KV_KEY};
use anyhow::{anyhow, Context};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

enum CompiledFilterStmt {
    Plugin(Box<dyn Filter>),
    Conditional {
        branches: Vec<(Expr, Vec<CompiledFilterStmt>)>,
        else_branch: Option<Vec<CompiledFilterStmt>>,
    },
}

enum CompiledOutputStmt {
    Sink(OutputSink),
    Conditional {
        branches: Vec<(Expr, Vec<CompiledOutputStmt>)>,
        else_branch: Option<Vec<CompiledOutputStmt>>,
    },
}

fn compile_filter_stmts(stmts: &[Statement]) -> anyhow::Result<Vec<CompiledFilterStmt>> {
    let mut out = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            Statement::Plugin(block) => {
                out.push(CompiledFilterStmt::Plugin(create_filter(block)?));
            }
            Statement::Conditional(cond) => {
                let mut branches = Vec::with_capacity(cond.branches.len());
                for (expr, body) in &cond.branches {
                    branches.push((expr.clone(), compile_filter_stmts(body)?));
                }
                let else_branch = match &cond.else_branch {
                    Some(body) => Some(compile_filter_stmts(body)?),
                    None => None,
                };
                out.push(CompiledFilterStmt::Conditional {
                    branches,
                    else_branch,
                });
            }
        }
    }
    Ok(out)
}

fn compile_output_stmts(stmts: &[Statement]) -> anyhow::Result<Vec<CompiledOutputStmt>> {
    let mut out = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            Statement::Plugin(block) => {
                out.push(CompiledOutputStmt::Sink(OutputSink::from_plugin_block(
                    block,
                )?));
            }
            Statement::Conditional(cond) => {
                let mut branches = Vec::with_capacity(cond.branches.len());
                for (expr, body) in &cond.branches {
                    branches.push((expr.clone(), compile_output_stmts(body)?));
                }
                let else_branch = match &cond.else_branch {
                    Some(body) => Some(compile_output_stmts(body)?),
                    None => None,
                };
                out.push(CompiledOutputStmt::Conditional {
                    branches,
                    else_branch,
                });
            }
        }
    }
    Ok(out)
}

fn collect_sinks(stmts: &[CompiledOutputStmt], out: &mut Vec<OutputSink>) {
    for stmt in stmts {
        match stmt {
            CompiledOutputStmt::Sink(s) => out.push(s.clone()),
            CompiledOutputStmt::Conditional {
                branches,
                else_branch,
            } => {
                for (_, b) in branches {
                    collect_sinks(b, out);
                }
                if let Some(eb) = else_branch {
                    collect_sinks(eb, out);
                }
            }
        }
    }
}

fn eval_filter_stmts(
    stmts: &[CompiledFilterStmt],
    events: Vec<Event>,
    state: &StateStore,
) -> anyhow::Result<Vec<Event>> {
    let mut current = events;
    for stmt in stmts {
        if current.is_empty() {
            break;
        }
        let mut next_batch = Vec::with_capacity(current.len());
        for ev in current {
            if ev.is_cancelled() {
                continue;
            }
            match stmt {
                CompiledFilterStmt::Plugin(filter) => {
                    let produced = filter.process(ev, state)?;
                    for p in produced {
                        if !p.is_cancelled() {
                            next_batch.push(p);
                        }
                    }
                }
                CompiledFilterStmt::Conditional {
                    branches,
                    else_branch,
                } => {
                    let mut matched = false;
                    for (expr, branch_stmts) in branches {
                        if eval_expr(expr, &ev) {
                            matched = true;
                            let res = eval_filter_stmts(branch_stmts, vec![ev.clone()], state)?;
                            next_batch.extend(res);
                            break;
                        }
                    }
                    if !matched {
                        if let Some(else_stmts) = else_branch {
                            let res = eval_filter_stmts(else_stmts, vec![ev], state)?;
                            next_batch.extend(res);
                        } else {
                            next_batch.push(ev);
                        }
                    }
                }
            }
        }
        current = next_batch;
    }
    Ok(current)
}

fn eval_output_stmts(
    stmts: &[CompiledOutputStmt],
    event: &Event,
    routed: &mut Vec<(String, Event)>,
) -> anyhow::Result<()> {
    for stmt in stmts {
        match stmt {
            CompiledOutputStmt::Sink(sink) => {
                sink.emit(event)?;
                routed.push((sink.target_name().to_string(), event.clone()));
            }
            CompiledOutputStmt::Conditional {
                branches,
                else_branch,
            } => {
                let mut matched = false;
                for (expr, branch_stmts) in branches {
                    if eval_expr(expr, event) {
                        matched = true;
                        eval_output_stmts(branch_stmts, event, routed)?;
                        break;
                    }
                }
                if !matched {
                    if let Some(else_stmts) = else_branch {
                        eval_output_stmts(else_stmts, event, routed)?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub struct CompiledPipeline {
    pub entry: PipelineEntry,
    pub inputs: Vec<InputSpec>,
    pub outputs: Vec<OutputSink>,
    filter_tree: Vec<CompiledFilterStmt>,
    output_tree: Vec<CompiledOutputStmt>,
}

impl CompiledPipeline {
    pub fn compile(entry: PipelineEntry, config: &PipelineConfig) -> anyhow::Result<Self> {
        let mut inputs = Vec::with_capacity(config.inputs.len());
        for block in &config.inputs {
            inputs.push(InputSpec::from_plugin_block(block, &entry.id)?);
        }

        let filter_tree = compile_filter_stmts(&config.filters)?;
        let output_tree = compile_output_stmts(&config.outputs)?;
        let mut outputs = Vec::new();
        collect_sinks(&output_tree, &mut outputs);

        Ok(Self {
            entry,
            inputs,
            outputs,
            filter_tree,
            output_tree,
        })
    }

    pub fn input_topics_and_group(&self) -> (Vec<String>, String) {
        let mut topics = Vec::new();
        let mut group = format!("redborder-vortex-{}", self.entry.id);
        for inp in &self.inputs {
            if let InputSpec::Kafka {
                topics: t,
                group_id,
                ..
            } = inp
            {
                topics.extend(t.iter().cloned());
                group = group_id.clone();
            }
        }
        (topics, group)
    }

    pub fn attach_live_producers(&mut self, node_name: &str) {
        fn attach_to_stmts(stmts: &mut [CompiledOutputStmt], node_name: &str) {
            for stmt in stmts.iter_mut() {
                match stmt {
                    CompiledOutputStmt::Sink(OutputSink::Kafka(k)) => {
                        let cfg = KafkaProducerConfig {
                            bootstrap_servers: k.bootstrap_servers.clone(),
                            topic_id: k.topic_id.clone(),
                            codec: k.codec.clone(),
                            client_id: Some(format!("redborder-vortex-{}", node_name)),
                            message_key: k.message_key.clone(),
                            auto_key_field: k.auto_key_field.clone(),
                            auto_key_topics: k.auto_key_topics.clone(),
                        };
                        if let Ok(producer) = LiveKafkaProducer::new(cfg) {
                            k.attach_live_producer(Arc::new(producer));
                        }
                    }
                    CompiledOutputStmt::Conditional {
                        branches,
                        else_branch,
                    } => {
                        for (_, b) in branches {
                            attach_to_stmts(b, node_name);
                        }
                        if let Some(eb) = else_branch {
                            attach_to_stmts(eb, node_name);
                        }
                    }
                    _ => {}
                }
            }
        }
        attach_to_stmts(&mut self.output_tree, node_name);
    }

    pub fn attach_pipeline_senders(
        &mut self,
        senders_map: &HashMap<String, tokio::sync::mpsc::UnboundedSender<Event>>,
    ) {
        fn attach_to_stmts(
            stmts: &mut [CompiledOutputStmt],
            senders_map: &HashMap<String, tokio::sync::mpsc::UnboundedSender<Event>>,
        ) {
            for stmt in stmts.iter_mut() {
                match stmt {
                    CompiledOutputStmt::Sink(OutputSink::Pipeline(p)) => {
                        let targets = p.send_to.clone();
                        for target in targets {
                            if let Some(tx) = senders_map.get(&target) {
                                p.attach_sender(tx.clone());
                            } else {
                                eprintln!(
                                    "Warning: Pipeline output target address '{}' not found in any pipeline input",
                                    target
                                );
                            }
                        }
                    }
                    CompiledOutputStmt::Conditional {
                        branches,
                        else_branch,
                    } => {
                        for (_, b) in branches {
                            attach_to_stmts(b, senders_map);
                        }
                        if let Some(eb) = else_branch {
                            attach_to_stmts(eb, senders_map);
                        }
                    }
                    _ => {}
                }
            }
        }
        attach_to_stmts(&mut self.output_tree, senders_map);
    }

    pub fn process_event(
        &self,
        event: Event,
        state: &StateStore,
        stats: &StatsRegistry,
    ) -> anyhow::Result<Vec<(String, Event)>> {
        let start = Instant::now();
        let res = eval_filter_stmts(&self.filter_tree, vec![event], state);
        let duration_us = start.elapsed().as_micros() as u64;

        match res {
            Ok(surviving) => {
                if surviving.is_empty() {
                    stats.record_pipeline_run(&self.entry.id, 1, 0, 1, 0, duration_us);
                    return Ok(Vec::new());
                }

                let mut routed = Vec::with_capacity(surviving.len());
                for ev in &surviving {
                    eval_output_stmts(&self.output_tree, ev, &mut routed)?;
                }

                let emitted_count = routed.len() as u64;
                stats.record_pipeline_run(&self.entry.id, 1, emitted_count, 0, 0, duration_us);
                Ok(routed)
            }
            Err(err) => {
                stats.record_pipeline_run(&self.entry.id, 1, 0, 0, 1, duration_us);
                Err(err)
            }
        }
    }
}

fn resolve_pipeline_dir(path_config: &str, pipeline_id: &str, base_dir: Option<&Path>) -> PathBuf {
    let trimmed = path_config
        .trim()
        .trim_end_matches("/*.conf")
        .trim_end_matches("*.conf");
    let candidate = PathBuf::from(trimmed);
    if candidate.is_dir() {
        return candidate;
    }
    if let Some(base) = base_dir {
        let p1 = base.join("pipelines").join(pipeline_id);
        if p1.is_dir() {
            return p1;
        }
        let p2 = base.join(pipeline_id);
        if p2.is_dir() {
            return p2;
        }
    }
    candidate
}

fn register_node_in_cluster(state: &StateStore, node_name: &str) {
    let mut nodes: Vec<String> = state
        .get_kv(CLUSTER_NODES_KV_KEY)
        .ok()
        .flatten()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if !nodes.iter().any(|n| n == node_name) {
        nodes.push(node_name.to_string());
        nodes.sort();
        nodes.dedup();
        let _ = state.set_kv(CLUSTER_NODES_KV_KEY, &nodes.join(","), None);
    }
}

pub struct VortexEngine {
    pub state: Arc<StateStore>,
    pub stats: Arc<StatsRegistry>,
    pub node_name: String,
    pub pipelines: HashMap<String, CompiledPipeline>,
    pipeline_senders: HashMap<String, tokio::sync::mpsc::UnboundedSender<Event>>,
    pipeline_receivers: Arc<std::sync::Mutex<Vec<(String, tokio::sync::mpsc::UnboundedReceiver<Event>)>>>,
}

impl VortexEngine {
    pub fn new(state: Arc<StateStore>, node_name: impl Into<String>) -> Self {
        let node = node_name.into();
        let stats = Arc::new(StatsRegistry::new(node.clone()));
        Self::new_with_stats(state, stats, node)
    }

    pub fn new_with_stats(
        state: Arc<StateStore>,
        stats: Arc<StatsRegistry>,
        node_name: impl Into<String>,
    ) -> Self {
        let node = node_name.into();
        register_node_in_cluster(&state, &node);
        Self {
            state,
            stats,
            node_name: node,
            pipelines: HashMap::new(),
            pipeline_senders: HashMap::new(),
            pipeline_receivers: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn from_settings_dir(
        settings_dir: &Path,
        state: Arc<StateStore>,
        node_name: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let yml_path = settings_dir.join("pipelines.yml");
        Self::from_pipelines_yml(&yml_path, Some(settings_dir), state, node_name)
    }

    pub fn from_settings_dir_with_stats(
        settings_dir: &Path,
        state: Arc<StateStore>,
        stats: Arc<StatsRegistry>,
        node_name: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let yml_path = settings_dir.join("pipelines.yml");
        Self::from_pipelines_yml_with_stats(&yml_path, Some(settings_dir), state, stats, node_name)
    }

    pub fn from_pipelines_yml(
        pipelines_yml_path: &Path,
        base_dir: Option<&Path>,
        state: Arc<StateStore>,
        node_name: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let node = node_name.into();
        let stats = Arc::new(StatsRegistry::new(node.clone()));
        Self::from_pipelines_yml_with_stats(pipelines_yml_path, base_dir, state, stats, node)
    }

    pub fn from_pipelines_yml_with_stats(
        pipelines_yml_path: &Path,
        base_dir: Option<&Path>,
        state: Arc<StateStore>,
        stats: Arc<StatsRegistry>,
        node_name: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let entries = load_pipelines_yml(pipelines_yml_path).with_context(|| {
            format!("Failed to load pipelines.yml from {:?}", pipelines_yml_path)
        })?;
        let node = node_name.into();
        let temp_stats = Arc::new(StatsRegistry::new(node.clone()));
        let mut engine = Self::new_with_stats(state, temp_stats, node);
        let fallback_base = base_dir.or_else(|| pipelines_yml_path.parent());

        let mut loaded_ids = Vec::new();
        for entry in entries {
            let dir = resolve_pipeline_dir(&entry.path_config, &entry.id, fallback_base);
            let cfg = load_pipeline_dir(&dir).with_context(|| {
                format!(
                    "Failed to load pipeline '{}' from directory {:?}",
                    entry.id, dir
                )
            })?;
            loaded_ids.push(entry.id.clone());
            engine.register_pipeline(entry, &cfg)?;
        }

        // Commit pipeline registrations to shared persistent stats only after full compilation succeeds
        for (id, p) in &engine.pipelines {
            let (topics, group) = p.input_topics_and_group();
            stats.update_or_register_pipeline(id, p.entry.workers, topics, group);
        }
        stats.retain_pipelines(&loaded_ids);
        engine.stats = stats;

        Ok(engine)
    }

    pub fn register_pipeline(
        &mut self,
        entry: PipelineEntry,
        config: &PipelineConfig,
    ) -> anyhow::Result<()> {
        let compiled = CompiledPipeline::compile(entry.clone(), config)?;
        let (topics, group) = compiled.input_topics_and_group();
        self.stats
            .update_or_register_pipeline(&entry.id, entry.workers, topics, group);
        self.pipelines.insert(entry.id, compiled);
        Ok(())
    }

    pub fn pipeline_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.pipelines.keys().cloned().collect();
        ids.sort();
        ids
    }

    pub fn process_pipeline_event(
        &self,
        pipeline_id: &str,
        event: Event,
    ) -> anyhow::Result<Vec<(String, Event)>> {
        let pipeline = self
            .pipelines
            .get(pipeline_id)
            .ok_or_else(|| anyhow!("Pipeline '{}' is not registered", pipeline_id))?;
        pipeline.process_event(event, &self.state, &self.stats)
    }

    pub fn run_rbwindow_tick(&self) -> anyhow::Result<Vec<(String, Event)>> {
        let pipeline = self
            .pipelines
            .get("rbwindow")
            .or_else(|| self.pipelines.get("rbwindow-pipeline"))
            .or_else(|| {
                self.pipelines
                    .iter()
                    .find(|(k, _)| k.starts_with("rbwindow"))
                    .map(|(_, p)| p)
            });
        let Some(pipeline) = pipeline else {
            return Ok(Vec::new());
        };
        let cfg = pipeline
            .inputs
            .iter()
            .find_map(|inp| match inp {
                InputSpec::Rbwindow(c) => Some(c.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let runner = RbwindowRunner::new(cfg);
        let events = runner.run_tick(&self.state, &self.node_name)?;
        let mut all_routed = Vec::new();
        for ev in events {
            let out = pipeline.process_event(ev, &self.state, &self.stats)?;
            all_routed.extend(out);
        }
        Ok(all_routed)
    }

    pub fn attach_live_producers(&mut self) {
        let node = self.node_name.clone();
        for pipeline in self.pipelines.values_mut() {
            pipeline.attach_live_producers(&node);
        }
    }

    pub fn wire_pipeline_channels(&mut self) {
        let mut senders: HashMap<String, tokio::sync::mpsc::UnboundedSender<Event>> = HashMap::new();
        let mut receivers: Vec<(String, tokio::sync::mpsc::UnboundedReceiver<Event>)> = Vec::new();

        for (pipeline_id, pipeline) in &self.pipelines {
            for inp in &pipeline.inputs {
                if let InputSpec::Pipeline { address } = inp {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
                    senders.insert(address.clone(), tx.clone());
                    senders.insert(pipeline_id.clone(), tx);
                    receivers.push((pipeline_id.clone(), rx));
                }
            }
        }

        for pipeline in self.pipelines.values_mut() {
            pipeline.attach_pipeline_senders(&senders);
        }

        self.pipeline_senders = senders;
        self.pipeline_receivers = Arc::new(std::sync::Mutex::new(receivers));
    }

    pub fn get_pipeline_sender(&self, address_or_id: &str) -> Option<tokio::sync::mpsc::UnboundedSender<Event>> {
        self.pipeline_senders.get(address_or_id).cloned()
    }

    pub fn spawn_pipeline_workers(
        engine: Arc<Self>,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        let receivers_arc = engine.pipeline_receivers.clone();

        let recvs = {
            let mut guard = receivers_arc.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        for (pipeline_id, mut rx) in recvs {
            let eng = engine.clone();
            let pid = pipeline_id.clone();
            let mut stop_rx = shutdown_rx.clone();

            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop_rx.changed() => {
                            if *stop_rx.borrow() {
                                // Drain any queued events before completing shutdown
                                while let Ok(ev) = rx.try_recv() {
                                    if let Err(e) = eng.process_pipeline_event(&pid, ev) {
                                        eprintln!("Pipeline '{}' in-memory worker drain error: {:#}", pid, e);
                                    }
                                }
                                break;
                            }
                        }
                        maybe_ev = rx.recv() => {
                            match maybe_ev {
                                Some(ev) => {
                                    if let Err(e) = eng.process_pipeline_event(&pid, ev) {
                                        eprintln!("Pipeline '{}' in-memory worker error: {:#}", pid, e);
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
            });
            handles.push(handle);
        }

        handles
    }

    pub fn spawn_kafka_workers(
        engine: Arc<Self>,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for (pipeline_id, pipeline) in &engine.pipelines {
            for inp in &pipeline.inputs {
                if let InputSpec::Kafka {
                    topics,
                    bootstrap_servers,
                    codec,
                    group_id,
                    decorate_events,
                } = inp
                {
                    if topics.is_empty() {
                        continue;
                    }
                    let workers_count = pipeline.entry.workers.max(1);
                    for worker_idx in 0..workers_count {
                        let pid = pipeline_id.clone();
                        let eng = engine.clone();
                        let mut rx = shutdown_rx.clone();
                        let cfg = KafkaConsumerConfig {
                            bootstrap_servers: bootstrap_servers.clone(),
                            group_id: group_id.clone(),
                            topics: topics.clone(),
                            codec: codec.clone(),
                            decorate_events: *decorate_events,
                            auto_offset_reset: "latest".to_string(),
                            session_timeout_ms: "45000".to_string(),
                        };
                        let decorate = *decorate_events;

                        let handle = tokio::spawn(async move {
                            let consumer = match cfg.create_consumer() {
                                Ok(c) => c,
                                Err(e) => {
                                    eprintln!(
                                        "Failed to create Kafka consumer for pipeline {} (worker {}): {}",
                                        pid, worker_idx, e
                                    );
                                    return;
                                }
                            };

                            println!(
                                "Pipeline '{}' worker #{} started on consumer group '{}' for topics: {:?}",
                                pid, worker_idx, cfg.group_id, cfg.topics
                            );

                            loop {
                                tokio::select! {
                                    _ = rx.changed() => {
                                        if *rx.borrow() {
                                            break;
                                        }
                                    }
                                    msg_res = consumer.recv() => {
                                        match msg_res {
                                            Ok(borrowed_msg) => {
                                                match borrowed_message_to_event(&borrowed_msg, decorate) {
                                                    Ok(ev) => {
                                                        let _ = eng.process_pipeline_event(&pid, ev);
                                                    }
                                                    Err(err) => {
                                                        eprintln!("Failed to parse Kafka event in {}: {}", pid, err);
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                eprintln!("Kafka receive error in {} (worker {}): {}", pid, worker_idx, err);
                                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                            }
                                        }
                                    }
                                }
                            }
                            println!("Pipeline '{}' worker #{} stopped", pid, worker_idx);
                        });
                        handles.push(handle);
                    }
                }
            }
        }

        handles
    }

    pub fn spawn_file_workers(
        engine: Arc<Self>,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for (pipeline_id, pipeline) in &engine.pipelines {
            for inp in &pipeline.inputs {
                if let InputSpec::File(cfg) = inp {
                    let pid = pipeline_id.clone();
                    let eng = engine.clone();
                    let mut rx = shutdown_rx.clone();
                    let mut consumer = FileConsumer::new(cfg.clone(), eng.node_name.clone());

                    println!(
                        "Pipeline '{}' file worker started for patterns: {:?}",
                        pid, cfg.path
                    );

                    let handle = tokio::spawn(async move {
                        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(500));
                        loop {
                            tokio::select! {
                                _ = rx.changed() => {
                                    if *rx.borrow() {
                                        break;
                                    }
                                }
                                _ = interval.tick() => {
                                    if let Err(e) = consumer.poll_and_process(&eng, &pid) {
                                        eprintln!("Pipeline '{}' file worker error: {:#}", pid, e);
                                    }
                                }
                            }
                        }
                        println!("Pipeline '{}' file worker stopped", pid);
                    });
                    handles.push(handle);
                }
            }
        }

        handles
    }
}
