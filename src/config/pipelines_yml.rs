use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

fn default_workers() -> usize {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineEntry {
    #[serde(rename = "pipeline.id")]
    pub id: String,
    #[serde(rename = "path.config")]
    pub path_config: String,
    #[serde(rename = "pipeline.workers", default = "default_workers")]
    pub workers: usize,
}

pub fn parse_pipelines_yml(yaml_content: &str) -> anyhow::Result<Vec<PipelineEntry>> {
    let entries: Vec<PipelineEntry> = serde_yaml::from_str(yaml_content)?;
    Ok(entries)
}

pub fn load_pipelines_yml(path: &Path) -> anyhow::Result<Vec<PipelineEntry>> {
    let content = fs::read_to_string(path)?;
    parse_pipelines_yml(&content)
}
