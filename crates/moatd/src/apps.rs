use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

const APPS_DIR: &str = "/etc/moatd/applications.d";

#[derive(Debug, Deserialize)]
pub struct AppProfile {
    pub name: String,
    /// Comma-separated list of ports or port ranges, e.g. `"80,443"` or
    /// `"60000-61000"`. Each entry expands to its own wire rule, so an app
    /// like `web` with `ports = "80,443"` becomes two rules.
    pub ports: String,
    #[serde(default = "default_proto")]
    pub proto: String,
}

fn default_proto() -> String {
    "any".to_string()
}

pub fn load(name: &str) -> Result<Option<AppProfile>> {
    let path = profile_path(name);
    if !path.exists() {
        return Ok(None);
    }
    let body =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let profile: AppProfile =
        toml::from_str(&body).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(profile))
}

pub fn list() -> Result<Vec<String>> {
    let dir = Path::new(APPS_DIR);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn profile_path(name: &str) -> PathBuf {
    PathBuf::from(format!("{APPS_DIR}/{name}.toml"))
}
