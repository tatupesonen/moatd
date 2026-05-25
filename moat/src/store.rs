use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use moat_common::control::{Action, UserRule};
use serde::{Deserialize, Serialize};

pub const CONFIG_DIR: &str = "/etc/moat";
pub const RULES_FILE: &str = "/etc/moat/rules.toml";

#[derive(Debug, Serialize, Deserialize)]
pub struct OnDisk {
    #[serde(default = "default_in_default")]
    pub default_in: Action,
    #[serde(default = "default_out_default")]
    pub default_out: Action,
    #[serde(default)]
    pub logging_enabled: bool,
    #[serde(default)]
    pub rules: Vec<UserRule>,
}

impl Default for OnDisk {
    fn default() -> Self {
        Self {
            default_in: default_in_default(),
            default_out: default_out_default(),
            logging_enabled: false,
            rules: Vec::new(),
        }
    }
}

fn default_in_default() -> Action {
    Action::Allow
}

fn default_out_default() -> Action {
    Action::Allow
}

pub fn load(path: impl AsRef<Path>) -> Result<OnDisk> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(OnDisk {
            default_in: default_in_default(),
            default_out: default_out_default(),
            logging_enabled: false,
            rules: Vec::new(),
        });
    }
    let bytes = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&bytes).with_context(|| format!("parsing {}", path.display()))
}

pub fn save(path: impl AsRef<Path>, on_disk: &OnDisk) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let body = toml::to_string_pretty(on_disk)?;
    let tmp = tmp_path(path);
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(body.as_bytes())?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).with_context(|| format!("renaming {}", path.display()))?;
    Ok(())
}

fn tmp_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}
