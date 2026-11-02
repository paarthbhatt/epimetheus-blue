//! Layered configuration. Unknown keys are a hard error so typos cannot
//! silently disable a control.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub scan: Scan,
    pub verdict: VerdictConfig,
    pub http: Http,
    pub dns: Dns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub bind: String,
    pub lists_dir: String,
    pub upstreams: Vec<String>,
    /// `nxdomain` (default) or `zero`.
    pub block_response: String,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:53".into(),
            lists_dir: "~/.local/share/blue/lists".into(),
            upstreams: vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()],
            block_response: "nxdomain".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    /// Unprivileged default: everything lives under the user's data dir.
    pub state_dir: String,
    pub log_level: String,
    pub kill_switch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scan {
    pub roots: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub max_file_size_mb: u64,
    pub workers: usize,
    pub debounce_ms: u64,
    /// `inotify` is the only supported mode in this build. `fanotify` is
    /// deliberately not implemented: it needs CAP_SYS_ADMIN and can block opens.
    pub mode: String,
    pub clamav: ClamAv,
    pub yara: Yara,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClamAv {
    pub socket: String,
    /// false => scanner degrades to YARA-only instead of failing.
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Yara {
    pub rule_paths: Vec<String>,
    pub rule_dirs: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerdictConfig {
    /// T2 = quarantine on corroboration. T3 = only after confirmation.
    pub quarantine_at: String,
    pub notify_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub bind: String,
    pub token: Option<String>,
}

impl Default for General {
    fn default() -> Self {
        Self {
            state_dir: "~/.local/share/blue".into(),
            log_level: "info".into(),
            kill_switch: false,
        }
    }
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            roots: vec!["~/Downloads".into(), "~/tmp".into()],
            exclude_globs: vec![
                "**/node_modules/**".into(),
                "**/.git/objects/**".into(),
                "**/*.iso".into(),
                "**/target/**".into(),
            ],
            max_file_size_mb: 512,
            workers: 4,
            debounce_ms: 500,
            mode: "inotify".into(),
            clamav: ClamAv::default(),
            yara: Yara::default(),
        }
    }
}

impl Default for ClamAv {
    fn default() -> Self {
        Self {
            socket: "/run/clamav/clamd.ctl".into(),
            required: false,
        }
    }
}

impl Default for Yara {
    fn default() -> Self {
        Self {
            rule_paths: vec![],
            rule_dirs: vec!["~/.local/share/blue/rules".into()],
            timeout_ms: 5000,
        }
    }
}

impl Default for VerdictConfig {
    fn default() -> Self {
        Self {
            quarantine_at: "T2".into(),
            notify_at: "T2".into(),
        }
    }
}

impl Default for Http {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8471".into(),
            token: None,
        }
    }
}

impl Config {
    /// Load `/etc/blue/config.toml`, then `~/.config/blue/config.toml`, then an
    /// explicit path. Later files win field-by-field at the TOML layer.
    pub fn load(explicit: Option<&Path>) -> Result<Config> {
        let mut cfg = Config::default();
        let mut candidates: Vec<PathBuf> = Vec::new();
        candidates.push(PathBuf::from("/etc/blue/config.toml"));
        if let Some(home) = home_dir() {
            candidates.push(home.join(".config/blue/config.toml"));
        }
        if let Some(p) = explicit {
            candidates.push(p.to_path_buf());
        }
        for path in candidates {
            if path.exists() {
                cfg = cfg.merge_file(&path)?;
            }
        }
        Ok(cfg)
    }

    fn merge_file(self, path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let over: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        Ok(over)
    }

    pub fn state_dir(&self) -> PathBuf {
        expand_tilde(&self.general.state_dir)
    }

    pub fn db_path(&self) -> PathBuf {
        self.state_dir().join("blue.db")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.state_dir().join("quarantine")
    }

    pub fn roots(&self) -> Vec<PathBuf> {
        self.scan.roots.iter().map(|p| expand_tilde(p)).collect()
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Expand a leading `~` only. No shell expansion, ever.
pub fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    }
    if p == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    }
    PathBuf::from(p)
}
