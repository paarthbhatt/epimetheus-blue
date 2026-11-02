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
    pub dns: Dns,
    pub guard: Guard,
    pub feeds: Feeds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Guard {
    /// Files and directories whose contents and metadata are watched.
    pub watch_paths: Vec<String>,
    /// Compare package file checksums against the pacman database.
    pub watch_packages: bool,
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            watch_paths: vec![
                "~/.config/systemd/user".into(),
                "~/.config/autostart".into(),
                "~/.config/hypr".into(),
                "~/.ssh/authorized_keys".into(),
                "~/.bashrc".into(),
                "~/.zshrc".into(),
                "~/.profile".into(),
                "/etc/ld.so.preload".into(),
                "/etc/systemd/system".into(),
                "/etc/cron.d".into(),
            ],
            // `pacman -Qkk` is intentionally opt-in: on a developer workstation
            // it can consume tens of CPU-seconds and hundreds of MiB.
            watch_packages: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Feeds {
    pub lists_dir: String,
    pub sources: Vec<FeedSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedSource {
    pub name: String,
    pub url: String,
    /// Recorded, not enforced. Lets the native app show provenance.
    pub license: Option<String>,
}

impl Default for Feeds {
    fn default() -> Self {
        Self {
            lists_dir: "~/.local/share/blue/lists".into(),
            sources: vec![FeedSource {
                name: "stevenblack".into(),
                url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
                license: Some("MIT".into()),
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    pub bind: String,
    pub upstreams: Vec<String>,
    /// `nxdomain` (default) or `zero`.
    pub block_response: String,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:53".into(),
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Scan {
    pub roots: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub max_file_size_mb: u64,
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

impl Default for General {
    fn default() -> Self {
        Self {
            state_dir: "~/.local/share/blue".into(),
            log_level: "info".into(),
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

impl Config {
    /// Load `/etc/blue/config.toml`, then `~/.config/blue/config.toml`, then an
    /// explicit path. Later files win field-by-field at the TOML layer.
    pub fn load(explicit: Option<&Path>) -> Result<Config> {
        let mut merged = toml::Value::try_from(Config::default())
            .context("serializing default configuration")?;
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
                let text = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading config {}", path.display()))?;
                let overlay: toml::Value = toml::from_str(&text)
                    .with_context(|| format!("parsing config {}", path.display()))?;
                merge_value(&mut merged, overlay);
            }
        }
        let config: Config = merged
            .try_into()
            .context("deserializing merged configuration")?;
        config.validate()?;
        Ok(config)
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

    fn validate(&self) -> Result<()> {
        if self.scan.mode != "inotify" {
            anyhow::bail!(
                "unsupported scan mode {:?}; this build supports only inotify",
                self.scan.mode
            );
        }
        if !matches!(self.dns.block_response.as_str(), "nxdomain" | "zero") {
            anyhow::bail!(
                "unsupported dns.block_response {:?}; use nxdomain or zero",
                self.dns.block_response
            );
        }
        if self.scan.max_file_size_mb == 0 {
            anyhow::bail!("scan.max_file_size_mb must be greater than zero");
        }
        Ok(())
    }
}

fn merge_value(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                match base.get_mut(&key) {
                    Some(existing) => merge_value(existing, value),
                    None => {
                        base.insert(key, value);
                    }
                }
            }
        }
        (base, overlay) => *base = overlay,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlays_replace_fields_not_whole_sections() {
        let mut base: toml::Value = toml::from_str(
            r#"
            [dns]
            bind = "127.0.0.1:53"
            upstreams = ["1.1.1.1:53"]
            block_response = "nxdomain"
            "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            [dns]
            bind = "127.0.0.1:5353"
            "#,
        )
        .unwrap();
        merge_value(&mut base, overlay);
        assert_eq!(base["dns"]["bind"].as_str(), Some("127.0.0.1:5353"));
        assert_eq!(base["dns"]["upstreams"][0].as_str(), Some("1.1.1.1:53"));
    }

    #[test]
    fn unknown_keys_are_rejected_after_merge() {
        let mut base = toml::Value::try_from(Config::default()).unwrap();
        let overlay: toml::Value = toml::from_str("[scan]\nmagic_typo = true").unwrap();
        merge_value(&mut base, overlay);
        assert!(base.try_into::<Config>().is_err());
    }

    #[test]
    fn unsupported_modes_are_rejected() {
        let mut config = Config::default();
        config.scan.mode = "fanotify".into();
        assert!(config.validate().is_err());
        config.scan.mode = "inotify".into();
        config.dns.block_response = "redirect".into();
        assert!(config.validate().is_err());
    }
}
