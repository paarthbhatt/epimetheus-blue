//! Read-only integrity and persistence auditing.

use anyhow::{anyhow, Context, Result};
use blue_core::config::expand_tilde;
use blue_core::{now_ms, Config, Db, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use walkdir::WalkDir;

const INVENTORY_KEY: &str = "guard:inventory";
const MAX_ENTRIES: usize = 50_000;
const MAX_HASH_SIZE: u64 = 64 * 1024 * 1024;
const PACKAGE_TIMEOUT: Duration = Duration::from_secs(60);
const PACKAGE_POLL_INTERVAL: Duration = Duration::from_millis(25);

const PERSISTENCE_PATH_PARTS: &[&str] = &[
    "systemd",
    "autostart",
    "hypr",
    "cron",
    ".bashrc",
    ".zshrc",
    ".profile",
    "authorized_keys",
    "ld.so.preload",
];

/// Configuration for a single guard pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardConfig {
    pub watch_paths: Vec<PathBuf>,
    pub watch_packages: bool,
}

impl GuardConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            watch_paths: config
                .guard
                .watch_paths
                .iter()
                .map(|path| expand_tilde(path))
                .collect(),
            watch_packages: config.guard.watch_packages,
        }
    }
}

/// Results from one guard pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GuardReport {
    pub baseline: bool,
    pub entries: usize,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub findings: usize,
    pub packages_checked: Option<usize>,
}

pub struct Guard {
    db: Arc<Db>,
    config: GuardConfig,
}

impl Guard {
    pub fn new(db: Arc<Db>, config: GuardConfig) -> Self {
        Self { db, config }
    }

    /// Compare the current read-only inventory with the last completed pass.
    ///
    /// The first pass only establishes a baseline. In particular, it emits no
    /// findings and must not be interpreted as a clean bill of health.
    pub fn run_once(&self) -> Result<GuardReport> {
        let current = self.collect_inventory()?;
        let stored = self.db.get_meta(INVENTORY_KEY)?;
        let baseline = stored.is_none();
        let previous = match stored {
            Some(value) => Some(
                serde_json::from_str::<Inventory>(&value)
                    .context("parsing stored guard inventory")?,
            ),
            None => None,
        };

        let now = now_ms();
        let mut report = GuardReport {
            baseline,
            entries: current.entries.len(),
            ..GuardReport::default()
        };

        if let Some(previous) = previous.as_ref() {
            self.record_changes(previous, &current, now, &mut report)?;
        }

        if self.config.watch_packages {
            match check_packages() {
                PackageCheck::Complete { checked, issues } => {
                    report.packages_checked = Some(checked);
                    if !baseline {
                        for issue in issues {
                            let detail = serde_json::to_string(&json!({
                                "source": "pacman -Qkk",
                                "line": issue.line,
                            }))?;
                            self.db.add_finding(
                                "package",
                                Tier::Candidate,
                                &issue.subject,
                                &detail,
                                now,
                            )?;
                            report.findings += 1;
                        }
                    }
                }
                PackageCheck::Degraded(reason) => {
                    self.record_package_degraded(&reason, now);
                }
            }
        }

        if current.truncated {
            tracing::warn!(
                max_entries = MAX_ENTRIES,
                "guard inventory reached its entry limit"
            );
            if !baseline {
                let detail = serde_json::to_string(&json!({
                    "change": "inventory_truncated",
                    "max_entries": MAX_ENTRIES,
                }))?;
                self.db.add_finding(
                    "integrity",
                    Tier::Candidate,
                    "guard inventory",
                    &detail,
                    now,
                )?;
                report.findings += 1;
            }
        }

        let encoded = serde_json::to_string(&current)?;
        self.db.set_meta(INVENTORY_KEY, &encoded)?;
        self.record_summary_event(&report, current.truncated, now)?;
        Ok(report)
    }

    fn collect_inventory(&self) -> Result<Inventory> {
        let mut inventory = Inventory::default();

        'roots: for root in &self.config.watch_paths {
            match fs::symlink_metadata(root) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("reading metadata for {}", root.display()));
                }
            }

            let walker = WalkDir::new(root).follow_links(false).sort_by_file_name();
            for item in walker {
                let entry = match item {
                    Ok(entry) => entry,
                    Err(error)
                        if error
                            .io_error()
                            .is_some_and(|source| source.kind() == io::ErrorKind::NotFound) =>
                    {
                        continue;
                    }
                    Err(error) => {
                        let location = error.path().map_or_else(
                            || root.display().to_string(),
                            |path| path.display().to_string(),
                        );
                        return Err(anyhow!("walking {location}: {error}"));
                    }
                };

                if entry.file_type().is_dir() {
                    continue;
                }

                let path = entry.path();
                let key = path.to_string_lossy().into_owned();
                if inventory.entries.contains_key(&key) {
                    continue;
                }
                if inventory.entries.len() >= MAX_ENTRIES {
                    inventory.truncated = true;
                    break 'roots;
                }

                let marker = marker_for(path)?;
                inventory.entries.insert(key, marker);
            }
        }

        Ok(inventory)
    }

    fn record_changes(
        &self,
        previous: &Inventory,
        current: &Inventory,
        now: i64,
        report: &mut GuardReport,
    ) -> Result<()> {
        for (path, marker) in &current.entries {
            match previous.entries.get(path) {
                None => {
                    self.record_path_finding(path, "added", None, Some(marker), now)?;
                    report.added += 1;
                    report.findings += 1;
                }
                Some(old_marker) if old_marker != marker => {
                    self.record_path_finding(
                        path,
                        "modified",
                        Some(old_marker),
                        Some(marker),
                        now,
                    )?;
                    report.modified += 1;
                    report.findings += 1;
                }
                Some(_) => {}
            }
        }

        for path in previous.entries.keys() {
            if !current.entries.contains_key(path) {
                self.record_path_finding(path, "removed", previous.entries.get(path), None, now)?;
                report.removed += 1;
                report.findings += 1;
            }
        }

        Ok(())
    }

    fn record_path_finding(
        &self,
        path: &str,
        change: &str,
        old: Option<&EntryMarker>,
        new: Option<&EntryMarker>,
        now: i64,
    ) -> Result<()> {
        let kind = if is_persistence_path(path) {
            "persistence"
        } else {
            "integrity"
        };
        let detail = serde_json::to_string(&json!({
            "path": path,
            "change": change,
            "old_sha256": old.and_then(EntryMarker::sha256),
            "new_sha256": new.and_then(EntryMarker::sha256),
        }))?;
        self.db
            .add_finding(kind, Tier::Candidate, path, &detail, now)?;
        Ok(())
    }

    fn record_package_degraded(&self, reason: &str, now: i64) {
        tracing::warn!(reason, "package integrity check degraded");
        let payload = match serde_json::to_string(&json!({
            "status": "degraded",
            "reason": reason,
        })) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(%error, "could not serialize package degradation event");
                return;
            }
        };
        if let Err(error) =
            self.db
                .event("guard.packages", "warn", Some("pacman -Qkk"), &payload, now)
        {
            tracing::warn!(%error, "could not record package degradation event");
        }
    }

    fn record_summary_event(&self, report: &GuardReport, truncated: bool, now: i64) -> Result<()> {
        let payload = serde_json::to_string(&json!({
            "baseline": report.baseline,
            "clean_claim": false,
            "entries": report.entries,
            "added": report.added,
            "removed": report.removed,
            "modified": report.modified,
            "findings": report.findings,
            "packages_checked": report.packages_checked,
            "truncated": truncated,
        }))?;
        self.db.event("guard", "info", None, &payload, now)?;
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Inventory {
    #[serde(default)]
    entries: BTreeMap<String, EntryMarker>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EntryMarker {
    File {
        sha256: String,
        size: u64,
        modified_ns: Option<u64>,
        mode: u32,
    },
    LargeFile {
        size: u64,
        modified_ns: Option<u64>,
        mode: u32,
    },
    Symlink {
        target: String,
    },
    Other {
        file_type: String,
        size: u64,
        modified_ns: Option<u64>,
        mode: u32,
    },
}

impl EntryMarker {
    fn sha256(&self) -> Option<&str> {
        match self {
            EntryMarker::File { sha256, .. } => Some(sha256),
            _ => None,
        }
    }
}

fn marker_for(path: &Path) -> Result<EntryMarker> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    let file_type = metadata.file_type();

    if file_type.is_symlink() {
        let target = fs::read_link(path)
            .with_context(|| format!("reading symlink target for {}", path.display()))?;
        return Ok(EntryMarker::Symlink {
            target: target.to_string_lossy().into_owned(),
        });
    }

    let size = metadata.len();
    let modified_ns = modified_ns(&metadata);
    let mode = metadata_mode(&metadata);
    if file_type.is_file() {
        if size <= MAX_HASH_SIZE {
            return Ok(EntryMarker::File {
                sha256: hash_file(path)?,
                size,
                modified_ns,
                mode,
            });
        }
        return Ok(EntryMarker::LargeFile {
            size,
            modified_ns,
            mode,
        });
    }

    Ok(EntryMarker::Other {
        file_type: special_file_type(&file_type).to_owned(),
        size,
        modified_ns,
        mode,
    })
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("opening {} for hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("hashing {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn modified_ns(metadata: &Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
}

#[cfg(unix)]
fn metadata_mode(metadata: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn metadata_mode(metadata: &Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

#[cfg(unix)]
fn special_file_type(file_type: &fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;

    if file_type.is_block_device() {
        "block_device"
    } else if file_type.is_char_device() {
        "char_device"
    } else if file_type.is_fifo() {
        "fifo"
    } else if file_type.is_socket() {
        "socket"
    } else {
        "other"
    }
}

#[cfg(not(unix))]
fn special_file_type(_file_type: &fs::FileType) -> &'static str {
    "other"
}

fn is_persistence_path(path: &str) -> bool {
    PERSISTENCE_PATH_PARTS
        .iter()
        .any(|part| path.contains(part))
}

struct PackageIssue {
    subject: String,
    line: String,
}

enum PackageCheck {
    Complete {
        checked: usize,
        issues: Vec<PackageIssue>,
    },
    Degraded(String),
}

fn check_packages() -> PackageCheck {
    let mut child = match Command::new("pacman")
        .arg("-Qkk")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return PackageCheck::Degraded(format!("could not start pacman: {error}"));
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_child(&mut child);
            return PackageCheck::Degraded("pacman stdout was unavailable".to_owned());
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            terminate_child(&mut child);
            return PackageCheck::Degraded("pacman stderr was unavailable".to_owned());
        }
    };

    let stdout_reader = thread::spawn(move || read_output(stdout));
    let stderr_reader = thread::spawn(move || read_output(stderr));
    let deadline = Instant::now() + PACKAGE_TIMEOUT;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                terminate_child(&mut child);
                drop(stdout_reader);
                drop(stderr_reader);
                return PackageCheck::Degraded("pacman timed out after 60 seconds".to_owned());
            }
            Ok(None) => thread::sleep(PACKAGE_POLL_INTERVAL),
            Err(error) => {
                terminate_child(&mut child);
                drop(stdout_reader);
                drop(stderr_reader);
                return PackageCheck::Degraded(format!("waiting for pacman failed: {error}"));
            }
        }
    };

    let stdout = match join_reader(stdout_reader, "stdout") {
        Ok(output) => output,
        Err(reason) => return PackageCheck::Degraded(reason),
    };
    let stderr = match join_reader(stderr_reader, "stderr") {
        Ok(output) => output,
        Err(reason) => return PackageCheck::Degraded(reason),
    };

    if !status.success() {
        return PackageCheck::Degraded(format!("pacman exited with {status}"));
    }

    parse_package_output(&stdout, &stderr)
}

fn terminate_child(child: &mut std::process::Child) {
    if let Err(error) = child.kill() {
        tracing::debug!(%error, "pacman was already stopped when kill was requested");
    }
    if let Err(error) = child.wait() {
        tracing::debug!(%error, "could not reap pacman process");
    }
}

fn read_output(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    Ok(output)
}

fn join_reader(
    handle: thread::JoinHandle<io::Result<Vec<u8>>>,
    stream: &str,
) -> std::result::Result<Vec<u8>, String> {
    match handle.join() {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => Err(format!("reading pacman {stream} failed: {error}")),
        Err(_) => Err(format!("pacman {stream} reader panicked")),
    }
}

fn parse_package_output(stdout: &[u8], stderr: &[u8]) -> PackageCheck {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    let lines = stdout.lines().chain(stderr.lines());
    let mut checked = 0;
    let mut issue_lines = BTreeSet::new();

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lowercase = trimmed.to_ascii_lowercase();
        if lowercase.contains(" total file") && lowercase.contains(" altered file") {
            checked += 1;
        }
        if lowercase.contains("warning") || reports_altered_files(&lowercase) {
            issue_lines.insert(truncate_chars(trimmed, 512));
        }
    }

    let issues = issue_lines
        .into_iter()
        .map(|line| PackageIssue {
            subject: package_subject(&line),
            line,
        })
        .collect();
    PackageCheck::Complete { checked, issues }
}

fn reports_altered_files(lowercase: &str) -> bool {
    let Some(index) = lowercase.find(" altered file") else {
        return false;
    };
    lowercase[..index]
        .split_whitespace()
        .next_back()
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|count| count > 0)
}

fn package_subject(line: &str) -> String {
    let lowercase = line.to_ascii_lowercase();
    let without_warning = if lowercase.starts_with("warning:") {
        line.get("warning:".len()..).map_or(line, str::trim)
    } else {
        line
    };
    let parsed_subject = without_warning
        .split(':')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let subject = parsed_subject.unwrap_or("pacman -Qkk");
    truncate_chars(subject, 200)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_guard(path: &Path) -> (Arc<Db>, Guard) {
        let db = Arc::new(Db::open_memory().unwrap());
        let config = GuardConfig {
            watch_paths: vec![path.to_path_buf()],
            watch_packages: false,
        };
        let guard = Guard::new(db.clone(), config);
        (db, guard)
    }

    fn detail(finding: &blue_core::Finding) -> serde_json::Value {
        serde_json::from_str(&finding.detail).unwrap()
    }

    #[test]
    fn baseline_empty() {
        let directory = TempDir::new().unwrap();
        let (db, guard) = test_guard(directory.path());

        let report = guard.run_once().unwrap();

        assert!(report.baseline);
        assert_eq!(report.entries, 0);
        assert_eq!(report.findings, 0);
        assert!(db.list_findings(10, true).unwrap().is_empty());
        assert!(db.get_meta(INVENTORY_KEY).unwrap().is_some());
    }

    #[test]
    fn unchanged_second_run_has_no_findings() {
        let directory = TempDir::new().unwrap();
        fs::write(directory.path().join("settings.conf"), b"same").unwrap();
        let (db, guard) = test_guard(directory.path());
        guard.run_once().unwrap();

        let report = guard.run_once().unwrap();

        assert!(!report.baseline);
        assert_eq!(report.entries, 1);
        assert_eq!(report.added, 0);
        assert_eq!(report.modified, 0);
        assert_eq!(report.removed, 0);
        assert_eq!(report.findings, 0);
        assert!(db.list_findings(10, true).unwrap().is_empty());
    }

    #[test]
    fn added_persistence_file_is_candidate_finding() {
        let directory = TempDir::new().unwrap();
        let (db, guard) = test_guard(directory.path());
        guard.run_once().unwrap();
        let persistence_dir = directory.path().join(".config/systemd/user");
        fs::create_dir_all(&persistence_dir).unwrap();
        let path = persistence_dir.join("example.service");
        fs::write(&path, b"[Service]\nExecStart=/bin/true\n").unwrap();

        let report = guard.run_once().unwrap();
        let findings = db.list_findings(10, true).unwrap();

        assert_eq!(report.added, 1);
        assert_eq!(report.findings, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "persistence");
        assert_eq!(findings[0].tier, Tier::Candidate);
        assert_eq!(findings[0].subject, path.to_string_lossy());
        let detail = detail(&findings[0]);
        assert_eq!(detail["change"], "added");
        assert_eq!(detail["path"], path.to_string_lossy().as_ref());
        assert!(detail["old_sha256"].is_null());
        assert!(detail["new_sha256"].is_string());
    }

    #[test]
    fn modified_file_is_candidate_finding() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("application.conf");
        fs::write(&path, b"before").unwrap();
        let (db, guard) = test_guard(directory.path());
        guard.run_once().unwrap();
        fs::write(&path, b"after").unwrap();

        let report = guard.run_once().unwrap();
        let findings = db.list_findings(10, true).unwrap();

        assert_eq!(report.modified, 1);
        assert_eq!(report.findings, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "integrity");
        assert_eq!(findings[0].tier, Tier::Candidate);
        assert_eq!(findings[0].subject, path.to_string_lossy());
        let detail = detail(&findings[0]);
        assert_eq!(detail["change"], "modified");
        assert_ne!(detail["old_sha256"], detail["new_sha256"]);
    }

    #[test]
    fn removed_file_is_candidate_finding() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("application.conf");
        fs::write(&path, b"present").unwrap();
        let (db, guard) = test_guard(directory.path());
        guard.run_once().unwrap();
        fs::remove_file(&path).unwrap(); // allowed-delete: test fixture only

        let report = guard.run_once().unwrap();
        let findings = db.list_findings(10, true).unwrap();

        assert_eq!(report.removed, 1);
        assert_eq!(report.findings, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "integrity");
        assert_eq!(findings[0].tier, Tier::Candidate);
        assert_eq!(findings[0].subject, path.to_string_lossy());
        let detail = detail(&findings[0]);
        assert_eq!(detail["change"], "removed");
        assert!(detail["old_sha256"].is_string());
        assert!(detail["new_sha256"].is_null());
    }

    #[test]
    fn packages_disabled_reports_none() {
        let directory = TempDir::new().unwrap();
        let (_db, guard) = test_guard(directory.path());
        guard.run_once().unwrap();

        let report = guard.run_once().unwrap();

        assert_eq!(report.packages_checked, None);
    }
}
