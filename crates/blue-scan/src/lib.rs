//! `blue-scan` — file scanning and quarantine.
//!
//! One pass over a file looks like: stat, size-cap check, SHA-256, YARA-X,
//! clamd (INSTREAM), then persist the observation, evidence and tier. A file
//! is only moved when the verdict reaches T2 *and* the kill switch is off.
//!
//! Nothing in this crate deletes a file. Quarantine moves it and records how to
//! move it back.

mod clamd;
mod watch;
mod yara;

pub use clamd::{clamd_ping, clamd_scan};
pub use watch::watch;

use anyhow::{Context, Result};
use blue_core::{
    classify, now_ms, reason, sha256_file, Config, Db, DetectorResult, Quarantine, Tier,
};
use blue_reputation::{ReputationConfig, ReputationEngine};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};
use yara::RuleSet;

/// How long clamd gets for one INSTREAM conversation, end to end.
const CLAMD_TIMEOUT: Duration = Duration::from_secs(30);

/// Scanning configuration, flattened out of [`blue_core::Config`].
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub roots: Vec<PathBuf>,
    pub exclude_globs: Vec<String>,
    pub max_file_size_bytes: u64,
    pub clamd_socket: PathBuf,
    pub clamd_required: bool,
    pub yara_dirs: Vec<PathBuf>,
    pub yara_timeout_ms: u64,
    pub reputation: ReputationConfig,
}

impl ScanConfig {
    pub fn from_config(c: &Config) -> ScanConfig {
        let mut yara_dirs: Vec<PathBuf> = c
            .scan
            .yara
            .rule_dirs
            .iter()
            .map(|p| blue_core::config::expand_tilde(p))
            .collect();
        // `rule_paths` names individual files; the engine works per directory,
        // so honour them by compiling the directory that contains each file.
        for file in &c.scan.yara.rule_paths {
            let path = blue_core::config::expand_tilde(file);
            let dir = path.parent().unwrap_or(&path).to_path_buf();
            if !yara_dirs.contains(&dir) {
                yara_dirs.push(dir);
            }
        }

        ScanConfig {
            roots: c.roots(),
            exclude_globs: c.scan.exclude_globs.clone(),
            max_file_size_bytes: c.scan.max_file_size_mb.saturating_mul(1024 * 1024),
            clamd_socket: blue_core::config::expand_tilde(&c.scan.clamav.socket),
            clamd_required: c.scan.clamav.required,
            yara_dirs,
            yara_timeout_ms: c.scan.yara.timeout_ms,
            reputation: ReputationConfig::from_config(c),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exclude_globs: Vec::new(),
            max_file_size_bytes: 512 * 1024 * 1024,
            clamd_socket: PathBuf::from("/run/clamav/clamd.ctl"),
            clamd_required: false,
            yara_dirs: Vec::new(),
            yara_timeout_ms: 5000,
            reputation: ReputationConfig::default(),
        }
    }
}

/// The outcome of looking at one path.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub path: PathBuf,
    pub sha256: String,
    pub artifact_id: i64,
    pub tier: Tier,
    pub results: Vec<DetectorResult>,
    /// Quarantine record id, when the file actually moved.
    pub quarantined: Option<i64>,
}

pub struct ScanEngine {
    db: Arc<Db>,
    quarantine: Arc<Quarantine>,
    cfg: ScanConfig,
    rules: Mutex<RuleSet>,
    exclude: GlobSet,
    degraded: Option<String>,
    reputation: Option<ReputationEngine>,
    reputation_online: bool,
}

impl ScanEngine {
    /// Build an engine, compile rules and probe for clamd.
    ///
    /// A missing clamd socket is fatal only when `clamd_required` is set;
    /// otherwise the engine starts degraded and YARA carries the load.
    pub fn new(db: Arc<Db>, quarantine: Arc<Quarantine>, cfg: ScanConfig) -> Result<Self> {
        let exclude = build_excludes(&cfg.exclude_globs)?;
        let rules = RuleSet::compile(&cfg.yara_dirs).context("loading YARA rules")?;

        let mut degraded_reasons = Vec::new();
        if !cfg.clamd_socket.exists() {
            if cfg.clamd_required {
                anyhow::bail!(
                    "clamd socket {} is required but missing",
                    cfg.clamd_socket.display()
                );
            }
            degraded_reasons.push(format!(
                "clamd socket {} missing; scanning with YARA only",
                cfg.clamd_socket.display()
            ));
        }
        let reputation_online = cfg.reputation.virustotal_query_on_scan;
        let reputation = match ReputationEngine::new(db.clone(), cfg.reputation.clone()) {
            Ok(engine) => Some(engine),
            Err(error) => {
                degraded_reasons.push(format!("local reputation unavailable: {error}"));
                None
            }
        };
        let degraded = (!degraded_reasons.is_empty()).then(|| degraded_reasons.join("; "));
        if let Some(reason) = &degraded {
            tracing::warn!("scanner degraded: {reason}");
        }

        Ok(Self {
            db,
            quarantine,
            cfg,
            rules: Mutex::new(rules),
            exclude,
            degraded,
            reputation,
            reputation_online,
        })
    }

    /// Compile YARA rules again, returning the number of rule files loaded.
    ///
    /// The existing rules stay active if the new set does not compile.
    pub fn reload_rules(&mut self) -> Result<usize> {
        let rules = RuleSet::compile(&self.cfg.yara_dirs).context("reloading YARA rules")?;
        let count = rules.file_count();
        let mut current = self
            .rules
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = rules;
        tracing::info!(files = count, "YARA rules reloaded");
        Ok(count)
    }

    /// Degraded-mode explanation, if the engine is not running at full power.
    pub fn degraded(&self) -> Option<String> {
        self.degraded.clone()
    }

    /// Scan a single path and persist the verdict.
    pub fn scan_path(&self, path: &Path) -> Result<ScanOutcome> {
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !meta.is_file() {
            anyhow::bail!("{} is not a regular file", path.display());
        }

        let size = meta.len();
        if size > self.cfg.max_file_size_bytes {
            tracing::debug!(
                path = %path.display(),
                size,
                cap = self.cfg.max_file_size_bytes,
                "skipping oversized file"
            );
            return Ok(ScanOutcome {
                path: path.to_path_buf(),
                sha256: String::new(),
                artifact_id: 0,
                tier: Tier::Observed,
                results: Vec::new(),
                quarantined: None,
            });
        }

        let mtime_ms = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as i64)
            .unwrap_or_else(now_ms);
        let size = i64::try_from(size).unwrap_or(i64::MAX);
        let sha256 = sha256_file(path).with_context(|| format!("hashing {}", path.display()))?;

        let mut results = self.run_detectors(path);
        if let Some(reputation) = &self.reputation {
            match reputation.check_hash(&sha256, self.reputation_online) {
                Ok(result) => {
                    if let Some(detector) = result.detector {
                        results.push(detector);
                    }
                }
                Err(error) => tracing::warn!(
                    path = %path.display(),
                    %error,
                    "reputation check degraded"
                ),
            }
        }
        results.sort_by(|a, b| {
            a.detector
                .as_str()
                .cmp(b.detector.as_str())
                .then_with(|| a.signature.cmp(&b.signature))
        });

        let now = now_ms();
        let artifact_id = self
            .db
            .record_artifact(&path.to_string_lossy(), &sha256, size, mtime_ms, now)
            .with_context(|| format!("recording artifact {}", path.display()))?;
        for result in &results {
            self.db
                .add_evidence(artifact_id, result, now)
                .with_context(|| format!("recording evidence for {}", path.display()))?;
        }

        let tier = classify(&results);
        self.db
            .set_tier(artifact_id, tier)
            .with_context(|| format!("setting tier for {}", path.display()))?;

        let kill_switch = self.db.kill_switch();
        let mut quarantined = None;
        let mut quarantine_error = None;

        // T2 is the floor, and the kill switch is absolute.
        if tier.may_quarantine() && !kill_switch {
            let why = reason(&results, tier);
            match self.quarantine.store(path, artifact_id, tier, &why) {
                Ok(item) => quarantined = Some(item.id),
                Err(e) => {
                    // Leave the file where it is and keep the observation.
                    tracing::error!(
                        path = %path.display(),
                        error = %e,
                        "quarantine failed"
                    );
                    quarantine_error = Some(e.to_string());
                }
            }
        }

        let payload = serde_json::json!({
            "sha256": sha256,
            "size": size,
            "tier": tier.label(),
            "kill_switch": kill_switch,
            "quarantined": quarantined,
            "quarantine_error": quarantine_error,
            "detectors": results.iter().map(|r| serde_json::json!({
                "detector": r.detector.as_str(),
                "signature": r.signature,
                "confidence": format!("{:?}", r.confidence).to_lowercase(),
                "detail": r.detail,
            })).collect::<Vec<_>>(),
        });
        let level = if tier >= Tier::Corroborated {
            "warn"
        } else if tier >= Tier::Candidate {
            "info"
        } else {
            "debug"
        };
        self.db
            .event(
                "scan",
                level,
                Some(&path.to_string_lossy()),
                &payload.to_string(),
                now_ms(),
            )
            .with_context(|| format!("recording scan event for {}", path.display()))?;

        Ok(ScanOutcome {
            path: path.to_path_buf(),
            sha256,
            artifact_id,
            tier,
            results,
            quarantined,
        })
    }

    pub(crate) fn is_excluded(&self, path: &Path) -> bool {
        self.exclude.is_match(path)
    }

    fn run_detectors(&self, path: &Path) -> Vec<DetectorResult> {
        let mut results = Vec::new();

        {
            let rules = self
                .rules
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match rules.scan(path, Duration::from_millis(self.cfg.yara_timeout_ms)) {
                Ok(found) => results.extend(found),
                Err(e) => {
                    // One unreadable or pathological file must not kill a scan.
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "YARA scan failed"
                    );
                }
            }
        }

        if let Some(hit) = clamd::clamd_scan(&self.cfg.clamd_socket, path, CLAMD_TIMEOUT) {
            results.push(hit);
        }

        results
    }
}

fn build_excludes(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob =
            Glob::new(pattern).with_context(|| format!("invalid exclude glob {pattern:?}"))?;
        builder.add(glob);
    }
    builder.build().context("building exclude glob set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use blue_core::Confidence;

    /// The standard EICAR antivirus test file, 68 bytes.
    const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    struct Fixture {
        dir: tempfile::TempDir,
        db: Arc<Db>,
        engine: ScanEngine,
    }

    fn fixture(adjust: impl FnOnce(&mut ScanConfig)) -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open_memory().unwrap());
        let quarantine =
            Arc::new(Quarantine::new(dir.path().join("quarantine"), db.clone()).unwrap());
        let mut reputation = ReputationConfig {
            local_dir: dir.path().join("hash-feeds"),
            ..ReputationConfig::default()
        };
        reputation.sources.clear();
        reputation.virustotal_enabled = false;

        let mut cfg = ScanConfig {
            roots: vec![dir.path().to_path_buf()],
            exclude_globs: vec!["**/excluded/**".into()],
            max_file_size_bytes: 8 * 1024 * 1024,
            clamd_socket: dir.path().join("no-clamd.sock"),
            clamd_required: false,
            yara_dirs: vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules")],
            yara_timeout_ms: 5000,
            reputation,
        };
        adjust(&mut cfg);

        let engine = ScanEngine::new(db.clone(), quarantine, cfg).unwrap();
        Fixture { dir, db, engine }
    }

    fn write(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn eicar_is_corroborated_and_quarantined() {
        let f = fixture(|_| {});
        let path = write(&f.dir, "eicar.com", EICAR.as_bytes());

        let outcome = f.engine.scan_path(&path).unwrap();
        assert!(
            outcome.tier >= Tier::Corroborated,
            "expected at least T2, got {}",
            outcome.tier.label()
        );
        assert!(outcome.quarantined.is_some());
        assert!(outcome
            .results
            .iter()
            .any(|r| r.detector == blue_core::Detector::Yara));
        assert!(!path.exists(), "quarantine should have moved the file");

        let items = f.db.list_quarantine(false).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].sha256, outcome.sha256);
        assert!(items[0].tier.may_quarantine());
    }

    #[test]
    fn clean_file_is_observed_and_untouched() {
        let f = fixture(|_| {});
        let path = write(&f.dir, "notes.txt", b"an ordinary note\n");

        let outcome = f.engine.scan_path(&path).unwrap();
        assert_eq!(outcome.tier, Tier::Observed);
        assert!(outcome.quarantined.is_none());
        assert!(outcome.artifact_id > 0);
        assert!(!outcome.sha256.is_empty());
        assert!(path.exists(), "a clean file must not move");
    }

    #[test]
    fn exact_local_reputation_hash_is_corroborated() {
        let bytes = b"known-malicious-hash-fixture";
        let hash = blue_core::sha256_bytes(bytes);
        let f = fixture(|cfg| {
            std::fs::create_dir_all(&cfg.reputation.local_dir).unwrap();
            std::fs::write(
                cfg.reputation.local_dir.join("test.sha256"),
                format!("{hash};unit test IOC\n"),
            )
            .unwrap();
        });
        let path = write(&f.dir, "known.bin", bytes);
        let outcome = f.engine.scan_path(&path).unwrap();
        assert_eq!(outcome.tier, Tier::Corroborated);
        assert!(outcome
            .results
            .iter()
            .any(|result| result.detector == blue_core::Detector::HashRep));
        assert!(outcome.quarantined.is_some());
    }

    #[test]
    fn oversized_file_is_not_scanned_or_quarantined() {
        let f = fixture(|cfg| cfg.max_file_size_bytes = 4);
        let path = write(&f.dir, "eicar.com", EICAR.as_bytes());

        let outcome = f.engine.scan_path(&path).unwrap();
        assert_eq!(outcome.tier, Tier::Observed);
        assert!(outcome.quarantined.is_none());
        assert!(outcome.results.is_empty());
        assert!(outcome.sha256.is_empty());
        assert_eq!(outcome.artifact_id, 0);
        assert!(path.exists());
        assert!(f.db.recent_artifacts(10).unwrap().is_empty());
    }

    #[test]
    fn kill_switch_records_but_does_not_move() {
        let f = fixture(|_| {});
        f.db.set_kill_switch(true).unwrap();
        let path = write(&f.dir, "eicar.com", EICAR.as_bytes());

        let outcome = f.engine.scan_path(&path).unwrap();
        assert!(outcome.tier >= Tier::Corroborated);
        assert!(outcome.quarantined.is_none());
        assert!(path.exists(), "kill switch must leave the file in place");
        assert!(f.db.list_quarantine(false).unwrap().is_empty());
    }

    #[test]
    fn webshell_indicators_stay_at_candidate() {
        let f = fixture(|_| {});
        let path = write(&f.dir, "tool.php", b"<?php eval($_POST['cmd']); ?>");

        let outcome = f.engine.scan_path(&path).unwrap();
        assert_eq!(outcome.tier, Tier::Candidate);
        assert!(outcome.quarantined.is_none());
        assert!(path.exists());
    }

    #[test]
    fn rules_reload_returns_at_least_two() {
        let mut f = fixture(|_| {});
        let count = f.engine.reload_rules().unwrap();
        assert!(count >= 2, "expected both shipped rule files, got {count}");
    }

    #[test]
    fn missing_clamd_degrades_when_optional() {
        let f = fixture(|_| {});
        assert!(f.engine.degraded().is_some());
    }

    #[test]
    fn watcher_scans_a_new_file() {
        let f = fixture(|_| {});
        let root = f.dir.path().join("watched");
        std::fs::create_dir(&root).unwrap();

        let db = f.db.clone();
        let engine = Arc::new(f.engine);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        watch(engine, vec![root], 50, stop_rx).unwrap();

        let path = write(&f.dir, "watched/new.txt", b"hello watcher\n");
        let key = path.to_string_lossy().to_string();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = db
                .recent_artifacts(20)
                .unwrap()
                .iter()
                .any(|a| a.path == key);
            if seen {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "watcher did not scan {} in time",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(25));
        }

        let _ = stop_tx.send(true);
        std::thread::sleep(Duration::from_millis(100));
    }

    #[test]
    fn missing_clamd_is_fatal_when_required() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open_memory().unwrap());
        let quarantine = Arc::new(Quarantine::new(dir.path().join("q"), db.clone()).unwrap());
        let cfg = ScanConfig {
            clamd_socket: dir.path().join("absent.sock"),
            clamd_required: true,
            ..ScanConfig::default()
        };
        assert!(ScanEngine::new(db, quarantine, cfg).is_err());
    }

    #[test]
    fn config_mapping_uses_megabytes_and_expanded_roots() {
        let cfg = Config::default();
        let scan = ScanConfig::from_config(&cfg);
        assert_eq!(
            scan.max_file_size_bytes,
            cfg.scan.max_file_size_mb * 1024 * 1024
        );
        assert!(!scan.yara_dirs.is_empty());
        assert_eq!(scan.clamd_required, cfg.scan.clamav.required);
    }

    #[test]
    fn confidence_metadata_is_read_by_the_engine() {
        // The shipped EICAR rule is high confidence; a high rule alone is T2.
        let f = fixture(|_| {});
        let path = write(&f.dir, "eicar.com", EICAR.as_bytes());
        let outcome = f.engine.scan_path(&path).unwrap();
        assert!(outcome
            .results
            .iter()
            .any(|r| r.confidence == Confidence::High));
    }
}
