//! YARA-X rule loading and scanning.
//!
//! Rules are compiled once at load time and recompiled on
//! [`crate::ScanEngine::reload_rules`]. The compiled [`yara_x::Rules`] value is
//! kept behind a mutex because the engine is shared across the watcher thread
//! and request handlers.

use anyhow::{Context, Result};
use blue_core::{Confidence, Detector, DetectorResult};
use std::path::{Path, PathBuf};
use std::time::Duration;
use yara_x::{Compiler, MetaValue, Rules, Scanner};

/// Compiled rules plus the number of source files they came from.
pub(crate) struct RuleSet {
    rules: Option<Rules>,
    files: usize,
}

impl RuleSet {
    /// Compile every `*.yar` / `*.yara` file found under `dirs`.
    ///
    /// Missing directories are logged and skipped: a fresh install with an
    /// empty rule directory should not stop the watcher. A file that exists but
    /// fails to parse is an error, so a bad rule cannot silently disappear.
    pub(crate) fn compile(dirs: &[PathBuf]) -> Result<RuleSet> {
        let mut files = Vec::new();
        for dir in dirs {
            collect_rule_files(dir, &mut files)?;
        }
        files.sort();
        files.dedup();

        if files.is_empty() {
            tracing::warn!("no YARA rule files configured; YARA scanning is inactive");
            return Ok(RuleSet {
                rules: None,
                files: 0,
            });
        }

        let mut compiler = Compiler::new();
        for file in &files {
            let source = std::fs::read_to_string(file)
                .with_context(|| format!("reading YARA rule {}", file.display()))?;
            compiler
                .add_source(source.as_str())
                .with_context(|| format!("compiling YARA rule {}", file.display()))?;
        }

        let count = files.len();
        let rules = compiler.build();
        tracing::info!(files = count, "YARA rules compiled");
        Ok(RuleSet {
            rules: Some(rules),
            files: count,
        })
    }

    /// Number of rule files in this set.
    pub(crate) fn file_count(&self) -> usize {
        self.files
    }

    /// Scan one file and translate matching rules into detector results.
    pub(crate) fn scan(&self, path: &Path, timeout: Duration) -> Result<Vec<DetectorResult>> {
        let Some(rules) = &self.rules else {
            return Ok(Vec::new());
        };

        let mut scanner = Scanner::new(rules);
        scanner.set_timeout(timeout);
        let results = scanner
            .scan_file(path)
            .with_context(|| format!("scanning {} with YARA", path.display()))?;

        let mut found = Vec::new();
        for rule in results.matching_rules() {
            let mut confidence = Confidence::Medium;
            let mut severity = None;
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("confidence", MetaValue::String(s)) => {
                        confidence = parse_confidence(s);
                    }
                    ("severity", MetaValue::String(s)) => {
                        severity = Some(s.to_string());
                    }
                    _ => {}
                }
            }

            let mut detail = format!("namespace={}", rule.namespace());
            if let Some(severity) = severity {
                detail.push_str("; severity=");
                detail.push_str(&severity);
            }
            found.push(
                DetectorResult::new(Detector::Yara, rule.identifier(), confidence)
                    .with_detail(detail),
            );
        }
        Ok(found)
    }
}

/// Rule metadata `confidence = "low" | "medium" | "high"`; default is medium.
fn parse_confidence(raw: &str) -> Confidence {
    match raw.trim().to_ascii_lowercase().as_str() {
        "low" => Confidence::Low,
        "high" => Confidence::High,
        _ => Confidence::Medium,
    }
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(dir = %dir.display(), "YARA rule directory does not exist");
            return Ok(());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading YARA rule dir {}", dir.display()));
        }
    };

    for entry in entries {
        let entry =
            entry.with_context(|| format!("reading entry in YARA rule dir {}", dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("stat {}", entry.path().display()))?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_rule_files(&path, out)?;
        } else if file_type.is_file() && is_rule_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_rule_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_defaults_and_parses() {
        assert_eq!(parse_confidence("HIGH"), Confidence::High);
        assert_eq!(parse_confidence(" low "), Confidence::Low);
        assert_eq!(parse_confidence("medium"), Confidence::Medium);
        assert_eq!(parse_confidence("nonsense"), Confidence::Medium);
    }

    #[test]
    fn missing_dir_is_not_fatal() {
        let set = RuleSet::compile(&[PathBuf::from("/definitely/not/a/rule/dir")])
            .expect("missing dir should be skipped");
        assert_eq!(set.file_count(), 0);
        assert!(set.rules.is_none());
    }
}
