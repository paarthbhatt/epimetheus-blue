//! Local and opt-in hash reputation.
//!
//! Local lists are loaded without following symlinks. Remote list updates are
//! validated and staged next to their destination before an atomic rename.
//! VirusTotal integration sends only a caller-supplied SHA-256 digest; this
//! crate has no file-upload code path.

use anyhow::{bail, Context, Result};
use blue_core::{
    now_ms, sha256_file, Confidence, Config, Db, Detector, DetectorResult, ReputationRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{Duration, Instant, SystemTime};

const VIRUSTOTAL_SOURCE: &str = "virustotal";
const VIRUSTOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const VIRUSTOTAL_MAX_BYTES: usize = 2 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_DOWNLOAD_BYTES: usize = 16 * 1024 * 1024;
const MIN_SOURCE_HASHES: usize = 100;
const MAX_SOURCE_NAME_BYTES: usize = 128;
const UNIQUE_PATH_ATTEMPTS: usize = 128;
const MILLIS_PER_HOUR: u64 = 60 * 60 * 1_000;
const LOCAL_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

static UNIQUE_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One configured remote hash-list provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSource {
    pub name: String,
    pub url: String,
    pub license: Option<String>,
}

/// Runtime configuration for [`ReputationEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    pub local_dir: PathBuf,
    pub sources: Vec<ReputationSource>,
    pub virustotal_enabled: bool,
    pub virustotal_query_on_scan: bool,
    /// Name of the environment variable holding the key, never the key itself.
    pub virustotal_api_key_env: String,
    pub virustotal_api_key_file: Option<PathBuf>,
    pub virustotal_min_malicious: u32,
    pub cache_hours: u64,
}

impl ReputationConfig {
    pub fn from_config(config: &Config) -> ReputationConfig {
        ReputationConfig {
            local_dir: blue_core::config::expand_tilde(&config.reputation.local_dir),
            sources: config
                .reputation
                .sources
                .iter()
                .map(|source| ReputationSource {
                    name: source.name.clone(),
                    url: source.url.clone(),
                    license: source.license.clone(),
                })
                .collect(),
            virustotal_enabled: config.reputation.virustotal_enabled,
            virustotal_query_on_scan: config.reputation.virustotal_query_on_scan,
            virustotal_api_key_env: config.reputation.virustotal_api_key_env.clone(),
            virustotal_api_key_file: config
                .reputation
                .virustotal_api_key_file
                .as_deref()
                .map(blue_core::config::expand_tilde),
            virustotal_min_malicious: config.reputation.virustotal_min_malicious,
            cache_hours: config.reputation.cache_hours,
        }
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self::from_config(&Config::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationResult {
    pub sha256: String,
    pub local_match: Option<String>,
    pub virustotal: Option<ReputationRecord>,
    pub detector: Option<DetectorResult>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationStatus {
    pub local_hashes: usize,
    pub local_sources: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HashSyncReport {
    pub updated: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub total_hashes: usize,
}

#[derive(Debug, Default)]
struct LocalIndex {
    hashes: HashMap<String, String>,
    source_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct LocalFileStamp {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}

struct LocalRefresh {
    checked: Instant,
    files: Vec<LocalFileStamp>,
}

pub struct ReputationEngine {
    db: Arc<Db>,
    cfg: ReputationConfig,
    local: RwLock<LocalIndex>,
    operation_lock: Mutex<()>,
    refresh: Mutex<LocalRefresh>,
}

impl ReputationEngine {
    pub fn new(db: Arc<Db>, cfg: ReputationConfig) -> Result<Self> {
        validate_config(&cfg)?;
        std::fs::create_dir_all(&cfg.local_dir)?;
        let files = local_file_stamps(&cfg.local_dir)?;
        let local = load_local_index(&cfg.local_dir)?;
        if files != local_file_stamps(&cfg.local_dir)? {
            bail!("local sources changed during initial load");
        }
        Ok(Self {
            db,
            cfg,
            local: RwLock::new(local),
            operation_lock: Mutex::new(()),
            refresh: Mutex::new(LocalRefresh {
                checked: Instant::now(),
                files,
            }),
        })
    }

    pub fn check_hash(&self, sha256: &str, online: bool) -> Result<ReputationResult> {
        let sha256 = canonical_sha256(sha256)?;
        self.refresh_local_if_due(Instant::now());
        let local_match = self.local_read().hashes.get(&sha256).cloned();

        // A known local IOC needs no network corroboration and survives outages.
        let virustotal = if online && self.cfg.virustotal_enabled && local_match.is_none() {
            Some(self.check_virustotal(&sha256)?)
        } else {
            None
        };
        let detector = detector_result(
            local_match.as_deref(),
            virustotal.as_ref(),
            self.cfg.virustotal_min_malicious,
        );

        Ok(ReputationResult {
            sha256,
            local_match,
            virustotal,
            detector,
        })
    }

    pub fn check_file(&self, path: &Path, online: bool) -> Result<ReputationResult> {
        let sha256 = sha256_file(path)?;
        self.check_hash(&sha256, online)
    }

    /// Fetch and activate every configured HTTPS source. Provider failures are
    /// collected independently and never replace that provider's active list.
    pub fn sync(&self) -> Result<HashSyncReport> {
        let agent = ureq::AgentBuilder::new()
            .timeout(DOWNLOAD_TIMEOUT)
            .redirects(0)
            .build();
        let mut report = HashSyncReport::default();

        for source in &self.cfg.sources {
            match self.sync_source(&agent, source) {
                Ok(hashes) => {
                    report.total_hashes += hashes;
                    report.updated.push(source.name.clone());
                }
                Err(error) => report.failed.push((source.name.clone(), error.to_string())),
            }
        }

        Ok(report)
    }

    pub fn status(&self) -> ReputationStatus {
        let local = self.local_read();
        ReputationStatus {
            local_hashes: local.hashes.len(),
            local_sources: local.source_count,
        }
    }

    /// Validate and atomically activate already-downloaded source text.
    pub(crate) fn activate_text(&self, name: &str, text: &str) -> Result<usize> {
        let _operation = self.operation_guard()?;
        self.activate_text_locked(name, text)
    }

    /// Restore the fixed `.prev` snapshot while retaining both it and the
    /// rejected active version.
    pub fn rollback(&self, name: &str) -> Result<()> {
        validate_source_name(name)?;
        let _operation = self.operation_guard()?;
        let active = self.cfg.local_dir.join(format!("{name}.txt"));
        let previous = self.cfg.local_dir.join(format!("{name}.txt.prev"));
        if !managed_file_exists(&previous, "previous hash source")? {
            bail!("no previous version for {name}");
        }
        let active_exists = managed_file_exists(&active, "active hash source")?;

        let staged =
            retain_at_unique_path(&previous, &self.cfg.local_dir, name, "rollback-staged")?;
        if active_exists {
            retain_at_unique_path(&active, &self.cfg.local_dir, name, "rejected")?;
        }
        std::fs::rename(&staged, &active)
            .with_context(|| format!("rolling back hash source {}", active.display()))?;
        sync_directory(&self.cfg.local_dir)?;
        self.reload_local()
    }

    fn sync_source(&self, agent: &ureq::Agent, source: &ReputationSource) -> Result<usize> {
        validate_source_name(&source.name)?;
        if !source.url.starts_with("https://") {
            bail!("hash source URL must use HTTPS");
        }

        let response = agent
            .get(&source.url)
            .call()
            .with_context(|| format!("fetching hash source {}", source.name))?;
        if (300..400).contains(&response.status()) {
            bail!("hash source redirects are not allowed");
        }
        let bytes = read_limited_response(
            response,
            MAX_DOWNLOAD_BYTES,
            "hash source response",
            "16 MiB",
        )?;
        let text = String::from_utf8(bytes).context("hash source is not UTF-8 text")?;
        self.activate_text(&source.name, &text)
    }

    fn activate_text_locked(&self, name: &str, text: &str) -> Result<usize> {
        validate_source_name(name)?;
        if text.len() > MAX_DOWNLOAD_BYTES {
            bail!("hash source exceeds 16 MiB limit");
        }
        let hashes = parse_hashes(text.as_bytes());
        if hashes.len() < MIN_SOURCE_HASHES {
            bail!(
                "hash source has {} distinct SHA-256 hashes; need at least {MIN_SOURCE_HASHES}",
                hashes.len()
            );
        }

        std::fs::create_dir_all(&self.cfg.local_dir).with_context(|| {
            format!(
                "creating hash source directory {}",
                self.cfg.local_dir.display()
            )
        })?;
        let active = self.cfg.local_dir.join(format!("{name}.txt"));
        let previous = self.cfg.local_dir.join(format!("{name}.txt.prev"));
        let active_exists = managed_file_exists(&active, "active hash source")?;
        let previous_exists = managed_file_exists(&previous, "previous hash source")?;

        let staged = write_unique_file(&self.cfg.local_dir, name, "staged", text.as_bytes())?;

        if active_exists {
            if previous_exists {
                retain_at_unique_path(&previous, &self.cfg.local_dir, name, "previous")?;
            }
            let pending_previous =
                retain_at_unique_path(&active, &self.cfg.local_dir, name, "pending-previous")?;
            std::fs::rename(&pending_previous, &previous)
                .with_context(|| format!("installing rollback copy {}", previous.display()))?;
        }

        std::fs::rename(&staged, &active)
            .with_context(|| format!("activating hash source {}", active.display()))?;
        sync_directory(&self.cfg.local_dir)?;
        self.reload_local()?;
        Ok(hashes.len())
    }

    fn reload_local(&self) -> Result<()> {
        let files = local_file_stamps(&self.cfg.local_dir)?;
        let new_index = load_local_index(&self.cfg.local_dir)?;
        if files != local_file_stamps(&self.cfg.local_dir)? {
            bail!("local sources changed during reload");
        }
        *self.local_write() = new_index;
        if let Ok(mut refresh) = self.refresh.try_lock() {
            refresh.files = files;
            refresh.checked = Instant::now();
        }
        Ok(())
    }

    /// Hot lookups avoid filesystem/DB work until this monotonic deadline.
    fn refresh_local_if_due(&self, now: Instant) {
        let Ok(mut refresh) = self.refresh.try_lock() else {
            return;
        };
        if now.saturating_duration_since(refresh.checked) < LOCAL_REFRESH_INTERVAL {
            return;
        }
        // Never wait behind an activation/rollback while holding refresh state.
        let Ok(_operation) = self.operation_lock.try_lock() else {
            return;
        };
        refresh.checked = now;
        self.refresh_local_checked(&mut refresh);
    }

    fn refresh_local_checked(&self, refresh: &mut LocalRefresh) {
        let result = (|| -> Result<()> {
            let files = local_file_stamps(&self.cfg.local_dir)?;
            if files == refresh.files {
                return Ok(());
            }
            for previous in &refresh.files {
                if let Ok(metadata) = std::fs::symlink_metadata(&previous.path) {
                    if !metadata.is_file() {
                        bail!("previous local source is no longer a regular file");
                    }
                }
            }
            let index = load_local_index(&self.cfg.local_dir)?;
            if files != local_file_stamps(&self.cfg.local_dir)? {
                bail!("local sources changed during reload");
            }
            *self.local_write() = index;
            refresh.files = files;
            Ok(())
        })();
        if let Err(error) = result {
            let payload = serde_json::json!({
                "status": "degraded", "retained_last_good": true,
                "reason": format!("{error:#}"),
            });
            let _ = self.db.event(
                "reputation.local",
                "warn",
                None,
                &payload.to_string(),
                now_ms(),
            );
        }
    }

    fn check_virustotal(&self, sha256: &str) -> Result<ReputationRecord> {
        let timestamp = now_ms();
        if let Some(cached) = self.db.reputation(sha256, VIRUSTOTAL_SOURCE)? {
            if cache_is_fresh(&cached, timestamp, self.cfg.cache_hours) {
                return Ok(cached);
            }
        }

        let api_key = read_api_key(
            &self.cfg.virustotal_api_key_env,
            self.cfg.virustotal_api_key_file.as_deref(),
        )?;
        if !self.db.reserve_virustotal_slot(timestamp)? {
            bail!("VirusTotal lookup deferred by the shared request budget; local detection remains available");
        }
        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        let agent = ureq::AgentBuilder::new()
            .timeout(VIRUSTOTAL_TIMEOUT)
            .redirects(0)
            .build();
        let response = agent.get(&url).set("x-apikey", &api_key).call();
        let record = match response {
            Ok(response) => {
                let bytes = read_limited_response(
                    response,
                    VIRUSTOTAL_MAX_BYTES,
                    "VirusTotal response",
                    "2 MiB",
                )?;
                parse_virustotal_response(sha256, &bytes, timestamp)?
            }
            Err(ureq::Error::Status(404, _)) => unknown_virustotal_record(sha256, timestamp),
            Err(ureq::Error::Status(status, _)) => {
                bail!("VirusTotal returned HTTP {status}")
            }
            Err(ureq::Error::Transport(error)) => {
                bail!("VirusTotal request failed: {error}")
            }
        };

        self.db.upsert_reputation(&record)?;
        Ok(record)
    }

    fn operation_guard(&self) -> Result<MutexGuard<'_, ()>> {
        self.operation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("reputation operation lock poisoned"))
    }

    fn local_read(&self) -> RwLockReadGuard<'_, LocalIndex> {
        match self.local.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn local_write(&self) -> RwLockWriteGuard<'_, LocalIndex> {
        match self.local.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn validate_config(cfg: &ReputationConfig) -> Result<()> {
    if cfg.virustotal_min_malicious == 0 {
        bail!("virustotal_min_malicious must be greater than zero");
    }
    if cfg.cache_hours == 0 {
        bail!("cache_hours must be greater than zero");
    }
    if cfg.virustotal_api_key_env.is_empty() || cfg.virustotal_api_key_env.contains(['=', '\0']) {
        bail!("virustotal_api_key_env is not a valid environment variable name");
    }
    Ok(())
}

fn canonical_sha256(value: &str) -> Result<String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("SHA-256 must be exactly 64 hexadecimal characters");
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_hashes(bytes: &[u8]) -> BTreeSet<String> {
    let mut hashes = BTreeSet::new();
    for raw_line in bytes.split(|byte| *byte == b'\n') {
        let line = trim_ascii_start(raw_line);
        let token_end = match line
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b';')
        {
            Some(index) => index,
            None => line.len(),
        };
        let token = &line[..token_end];
        if token.len() == 64 && token.iter().all(|byte| byte.is_ascii_hexdigit()) {
            let hash: String = token
                .iter()
                .map(|byte| (*byte as char).to_ascii_lowercase())
                .collect();
            hashes.insert(hash);
        }
    }
    hashes
}

fn trim_ascii_start(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if !first.is_ascii_whitespace() {
            break;
        }
        value = rest;
    }
    value
}

fn local_file_stamp(path: PathBuf, metadata: &std::fs::Metadata) -> LocalFileStamp {
    LocalFileStamp {
        path,
        size: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            )
        },
    }
}

fn local_file_stamps(directory: &Path) -> Result<Vec<LocalFileStamp>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if !is_hash_list_path(&path) {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() {
            continue;
        }
        files.push(local_file_stamp(path, &metadata));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn load_local_index(directory: &Path) -> Result<LocalIndex> {
    std::fs::create_dir_all(directory)
        .with_context(|| format!("creating hash source directory {}", directory.display()))?;

    let mut paths = Vec::new();
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("reading hash source directory {}", directory.display()))?
    {
        let entry = entry.with_context(|| {
            format!(
                "reading entry in hash source directory {}",
                directory.display()
            )
        })?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if is_hash_list_path(&path) {
            paths.push(path);
        }
    }
    paths.sort();

    let mut index = LocalIndex::default();
    let mut sources = BTreeSet::new();
    for path in paths {
        let source = source_name(&path);
        let file = open_regular_nofollow(&path)?;
        let mut bytes = Vec::new();
        file.take((MAX_DOWNLOAD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading local hash source {}", path.display()))?;
        if bytes.len() > MAX_DOWNLOAD_BYTES {
            bail!("local hash source exceeds 16 MiB limit");
        }
        let hashes = parse_hashes(&bytes);
        if hashes.is_empty() {
            bail!(
                "local hash source {} has no valid SHA-256 hashes",
                path.display()
            );
        }
        for hash in hashes {
            index.hashes.entry(hash).or_insert_with(|| source.clone());
        }
        sources.insert(source);
    }
    index.source_count = sources.len();
    Ok(index)
}

fn is_hash_list_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("txt" | "hashes" | "sha256")
    )
}

fn source_name(path: &Path) -> String {
    match path.file_stem() {
        Some(stem) => stem.to_string_lossy().into_owned(),
        None => path.to_string_lossy().into_owned(),
    }
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn open_regular_nofollow(path: &Path) -> Result<File> {
    let file = open_nofollow(path)
        .with_context(|| format!("opening local hash source {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("local hash source {} is not a regular file", path.display());
    }
    Ok(file)
}

fn detector_result(
    local_match: Option<&str>,
    virustotal: Option<&ReputationRecord>,
    malicious_threshold: u32,
) -> Option<DetectorResult> {
    if let Some(source) = local_match {
        return Some(
            DetectorResult::new(
                Detector::HashRep,
                format!("local:{source}"),
                Confidence::High,
            )
            .with_detail(format!("source={source}; local_matches=1")),
        );
    }

    let record = virustotal?;
    let confidence = if record.malicious >= i64::from(malicious_threshold) {
        Confidence::High
    } else if record.malicious > 0 || record.suspicious > 0 {
        Confidence::Medium
    } else {
        return None;
    };
    Some(
        DetectorResult::new(Detector::HashRep, VIRUSTOTAL_SOURCE, confidence).with_detail(format!(
            "source={VIRUSTOTAL_SOURCE}; malicious={}; suspicious={}; harmless={}",
            record.malicious, record.suspicious, record.harmless
        )),
    )
}

fn cache_is_fresh(record: &ReputationRecord, timestamp: i64, cache_hours: u64) -> bool {
    let ttl_ms = cache_hours
        .saturating_mul(MILLIS_PER_HOUR)
        .min(i64::MAX as u64) as i64;
    record.checked_at_ms >= timestamp.saturating_sub(ttl_ms)
}

fn read_api_key(environment_variable: &str, credential_file: Option<&Path>) -> Result<String> {
    if std::env::var_os(environment_variable).is_none() {
        return read_protected_key(credential_file.context("VirusTotal key is not configured")?);
    }
    let value = std::env::var_os(environment_variable).ok_or_else(|| {
        anyhow::anyhow!("VirusTotal API key environment variable {environment_variable} is not set")
    })?;
    let value = value.into_string().map_err(|_| {
        anyhow::anyhow!(
            "VirusTotal API key environment variable {environment_variable} is not valid Unicode"
        )
    })?;
    if value.trim().is_empty() {
        bail!("VirusTotal API key environment variable {environment_variable} is empty");
    }
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!(
            "VirusTotal API key environment variable {environment_variable} contains invalid header characters"
        );
    }
    Ok(value)
}

fn validate_key_permissions(before: &std::fs::Metadata, after: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/proc/self")?.uid();
    if after.uid() != uid || after.mode() & 0o077 != 0 {
        bail!("VirusTotal credential must be user-owned with mode 0600");
    }
    if before.dev() != after.dev() || before.ino() != after.ino() {
        bail!("VirusTotal credential changed while opening");
    }
    Ok(())
}

fn read_protected_key(path: &Path) -> Result<String> {
    let before = std::fs::symlink_metadata(path).context("reading credential metadata")?;
    if !before.is_file() || before.file_type().is_symlink() {
        bail!("VirusTotal credential must be a regular file, not a symlink");
    }
    let file = File::open(path).context("opening VirusTotal credential file")?;
    validate_key_permissions(&before, &file.metadata()?)?;
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    if value.len() > 4096 || value.trim().is_empty() {
        bail!("VirusTotal credential is empty or oversized");
    }
    let value = value.trim().to_owned();
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("VirusTotal credential contains invalid header characters");
    }
    Ok(value)
}

#[derive(Debug, Deserialize)]
struct VirusTotalEnvelope {
    data: VirusTotalData,
}

#[derive(Debug, Deserialize)]
struct VirusTotalData {
    attributes: VirusTotalAttributes,
}

#[derive(Debug, Deserialize)]
struct VirusTotalAttributes {
    last_analysis_stats: VirusTotalStats,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct VirusTotalStats {
    malicious: i64,
    suspicious: i64,
    harmless: i64,
}

fn parse_virustotal_response(
    sha256: &str,
    bytes: &[u8],
    checked_at_ms: i64,
) -> Result<ReputationRecord> {
    let response: VirusTotalEnvelope =
        serde_json::from_slice(bytes).context("parsing VirusTotal response")?;
    let stats = response.data.attributes.last_analysis_stats;
    if stats.malicious < 0 || stats.suspicious < 0 || stats.harmless < 0 {
        bail!("VirusTotal response contains negative analysis counts");
    }
    let verdict = if stats.malicious > 0 {
        "malicious"
    } else if stats.suspicious > 0 {
        "suspicious"
    } else if stats.harmless > 0 {
        "harmless"
    } else {
        "unknown"
    };
    Ok(ReputationRecord {
        sha256: sha256.to_owned(),
        source: VIRUSTOTAL_SOURCE.to_owned(),
        verdict: verdict.to_owned(),
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        harmless: stats.harmless,
        checked_at_ms,
        detail: format!(
            "source={VIRUSTOTAL_SOURCE}; malicious={}; suspicious={}; harmless={}",
            stats.malicious, stats.suspicious, stats.harmless
        ),
    })
}

fn unknown_virustotal_record(sha256: &str, checked_at_ms: i64) -> ReputationRecord {
    ReputationRecord {
        sha256: sha256.to_owned(),
        source: VIRUSTOTAL_SOURCE.to_owned(),
        verdict: "unknown".to_owned(),
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        checked_at_ms,
        detail: "source=virustotal; status=unknown; malicious=0; suspicious=0; harmless=0"
            .to_owned(),
    }
}

fn read_limited_response(
    response: ureq::Response,
    max_bytes: usize,
    description: &str,
    human_limit: &str,
) -> Result<Vec<u8>> {
    let declared = response
        .header("content-length")
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|bytes| bytes > max_bytes as u64) {
        bail!("{description} exceeds {human_limit} limit");
    }

    let mut bytes = Vec::new();
    response
        .into_reader()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {description}"))?;
    if bytes.len() > max_bytes {
        bail!("{description} exceeds {human_limit} limit");
    }
    Ok(bytes)
}

fn validate_source_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_SOURCE_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("invalid hash source name {name:?}");
    }
    Ok(())
}

fn managed_file_exists(path: &Path, description: &str) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => bail!("{description} {} is not a regular file", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn unique_path(directory: &Path, name: &str, kind: &str) -> PathBuf {
    let counter = UNIQUE_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
    directory.join(format!(
        "{name}.txt.{kind}.{}.{}.{}",
        now_ms(),
        std::process::id(),
        counter
    ))
}

fn write_unique_file(directory: &Path, name: &str, kind: &str, bytes: &[u8]) -> Result<PathBuf> {
    for _ in 0..UNIQUE_PATH_ATTEMPTS {
        let path = unique_path(directory, name, kind);
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("creating stage {}", path.display()));
            }
        };
        file.write_all(bytes)
            .with_context(|| format!("writing stage {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing stage {}", path.display()))?;
        return Ok(path);
    }
    bail!("could not allocate a unique stage for hash source {name:?}")
}

fn retain_at_unique_path(
    source: &Path,
    directory: &Path,
    name: &str,
    kind: &str,
) -> Result<PathBuf> {
    for _ in 0..UNIQUE_PATH_ATTEMPTS {
        let retained = unique_path(directory, name, kind);
        match clone_file_noclobber(source, &retained) {
            Ok(()) => return Ok(retained),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("retaining {} as {}", source.display(), retained.display())
                });
            }
        }
    }
    bail!("could not allocate a retained path for hash source {name:?}")
}

fn clone_file_noclobber(source: &Path, destination: &Path) -> io::Result<()> {
    match std::fs::hard_link(source, destination) {
        Ok(()) => open_nofollow(destination)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(_) => {
            let mut input = open_nofollow(source)?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()
        }
    }
}

fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("flushing hash source directory {}", directory.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_key_file_rejects_public_permissions_and_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "test-credential\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_protected_key(&path).unwrap(), "test-credential");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_protected_key(&path).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_protected_key(&link).is_err());
    }

    fn hash(number: u64) -> String {
        format!("{number:064x}")
    }

    fn source_text(start: u64) -> String {
        (start..start + MIN_SOURCE_HASHES as u64)
            .map(|number| format!("{}; test {number}\n", hash(number)))
            .collect()
    }

    fn fixture(enabled: bool) -> (tempfile::TempDir, Arc<Db>, ReputationEngine) {
        let directory = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open(&directory.path().join("blue.db")).unwrap());
        let engine = ReputationEngine::new(
            db.clone(),
            ReputationConfig {
                local_dir: directory.path().join("hashes"),
                sources: Vec::new(),
                virustotal_enabled: enabled,
                virustotal_query_on_scan: false,
                virustotal_api_key_env: "BLUE_REPUTATION_TEST_MISSING_KEY".into(),
                virustotal_api_key_file: None,
                virustotal_min_malicious: 3,
                cache_hours: 24,
            },
        )
        .unwrap();
        (directory, db, engine)
    }

    #[test]
    fn parses_mixed_hashes_rejects_short_digests_and_uses_first_source() {
        let directory = tempfile::TempDir::new().unwrap();
        let lists = directory.path().join("hashes");
        std::fs::create_dir_all(&lists).unwrap();
        let first = hash(11);
        let second = hash(12);
        std::fs::write(
            lists.join("a.txt"),
            format!(
                "# comment\n  {first}; family\n{} extra\n{}\n{}\nnot-a-hash\n",
                second.to_ascii_uppercase(),
                "a".repeat(32),
                "b".repeat(40)
            ),
        )
        .unwrap();
        std::fs::write(lists.join("b.hashes"), format!("{first} duplicate\n")).unwrap();
        std::fs::write(lists.join("ignored.csv"), hash(13)).unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(lists.join("a.txt"), lists.join("linked.sha256")).unwrap();

        let db = Arc::new(Db::open(&directory.path().join("blue.db")).unwrap());
        let engine = ReputationEngine::new(
            db,
            ReputationConfig {
                local_dir: lists,
                sources: Vec::new(),
                virustotal_enabled: false,
                virustotal_query_on_scan: false,
                virustotal_api_key_env: "UNUSED".into(),
                virustotal_api_key_file: None,
                virustotal_min_malicious: 3,
                cache_hours: 24,
            },
        )
        .unwrap();

        assert_eq!(engine.status().local_hashes, 2);
        assert_eq!(engine.status().local_sources, 2);
        assert_eq!(
            engine
                .check_hash(&first, false)
                .unwrap()
                .local_match
                .as_deref(),
            Some("a")
        );
        assert_eq!(
            engine
                .check_hash(&second, false)
                .unwrap()
                .local_match
                .as_deref(),
            Some("a")
        );
    }

    #[test]
    fn local_match_is_high_confidence_hash_reputation() {
        let (_directory, _db, engine) = fixture(true);
        let target = hash(42);
        std::fs::write(
            engine.cfg.local_dir.join("local.sha256"),
            format!("{target}; known bad\n"),
        )
        .unwrap();
        engine.reload_local().unwrap();

        let result = engine.check_hash(&target, true).unwrap();
        assert_eq!(result.local_match.as_deref(), Some("local"));
        let detector = result.detector.unwrap();
        assert_eq!(detector.detector, Detector::HashRep);
        assert_eq!(detector.confidence, Confidence::High);
        assert!(detector.detail.unwrap().contains("source=local"));
    }

    #[test]
    fn clean_unknown_has_no_detector() {
        let (_directory, _db, engine) = fixture(false);
        let result = engine.check_hash(&hash(99), false).unwrap();
        assert!(result.local_match.is_none());
        assert!(result.virustotal.is_none());
        assert!(result.detector.is_none());
    }

    #[test]
    fn malformed_hash_is_rejected() {
        let (_directory, _db, engine) = fixture(false);
        for malformed in [
            String::new(),
            "a".repeat(32),
            "a".repeat(40),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            format!(" {}", "a".repeat(64)),
        ] {
            assert!(engine.check_hash(&malformed, false).is_err());
        }
    }

    fn refresh_due(engine: &ReputationEngine) {
        let next = engine.refresh.lock().unwrap().checked + LOCAL_REFRESH_INTERVAL;
        engine.refresh_local_if_due(next);
    }

    fn matches_local(engine: &ReputationEngine, number: u64) -> bool {
        engine
            .check_hash(&hash(number), false)
            .unwrap()
            .local_match
            .is_some()
    }

    #[test]
    fn separate_engine_observes_activation_and_rollback() {
        let (_directory, db, updater) = fixture(false);
        updater.activate_text("community", &source_text(0)).unwrap();
        let reader = ReputationEngine::new(db, updater.cfg.clone()).unwrap();
        updater
            .activate_text("community", &source_text(1000))
            .unwrap();
        assert!(!matches_local(&reader, 1000));
        refresh_due(&reader);
        assert!(matches_local(&reader, 1000));
        updater.rollback("community").unwrap();
        refresh_due(&reader);
        assert!(matches_local(&reader, 0));
        assert!(!matches_local(&reader, 1000));
    }

    #[test]
    fn invalid_external_update_retains_last_good_and_valid_update_recovers() {
        let (_directory, db, updater) = fixture(false);
        updater.activate_text("community", &source_text(0)).unwrap();
        let reader = ReputationEngine::new(db.clone(), updater.cfg.clone()).unwrap();
        let staged = updater.cfg.local_dir.join("invalid-stage");
        std::fs::write(&staged, b"not a hash source").unwrap();
        std::fs::rename(&staged, updater.cfg.local_dir.join("community.txt")).unwrap();
        refresh_due(&reader);
        assert!(matches_local(&reader, 0));
        assert_eq!(reader.status().local_hashes, MIN_SOURCE_HASHES);
        assert!(db
            .recent_events(10)
            .unwrap()
            .iter()
            .any(|event| event.kind == "reputation.local"));
        updater
            .activate_text("community", &source_text(2000))
            .unwrap();
        refresh_due(&reader);
        assert!(matches_local(&reader, 2000));
    }

    #[test]
    fn unchanged_sources_and_hot_lookups_do_not_reparse() {
        let (_directory, _db, engine) = fixture(false);
        engine.activate_text("community", &source_text(0)).unwrap();
        // A test-only marker disappears if the unchanged index is rebuilt.
        engine
            .local_write()
            .hashes
            .insert(hash(9000), "sentinel".into());
        refresh_due(&engine);
        assert_eq!(
            engine
                .check_hash(&hash(9000), false)
                .unwrap()
                .local_match
                .as_deref(),
            Some("sentinel")
        );
        let checked = engine.refresh.lock().unwrap().checked;
        std::fs::write(
            engine.cfg.local_dir.join("community.txt"),
            b"invalid update",
        )
        .unwrap();
        for _ in 0..10 {
            assert!(matches_local(&engine, 0));
        }
        assert_eq!(engine.refresh.lock().unwrap().checked, checked);
        refresh_due(&engine);
        assert!(matches_local(&engine, 0));
    }

    #[test]
    fn activation_preserves_good_data_and_prev_supports_rollback() {
        let (_directory, _db, engine) = fixture(false);
        let first = source_text(0);
        let second = source_text(1_000);
        assert_eq!(engine.activate_text("community", &first).unwrap(), 100);
        let active = engine.cfg.local_dir.join("community.txt");
        let previous = engine.cfg.local_dir.join("community.txt.prev");

        let invalid = source_text(2_000)
            .lines()
            .take(MIN_SOURCE_HASHES - 1)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(engine.activate_text("community", &invalid).is_err());
        assert_eq!(std::fs::read(&active).unwrap(), first.as_bytes());
        assert!(!previous.exists());

        engine.activate_text("community", &second).unwrap();
        assert_eq!(std::fs::read(&active).unwrap(), second.as_bytes());
        assert_eq!(std::fs::read(&previous).unwrap(), first.as_bytes());

        engine.rollback("community").unwrap();
        assert_eq!(std::fs::read(&active).unwrap(), first.as_bytes());
        assert_eq!(std::fs::read(&previous).unwrap(), first.as_bytes());
        assert_eq!(engine.status().local_hashes, 100);
    }

    #[test]
    fn sync_collects_non_https_failure_without_replacing_active_data() {
        let directory = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open(&directory.path().join("blue.db")).unwrap());
        let engine = ReputationEngine::new(
            db,
            ReputationConfig {
                local_dir: directory.path().join("hashes"),
                sources: vec![ReputationSource {
                    name: "community".into(),
                    url: "http://127.0.0.1:9/must-not-be-fetched".into(),
                    license: None,
                }],
                virustotal_enabled: false,
                virustotal_query_on_scan: false,
                virustotal_api_key_env: "UNUSED".into(),
                virustotal_api_key_file: None,
                virustotal_min_malicious: 3,
                cache_hours: 24,
            },
        )
        .unwrap();
        let original = source_text(3_000);
        engine.activate_text("community", &original).unwrap();

        let report = engine.sync().unwrap();
        assert!(report.updated.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("HTTPS"));
        assert_eq!(
            std::fs::read(engine.cfg.local_dir.join("community.txt")).unwrap(),
            original.as_bytes()
        );
        assert!(!engine.cfg.local_dir.join("community.txt.prev").exists());
    }

    #[test]
    fn cached_virustotal_result_is_classified_without_network() {
        let (_directory, db, engine) = fixture(true);
        let target = hash(500);
        db.upsert_reputation(&ReputationRecord {
            sha256: target.clone(),
            source: VIRUSTOTAL_SOURCE.into(),
            verdict: "suspicious".into(),
            malicious: 1,
            suspicious: 2,
            harmless: 60,
            checked_at_ms: now_ms(),
            detail: "cached fixture".into(),
        })
        .unwrap();

        let result = engine.check_hash(&target, true).unwrap();
        assert_eq!(result.virustotal.unwrap().malicious, 1);
        let detector = result.detector.unwrap();
        assert_eq!(detector.detector, Detector::HashRep);
        assert_eq!(detector.confidence, Confidence::Medium);
        let detail = detector.detail.unwrap();
        assert!(detail.contains("source=virustotal"));
        assert!(detail.contains("malicious=1"));
        assert!(!detail.contains("cached fixture"));
    }

    #[test]
    fn virustotal_disabled_never_requires_a_key_or_network() {
        let (_directory, _db, engine) = fixture(false);
        let result = engine.check_hash(&hash(800), true).unwrap();
        assert!(result.virustotal.is_none());
        assert!(result.detector.is_none());
    }

    #[test]
    fn parses_virustotal_json_and_classifies_thresholds() {
        let target = hash(900);
        let record = parse_virustotal_response(
            &target,
            br#"{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"suspicious":1,"harmless":55,"undetected":10}}}}"#,
            123,
        )
        .unwrap();
        assert_eq!(record.verdict, "malicious");
        assert_eq!(record.checked_at_ms, 123);
        assert_eq!(
            detector_result(None, Some(&record), 3).unwrap().confidence,
            Confidence::High
        );

        let harmless = parse_virustotal_response(
            &target,
            br#"{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":68}}}}"#,
            124,
        )
        .unwrap();
        assert_eq!(harmless.verdict, "harmless");
        assert!(detector_result(None, Some(&harmless), 3).is_none());
    }
}
