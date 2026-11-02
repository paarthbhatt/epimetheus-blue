//! Versioned DNS blocklist feeds.
//!
//! Downloads are staged, validated, then atomically activated. The old file is
//! always retained. A bad response cannot replace a working list.

use anyhow::{bail, Context, Result};
use blue_core::{now_ms, sha256_bytes, sha256_file, Config, Db};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_DOWNLOAD_BYTES: usize = 32 * 1024 * 1024;
const MIN_HOST_LINES: usize = 100;
const MAX_FEED_NAME_BYTES: usize = 128;
const UNIQUE_PATH_ATTEMPTS: usize = 128;

static UNIQUE_PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct FeedSourceCfg {
    pub name: String,
    pub url: String,
    pub license: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FeedsConfig {
    pub lists_dir: PathBuf,
    pub sources: Vec<FeedSourceCfg>,
}

impl FeedsConfig {
    pub fn from_config(c: &Config) -> FeedsConfig {
        FeedsConfig {
            lists_dir: blue_core::config::expand_tilde(&c.feeds.lists_dir),
            sources: c
                .feeds
                .sources
                .iter()
                .map(|s| FeedSourceCfg {
                    name: s.name.clone(),
                    url: s.url.clone(),
                    license: s.license.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    pub updated: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub total_lines: usize,
}

#[derive(Debug, Clone)]
pub struct LocalList {
    pub name: String,
    pub path: PathBuf,
    pub lines: usize,
    pub bytes: u64,
    pub modified_ms: i64,
}

pub struct Feeds {
    db: Arc<Db>,
    cfg: FeedsConfig,
    operation_lock: Mutex<()>,
}

impl Feeds {
    pub fn new(db: Arc<Db>, cfg: FeedsConfig) -> Feeds {
        Feeds {
            db,
            cfg,
            operation_lock: Mutex::new(()),
        }
    }

    /// Update every configured source. One failed provider never aborts the
    /// others and never replaces its last known-good file.
    pub fn sync(&self) -> Result<SyncReport> {
        let agent = ureq::AgentBuilder::new().timeout(DOWNLOAD_TIMEOUT).build();
        let mut report = SyncReport::default();

        for source in &self.cfg.sources {
            let result = self.sync_source(&agent, source);

            match result {
                Ok(lines) => {
                    report.total_lines += lines;
                    report.updated.push(source.name.clone());
                }
                Err(error) => report.failed.push((source.name.clone(), error.to_string())),
            }
        }

        Ok(report)
    }

    fn sync_source(&self, agent: &ureq::Agent, source: &FeedSourceCfg) -> Result<usize> {
        // Reject path-like names before making a request. A hostile name never
        // gets a chance to influence a staging or activation path.
        validate_name(&source.name)?;

        let response = agent
            .get(&source.url)
            .call()
            .with_context(|| format!("fetching {}", source.url))?;
        let declared = response
            .header("content-length")
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|bytes| bytes > MAX_DOWNLOAD_BYTES as u64) {
            bail!("response exceeds 32 MiB limit");
        }

        let mut bytes = Vec::new();
        response
            .into_reader()
            .take((MAX_DOWNLOAD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", source.url))?;
        if bytes.len() > MAX_DOWNLOAD_BYTES {
            bail!("response exceeds 32 MiB limit");
        }

        let text = String::from_utf8(bytes).context("feed is not UTF-8 text")?;
        self.activate_text(&source.name, &text, Some(&source.url))
    }

    /// Validate and atomically activate already-downloaded text.
    pub(crate) fn activate_text(
        &self,
        name: &str,
        text: &str,
        source_url: Option<&str>,
    ) -> Result<usize> {
        validate_name(name)?;
        let lines = validate_feed_text(text)?;
        let _operation = self.operation_guard()?;

        std::fs::create_dir_all(&self.cfg.lists_dir)
            .with_context(|| format!("creating feed directory {}", self.cfg.lists_dir.display()))?;
        let active = self.cfg.lists_dir.join(format!("{name}.txt"));
        let previous = self.cfg.lists_dir.join(format!("{name}.txt.prev"));
        let active_exists = managed_file_exists(&active, "active feed")?;
        let previous_exists = managed_file_exists(&previous, "previous feed")?;

        // The unique create-new stage cannot follow a pre-planted symlink and
        // is fully flushed before any managed path is changed.
        let staged = write_unique_file(&self.cfg.lists_dir, name, "staged", text.as_bytes())?;

        if active_exists {
            // Preserve the prior rollback slot before replacing it. Retention
            // uses a no-clobber hard link (or copy fallback), so no version is
            // ever overwritten even when updates land in the same millisecond.
            if previous_exists {
                retain_at_unique_path(&previous, &self.cfg.lists_dir, name, "previous")?;
            }

            let pending_previous =
                retain_at_unique_path(&active, &self.cfg.lists_dir, name, "pending-previous")?;
            std::fs::rename(&pending_previous, &previous)
                .with_context(|| format!("installing rollback copy {}", previous.display()))?;
        }

        // Both paths are in the same directory. On the supported Linux target,
        // rename atomically replaces the active directory entry. The old bytes
        // remain reachable through `.prev` before this replacement occurs.
        std::fs::rename(&staged, &active)
            .with_context(|| format!("activating staged feed {}", active.display()))?;
        sync_directory(&self.cfg.lists_dir)?;

        self.record_activation(name, text.as_bytes(), lines, source_url)?;
        Ok(lines)
    }

    pub fn rollback(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let _operation = self.operation_guard()?;
        let active = self.cfg.lists_dir.join(format!("{name}.txt"));
        let previous = self.cfg.lists_dir.join(format!("{name}.txt.prev"));
        let previous_exists = managed_file_exists(&previous, "previous feed")?;
        if !previous_exists {
            bail!("no previous version for {name}");
        }
        let active_exists = managed_file_exists(&active, "active feed")?;

        // Snapshot the rollback source first and retain the current active
        // version before atomically replacing its path. The fixed `.prev` file
        // is intentionally retained as well.
        let staged =
            retain_at_unique_path(&previous, &self.cfg.lists_dir, name, "rollback-staged")?;
        if active_exists {
            retain_at_unique_path(&active, &self.cfg.lists_dir, name, "rejected")?;
        }
        std::fs::rename(&staged, &active)
            .with_context(|| format!("rolling back feed {}", active.display()))?;
        sync_directory(&self.cfg.lists_dir)?;

        self.record_rollback(name, &active)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<LocalList>> {
        let _operation = self.operation_guard()?;
        if !self
            .cfg
            .lists_dir
            .try_exists()
            .with_context(|| format!("checking {}", self.cfg.lists_dir.display()))?
        {
            return Ok(Vec::new());
        }
        let mut lists = Vec::new();
        for entry in std::fs::read_dir(&self.cfg.lists_dir)
            .with_context(|| format!("reading {}", self.cfg.lists_dir.display()))?
        {
            let entry = entry
                .with_context(|| format!("reading entry in {}", self.cfg.lists_dir.display()))?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("txt") {
                continue;
            }
            let name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(value) => value.to_owned(),
                None => continue,
            };
            if validate_name(&name).is_err() {
                continue;
            }
            let meta = entry.metadata()?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading feed {}", path.display()))?;
            lists.push(LocalList {
                name,
                path,
                lines: text.lines().count(),
                bytes: meta.len(),
                modified_ms: metadata_modified_ms(&meta),
            });
        }
        lists.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(lists)
    }

    fn operation_guard(&self) -> Result<MutexGuard<'_, ()>> {
        self.operation_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("feed operation lock poisoned"))
    }

    fn record_activation(
        &self,
        name: &str,
        bytes: &[u8],
        lines: usize,
        source_url: Option<&str>,
    ) -> Result<()> {
        let hash = sha256_bytes(bytes);
        let version = short_version(&hash);
        let size = i64::try_from(bytes.len()).context("feed size does not fit in database")?;
        let timestamp = now_ms();
        self.db
            .add_dataset(name, version, source_url, &hash, size, timestamp)?;
        let payload = serde_json::json!({
            "name": name,
            "version": version,
            "sha256": hash,
            "lines": lines,
            "source_url": source_url,
        })
        .to_string();
        self.db
            .event("feeds", "info", Some(name), &payload, timestamp)?;
        Ok(())
    }

    fn record_rollback(&self, name: &str, active: &Path) -> Result<()> {
        let hash = sha256_file(active)?;
        let version = short_version(&hash);
        let size = i64::try_from(std::fs::metadata(active)?.len())
            .context("feed size does not fit in database")?;
        let timestamp = now_ms();
        self.db
            .add_dataset(name, version, None, &hash, size, timestamp)?;
        let payload = serde_json::json!({
            "name": name,
            "version": version,
            "sha256": hash,
            "rollback": true,
        })
        .to_string();
        self.db
            .event("feeds", "warn", Some(name), &payload, timestamp)?;
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_FEED_NAME_BYTES
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid feed name {name:?}");
    }
    Ok(())
}

fn validate_feed_text(text: &str) -> Result<usize> {
    if text.len() > MAX_DOWNLOAD_BYTES {
        bail!("response exceeds 32 MiB limit");
    }
    if text.trim().is_empty() {
        bail!("feed is empty");
    }
    let lines = host_line_count(text);
    if lines < MIN_HOST_LINES {
        bail!("feed has {lines} usable host lines; need at least {MIN_HOST_LINES}");
    }
    Ok(lines)
}

fn host_line_count(text: &str) -> usize {
    text.lines()
        .filter(|line| looks_like_host_line(line))
        .count()
}

fn looks_like_host_line(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return false;
    }
    let line = match line.find('#') {
        Some(index) => line[..index].trim(),
        None => line,
    };
    let mut tokens = line.split_whitespace();
    let first = match tokens.next() {
        Some(value) => value,
        None => return false,
    };
    if first == "0" || first.parse::<std::net::IpAddr>().is_ok() {
        return tokens.any(valid_domain);
    }
    valid_domain(first) && tokens.next().is_none()
}

fn valid_domain(raw: &str) -> bool {
    let domain = match raw.strip_suffix('.') {
        Some(value) => value,
        None => raw,
    };
    if domain.is_empty()
        || domain.ends_with('.')
        || domain.len() > 253
        || domain.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }

    let mut labels = 0usize;
    let mut final_label_has_letter = false;
    for label in domain.split('.') {
        labels += 1;
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return false;
        }
        final_label_has_letter = label.bytes().any(|byte| byte.is_ascii_alphabetic());
    }
    labels >= 2 && final_label_has_letter
}

fn short_version(hash: &str) -> &str {
    match hash.get(..8) {
        Some(version) => version,
        None => hash,
    }
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
    bail!("could not allocate a unique stage for feed {name:?}")
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
    bail!("could not allocate a retained path for feed {name:?}")
}

fn clone_file_noclobber(source: &Path, destination: &Path) -> io::Result<()> {
    match std::fs::hard_link(source, destination) {
        Ok(()) => File::open(destination)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(error),
        Err(_) => {
            let mut input = File::open(source)?;
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
        .with_context(|| format!("flushing feed directory {}", directory.display()))
}

fn metadata_modified_ms(metadata: &std::fs::Metadata) -> i64 {
    let modified = match metadata.modified() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let elapsed = match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    elapsed.as_millis().min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn valid(prefix: &str) -> String {
        (0..120)
            .map(|n| format!("0.0.0.0 {prefix}{n}.example.test\n"))
            .collect()
    }

    fn fixture_with_sources(sources: Vec<FeedSourceCfg>) -> (tempfile::TempDir, Arc<Db>, Feeds) {
        let dir = tempfile::TempDir::new().unwrap();
        let db = Arc::new(Db::open_memory().unwrap());
        let feeds = Feeds::new(
            db.clone(),
            FeedsConfig {
                lists_dir: dir.path().join("lists"),
                sources,
            },
        );
        (dir, db, feeds)
    }

    fn fixture() -> (tempfile::TempDir, Arc<Db>, Feeds) {
        fixture_with_sources(Vec::new())
    }

    fn serve_once(body: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
        });
        (format!("http://{address}/feed"), handle)
    }

    fn serve_declared_size(size: u64) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            let headers =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n");
            stream.write_all(headers.as_bytes()).unwrap();
        });
        (format!("http://{address}/feed"), handle)
    }

    fn retained_files(feeds: &Feeds, marker: &str) -> Vec<PathBuf> {
        let mut paths: Vec<_> = std::fs::read_dir(&feeds.cfg.lists_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(marker))
            })
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn activates_valid_text_and_records_dataset_and_event() {
        let (_dir, db, feeds) = fixture();
        let text = valid("a");
        assert_eq!(
            feeds
                .activate_text("ads", &text, Some("https://example.test/ads"))
                .unwrap(),
            120
        );
        assert_eq!(
            std::fs::read(feeds.cfg.lists_dir.join("ads.txt")).unwrap(),
            text.as_bytes()
        );

        let datasets = db.list_datasets().unwrap();
        assert_eq!(datasets.len(), 1);
        assert!(datasets[0].active);
        assert_eq!(datasets[0].name, "ads");
        assert_eq!(
            datasets[0].source_url.as_deref(),
            Some("https://example.test/ads")
        );
        assert_eq!(
            datasets[0].sha256.as_deref(),
            Some(sha256_bytes(text.as_bytes()).as_str())
        );

        let events = db.recent_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "feeds");
        assert_eq!(events[0].subject.as_deref(), Some("ads"));
        let payload: serde_json::Value = serde_json::from_str(&events[0].payload).unwrap();
        assert_eq!(payload["lines"], 120);
        assert_eq!(payload["name"], "ads");
    }

    #[test]
    fn invalid_does_not_replace_good_list() {
        let (_dir, db, feeds) = fixture();
        let first = valid("old");
        feeds.activate_text("ads", &first, None).unwrap();
        let active = feeds.cfg.lists_dir.join("ads.txt");
        let before = std::fs::read(&active).unwrap();

        assert!(feeds.activate_text("ads", "  \n\t", None).is_err());
        let too_short: String = (0..99)
            .map(|n| format!("0.0.0.0 short{n}.example.test\n"))
            .collect();
        assert!(feeds.activate_text("ads", &too_short, None).is_err());

        assert_eq!(std::fs::read(&active).unwrap(), before);
        assert!(!feeds.cfg.lists_dir.join("ads.txt.prev").exists());
        assert_eq!(db.list_datasets().unwrap().len(), 1);
        assert_eq!(db.recent_events(10).unwrap().len(), 1);
    }

    #[test]
    fn second_activation_and_rollback_are_byte_exact_and_retain_versions() {
        let (_dir, db, feeds) = fixture();
        let first = valid("old");
        let second = valid("new");
        feeds.activate_text("ads", &first, None).unwrap();
        feeds.activate_text("ads", &second, None).unwrap();

        let active = feeds.cfg.lists_dir.join("ads.txt");
        let previous = feeds.cfg.lists_dir.join("ads.txt.prev");
        assert_eq!(std::fs::read(&active).unwrap(), second.as_bytes());
        assert_eq!(std::fs::read(&previous).unwrap(), first.as_bytes());

        feeds.rollback("ads").unwrap();
        assert_eq!(std::fs::read(&active).unwrap(), first.as_bytes());
        assert_eq!(std::fs::read(&previous).unwrap(), first.as_bytes());

        let rejected = retained_files(&feeds, ".rejected.");
        assert_eq!(rejected.len(), 1);
        assert_eq!(std::fs::read(&rejected[0]).unwrap(), second.as_bytes());

        let datasets = db.list_datasets().unwrap();
        assert_eq!(datasets.len(), 3);
        assert_eq!(datasets.iter().filter(|dataset| dataset.active).count(), 1);
        assert_eq!(
            datasets[0].sha256.as_deref(),
            Some(sha256_bytes(first.as_bytes()).as_str())
        );
        let events = db.recent_events(10).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].level, "warn");
        let payload: serde_json::Value = serde_json::from_str(&events[0].payload).unwrap();
        assert_eq!(payload["rollback"], true);
    }

    #[test]
    fn repeated_activation_never_overwrites_retained_versions() {
        let (_dir, _db, feeds) = fixture();
        let first = valid("first");
        let second = valid("second");
        let third = valid("third");
        let fourth = valid("fourth");

        for text in [&first, &second, &third, &fourth] {
            feeds.activate_text("ads", text, None).unwrap();
        }

        assert_eq!(
            std::fs::read(feeds.cfg.lists_dir.join("ads.txt")).unwrap(),
            fourth.as_bytes()
        );
        assert_eq!(
            std::fs::read(feeds.cfg.lists_dir.join("ads.txt.prev")).unwrap(),
            third.as_bytes()
        );
        let archives = retained_files(&feeds, ".previous.");
        assert_eq!(archives.len(), 2);
        let mut archived_bytes: Vec<_> = archives
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect();
        archived_bytes.sort();
        let mut expected = vec![first.into_bytes(), second.into_bytes()];
        expected.sort();
        assert_eq!(archived_bytes, expected);
    }

    #[test]
    fn list_reports_sorted_active_text_files_only() {
        let (_dir, _db, feeds) = fixture();
        let zeta = valid("z");
        let alpha = valid("a");
        feeds.activate_text("zeta", &zeta, None).unwrap();
        feeds.activate_text("zeta", &valid("z2"), None).unwrap();
        feeds.activate_text("alpha", &alpha, None).unwrap();
        std::fs::write(feeds.cfg.lists_dir.join("unsafe.name.txt"), valid("u")).unwrap();

        let items = feeds.list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "alpha");
        assert_eq!(items[1].name, "zeta");
        assert_eq!(items[0].lines, 120);
        assert_eq!(items[0].bytes, alpha.len() as u64);
        assert!(items[0].modified_ms > 0);
    }

    #[test]
    fn parser_accepts_hosts_and_bare_domains() {
        assert!(looks_like_host_line("0.0.0.0 ads.example.com"));
        assert!(looks_like_host_line("0 tracker.example.org"));
        assert!(looks_like_host_line(
            "::1 ads.example.com tracker.example.net"
        ));
        assert!(looks_like_host_line("tracker.example.org"));
        assert!(looks_like_host_line("tracker.example.org # comment"));
        assert!(!looks_like_host_line("# comment.example"));
        assert!(!looks_like_host_line("localhost"));
        assert!(!looks_like_host_line("tracker.example.org extra-token"));
        assert!(!looks_like_host_line("1.2.3.4"));
        assert!(!looks_like_host_line("||tracker.example.org^"));

        let bare_domains: String = (0..MIN_HOST_LINES)
            .map(|index| format!("bare{index}.example.test\n"))
            .collect();
        assert_eq!(validate_feed_text(&bare_domains).unwrap(), MIN_HOST_LINES);
    }

    #[test]
    fn unsafe_feed_names_are_rejected() {
        let (_dir, _db, feeds) = fixture();
        let long_name = "a".repeat(MAX_FEED_NAME_BYTES + 1);
        for name in [
            "",
            ".",
            "..",
            "../escape",
            "nested/feed",
            "nested\\feed",
            "/absolute",
            "with space",
            "non-ascii-é",
            &long_name,
        ] {
            assert!(
                feeds.activate_text(name, &valid("x"), None).is_err(),
                "unsafe name was accepted: {name:?}"
            );
            assert!(
                feeds.rollback(name).is_err(),
                "unsafe rollback name was accepted: {name:?}"
            );
        }
        assert!(!feeds.cfg.lists_dir.exists());

        let (_dir, _db, feeds) = fixture_with_sources(vec![FeedSourceCfg {
            name: "../escape".into(),
            url: "http://127.0.0.1:9/should-not-be-fetched".into(),
            license: None,
        }]);
        let report = feeds.sync().unwrap();
        assert!(report.updated.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("invalid feed name"));
        assert!(!feeds.cfg.lists_dir.exists());
    }

    #[test]
    fn one_provider_failure_does_not_abort_later_sources() {
        let good = valid("good");
        let (url, server) = serve_once(good.clone());
        let (_dir, _db, feeds) = fixture_with_sources(vec![
            FeedSourceCfg {
                name: "broken".into(),
                url: "not a valid URL".into(),
                license: None,
            },
            FeedSourceCfg {
                name: "good".into(),
                url,
                license: Some("test".into()),
            },
        ]);

        let report = feeds.sync().unwrap();
        server.join().unwrap();
        assert_eq!(report.updated, vec!["good"]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "broken");
        assert_eq!(report.total_lines, 120);
        assert_eq!(
            std::fs::read(feeds.cfg.lists_dir.join("good.txt")).unwrap(),
            good.as_bytes()
        );
    }

    #[test]
    fn oversized_download_does_not_touch_existing_list() {
        let (url, server) = serve_declared_size(MAX_DOWNLOAD_BYTES as u64 + 1);
        let (_dir, db, feeds) = fixture_with_sources(vec![FeedSourceCfg {
            name: "ads".into(),
            url,
            license: None,
        }]);
        let original = valid("original");
        feeds.activate_text("ads", &original, None).unwrap();

        let report = feeds.sync().unwrap();
        server.join().unwrap();

        assert!(report.updated.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("32 MiB"));
        assert_eq!(
            std::fs::read(feeds.cfg.lists_dir.join("ads.txt")).unwrap(),
            original.as_bytes()
        );
        assert!(!feeds.cfg.lists_dir.join("ads.txt.prev").exists());
        assert_eq!(db.list_datasets().unwrap().len(), 1);
        assert_eq!(db.recent_events(10).unwrap().len(), 1);
    }
}
