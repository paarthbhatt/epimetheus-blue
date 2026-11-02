//! Conservative cleanup inventory and execution.
//!
//! Cleanup is deliberately a two-step operation: callers inventory candidates,
//! explicitly choose candidate IDs, and then provide the exact confirmation
//! phrase for that selection. Size values are estimates. In particular, hard
//! links may be counted more than once. Directory walks never follow symbolic
//! links and are capped at [`MAX_ENTRIES_PER_CANDIDATE`] entries per candidate.

use anyhow::{bail, Context, Result};
use blue_core::config::expand_tilde;
use blue_core::{now_ms, sha256_bytes, Config, Db};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::Metadata;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const CANDIDATE_ID_VERSION: &str = "blue-cleanup-candidate-v1";
const MAX_ENTRIES_PER_CANDIDATE: usize = 1_000_000;
const MAX_DISCOVERY_ENTRIES: usize = 1_000_000;

/// The amount of judgment required before a candidate may be removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CleanupRisk {
    Safe,
    Review,
    Protected,
}

/// The source or purpose of a cleanup candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupCategory {
    Cache,
    Trash,
    BuildArtifact,
    Download,
    Container,
    PackageCache,
    Journal,
    Snapshot,
    Boot,
    Backup,
    Other,
}

impl CleanupCategory {
    fn stable_name(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Trash => "trash",
            Self::BuildArtifact => "build_artifact",
            Self::Download => "download",
            Self::Container => "container",
            Self::PackageCache => "package_cache",
            Self::Journal => "journal",
            Self::Snapshot => "snapshot",
            Self::Boot => "boot",
            Self::Backup => "backup",
            Self::Other => "other",
        }
    }
}

/// One item found during inventory. Nothing in this type is preselected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupCandidate {
    pub id: String,
    pub label: String,
    pub path: Option<PathBuf>,
    /// Estimated bytes. Hard-linked files may be counted more than once.
    pub bytes: u64,
    pub risk: CleanupRisk,
    pub category: CleanupCategory,
    pub reason: String,
    pub reproducible: bool,
    pub requires_root: bool,
    pub supported: bool,
    pub warning: Option<String>,
}

/// A bounded inventory. Candidates are observations, not a default selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub candidates: Vec<CleanupCandidate>,
    pub safe_bytes: u64,
    pub review_bytes: u64,
    pub protected_bytes: u64,
    pub diagnostics: Vec<String>,
    pub truncated: bool,
}

/// One attempted, explicitly approved action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReceipt {
    pub id: String,
    pub label: String,
    pub bytes_before: u64,
    pub success: bool,
    pub error: Option<String>,
}

/// Results from applying an explicit selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReport {
    pub receipts: Vec<ApplyReceipt>,
    pub reclaimed_estimate: u64,
}

/// A process observation used by the read-only performance snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceProcess {
    pub pid: u32,
    pub name: String,
    pub rss_bytes: u64,
}

/// Current Linux memory pressure and the largest resident processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceSnapshot {
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub process_count: usize,
    pub top_memory: Vec<PerformanceProcess>,
}

/// Read Linux memory totals and process RSS values without changing process or
/// service state. Processes that exit or become unreadable during inventory are
/// counted when observed but omitted from `top_memory`.
pub fn performance_snapshot() -> Result<PerformanceSnapshot> {
    performance_snapshot_from_proc(Path::new("/proc"))
}

/// Filesystem locations and bounds used by the cleanup engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupConfig {
    pub home: PathBuf,
    pub scan_roots: Vec<PathBuf>,
    pub download_age_days: u64,
    pub build_artifact_depth: usize,
    pub max_candidates: usize,
}

impl CleanupConfig {
    /// Build cleanup settings from the shared configuration, expanding `~`
    /// without invoking a shell.
    pub fn from_config(config: &Config) -> Self {
        let expanded_home = expand_tilde("~");
        let home_available = expanded_home != Path::new("~");
        let home = if home_available {
            absolute_lexical(&expanded_home)
        } else {
            PathBuf::from("/dev/null/blue-home-unavailable")
        };
        let mut seen = HashSet::new();
        let scan_roots = config
            .cleanup
            .scan_roots
            .iter()
            .filter(|path| home_available || !(path.as_str() == "~" || path.starts_with("~/")))
            .map(|path| absolute_lexical(&expand_tilde(path)))
            .filter(|path| seen.insert(path.clone()))
            .collect();

        Self {
            home,
            scan_roots,
            download_age_days: config.cleanup.download_age_days,
            build_artifact_depth: config.cleanup.build_artifact_depth,
            max_candidates: config.cleanup.max_candidates,
        }
    }
}

/// Injectable equivalents of the fixed, observation-only system locations.
///
/// Production code should use [`Default`]. Tests and sandboxed callers can use
/// [`SystemObservationRoots::under`] so an inventory never touches host paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemObservationRoots {
    pub pacman_cache: PathBuf,
    pub journal: PathBuf,
    pub debtap_cache: PathBuf,
    pub snapshots: PathBuf,
    pub efi: PathBuf,
    pub ryoku_backups: PathBuf,
}

impl SystemObservationRoots {
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            pacman_cache: root.join("var/cache/pacman/pkg"),
            journal: root.join("var/log/journal"),
            debtap_cache: root.join("var/cache/debtap"),
            snapshots: root.join(".snapshots"),
            efi: root.join("efi"),
            ryoku_backups: root.join("var/backups/ryoku"),
        }
    }

    fn all(&self) -> [&Path; 6] {
        [
            &self.pacman_cache,
            &self.journal,
            &self.debtap_cache,
            &self.snapshots,
            &self.efi,
            &self.ryoku_backups,
        ]
    }
}

impl Default for SystemObservationRoots {
    fn default() -> Self {
        Self {
            pacman_cache: PathBuf::from("/var/cache/pacman/pkg"),
            journal: PathBuf::from("/var/log/journal"),
            debtap_cache: PathBuf::from("/var/cache/debtap"),
            snapshots: PathBuf::from("/.snapshots"),
            efi: PathBuf::from("/efi"),
            ryoku_backups: PathBuf::from("/var/backups/ryoku"),
        }
    }
}

/// Inventory and explicitly apply conservative cleanup candidates.
pub struct CleanupEngine {
    db: Arc<Db>,
    config: CleanupConfig,
    observation_roots: SystemObservationRoots,
}

impl CleanupEngine {
    pub fn new(db: Arc<Db>, config: CleanupConfig) -> Self {
        Self::new_with_observation_roots(db, config, SystemObservationRoots::default())
    }

    /// Construct an engine with sandboxed system-observation paths.
    pub fn new_with_observation_roots(
        db: Arc<Db>,
        mut config: CleanupConfig,
        mut observation_roots: SystemObservationRoots,
    ) -> Self {
        config.home = absolute_lexical(&config.home);
        config.scan_roots = deduplicate_paths(
            config
                .scan_roots
                .into_iter()
                .map(|path| absolute_lexical(&path)),
        );
        observation_roots.pacman_cache = absolute_lexical(&observation_roots.pacman_cache);
        observation_roots.journal = absolute_lexical(&observation_roots.journal);
        observation_roots.debtap_cache = absolute_lexical(&observation_roots.debtap_cache);
        observation_roots.snapshots = absolute_lexical(&observation_roots.snapshots);
        observation_roots.efi = absolute_lexical(&observation_roots.efi);
        observation_roots.ryoku_backups = absolute_lexical(&observation_roots.ryoku_backups);
        Self {
            db,
            config,
            observation_roots,
        }
    }

    /// Inventory candidates. This method never removes or changes anything.
    pub fn scan(&self) -> Result<CleanupReport> {
        Ok(self.scan_internal()?.into_report())
    }

    /// Return the exact, case-sensitive phrase required for a selection.
    pub fn required_confirmation(candidates: &[CleanupCandidate]) -> String {
        if candidates
            .iter()
            .any(|candidate| candidate.risk != CleanupRisk::Safe)
        {
            format!("DELETE REVIEWED {}", candidates.len())
        } else {
            format!("DELETE SAFE {}", candidates.len())
        }
    }

    /// Re-inventory, resolve IDs only against the fresh inventory, validate the
    /// exact confirmation, and then attempt each approved item independently.
    pub fn apply(&self, ids: &[String], confirmation: &str) -> Result<ApplyReport> {
        if ids.is_empty() {
            bail!("cleanup selection is empty; nothing is ever selected by default");
        }

        let mut unique = HashSet::new();
        if ids.iter().any(|id| !unique.insert(id.as_str())) {
            bail!("cleanup selection contains duplicate candidate IDs");
        }

        let inventory = self.scan_internal()?;
        let by_id: HashMap<&str, &DiscoveredCandidate> = inventory
            .candidates
            .iter()
            .map(|candidate| (candidate.public.id.as_str(), candidate))
            .collect();

        let mut selected = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(candidate) = by_id.get(id.as_str()).copied() else {
                bail!("unknown or stale cleanup candidate ID: {id}");
            };
            if !candidate.public.supported
                || candidate.public.requires_root
                || candidate.public.risk == CleanupRisk::Protected
            {
                bail!(
                    "cleanup candidate {} is protected, root-owned, or unsupported",
                    candidate.public.id
                );
            }
            selected.push(candidate.clone());
        }

        let public_selection: Vec<_> = selected
            .iter()
            .map(|candidate| candidate.public.clone())
            .collect();
        let required = Self::required_confirmation(&public_selection);
        if confirmation != required {
            bail!("confirmation did not exactly match `{required}`");
        }

        let mounts = MountTable::load();
        for candidate in &selected {
            self.validate_before_action(candidate, &mounts)
                .with_context(|| {
                    format!("preflight failed for candidate {}", candidate.public.id)
                })?;
        }

        let mut receipts = Vec::with_capacity(selected.len());
        let mut reclaimed_estimate = 0u64;
        for candidate in selected {
            let result = self
                .validate_before_action(&candidate, &mounts)
                .and_then(|()| execute_action(&candidate.action, &mounts));
            let success = result.is_ok();
            if success {
                reclaimed_estimate = reclaimed_estimate.saturating_add(candidate.public.bytes);
            }
            receipts.push(ApplyReceipt {
                id: candidate.public.id,
                label: candidate.public.label,
                bytes_before: candidate.public.bytes,
                success,
                error: result.err().map(|error| format!("{error:#}")),
            });
        }

        let report = ApplyReport {
            receipts,
            reclaimed_estimate,
        };
        self.persist_receipts(&report)?;
        Ok(report)
    }

    fn scan_internal(&self) -> Result<Inventory> {
        let mut inventory = Inventory::new(self.config.max_candidates);
        let home_inventory_allowed = !is_filesystem_root(&self.config.home)
            && !path_has_symlink_component(&self.config.home)
            && std::fs::symlink_metadata(&self.config.home)
                .map(|metadata| !metadata.file_type().is_symlink() && metadata.is_dir())
                .unwrap_or(false);
        if home_inventory_allowed {
            self.scan_known_caches(&mut inventory);
            if !inventory.candidate_limit_reached {
                self.scan_trash(&mut inventory);
            }
        } else {
            inventory.diagnostics.push(format!(
                "Home inventory was disabled because {} is unavailable, root, or crosses a symbolic link",
                self.config.home.display()
            ));
        }
        if !inventory.candidate_limit_reached {
            self.scan_build_artifacts(&mut inventory);
        }
        if home_inventory_allowed && !inventory.candidate_limit_reached {
            self.scan_downloads(&mut inventory);
        }
        if !inventory.candidate_limit_reached {
            self.scan_system_observations(&mut inventory);
        }
        inventory.sort_candidates();
        Ok(inventory)
    }

    fn scan_known_caches(&self, inventory: &mut Inventory) {
        for spec in known_cache_specs() {
            let path = self.config.home.join(spec.relative);
            let Some(fingerprint) = self.inspect_candidate_directory(&path, inventory) else {
                continue;
            };
            if self.reject_candidate_path(&path, inventory, "known cache") {
                continue;
            }
            if !directory_is_nonempty(&path, &mut inventory.diagnostics) {
                continue;
            }
            if !inventory.has_capacity_for(&path) {
                break;
            }
            let estimate = estimate_paths(&[path.as_path()]);
            inventory.absorb_estimate(&estimate);
            let public = make_candidate(CandidateSpec {
                label: spec.label.to_owned(),
                path: Some(path.clone()),
                bytes: estimate.bytes,
                risk: spec.risk,
                category: CleanupCategory::Cache,
                reason: spec.reason.to_owned(),
                reproducible: spec.reproducible,
                requires_root: false,
                supported: true,
                warning: spec.warning.map(str::to_owned),
            });
            inventory.push(DiscoveredCandidate {
                public,
                action: CleanupAction::Directory { path, fingerprint },
            });
        }
    }

    fn scan_trash(&self, inventory: &mut Inventory) {
        let trash_root = self.config.home.join(".local/share/Trash");
        if self.reject_candidate_path(&trash_root, inventory, "Trash") {
            return;
        }

        let files = trash_root.join("files");
        let info = trash_root.join("info");
        let mut roots = Vec::new();
        let mut invalid = false;
        for path in [&files, &info] {
            match inspect_optional_directory(path) {
                Ok(Some(fingerprint)) => roots.push((path.to_path_buf(), fingerprint)),
                Ok(None) => {}
                Err(error) => {
                    inventory.diagnostics.push(format!(
                        "Trash root {} was skipped: {error:#}",
                        path.display()
                    ));
                    invalid = true;
                }
            }
        }
        if invalid || roots.is_empty() {
            return;
        }
        if !roots
            .iter()
            .any(|(path, _)| directory_is_nonempty(path, &mut inventory.diagnostics))
        {
            return;
        }
        if !inventory.has_capacity_for(&trash_root) {
            return;
        }

        let root_paths: Vec<_> = roots.iter().map(|(path, _)| path.as_path()).collect();
        let estimate = estimate_paths(&root_paths);
        inventory.absorb_estimate(&estimate);
        let public = make_candidate(CandidateSpec {
            label: "Trash contents".to_owned(),
            path: Some(trash_root),
            bytes: estimate.bytes,
            risk: CleanupRisk::Review,
            category: CleanupCategory::Trash,
            reason: "Permanently removes trashed files and their metadata; they cannot be restored afterward."
                .to_owned(),
            reproducible: false,
            requires_root: false,
            supported: true,
            warning: Some("Review Trash before permanently emptying it.".to_owned()),
        });
        inventory.push(DiscoveredCandidate {
            public,
            action: CleanupAction::Trash { roots },
        });
    }

    fn scan_build_artifacts(&self, inventory: &mut Inventory) {
        let mut roots = self.config.scan_roots.clone();
        roots.sort_by(|left, right| {
            component_count(left)
                .cmp(&component_count(right))
                .then_with(|| left.cmp(right))
        });

        let mut selected_roots: Vec<PathBuf> = Vec::new();
        for root in roots {
            if inventory.candidate_limit_reached || inventory.discovery_limit_reached {
                break;
            }
            if selected_roots
                .iter()
                .any(|selected| path_is_within(&root, selected))
            {
                continue;
            }
            if let Some(reason) = self.scan_root_rejection_reason(&root) {
                inventory.diagnostics.push(format!(
                    "Build scan root {} was skipped: {reason}",
                    root.display()
                ));
                continue;
            }
            let metadata = match std::fs::symlink_metadata(&root) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    inventory.diagnostics.push(format!(
                        "Build scan root {} was unreadable: {error}",
                        root.display()
                    ));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                inventory.diagnostics.push(format!(
                    "Build scan root {} is not a real directory and was skipped",
                    root.display()
                ));
                continue;
            }

            let mut queue = VecDeque::from([(root.clone(), 0usize)]);
            while let Some((directory, depth)) = queue.pop_front() {
                if inventory.candidate_limit_reached || inventory.discovery_limit_reached {
                    break;
                }
                if depth >= self.config.build_artifact_depth {
                    continue;
                }

                let mut entries = match sorted_directory_entries(&directory) {
                    Ok(entries) => entries,
                    Err(error) => {
                        inventory.diagnostics.push(format!(
                            "Could not inspect build directory {}: {error}",
                            directory.display()
                        ));
                        continue;
                    }
                };
                if entries.truncated {
                    inventory.mark_discovery_limit(&directory);
                }
                for entry in entries.entries.drain(..) {
                    if !inventory.record_discovery_entry(&directory) {
                        break;
                    }
                    let path = entry.path();
                    let metadata = match std::fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            inventory.diagnostics.push(format!(
                                "Could not inspect build path {}: {error}",
                                path.display()
                            ));
                            continue;
                        }
                    };
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        continue;
                    }
                    if is_dot_git(&path) || self.path_is_protected_zone(&path) {
                        continue;
                    }

                    let next_depth = depth.saturating_add(1);
                    if is_build_directory(&path) {
                        if self.reject_candidate_path(&path, inventory, "build artifact") {
                            continue;
                        }
                        if selected_roots
                            .iter()
                            .any(|selected| path_is_within(&path, selected))
                            || inventory.directory_candidate_covers(&path)
                        {
                            continue;
                        }
                        if !inventory.has_capacity_for(&path) {
                            break;
                        }
                        let estimate = estimate_paths(&[path.as_path()]);
                        inventory.absorb_estimate(&estimate);
                        let Some(fingerprint) = Fingerprint::from_metadata(&metadata) else {
                            inventory.diagnostics.push(format!(
                                "Build artifact {} changed type during inventory",
                                path.display()
                            ));
                            continue;
                        };
                        let name = path
                            .file_name()
                            .and_then(OsStr::to_str)
                            .unwrap_or("generated directory");
                        let public = make_candidate(CandidateSpec {
                            label: format!("Build artifacts: {name}"),
                            path: Some(path.clone()),
                            bytes: estimate.bytes,
                            risk: CleanupRisk::Review,
                            category: CleanupCategory::BuildArtifact,
                            reason: "Generated build dependencies; the next build may be slow and may re-download packages."
                                .to_owned(),
                            reproducible: true,
                            requires_root: false,
                            supported: true,
                            warning: Some(
                                "Review active projects before forcing a rebuild or re-download."
                                    .to_owned(),
                            ),
                        });
                        selected_roots.push(path.clone());
                        inventory.push(DiscoveredCandidate {
                            public,
                            action: CleanupAction::Directory { path, fingerprint },
                        });
                        continue;
                    }
                    queue.push_back((path, next_depth));
                }
            }
        }
    }

    fn scan_downloads(&self, inventory: &mut Inventory) {
        let downloads = self.config.home.join("Downloads");
        if path_has_symlink_component(&downloads) {
            inventory.diagnostics.push(format!(
                "Downloads directory {} crosses a symbolic link and was skipped",
                downloads.display()
            ));
            return;
        }
        let metadata = match std::fs::symlink_metadata(&downloads) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                inventory.diagnostics.push(format!(
                    "Downloads directory {} was unreadable: {error}",
                    downloads.display()
                ));
                return;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            inventory.diagnostics.push(format!(
                "Downloads directory {} is not a real directory and was skipped",
                downloads.display()
            ));
            return;
        }

        let entries = match sorted_directory_entries(&downloads) {
            Ok(entries) => entries,
            Err(error) => {
                inventory.diagnostics.push(format!(
                    "Could not read Downloads directory {}: {error}",
                    downloads.display()
                ));
                return;
            }
        };
        if entries.truncated {
            inventory.mark_discovery_limit(&downloads);
        }
        let age = Duration::from_secs(self.config.download_age_days.saturating_mul(86_400));
        let now = SystemTime::now();

        for entry in entries.entries {
            if inventory.candidate_limit_reached || inventory.discovery_limit_reached {
                break;
            }
            if !inventory.record_discovery_entry(&downloads) {
                break;
            }
            let path = entry.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    inventory.diagnostics.push(format!(
                        "Could not inspect download {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            if self.reject_candidate_path(&path, inventory, "download") {
                continue;
            }

            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| "download".to_owned());
            if is_partial_download(&name) {
                if !inventory.has_capacity_for(&path) {
                    break;
                }
                let public = make_candidate(CandidateSpec {
                    label: format!("Incomplete download (protected): {name}"),
                    path: Some(path),
                    bytes: metadata.len(),
                    risk: CleanupRisk::Protected,
                    category: CleanupCategory::Download,
                    reason: "Possibly active/incomplete download; Blue protects it and refuses deletion."
                        .to_owned(),
                    reproducible: false,
                    requires_root: false,
                    supported: false,
                    warning: Some(
                        "Let the download finish or remove it manually after verifying it is inactive."
                            .to_owned(),
                    ),
                });
                inventory.push(DiscoveredCandidate {
                    public,
                    action: CleanupAction::ObservationOnly,
                });
                continue;
            }
            if !is_cleanup_download(&name) {
                continue;
            }
            let modified = match metadata.modified() {
                Ok(modified) => modified,
                Err(error) => {
                    inventory.diagnostics.push(format!(
                        "Could not read modification time for {}: {error}",
                        path.display()
                    ));
                    continue;
                }
            };
            let old_enough = now
                .duration_since(modified)
                .map(|elapsed| elapsed >= age)
                .unwrap_or(false);
            if !old_enough {
                continue;
            }
            if !inventory.has_capacity_for(&path) {
                break;
            }
            let Some(fingerprint) = Fingerprint::from_metadata(&metadata) else {
                continue;
            };
            let public = make_candidate(CandidateSpec {
                label: format!("Old download artifact: {name}"),
                path: Some(path.clone()),
                bytes: metadata.len(),
                risk: CleanupRisk::Review,
                category: CleanupCategory::Download,
                reason: format!(
                    "Package/archive in Downloads is at least {} days old; confirm it can be re-downloaded or is no longer needed.",
                    self.config.download_age_days
                ),
                reproducible: false,
                requires_root: false,
                supported: true,
                warning: Some(
                    "Archives may be the only copy of personal data; review this exact file."
                        .to_owned(),
                ),
            });
            inventory.push(DiscoveredCandidate {
                public,
                action: CleanupAction::File { path, fingerprint },
            });
        }
    }

    fn scan_system_observations(&self, inventory: &mut Inventory) {
        let specs = [
            SystemSpec {
                path: &self.observation_roots.pacman_cache,
                label: "Pacman package cache",
                risk: CleanupRisk::Review,
                category: CleanupCategory::PackageCache,
                reason: "Use pacman/paccache owner tools; Blue refuses direct deletion.",
                reproducible: true,
                enumerate_size: true,
            },
            SystemSpec {
                path: &self.observation_roots.journal,
                label: "System journal",
                risk: CleanupRisk::Review,
                category: CleanupCategory::Journal,
                reason: "Use journalctl owner tools and an explicit retention policy; Blue refuses direct deletion.",
                reproducible: false,
                enumerate_size: true,
            },
            SystemSpec {
                path: &self.observation_roots.debtap_cache,
                label: "Debtap package cache",
                risk: CleanupRisk::Safe,
                category: CleanupCategory::PackageCache,
                reason: "Use debtap/package-cache owner tools; Blue refuses direct deletion.",
                reproducible: true,
                enumerate_size: true,
            },
            SystemSpec {
                path: &self.observation_roots.snapshots,
                label: "System snapshots (protected)",
                risk: CleanupRisk::Protected,
                category: CleanupCategory::Snapshot,
                reason: "Use snapshot owner tools; Blue refuses direct deletion and never enumerates individual snapshots.",
                reproducible: false,
                enumerate_size: false,
            },
            SystemSpec {
                path: &self.observation_roots.efi,
                label: "EFI system partition (protected)",
                risk: CleanupRisk::Protected,
                category: CleanupCategory::Boot,
                reason: "Use firmware/boot owner tools; Blue refuses direct deletion and never enumerates EFI entries.",
                reproducible: false,
                enumerate_size: false,
            },
            SystemSpec {
                path: &self.observation_roots.ryoku_backups,
                label: "Ryoku backups (protected)",
                risk: CleanupRisk::Protected,
                category: CleanupCategory::Backup,
                reason: "Use Ryoku backup owner tools; Blue refuses direct deletion and never enumerates backup entries.",
                reproducible: false,
                enumerate_size: false,
            },
        ];

        for spec in specs {
            if inventory.candidate_limit_reached {
                break;
            }
            if path_has_symlink_component(spec.path) {
                inventory.diagnostics.push(format!(
                    "System observation {} crosses a symbolic link and was skipped",
                    spec.path.display()
                ));
                continue;
            }
            let metadata = match std::fs::symlink_metadata(spec.path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    inventory.diagnostics.push(format!(
                        "System observation {} was unreadable: {error}",
                        spec.path.display()
                    ));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                inventory.diagnostics.push(format!(
                    "System observation {} is not a real directory and was skipped",
                    spec.path.display()
                ));
                continue;
            }
            if std::fs::read_dir(spec.path).is_err() {
                inventory.diagnostics.push(format!(
                    "System observation {} could not be read and was skipped",
                    spec.path.display()
                ));
                continue;
            }
            if self.is_configured_root(spec.path) {
                inventory.diagnostics.push(format!(
                    "System observation {} is a configured scan root and was not offered",
                    spec.path.display()
                ));
                continue;
            }
            if !inventory.has_capacity_for(spec.path) {
                break;
            }
            let bytes = if spec.enumerate_size {
                let estimate = estimate_paths(&[spec.path]);
                inventory.absorb_estimate(&estimate);
                estimate.bytes
            } else {
                0
            };
            let public = make_candidate(CandidateSpec {
                label: spec.label.to_owned(),
                path: Some(spec.path.to_path_buf()),
                bytes,
                risk: spec.risk,
                category: spec.category,
                reason: spec.reason.to_owned(),
                reproducible: spec.reproducible,
                requires_root: true,
                supported: false,
                warning: Some(
                    "Observation only: Blue performs no root escalation or direct deletion here."
                        .to_owned(),
                ),
            });
            inventory.push(DiscoveredCandidate {
                public,
                action: CleanupAction::ObservationOnly,
            });
        }
    }

    fn inspect_candidate_directory(
        &self,
        path: &Path,
        inventory: &mut Inventory,
    ) -> Option<Fingerprint> {
        if path_has_symlink_component(path) {
            inventory.diagnostics.push(format!(
                "Candidate directory {} crosses a symbolic link and was skipped",
                path.display()
            ));
            return None;
        }
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                inventory.diagnostics.push(format!(
                    "Candidate directory {} was unreadable: {error}",
                    path.display()
                ));
                return None;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            inventory.diagnostics.push(format!(
                "Candidate directory {} is not a real directory and was skipped",
                path.display()
            ));
            return None;
        }
        Fingerprint::from_metadata(&metadata)
    }

    fn reject_candidate_path(&self, path: &Path, inventory: &mut Inventory, kind: &str) -> bool {
        if let Some(reason) = self.candidate_rejection_reason(path) {
            inventory.diagnostics.push(format!(
                "The {kind} candidate {} was not offered: {reason}",
                path.display()
            ));
            true
        } else {
            false
        }
    }

    fn candidate_rejection_reason(&self, path: &Path) -> Option<&'static str> {
        if is_filesystem_root(path) {
            return Some("filesystem root is protected");
        }
        if same_path(path, &self.config.home) {
            return Some("the home directory itself is protected");
        }
        if self.is_configured_root(path) {
            return Some("configured scan roots are inventory boundaries, not candidates");
        }
        if self
            .config
            .scan_roots
            .iter()
            .any(|root| path_is_within(root, path))
        {
            return Some("candidate contains a configured scan root");
        }
        if same_path(path, &self.config.home.join(".cache")) {
            return Some("the complete user cache is never a candidate");
        }
        if same_path(path, &self.config.home.join(".cargo")) {
            return Some("the complete Cargo directory is never a candidate");
        }
        if is_dot_git(path) {
            return Some("repository .git data is protected");
        }
        if self.path_overlaps_protected_zone(path) {
            return Some("the path overlaps a protected boot, system, backup, or user-data zone");
        }
        None
    }

    fn scan_root_rejection_reason(&self, path: &Path) -> Option<&'static str> {
        if path_has_symlink_component(path) {
            return Some("scan root crosses a symbolic link");
        }
        if is_filesystem_root(path) {
            return Some("filesystem root is never scanned");
        }
        if same_path(path, &self.config.home) || path_is_within(&self.config.home, path) {
            return Some("all of home is never scanned");
        }
        if same_path(path, &self.config.home.join(".cache")) {
            return Some("all of ~/.cache is never scanned");
        }
        if same_path(path, &self.config.home.join(".cargo")) {
            return Some("all of ~/.cargo is never scanned");
        }
        if is_dot_git(path) {
            return Some("repository .git data is protected");
        }
        if self.path_overlaps_protected_zone(path) {
            return Some("scan root overlaps a protected boot, system, backup, or user-data zone");
        }
        None
    }

    fn is_configured_root(&self, path: &Path) -> bool {
        self.config
            .scan_roots
            .iter()
            .any(|root| same_path(path, root))
    }

    fn path_is_protected_zone(&self, path: &Path) -> bool {
        let omnirush_box = self.config.home.join(".omnirush/box");
        let omnirush_sandbox = self.config.home.join(".omnirush/sandbox");
        if path_is_within(path, &omnirush_box) || path_is_within(path, &omnirush_sandbox) {
            return true;
        }
        if self
            .observation_roots
            .all()
            .iter()
            .any(|root| path_is_within(path, root))
        {
            return true;
        }
        if path_is_within(path, &self.config.home) {
            return false;
        }
        system_protected_prefixes()
            .iter()
            .any(|root| path_is_within(path, root))
    }

    fn path_overlaps_protected_zone(&self, path: &Path) -> bool {
        let omnirush_box = self.config.home.join(".omnirush/box");
        let omnirush_sandbox = self.config.home.join(".omnirush/sandbox");
        let overlaps = |root: &Path| path_is_within(path, root) || path_is_within(root, path);
        overlaps(&omnirush_box)
            || overlaps(&omnirush_sandbox)
            || self
                .observation_roots
                .all()
                .iter()
                .any(|root| overlaps(root))
            || (!path_is_within(path, &self.config.home)
                && system_protected_prefixes()
                    .iter()
                    .any(|root| overlaps(root)))
    }

    fn validate_before_action(
        &self,
        candidate: &DiscoveredCandidate,
        mounts: &MountTable,
    ) -> Result<()> {
        let Some(path) = candidate.public.path.as_deref() else {
            bail!("candidate has no exact filesystem path");
        };
        if path_has_symlink_component(path) {
            bail!("candidate path crosses or became a symbolic link");
        }
        if let Some(reason) = self.candidate_rejection_reason(path) {
            bail!("candidate path became protected: {reason}");
        }
        match &candidate.action {
            CleanupAction::Directory { path, fingerprint }
            | CleanupAction::File { path, fingerprint } => {
                validate_fingerprint(path, fingerprint)?;
                validate_no_mount_at_or_below(path, mounts)?;
                validate_user_owned_tree(path)?;
            }
            CleanupAction::Trash { roots } => {
                if path_has_symlink_component(path) {
                    bail!("Trash path crosses a symbolic link");
                }
                for (root, fingerprint) in roots {
                    validate_fingerprint(root, fingerprint)?;
                    validate_no_mount_at_or_below(root, mounts)?;
                    validate_trash_entries(root, mounts)?;
                    validate_user_owned_tree(root)?;
                }
            }
            CleanupAction::ObservationOnly => {
                bail!("observation-only candidate cannot be applied");
            }
        }
        Ok(())
    }

    fn persist_receipts(&self, report: &ApplyReport) -> Result<()> {
        let receipts: Vec<_> = report
            .receipts
            .iter()
            .map(|receipt| {
                json!({
                    "id": receipt.id,
                    "bytes_before": receipt.bytes_before,
                    "success": receipt.success,
                })
            })
            .collect();
        let failed = report
            .receipts
            .iter()
            .filter(|receipt| !receipt.success)
            .count();
        let payload = serde_json::to_string(&json!({
            "receipts": receipts,
            "reclaimed_estimate": report.reclaimed_estimate,
            "failed": failed,
        }))?;
        let level = if failed == 0 { "info" } else { "warn" };
        self.db
            .event("cleanup.apply", level, None, &payload, now_ms())
            .context("persisting cleanup receipt event")?;
        Ok(())
    }
}

/// Refuse mixed-ownership trees before the first deletion. Without this pass,
/// Recursive deletion can reclaim user-owned children and then fail on a
/// root-owned package-build directory, producing a misleading partial result.
#[cfg(unix)]
fn validate_user_owned_tree(path: &Path) -> Result<()> {
    let own_uid = std::fs::metadata("/proc/self")?.uid();
    let mut pending = vec![path.to_path_buf()];
    let mut seen = 0usize;
    while let Some(current) = pending.pop() {
        seen = seen.saturating_add(1);
        if seen > MAX_ENTRIES_PER_CANDIDATE {
            bail!("ownership preflight exceeded its bounded entry limit");
        }
        let metadata = std::fs::symlink_metadata(&current)
            .with_context(|| format!("reading ownership for {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("ownership preflight encountered a symbolic link");
        }
        if metadata.uid() != own_uid {
            bail!(
                "candidate contains data owned by uid {}; refusing partial cleanup",
                metadata.uid()
            );
        }
        if metadata.is_dir() {
            for entry in std::fs::read_dir(&current).with_context(|| {
                format!("reading {} during ownership preflight", current.display())
            })? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_user_owned_tree(_path: &Path) -> Result<()> {
    Ok(())
}

#[derive(Clone)]
struct DiscoveredCandidate {
    public: CleanupCandidate,
    action: CleanupAction,
}

#[derive(Clone)]
enum CleanupAction {
    Directory {
        path: PathBuf,
        fingerprint: Fingerprint,
    },
    File {
        path: PathBuf,
        fingerprint: Fingerprint,
    },
    Trash {
        roots: Vec<(PathBuf, Fingerprint)>,
    },
    ObservationOnly,
}

struct Inventory {
    candidates: Vec<DiscoveredCandidate>,
    diagnostics: Vec<String>,
    truncated: bool,
    max_candidates: usize,
    seen_ids: HashSet<String>,
    discovery_entries: usize,
    candidate_limit_reached: bool,
    discovery_limit_reached: bool,
}

impl Inventory {
    fn new(max_candidates: usize) -> Self {
        Self {
            candidates: Vec::new(),
            diagnostics: Vec::new(),
            truncated: false,
            max_candidates,
            seen_ids: HashSet::new(),
            discovery_entries: 0,
            candidate_limit_reached: false,
            discovery_limit_reached: false,
        }
    }

    fn has_capacity_for(&mut self, path: &Path) -> bool {
        if self.candidates.len() < self.max_candidates {
            return true;
        }
        if !self.candidate_limit_reached {
            self.diagnostics.push(format!(
                "Candidate limit {} reached before {}",
                self.max_candidates,
                path.display()
            ));
        }
        self.truncated = true;
        self.candidate_limit_reached = true;
        false
    }

    fn record_discovery_entry(&mut self, root: &Path) -> bool {
        if self.discovery_entries >= MAX_DISCOVERY_ENTRIES {
            if !self.discovery_limit_reached {
                self.diagnostics.push(format!(
                    "Discovery entry limit {MAX_DISCOVERY_ENTRIES} reached while scanning {}",
                    root.display()
                ));
            }
            self.truncated = true;
            self.discovery_limit_reached = true;
            return false;
        }
        self.discovery_entries = self.discovery_entries.saturating_add(1);
        true
    }

    fn mark_discovery_limit(&mut self, root: &Path) {
        if !self.discovery_limit_reached {
            self.diagnostics.push(format!(
                "Directory entry limit {MAX_DISCOVERY_ENTRIES} reached while reading {}",
                root.display()
            ));
        }
        self.truncated = true;
        self.discovery_limit_reached = true;
    }

    fn absorb_estimate(&mut self, estimate: &SizeEstimate) {
        self.diagnostics
            .extend(estimate.diagnostics.iter().cloned());
        self.truncated |= estimate.truncated;
    }

    fn push(&mut self, candidate: DiscoveredCandidate) {
        if self.seen_ids.insert(candidate.public.id.clone()) {
            self.candidates.push(candidate);
        }
    }

    fn directory_candidate_covers(&self, path: &Path) -> bool {
        self.candidates
            .iter()
            .any(|candidate| match &candidate.action {
                CleanupAction::Directory { path: root, .. } => path_is_within(path, root),
                CleanupAction::File { .. }
                | CleanupAction::Trash { .. }
                | CleanupAction::ObservationOnly => false,
            })
    }

    fn sort_candidates(&mut self) {
        self.candidates.sort_by(|left, right| {
            left.public
                .risk
                .cmp(&right.public.risk)
                .then_with(|| {
                    left.public
                        .category
                        .stable_name()
                        .cmp(right.public.category.stable_name())
                })
                .then_with(|| left.public.path.cmp(&right.public.path))
                .then_with(|| left.public.label.cmp(&right.public.label))
        });
    }

    fn into_report(self) -> CleanupReport {
        let mut safe_bytes = 0u64;
        let mut review_bytes = 0u64;
        let mut protected_bytes = 0u64;
        let candidates = self
            .candidates
            .into_iter()
            .map(|candidate| {
                match candidate.public.risk {
                    CleanupRisk::Safe => {
                        safe_bytes = safe_bytes.saturating_add(candidate.public.bytes)
                    }
                    CleanupRisk::Review => {
                        review_bytes = review_bytes.saturating_add(candidate.public.bytes)
                    }
                    CleanupRisk::Protected => {
                        protected_bytes = protected_bytes.saturating_add(candidate.public.bytes)
                    }
                }
                candidate.public
            })
            .collect();
        CleanupReport {
            candidates,
            safe_bytes,
            review_bytes,
            protected_bytes,
            diagnostics: self.diagnostics,
            truncated: self.truncated,
        }
    }
}

struct CandidateSpec {
    label: String,
    path: Option<PathBuf>,
    bytes: u64,
    risk: CleanupRisk,
    category: CleanupCategory,
    reason: String,
    reproducible: bool,
    requires_root: bool,
    supported: bool,
    warning: Option<String>,
}

fn make_candidate(spec: CandidateSpec) -> CleanupCandidate {
    let path_key = spec
        .path
        .as_deref()
        .map(canonical_or_lexical)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<no-path>".to_owned());
    let identity = format!(
        "{CANDIDATE_ID_VERSION}\0{}\0{path_key}\0{}",
        spec.category.stable_name(),
        spec.label
    );
    CleanupCandidate {
        id: sha256_bytes(identity.as_bytes()),
        label: spec.label,
        path: spec.path,
        bytes: spec.bytes,
        risk: spec.risk,
        category: spec.category,
        reason: spec.reason,
        reproducible: spec.reproducible,
        requires_root: spec.requires_root,
        supported: spec.supported,
        warning: spec.warning,
    }
}

#[derive(Clone, Copy)]
struct KnownCacheSpec {
    relative: &'static str,
    label: &'static str,
    risk: CleanupRisk,
    reason: &'static str,
    reproducible: bool,
    warning: Option<&'static str>,
}

fn known_cache_specs() -> [KnownCacheSpec; 16] {
    [
        KnownCacheSpec {
            relative: ".cache/yay",
            label: "yay cache",
            risk: CleanupRisk::Safe,
            reason: "Cached package builds and downloads; needed data will be re-downloaded.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cache/pip",
            label: "pip cache",
            risk: CleanupRisk::Safe,
            reason: "Cached Python packages; later installs will re-download them.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cache/node-gyp",
            label: "node-gyp cache",
            risk: CleanupRisk::Safe,
            reason: "Cached build headers; the next native build may re-download them.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cache/thumbnails",
            label: "thumbnail cache",
            risk: CleanupRisk::Safe,
            reason: "Generated thumbnails; the file browser will regenerate them on first use.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cache/chromium-headless",
            label: "Chromium headless cache",
            risk: CleanupRisk::Safe,
            reason: "Generated headless-browser cache; the next launch may re-download or rebuild it.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cache/uv",
            label: "uv cache",
            risk: CleanupRisk::Safe,
            reason: "Cached Python packages; later environments will re-download them.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".npm/_cacache",
            label: "npm content cache",
            risk: CleanupRisk::Safe,
            reason: "Cached npm package content; later installs will re-download it.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".npm/_logs",
            label: "npm logs",
            risk: CleanupRisk::Safe,
            reason: "Old npm diagnostic logs; installed packages and projects are unchanged.",
            reproducible: false,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cargo/registry/cache",
            label: "Cargo registry archive cache",
            risk: CleanupRisk::Safe,
            reason: "Cached crate archives; Cargo will re-download them when needed.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cargo/registry/src",
            label: "Cargo registry source cache",
            risk: CleanupRisk::Safe,
            reason: "Extracted crate sources; Cargo will restore them from cache or re-download them.",
            reproducible: true,
            warning: None,
        },
        KnownCacheSpec {
            relative: ".cache/chromium",
            label: "Chromium cache",
            risk: CleanupRisk::Review,
            reason: "Browser cache will be rebuilt; the first launch may be slower and sites may re-download data.",
            reproducible: true,
            warning: Some("Close Chromium and review the exact cache path first."),
        },
        KnownCacheSpec {
            relative: ".cache/spotify",
            label: "Spotify cache",
            risk: CleanupRisk::Review,
            reason: "Media will be re-downloaded; the next launch or relogin may be slower.",
            reproducible: true,
            warning: Some("Close Spotify and confirm offline media is not required."),
        },
        KnownCacheSpec {
            relative: ".cache/hyperframes",
            label: "HyperFrames cache",
            risk: CleanupRisk::Review,
            reason: "Generated assets may be rebuilt or re-downloaded on first launch.",
            reproducible: true,
            warning: Some("Close active HyperFrames jobs before cleanup."),
        },
        KnownCacheSpec {
            relative: ".cache/tracker3",
            label: "Tracker search index cache",
            risk: CleanupRisk::Review,
            reason: "Desktop search data will be rebuilt after relogin and indexing may take time.",
            reproducible: true,
            warning: Some("Review before forcing a desktop search re-index."),
        },
        KnownCacheSpec {
            relative: ".npm/_npx",
            label: "npx package cache",
            risk: CleanupRisk::Review,
            reason: "Cached npx tools will be re-downloaded the next time they run.",
            reproducible: true,
            warning: Some("Offline npx use will no longer have these cached tools."),
        },
        KnownCacheSpec {
            relative: ".local/share/pnpm/store",
            label: "pnpm package store",
            risk: CleanupRisk::Review,
            reason: "Shared package content will be re-downloaded by later pnpm installs.",
            reproducible: true,
            warning: Some("Review projects and offline package needs before clearing the shared store."),
        },
    ]
}

struct SystemSpec<'a> {
    path: &'a Path,
    label: &'static str,
    risk: CleanupRisk,
    category: CleanupCategory,
    reason: &'static str,
    reproducible: bool,
    enumerate_size: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FingerprintKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    kind: FingerprintKind,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    file_len: u64,
    modified_nanos: Option<u128>,
}

impl Fingerprint {
    fn from_metadata(metadata: &Metadata) -> Option<Self> {
        if metadata.file_type().is_symlink() {
            return None;
        }
        let kind = if metadata.is_dir() {
            FingerprintKind::Directory
        } else if metadata.is_file() {
            FingerprintKind::File
        } else {
            return None;
        };
        Some(Self {
            kind,
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            file_len: metadata.len(),
            modified_nanos: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        })
    }
}

fn validate_fingerprint(path: &Path, expected: &Fingerprint) -> Result<()> {
    if path_has_symlink_component(path) {
        bail!("{} crosses or became a symbolic link", path.display());
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("revalidating {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{} became a symbolic link", path.display());
    }
    let Some(actual) = Fingerprint::from_metadata(&metadata) else {
        bail!("{} changed to an unsupported file type", path.display());
    };
    if actual.kind != expected.kind {
        bail!("{} changed file type after inventory", path.display());
    }
    #[cfg(unix)]
    if actual.device != expected.device || actual.inode != expected.inode {
        bail!("{} was replaced after inventory", path.display());
    }
    if expected.kind == FingerprintKind::File
        && (actual.file_len != expected.file_len
            || actual.modified_nanos != expected.modified_nanos)
    {
        bail!("{} changed after inventory", path.display());
    }
    Ok(())
}

#[derive(Default)]
struct SizeEstimate {
    bytes: u64,
    diagnostics: Vec<String>,
    truncated: bool,
}

fn estimate_paths(roots: &[&Path]) -> SizeEstimate {
    let mut estimate = SizeEstimate::default();
    let mut entries_seen = 0usize;
    let mut stack: Vec<PathBuf> = roots.iter().map(|path| (*path).to_path_buf()).collect();

    while let Some(directory) = stack.pop() {
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                estimate.diagnostics.push(format!(
                    "Could not estimate {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        for entry in entries {
            if entries_seen >= MAX_ENTRIES_PER_CANDIDATE {
                estimate.truncated = true;
                estimate.diagnostics.push(format!(
                    "Size estimate for {} stopped at {MAX_ENTRIES_PER_CANDIDATE} entries",
                    roots
                        .first()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "candidate".to_owned())
                ));
                return estimate;
            }
            entries_seen = entries_seen.saturating_add(1);
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    estimate.diagnostics.push(format!(
                        "Could not read an entry under {}: {error}",
                        directory.display()
                    ));
                    continue;
                }
            };
            let path = entry.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    estimate
                        .diagnostics
                        .push(format!("Could not size {}: {error}", path.display()));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                estimate.bytes = estimate.bytes.saturating_add(metadata.len());
            }
        }
    }
    estimate
}

fn inspect_optional_directory(path: &Path) -> Result<Option<Fingerprint>> {
    if path_has_symlink_component(path) {
        bail!("path crosses a symbolic link");
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("path is not a real directory");
    }
    Ok(Fingerprint::from_metadata(&metadata))
}

fn directory_is_nonempty(path: &Path, diagnostics: &mut Vec<String>) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => match entries.next() {
            Some(Ok(_)) => true,
            Some(Err(error)) => {
                diagnostics.push(format!("Could not inspect {}: {error}", path.display()));
                false
            }
            None => false,
        },
        Err(error) => {
            diagnostics.push(format!("Could not read {}: {error}", path.display()));
            false
        }
    }
}

struct BoundedDirectoryEntries {
    entries: Vec<std::fs::DirEntry>,
    truncated: bool,
}

fn sorted_directory_entries(path: &Path) -> std::io::Result<BoundedDirectoryEntries> {
    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in std::fs::read_dir(path)? {
        if entries.len() >= MAX_DISCOVERY_ENTRIES {
            truncated = true;
            break;
        }
        entries.push(entry?);
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    Ok(BoundedDirectoryEntries { entries, truncated })
}

fn is_build_directory(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(OsStr::to_str),
        Some("target" | "node_modules")
    )
}

fn is_cleanup_download(name: &str) -> bool {
    [
        ".deb",
        ".pacman",
        ".pkg.tar.zst",
        ".AppImage",
        ".iso",
        ".zip",
        ".tar",
        ".tar.gz",
        ".tar.xz",
    ]
    .iter()
    .any(|suffix| name.ends_with(suffix))
}

fn is_partial_download(name: &str) -> bool {
    [".crdownload", ".part", ".tmp"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

fn execute_action(action: &CleanupAction, mounts: &MountTable) -> Result<()> {
    match action {
        CleanupAction::Directory { path, fingerprint } => {
            validate_fingerprint(path, fingerprint)?;
            validate_no_mount_at_or_below(path, mounts)?;
            remove_approved_directory(path)
        }
        CleanupAction::File { path, fingerprint } => {
            validate_fingerprint(path, fingerprint)?;
            validate_no_mount_at_or_below(path, mounts)?;
            remove_approved_file(path)
        }
        CleanupAction::Trash { roots } => {
            for (root, fingerprint) in roots {
                validate_fingerprint(root, fingerprint)?;
                validate_no_mount_at_or_below(root, mounts)?;
            }
            for (root, _) in roots {
                empty_approved_directory(root, mounts)?;
            }
            Ok(())
        }
        CleanupAction::ObservationOnly => bail!("observation-only candidate cannot be applied"),
    }
}

fn empty_approved_directory(root: &Path, mounts: &MountTable) -> Result<()> {
    validate_trash_entries(root, mounts)?;
    let entries = sorted_directory_entries(root)
        .with_context(|| format!("reading approved Trash root {}", root.display()))?;
    if entries.truncated {
        bail!(
            "Trash root {} exceeds the bounded executor entry limit",
            root.display()
        );
    }
    for entry in entries.entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("revalidating Trash entry {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            remove_approved_file(&path)?;
        } else {
            validate_no_mount_at_or_below(&path, mounts)?;
            if metadata.is_dir() {
                remove_approved_directory(&path)?;
            } else {
                remove_approved_file(&path)?;
            }
        }
    }
    Ok(())
}

fn validate_trash_entries(root: &Path, mounts: &MountTable) -> Result<()> {
    let entries = sorted_directory_entries(root)
        .with_context(|| format!("reading approved Trash root {}", root.display()))?;
    if entries.truncated {
        bail!(
            "Trash root {} exceeds the bounded executor entry limit",
            root.display()
        );
    }
    for entry in entries.entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("revalidating Trash entry {}", path.display()))?;
        if !metadata.file_type().is_symlink() {
            validate_no_mount_at_or_below(&path, mounts)?;
        }
    }
    Ok(())
}

fn remove_approved_file(path: &Path) -> Result<()> {
    let result = std::fs::remove_file(path); // allowed-delete: user-approved cleanup candidate
    result.with_context(|| format!("removing approved file {}", path.display()))
}

fn remove_approved_directory(path: &Path) -> Result<()> {
    let result = std::fs::remove_dir_all(path); // allowed-delete: user-approved cleanup candidate
    result.with_context(|| format!("removing approved directory {}", path.display()))
}

#[derive(Default)]
struct MountTable {
    mount_points: Vec<PathBuf>,
    loaded: bool,
}

impl MountTable {
    fn load() -> Self {
        let Ok(contents) = std::fs::read_to_string("/proc/self/mountinfo") else {
            return Self::default();
        };
        let mount_points = contents
            .lines()
            .filter_map(|line| line.split_whitespace().nth(4))
            .map(decode_mountinfo_path)
            .map(|path| absolute_lexical(&path))
            .collect();
        Self {
            mount_points,
            loaded: true,
        }
    }

    fn at_or_below(&self, path: &Path) -> Option<&Path> {
        let path = canonical_or_lexical(path);
        self.mount_points
            .iter()
            .find(|mount| path_is_within(mount, &path))
            .map(PathBuf::as_path)
    }
}

fn validate_no_mount_at_or_below(path: &Path, mounts: &MountTable) -> Result<()> {
    if !mounts.loaded {
        bail!("mount table is unavailable; refusing cleanup");
    }
    if let Some(mount) = mounts.at_or_below(path) {
        bail!(
            "{} is or contains mount point {}; refusing cleanup",
            path.display(),
            mount.display()
        );
    }
    #[cfg(unix)]
    {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("checking mount status for {}", path.display()))?;
        if let Some(parent) = path.parent() {
            let parent_metadata = std::fs::symlink_metadata(parent)
                .with_context(|| format!("checking parent mount for {}", path.display()))?;
            if metadata.dev() != parent_metadata.dev() {
                bail!("{} is a mount point; refusing cleanup", path.display());
            }
        }
    }
    Ok(())
}

fn decode_mountinfo_path(value: &str) -> PathBuf {
    PathBuf::from(
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\"),
    )
}

fn path_has_symlink_component(path: &Path) -> bool {
    let absolute = absolute_lexical(path);
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            Err(_) => return true,
        }
    }
    false
}

fn canonical_or_lexical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .map(|path| lexical_normalize(&path))
        .unwrap_or_else(|_| absolute_lexical(path))
}

fn same_path(left: &Path, right: &Path) -> bool {
    canonical_or_lexical(left) == canonical_or_lexical(right)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    canonical_or_lexical(path).starts_with(canonical_or_lexical(root))
}

fn absolute_lexical(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return lexical_normalize(path);
    }
    let base = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    lexical_normalize(&base.join(path))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !path.is_absolute() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn deduplicate_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|path| seen.insert(path.clone()))
        .collect()
}

fn component_count(path: &Path) -> usize {
    path.components().count()
}

fn is_filesystem_root(path: &Path) -> bool {
    absolute_lexical(path).parent().is_none()
}

fn is_dot_git(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == OsStr::new(".git"))
}

fn system_protected_prefixes() -> [&'static Path; 15] {
    [
        Path::new("/.snapshots"),
        Path::new("/bin"),
        Path::new("/boot"),
        Path::new("/dev"),
        Path::new("/efi"),
        Path::new("/etc"),
        Path::new("/lib"),
        Path::new("/lib64"),
        Path::new("/proc"),
        Path::new("/root"),
        Path::new("/run"),
        Path::new("/sbin"),
        Path::new("/sys"),
        Path::new("/usr"),
        Path::new("/var"),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedMemoryInfo {
    total: u64,
    available: u64,
    swap_total: u64,
    swap_free: u64,
}

fn performance_snapshot_from_proc(proc_root: &Path) -> Result<PerformanceSnapshot> {
    let meminfo_path = proc_root.join("meminfo");
    let meminfo = std::fs::read_to_string(&meminfo_path)
        .with_context(|| format!("reading {}", meminfo_path.display()))?;
    let memory = parse_meminfo(&meminfo)?;

    let mut process_count = 0usize;
    let mut processes = Vec::new();
    let entries = std::fs::read_dir(proc_root)
        .with_context(|| format!("reading process inventory {}", proc_root.display()))?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Some(pid_text) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        process_count = process_count.saturating_add(1);
        let status = match std::fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(_) => continue,
        };
        if let Some(process) = parse_process_status(pid, &status) {
            processes.push(process);
        }
    }
    let top_memory = top_memory_processes(processes);

    Ok(PerformanceSnapshot {
        memory_total_bytes: memory.total,
        memory_available_bytes: memory.available,
        swap_total_bytes: memory.swap_total,
        swap_free_bytes: memory.swap_free,
        process_count,
        top_memory,
    })
}

fn parse_meminfo(input: &str) -> Result<ParsedMemoryInfo> {
    let mut total = None;
    let mut available = None;
    let mut swap_total = None;
    let mut swap_free = None;

    for line in input.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let destination = match key.trim() {
            "MemTotal" => &mut total,
            "MemAvailable" => &mut available,
            "SwapTotal" => &mut swap_total,
            "SwapFree" => &mut swap_free,
            _ => continue,
        };
        let Some(bytes) = parse_proc_bytes(value) else {
            bail!("invalid {key} value in /proc/meminfo");
        };
        *destination = Some(bytes);
    }

    let Some(total) = total else {
        bail!("missing MemTotal in /proc/meminfo");
    };
    let Some(available) = available else {
        bail!("missing MemAvailable in /proc/meminfo");
    };
    let Some(swap_total) = swap_total else {
        bail!("missing SwapTotal in /proc/meminfo");
    };
    let Some(swap_free) = swap_free else {
        bail!("missing SwapFree in /proc/meminfo");
    };

    Ok(ParsedMemoryInfo {
        total,
        available,
        swap_total,
        swap_free,
    })
}

fn parse_process_status(pid: u32, input: &str) -> Option<PerformanceProcess> {
    let mut name = None;
    let mut rss_bytes = None;
    for line in input.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "Name" => {
                let value = value.trim();
                if !value.is_empty() {
                    name = Some(value.to_owned());
                }
            }
            "VmRSS" => rss_bytes = parse_proc_bytes(value),
            _ => {}
        }
    }
    Some(PerformanceProcess {
        pid,
        name: name?,
        rss_bytes: rss_bytes?,
    })
}

fn parse_proc_bytes(value: &str) -> Option<u64> {
    let mut fields = value.split_whitespace();
    let amount = fields.next()?.parse::<u64>().ok()?;
    match fields.next() {
        Some("kB") => Some(amount.saturating_mul(1024)),
        Some("B") | None => Some(amount),
        Some(_) => None,
    }
}

fn top_memory_processes(mut processes: Vec<PerformanceProcess>) -> Vec<PerformanceProcess> {
    processes.sort_unstable_by(|left, right| {
        right
            .rss_bytes
            .cmp(&left.rss_bytes)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    processes.truncate(8);
    processes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes};
    use tempfile::TempDir;

    fn write_file(path: &Path, contents: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn test_config(
        home: &Path,
        scan_roots: Vec<PathBuf>,
        build_artifact_depth: usize,
    ) -> CleanupConfig {
        CleanupConfig {
            home: home.to_path_buf(),
            scan_roots,
            download_age_days: 1,
            build_artifact_depth,
            max_candidates: 100,
        }
    }

    fn test_engine(
        sandbox: &TempDir,
        home: &Path,
        scan_roots: Vec<PathBuf>,
        build_artifact_depth: usize,
    ) -> (CleanupEngine, Arc<Db>) {
        let db = Arc::new(Db::open_memory().unwrap());
        let engine = CleanupEngine::new_with_observation_roots(
            db.clone(),
            test_config(home, scan_roots, build_artifact_depth),
            SystemObservationRoots::under(sandbox.path().join("system-observations")),
        );
        (engine, db)
    }

    fn candidate_at(report: &CleanupReport, path: &Path) -> CleanupCandidate {
        report
            .candidates
            .iter()
            .find(|candidate| candidate.path.as_deref() == Some(path))
            .unwrap()
            .clone()
    }

    fn set_modified(path: &Path, modified: SystemTime) {
        let file = File::options().write(true).open(path).unwrap();
        file.set_times(FileTimes::new().set_modified(modified))
            .unwrap();
    }

    #[test]
    fn parses_meminfo_fixture_as_bytes() {
        let fixture = r#"
MemTotal:       16384 kB
MemFree:         1024 kB
MemAvailable:    8192 kB
SwapTotal:       4096 kB
SwapFree:        3072 kB
"#;

        let parsed = parse_meminfo(fixture).unwrap();
        assert_eq!(parsed.total, 16_384 * 1024);
        assert_eq!(parsed.available, 8_192 * 1024);
        assert_eq!(parsed.swap_total, 4_096 * 1024);
        assert_eq!(parsed.swap_free, 3_072 * 1024);
        assert!(parse_meminfo("MemTotal: 1 kB").is_err());
    }

    #[test]
    fn parses_process_status_fixture_best_effort() {
        let fixture =
            "Name:\tblue worker\nState:\tS (sleeping)\nVmSize:\t5000 kB\nVmRSS:\t1536 kB\n";

        let process = parse_process_status(42, fixture).unwrap();
        assert_eq!(process.pid, 42);
        assert_eq!(process.name, "blue worker");
        assert_eq!(process.rss_bytes, 1_536 * 1024);
        assert!(parse_process_status(43, "Name:\tvanished\n").is_none());
    }

    #[test]
    fn top_memory_is_descending_deterministic_and_limited_to_eight() {
        let processes = (1..=10)
            .map(|pid| PerformanceProcess {
                pid,
                name: format!("process-{pid}"),
                rss_bytes: u64::from(pid) * 1024,
            })
            .collect();

        let top = top_memory_processes(processes);
        assert_eq!(top.len(), 8);
        assert_eq!(top[0].pid, 10);
        assert_eq!(top[7].pid, 3);
        assert!(top
            .windows(2)
            .all(|pair| pair[0].rss_bytes >= pair[1].rss_bytes));
    }

    #[test]
    fn performance_snapshot_tolerates_disappearing_process_status() {
        let sandbox = TempDir::new().unwrap();
        write_file(
            &sandbox.path().join("meminfo"),
            b"MemTotal: 100 kB\nMemAvailable: 40 kB\nSwapTotal: 20 kB\nSwapFree: 10 kB\n",
        );
        write_file(
            &sandbox.path().join("100/status"),
            b"Name:\tfixture\nVmRSS:\t7 kB\n",
        );
        std::fs::create_dir_all(sandbox.path().join("101")).unwrap();
        write_file(
            &sandbox.path().join("self/status"),
            b"Name:\tignored\nVmRSS:\t99 kB\n",
        );

        let snapshot = performance_snapshot_from_proc(sandbox.path()).unwrap();
        assert_eq!(snapshot.memory_total_bytes, 100 * 1024);
        assert_eq!(snapshot.process_count, 2);
        assert_eq!(snapshot.top_memory.len(), 1);
        assert_eq!(snapshot.top_memory[0].pid, 100);
        assert_eq!(snapshot.top_memory[0].rss_bytes, 7 * 1024);
    }

    #[test]
    fn inventories_known_safe_cache() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/yay");
        write_file(&cache.join("package.tar.zst"), b"cache");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);

        let report = engine.scan().unwrap();
        let candidate = candidate_at(&report, &cache);
        assert_eq!(candidate.risk, CleanupRisk::Safe);
        assert_eq!(candidate.category, CleanupCategory::Cache);
        assert!(candidate.supported);
        assert!(!candidate.requires_root);
        assert_eq!(candidate.bytes, 5);
        assert!(candidate.reason.contains("re-downloaded"));
        assert_eq!(report.safe_bytes, 5);
    }

    #[test]
    fn inventories_review_cache_without_preselection() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/spotify");
        write_file(&cache.join("media"), b"review");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);

        let report = engine.scan().unwrap();
        let candidate = candidate_at(&report, &cache);
        assert_eq!(candidate.risk, CleanupRisk::Review);
        assert!(candidate.supported);
        assert!(candidate.warning.is_some());
        assert!(candidate.reason.contains("re-downloaded"));
        assert!(candidate.reason.contains("relogin"));
    }

    #[cfg(unix)]
    #[test]
    fn build_discovery_is_depth_bounded_deduplicated_and_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let projects = home.join("Projects");
        let target = projects.join("alpha/target");
        let node_modules = projects.join("beta/node_modules");
        let too_deep = projects.join("deep/one/two/target");
        let nested = target.join("nested/node_modules");
        write_file(&target.join("debug/app"), b"target");
        write_file(&node_modules.join("pkg/index.js"), b"node");
        write_file(&too_deep.join("artifact"), b"deep");
        write_file(&nested.join("artifact"), b"nested");
        let external = sandbox.path().join("external-target");
        write_file(&external.join("artifact"), b"external");
        std::fs::create_dir_all(projects.join("gamma")).unwrap();
        symlink(&external, projects.join("gamma/target")).unwrap();

        let (engine, _) = test_engine(&sandbox, &home, vec![projects], 2);
        let report = engine.scan().unwrap();
        let build_paths: Vec<_> = report
            .candidates
            .iter()
            .filter(|candidate| candidate.category == CleanupCategory::BuildArtifact)
            .filter_map(|candidate| candidate.path.clone())
            .collect();

        assert!(build_paths.contains(&target));
        assert!(build_paths.contains(&node_modules));
        assert!(!build_paths.contains(&too_deep));
        assert!(!build_paths.contains(&nested));
        assert!(!build_paths.contains(&home.join("Projects/gamma/target")));
        assert_eq!(build_paths.len(), 2);
    }

    #[test]
    fn downloads_include_only_old_artifacts_and_protect_partials() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let downloads = home.join("Downloads");
        let old = downloads.join("old.zip");
        let fresh = downloads.join("fresh.iso");
        let partial = downloads.join("active.zip.part");
        let personal = downloads.join("notes.txt");
        write_file(&old, b"old");
        write_file(&fresh, b"fresh");
        write_file(&partial, b"partial");
        write_file(&personal, b"personal");
        set_modified(&old, SystemTime::now() - Duration::from_secs(2 * 86_400));
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);

        let report = engine.scan().unwrap();
        let old_candidate = candidate_at(&report, &old);
        let partial_candidate = candidate_at(&report, &partial);
        assert_eq!(old_candidate.risk, CleanupRisk::Review);
        assert!(old_candidate.supported);
        assert_eq!(partial_candidate.risk, CleanupRisk::Protected);
        assert!(!partial_candidate.supported);
        assert!(partial_candidate.reason.contains("active/incomplete"));
        assert!(report
            .candidates
            .iter()
            .all(|candidate| candidate.path.as_deref() != Some(&fresh)));
        assert!(report
            .candidates
            .iter()
            .all(|candidate| candidate.path.as_deref() != Some(&personal)));
    }

    #[test]
    fn system_roots_are_observations_and_protected_roots_are_not_enumerated() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let system = sandbox.path().join("observed-system");
        let roots = SystemObservationRoots::under(&system);
        for root in roots.all() {
            write_file(&root.join("entry/secret-name"), b"system");
        }
        let db = Arc::new(Db::open_memory().unwrap());
        let engine = CleanupEngine::new_with_observation_roots(
            db,
            test_config(&home, Vec::new(), 4),
            roots.clone(),
        );

        let report = engine.scan().unwrap();
        assert_eq!(report.candidates.len(), 6);
        let pacman = candidate_at(&report, &roots.pacman_cache);
        assert_eq!(pacman.risk, CleanupRisk::Review);
        assert!(pacman.requires_root);
        assert!(!pacman.supported);
        let debtap = candidate_at(&report, &roots.debtap_cache);
        assert_eq!(debtap.risk, CleanupRisk::Safe);
        assert!(debtap.requires_root);

        for protected in [&roots.snapshots, &roots.efi, &roots.ryoku_backups] {
            let candidate = candidate_at(&report, protected);
            assert_eq!(candidate.risk, CleanupRisk::Protected);
            assert_eq!(candidate.bytes, 0);
            assert!(candidate.reason.contains("Blue refuses direct deletion"));
        }
    }

    #[test]
    fn confirmation_phrases_are_exact_and_risk_sensitive() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let safe = home.join(".cache/yay");
        let review = home.join(".cache/spotify");
        write_file(&safe.join("safe"), b"safe");
        write_file(&review.join("review"), b"review");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let report = engine.scan().unwrap();
        let safe_candidate = candidate_at(&report, &safe);
        let review_candidate = candidate_at(&report, &review);

        assert_eq!(
            CleanupEngine::required_confirmation(std::slice::from_ref(&safe_candidate)),
            "DELETE SAFE 1"
        );
        assert_eq!(
            CleanupEngine::required_confirmation(&[safe_candidate, review_candidate]),
            "DELETE REVIEWED 2"
        );
    }

    #[test]
    fn stale_id_is_rejected_before_any_action() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/yay");
        let moved = home.join(".cache/yay-moved");
        write_file(&cache.join("artifact"), b"keep");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let candidate = candidate_at(&engine.scan().unwrap(), &cache);
        std::fs::rename(&cache, &moved).unwrap();

        let error = engine.apply(&[candidate.id], "DELETE SAFE 1").unwrap_err();
        assert!(format!("{error:#}").contains("unknown or stale"));
        assert_eq!(std::fs::read(moved.join("artifact")).unwrap(), b"keep");
    }

    #[test]
    fn safe_apply_removes_only_the_exact_candidate_and_records_a_receipt() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/yay");
        let unrelated = home.join("Documents/keep.txt");
        write_file(&cache.join("artifact"), b"cache");
        write_file(&unrelated, b"keep");
        let (engine, db) = test_engine(&sandbox, &home, Vec::new(), 4);
        let candidate = candidate_at(&engine.scan().unwrap(), &cache);

        let report = engine
            .apply(std::slice::from_ref(&candidate.id), "DELETE SAFE 1")
            .unwrap();
        assert_eq!(report.receipts.len(), 1);
        assert!(report.receipts[0].success);
        assert_eq!(report.reclaimed_estimate, 5);
        assert!(!cache.exists());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"keep");

        let events = db.recent_events(1).unwrap();
        assert_eq!(events[0].kind, "cleanup.apply");
        assert!(events[0].payload.contains(&candidate.id));
        assert!(!events[0]
            .payload
            .contains(&home.to_string_lossy().to_string()));
        assert!(!events[0].payload.contains("yay cache"));
    }

    #[test]
    fn review_apply_requires_exact_reviewed_confirmation() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/spotify");
        write_file(&cache.join("media"), b"review");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let candidate = candidate_at(&engine.scan().unwrap(), &cache);

        assert!(engine
            .apply(std::slice::from_ref(&candidate.id), "delete reviewed 1")
            .is_err());
        assert!(cache.exists());
        let report = engine.apply(&[candidate.id], "DELETE REVIEWED 1").unwrap();
        assert!(report.receipts[0].success);
        assert!(!cache.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_swap_is_refused() {
        use std::os::unix::fs::symlink;

        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/yay");
        let moved = home.join(".cache/yay-real");
        write_file(&cache.join("artifact"), b"keep");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let candidate = candidate_at(&engine.scan().unwrap(), &cache);
        std::fs::rename(&cache, &moved).unwrap();
        symlink(&moved, &cache).unwrap();

        assert!(engine.apply(&[candidate.id], "DELETE SAFE 1").is_err());
        assert_eq!(std::fs::read(moved.join("artifact")).unwrap(), b"keep");
    }

    #[test]
    fn configured_scan_root_is_never_offered_or_removed() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/yay");
        let configured_root = cache.join("configured-root");
        write_file(&configured_root.join("artifact"), b"keep");
        let (initial_engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let initial = candidate_at(&initial_engine.scan().unwrap(), &cache);
        let (protected_engine, _) = test_engine(&sandbox, &home, vec![configured_root.clone()], 4);

        let report = protected_engine.scan().unwrap();
        assert!(report
            .candidates
            .iter()
            .all(|candidate| candidate.path.as_deref() != Some(&cache)));
        assert!(protected_engine
            .apply(&[initial.id], "DELETE SAFE 1")
            .is_err());
        assert_eq!(
            std::fs::read(configured_root.join("artifact")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn no_selection_is_an_error() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);

        let error = engine.apply(&[], "DELETE SAFE 0").unwrap_err();
        assert!(format!("{error:#}").contains("empty"));
    }

    #[test]
    fn protected_selection_rejects_the_batch_before_safe_deletion() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let cache = home.join(".cache/yay");
        let partial = home.join("Downloads/active.iso.part");
        write_file(&cache.join("artifact"), b"keep");
        write_file(&partial, b"partial");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let report = engine.scan().unwrap();
        let safe = candidate_at(&report, &cache);
        let protected = candidate_at(&report, &partial);

        let error = engine
            .apply(&[safe.id, protected.id], "DELETE REVIEWED 2")
            .unwrap_err();
        assert!(format!("{error:#}").contains("protected"));
        assert_eq!(std::fs::read(cache.join("artifact")).unwrap(), b"keep");
    }

    #[test]
    fn trash_apply_keeps_roots_and_removes_only_their_contents() {
        let sandbox = TempDir::new().unwrap();
        let home = sandbox.path().join("home");
        let trash = home.join(".local/share/Trash");
        let files = trash.join("files");
        let info = trash.join("info");
        write_file(&files.join("folder/item"), b"trash");
        write_file(&info.join("item.trashinfo"), b"metadata");
        let unrelated = home.join("Documents/keep");
        write_file(&unrelated, b"keep");
        let (engine, _) = test_engine(&sandbox, &home, Vec::new(), 4);
        let candidate = candidate_at(&engine.scan().unwrap(), &trash);

        let report = engine.apply(&[candidate.id], "DELETE REVIEWED 1").unwrap();
        assert!(report.receipts[0].success);
        assert!(files.is_dir());
        assert!(info.is_dir());
        assert_eq!(std::fs::read_dir(&files).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&info).unwrap().count(), 0);
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"keep");
    }
}
