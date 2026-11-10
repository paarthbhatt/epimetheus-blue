//! Native Epimetheus Blue control center.
//!
//! This is an actual Wayland/X11 application built with egui/eframe. There is
//! no web server, browser shell, Electron runtime, or embedded web view.

mod pages;
mod shell;
mod theme;
mod visuals;

use anyhow::{Context, Result};
use blue_core::{Config, Counts, Dataset, Db, Event, Quarantine, Quarantined, Tier};
use blue_feeds::{Feeds, FeedsConfig, SyncReport};
use blue_guard::{Guard, GuardConfig, GuardReport};
use blue_scan::{ScanConfig, ScanEngine};
use eframe::egui::{self, Align, Color32, CornerRadius, FontId, Frame, RichText, Stroke, Vec2};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use theme::{AMBER, BG, BLUE, BORDER, GREEN, MUTED, PANEL, PANEL_HOVER, RED, TEXT};

#[derive(Clone)]
pub struct AppDeps {
    pub config: Config,
    pub db: Arc<Db>,
    pub quarantine: Arc<Quarantine>,
}

/// Open the native control center and block until its window closes.
pub fn run(deps: AppDeps) -> Result<()> {
    let renderer = preferred_renderer(std::env::var("BLUE_RENDERER").ok().as_deref());
    let can_retry_with_glow = matches!(renderer, eframe::Renderer::Wgpu);
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title("Epimetheus Blue")
            .with_app_id("epimetheus-blue")
            .with_active(true)
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 620.0]),
        ..Default::default()
    };
    match eframe::run_native(
        "Epimetheus Blue",
        options,
        Box::new(move |cc| Ok(Box::new(BlueApp::new(cc, deps)))),
    ) {
        Ok(()) => Ok(()),
        Err(error) if can_retry_with_glow => {
            // winit cannot create a second event loop in this process. The child
            // selects Glow, so a compatibility failure cannot restart again.
            eprintln!(
                "Epimetheus Blue: wgpu failed ({error}); trying the OpenGL compatibility renderer."
            );
            let executable = std::env::current_exe()
                .with_context(|| format!("locating the executable after wgpu failed: {error}"))?;
            let status = glow_compatibility_command(&executable, std::env::args_os().skip(1))
                .spawn()
                .with_context(|| {
                    format!("starting OpenGL compatibility after wgpu failed: {error}")
                })?
                .wait()
                .context("waiting for the OpenGL compatibility window")?;
            anyhow::ensure!(
                status.success(),
                "OpenGL compatibility exited with {status}; wgpu failed: {error}"
            );
            Ok(())
        }
        Err(error) => Err(anyhow::anyhow!(error.to_string())),
    }
}

fn preferred_renderer(preference: Option<&str>) -> eframe::Renderer {
    if preference.is_some_and(|value| value.eq_ignore_ascii_case("glow")) {
        eframe::Renderer::Glow
    } else {
        eframe::Renderer::Wgpu
    }
}

fn glow_compatibility_command(
    executable: &Path,
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> std::process::Command {
    let mut command = std::process::Command::new(executable);
    command.args(arguments).env("BLUE_RENDERER", "glow");
    command
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Page {
    Overview,
    Scanner,
    Integrity,
    Network,
    Firewall,
    Reputation,
    Cleanup,
    Quarantine,
    Filters,
    Browser,
    Settings,
}

struct Snapshot {
    counts: Counts,
    events: Vec<Event>,
    finding_groups: Vec<blue_core::FindingGroup>,
    quarantine: Vec<Quarantined>,
    datasets: Vec<Dataset>,
}

impl Snapshot {
    fn load(db: &Db) -> Result<Snapshot> {
        let finding_groups = db.list_finding_groups(250, true)?;
        Ok(Snapshot {
            counts: db.counts()?,
            events: db.recent_events(60)?,
            finding_groups,
            quarantine: db.list_quarantine(false)?,
            datasets: db.list_datasets()?,
        })
    }

    fn empty() -> Snapshot {
        Snapshot {
            counts: Counts::default(),
            events: Vec::new(),
            finding_groups: Vec::new(),
            quarantine: Vec::new(),
            datasets: Vec::new(),
        }
    }
}

enum JobResult {
    Scan(Result<ScanSummary, String>),
    Guard(Result<GuardReport, String>),
    Network(Result<blue_net::NetReport, String>),
    Firewall(Result<String, String>),
    ReputationSync(Result<blue_reputation::HashSyncReport, String>),
    ReputationCheck(Result<blue_reputation::ReputationResult, String>),
    CleanupScan(
        Result<
            (
                blue_cleanup::CleanupReport,
                blue_cleanup::PerformanceSnapshot,
            ),
            String,
        >,
    ),
    CleanupApply(Result<blue_cleanup::ApplyReport, String>),
    Feeds(Result<SyncReport, String>),
    Rollback(String, Result<(), String>),
    Restore(i64, Result<PathBuf, String>),
    DnsStopped(Result<(), String>),
}

#[derive(Default)]
struct ScanSummary {
    files: usize,
    candidates: usize,
    threats: usize,
    quarantined: usize,
    containment_failures: usize,
    errors: usize,
}

struct BlueApp {
    reduced_motion: bool,
    guardian: visuals::Shield,
    deps: AppDeps,
    page: Page,
    snapshot: Snapshot,
    last_refresh: Instant,
    refresh_error: Option<String>,
    tx: mpsc::Sender<JobResult>,
    rx: mpsc::Receiver<JobResult>,
    jobs: HashSet<&'static str>,
    message: Option<(String, bool)>,
    scan_path: String,
    last_scan: Option<ScanSummary>,
    last_guard: Option<GuardReport>,
    last_net: Option<blue_net::NetReport>,
    firewall_policy: blue_firewall::FirewallPolicy,
    firewall_status: blue_firewall::FirewallStatus,
    firewall_approval: bool,
    firewall_rule_name: String,
    firewall_rule_port: String,
    firewall_rule_source: String,
    firewall_rule_udp: bool,
    reputation_status: Option<blue_reputation::ReputationStatus>,
    reputation_result: Option<blue_reputation::ReputationResult>,
    reputation_path: String,
    reputation_online: bool,
    cleanup_report: Option<blue_cleanup::CleanupReport>,
    last_cleanup_apply: Option<blue_cleanup::ApplyReport>,
    cleanup_apply_error: Option<String>,
    cleanup_performance: Option<blue_cleanup::PerformanceSnapshot>,
    cleanup_selected: HashSet<String>,
    cleanup_confirmation: String,
    last_feed: Option<SyncReport>,
    realtime: bool,
    watcher_stop: Option<tokio::sync::watch::Sender<bool>>,
    dns: bool,
    dns_stop: Option<tokio::sync::watch::Sender<bool>>,
    dns_stats: Arc<blue_dns::DnsStats>,
    dns_routed: bool,
    guard_timer: bool,
    feed_timer: bool,
    net_timer: bool,
    reputation_timer: bool,
    watch_unit_installed: bool,
    guard_unit_installed: bool,
    feed_unit_installed: bool,
    net_unit_installed: bool,
    reputation_unit_installed: bool,
    dns_unit_installed: bool,
    last_service_refresh: Instant,
}

impl BlueApp {
    fn new(cc: &eframe::CreationContext<'_>, deps: AppDeps) -> BlueApp {
        let reduced_motion =
            std::env::var("BLUE_REDUCED_MOTION").is_ok_and(|value| value == "1" || value == "true");
        theme::apply(&cc.egui_ctx, reduced_motion);
        let (tx, rx) = mpsc::channel();
        let scan_path = deps
            .config
            .roots()
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."))
            .to_string_lossy()
            .into_owned();
        let (snapshot, refresh_error) = match Snapshot::load(&deps.db) {
            Ok(snapshot) => (snapshot, None),
            Err(error) => (
                Snapshot::empty(),
                Some(format!("Status unavailable: {error}")),
            ),
        };
        let watch_unit_installed = user_unit_exists("blue-watch.service");
        let guard_unit_installed = user_unit_exists("blue-guard.timer");
        let feed_unit_installed = user_unit_exists("blue-feeds.timer");
        let net_unit_installed = user_unit_exists("blue-net.timer");
        let reputation_unit_installed = user_unit_exists("blue-reputation.timer");
        let dns_unit_installed = user_unit_exists("blue-dns.service");
        let dns_routed = system_dns_uses_loopback();
        let reputation_path = scan_path.clone();
        BlueApp {
            reduced_motion,
            guardian: visuals::Shield::new(cc),
            deps,
            page: Page::Overview,
            snapshot,
            last_refresh: Instant::now(),
            refresh_error,
            tx,
            rx,
            jobs: HashSet::new(),
            message: None,
            scan_path,
            last_scan: None,
            last_guard: None,
            last_net: None,
            firewall_policy: blue_firewall::FirewallPolicy::new(
                blue_firewall::FirewallProfile::Public,
            ),
            firewall_status: blue_firewall::FirewallClient::new()
                .status()
                .unwrap_or_default(),
            firewall_approval: false,
            firewall_rule_name: String::new(),
            firewall_rule_port: String::new(),
            firewall_rule_source: String::new(),
            firewall_rule_udp: false,
            reputation_status: None,
            reputation_result: None,
            reputation_path,
            reputation_online: false,
            cleanup_report: None,
            last_cleanup_apply: None,
            cleanup_apply_error: None,
            cleanup_performance: None,
            cleanup_selected: HashSet::new(),
            cleanup_confirmation: String::new(),
            last_feed: None,
            realtime: watch_unit_installed && user_unit_active("blue-watch.service"),
            watcher_stop: None,
            dns: dns_unit_installed && dns_routed && user_unit_active("blue-dns.service"),
            dns_stop: None,
            dns_stats: Arc::new(blue_dns::DnsStats::default()),
            dns_routed,
            guard_timer: guard_unit_installed && user_unit_active("blue-guard.timer"),
            feed_timer: feed_unit_installed && user_unit_active("blue-feeds.timer"),
            net_timer: net_unit_installed && user_unit_active("blue-net.timer"),
            reputation_timer: reputation_unit_installed
                && user_unit_active("blue-reputation.timer"),
            watch_unit_installed,
            guard_unit_installed,
            feed_unit_installed,
            net_unit_installed,
            reputation_unit_installed,
            dns_unit_installed,
            last_service_refresh: Instant::now(),
        }
    }

    fn refresh(&mut self) {
        match Snapshot::load(&self.deps.db) {
            Ok(snapshot) => {
                self.snapshot = snapshot;
                self.refresh_error = None;
            }
            Err(error) => self.refresh_error = Some(error.to_string()),
        }
        if self.last_service_refresh.elapsed() > Duration::from_secs(30) {
            self.dns_routed = system_dns_uses_loopback();
            if self.watch_unit_installed {
                self.realtime = user_unit_active("blue-watch.service");
            }
            if self.guard_unit_installed {
                self.guard_timer = user_unit_active("blue-guard.timer");
            }
            if self.feed_unit_installed {
                self.feed_timer = user_unit_active("blue-feeds.timer");
            }
            if self.net_unit_installed {
                self.net_timer = user_unit_active("blue-net.timer");
            }
            if self.reputation_unit_installed {
                self.reputation_timer = user_unit_active("blue-reputation.timer");
            }
            if self.dns_unit_installed && self.dns_routed {
                self.dns = user_unit_active("blue-dns.service");
            }
            self.last_service_refresh = Instant::now();
        }
        self.last_refresh = Instant::now();
    }

    fn process_jobs(&mut self) {
        while let Ok(result) = self.rx.try_recv() {
            match result {
                JobResult::Scan(result) => {
                    self.jobs.remove("scan");
                    match result {
                        Ok(summary) => {
                            self.message = Some((
                                format!(
                                    "Scan complete: {} files, {} T2+ detections, {} quarantined, {} containment failures",
                                    summary.files, summary.threats, summary.quarantined, summary.containment_failures
                                ),
                                summary.containment_failures == 0 && summary.errors == 0,
                            ));
                            self.last_scan = Some(summary);
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::Guard(result) => {
                    self.jobs.remove("guard");
                    match result {
                        Ok(report) => {
                            let text = if report.baseline {
                                format!(
                                    "Integrity baseline established ({} entries)",
                                    report.entries
                                )
                            } else {
                                format!(
                                    "Integrity check: {} added, {} modified, {} removed",
                                    report.added, report.modified, report.removed
                                )
                            };
                            self.message = Some((text, report.findings == 0));
                            self.last_guard = Some(report);
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::Network(result) => {
                    self.jobs.remove("network");
                    match result {
                        Ok(report) => {
                            self.message = Some((
                                if report.baseline {
                                    format!(
                                        "Network baseline established: {} public destination(s)",
                                        report.observed
                                    )
                                } else {
                                    format!(
                                        "Network observation: {} new destination(s)",
                                        report.new_remote
                                    )
                                },
                                report.findings == 0,
                            ));
                            self.last_net = Some(report);
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::Firewall(result) => {
                    self.jobs.remove("firewall");
                    self.firewall_approval = false;
                    self.message = Some(match result {
                        Ok(message) => (message, true),
                        Err(error) => (format!("Firewall operation failed: {error}"), false),
                    });
                    self.refresh_firewall();
                }
                JobResult::ReputationSync(result) => {
                    self.jobs.remove("reputation-sync");
                    match result {
                        Ok(report) => {
                            self.message = Some((
                                format!(
                                    "Hash feeds updated: {} source(s), {} SHA-256 hashes",
                                    report.updated.len(),
                                    report.total_hashes
                                ),
                                report.failed.is_empty(),
                            ));
                            self.refresh_reputation_status();
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::ReputationCheck(result) => {
                    self.jobs.remove("reputation-check");
                    match result {
                        Ok(result) => {
                            let matched = result.detector.is_some();
                            self.message = Some((
                                if matched {
                                    "Reputation signal found; review the source and counts below"
                                        .into()
                                } else {
                                    "No configured reputation source listed this exact hash".into()
                                },
                                !matched,
                            ));
                            self.reputation_result = Some(result);
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::CleanupScan(result) => {
                    self.jobs.remove("cleanup-scan");
                    match result {
                        Ok((report, performance)) => {
                            self.cleanup_selected.clear();
                            self.cleanup_report = Some(report);
                            self.cleanup_performance = Some(performance);
                            self.cleanup_confirmation.clear();
                            self.message = Some((
                                "Cleanup analysis complete. Nothing was selected or deleted."
                                    .into(),
                                true,
                            ));
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::CleanupApply(result) => {
                    self.jobs.remove("cleanup-apply");
                    match result {
                        Ok(report) => {
                            let succeeded = report
                                .receipts
                                .iter()
                                .filter(|receipt| receipt.success)
                                .count();
                            let failed = report.receipts.len().saturating_sub(succeeded);
                            self.message = Some((
                                format!(
                                    "Cleanup complete: {succeeded} removed, {failed} failed, {} estimated reclaimed",
                                    format_bytes(report.reclaimed_estimate)
                                ),
                                failed == 0,
                            ));
                            self.last_cleanup_apply = Some(report);
                            self.cleanup_selected.clear();
                            self.cleanup_confirmation.clear();
                            if succeeded > 0 {
                                self.run_cleanup_scan();
                            }
                        }
                        Err(error) => {
                            self.cleanup_apply_error = Some(error.clone());
                            self.message = Some((error, false));
                        }
                    }
                }
                JobResult::Feeds(result) => {
                    self.jobs.remove("feeds");
                    match result {
                        Ok(report) => {
                            self.message = Some((
                                format!(
                                    "Filters updated: {}, failed: {}",
                                    report.updated.len(),
                                    report.failed.len()
                                ),
                                report.failed.is_empty(),
                            ));
                            self.last_feed = Some(report);
                        }
                        Err(error) => self.message = Some((error, false)),
                    }
                }
                JobResult::Rollback(name, result) => {
                    self.jobs.remove("rollback");
                    self.message = Some(match result {
                        Ok(()) => (format!("Rolled {name} back to its previous version"), true),
                        Err(error) => (format!("Rollback failed: {error}"), false),
                    });
                }
                JobResult::Restore(id, result) => {
                    self.jobs.remove("restore");
                    self.message = Some(match result {
                        Ok(path) => (format!("Restored #{id} to {}", path.display()), true),
                        Err(error) => (format!("Restore failed: {error}"), false),
                    });
                }
                JobResult::DnsStopped(result) => {
                    self.dns = false;
                    self.dns_stop = None;
                    if let Err(error) = result {
                        self.message = Some((format!("DNS shield stopped: {error}"), false));
                    }
                }
            }
            self.refresh();
        }
    }

    fn start_scan(&mut self) {
        if !self.jobs.insert("scan") {
            return;
        }
        let path = blue_core::config::expand_tilde(self.scan_path.trim());
        let deps = self.deps.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = scan_tree(&deps, &path).map_err(|error| format!("Scan failed: {error:#}"));
            let _ = tx.send(JobResult::Scan(result));
        });
    }

    fn run_guard(&mut self) {
        if !self.jobs.insert("guard") {
            return;
        }
        let db = self.deps.db.clone();
        let cfg = GuardConfig::from_config(&self.deps.config);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = Guard::new(db, cfg)
                .run_once()
                .map_err(|error| format!("Integrity check failed: {error:#}"));
            let _ = tx.send(JobResult::Guard(result));
        });
    }

    fn refresh_firewall(&mut self) {
        self.firewall_status = blue_firewall::FirewallClient::new()
            .status()
            .unwrap_or_else(|error| blue_firewall::FirewallStatus {
                message: error.to_string(),
                ..Default::default()
            });
    }

    fn run_firewall(&mut self, action: &'static str) {
        if !self.jobs.insert("firewall") {
            return;
        }
        let policy = self.firewall_policy.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let client = blue_firewall::FirewallClient::new();
            let result = match action {
                "apply" => client.apply(&policy),
                "confirm" => client.confirm(),
                "rollback" => client.rollback(),
                "disable" => client.disable(),
                _ => Err(anyhow::anyhow!("unknown firewall action")),
            }
            .map_err(|error| error.to_string());
            let _ = tx.send(JobResult::Firewall(result));
        });
    }

    fn run_network(&mut self) {
        if !self.jobs.insert("network") {
            return;
        }
        let observer = blue_net::NetObserver::new(
            self.deps.db.clone(),
            blue_net::NetConfig::from_config(&self.deps.config),
        );
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = observer
                .run_once()
                .map_err(|error| format!("Network observation failed: {error:#}"));
            let _ = tx.send(JobResult::Network(result));
        });
    }

    fn reputation_engine(&self) -> Result<blue_reputation::ReputationEngine> {
        blue_reputation::ReputationEngine::new(
            self.deps.db.clone(),
            blue_reputation::ReputationConfig::from_config(&self.deps.config),
        )
    }

    fn refresh_reputation_status(&mut self) {
        match self.reputation_engine() {
            Ok(engine) => self.reputation_status = Some(engine.status()),
            Err(error) => {
                self.message = Some((format!("Reputation unavailable: {error:#}"), false))
            }
        }
    }

    fn sync_reputation(&mut self) {
        if !self.jobs.insert("reputation-sync") {
            return;
        }
        let db = self.deps.db.clone();
        let config = blue_reputation::ReputationConfig::from_config(&self.deps.config);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = blue_reputation::ReputationEngine::new(db, config)
                .and_then(|engine| engine.sync())
                .map_err(|error| format!("Hash feed update failed: {error:#}"));
            let _ = tx.send(JobResult::ReputationSync(result));
        });
    }

    fn check_reputation(&mut self) {
        if !self.jobs.insert("reputation-check") {
            return;
        }
        let path = blue_core::config::expand_tilde(self.reputation_path.trim());
        let online = self.reputation_online;
        let db = self.deps.db.clone();
        let config = blue_reputation::ReputationConfig::from_config(&self.deps.config);
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = blue_reputation::ReputationEngine::new(db, config)
                .and_then(|engine| engine.check_file(&path, online))
                .map_err(|error| format!("Reputation check failed: {error:#}"));
            let _ = tx.send(JobResult::ReputationCheck(result));
        });
    }

    fn cleanup_engine(&self) -> blue_cleanup::CleanupEngine {
        blue_cleanup::CleanupEngine::new(
            self.deps.db.clone(),
            blue_cleanup::CleanupConfig::from_config(&self.deps.config),
        )
    }

    fn run_cleanup_scan(&mut self) {
        if self.jobs.contains("cleanup-apply") {
            return;
        }
        if !self.jobs.insert("cleanup-scan") {
            return;
        }
        self.cleanup_confirmation.clear();
        let engine = self.cleanup_engine();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = engine
                .scan()
                .and_then(|report| {
                    blue_cleanup::performance_snapshot().map(|performance| (report, performance))
                })
                .map_err(|error| format!("Cleanup analysis failed: {error:#}"));
            let _ = tx.send(JobResult::CleanupScan(result));
        });
    }

    fn apply_cleanup(&mut self) {
        if self.jobs.contains("cleanup-scan") {
            self.message = Some((
                "Wait for storage analysis to finish before approving deletion.".into(),
                false,
            ));
            return;
        }
        if !self.jobs.insert("cleanup-apply") {
            return;
        }
        self.last_cleanup_apply = None;
        self.cleanup_apply_error = None;
        self.message = Some((
            format!(
                "Revalidating {} explicitly approved cleanup candidates…",
                self.cleanup_selected.len()
            ),
            true,
        ));
        let ids = self.cleanup_selected.iter().cloned().collect::<Vec<_>>();
        let confirmation = self.cleanup_confirmation.clone();
        let engine = self.cleanup_engine();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = engine
                .apply(&ids, &confirmation)
                .map_err(|error| format!("Cleanup refused: {error:#}"));
            let _ = tx.send(JobResult::CleanupApply(result));
        });
    }

    fn sync_feeds(&mut self) {
        if !self.jobs.insert("feeds") {
            return;
        }
        let feeds = Feeds::new(
            self.deps.db.clone(),
            FeedsConfig::from_config(&self.deps.config),
        );
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = feeds
                .sync()
                .map_err(|error| format!("Filter update failed: {error:#}"));
            let _ = tx.send(JobResult::Feeds(result));
        });
    }

    fn restore(&mut self, id: i64) {
        if !self.jobs.insert("restore") {
            return;
        }
        let quarantine = self.deps.quarantine.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = quarantine.restore(id).map_err(|error| error.to_string());
            let _ = tx.send(JobResult::Restore(id, result));
        });
    }

    fn rollback_feed(&mut self, name: String) {
        if !self.jobs.insert("rollback") {
            return;
        }
        let feeds = Feeds::new(
            self.deps.db.clone(),
            FeedsConfig::from_config(&self.deps.config),
        );
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = feeds.rollback(&name).map_err(|error| error.to_string());
            let _ = tx.send(JobResult::Rollback(name, result));
        });
    }

    fn toggle_realtime(&mut self, on: bool) {
        if self.watch_unit_installed {
            match set_user_unit("blue-watch.service", on) {
                Ok(()) => {
                    self.realtime = on;
                    self.message = Some((
                        if on {
                            "Always-on realtime protection started"
                        } else {
                            "Always-on realtime protection stopped"
                        }
                        .into(),
                        true,
                    ));
                }
                Err(error) => {
                    self.realtime = !on;
                    self.message = Some((format!("Service control failed: {error:#}"), false));
                }
            }
            return;
        }
        if !on {
            if let Some(stop) = self.watcher_stop.take() {
                let _ = stop.send(true);
            }
            self.realtime = false;
            return;
        }
        let cfg = ScanConfig::from_config(&self.deps.config);
        let roots = cfg.roots.clone();
        let debounce = self.deps.config.scan.debounce_ms;
        let engine = match ScanEngine::new(self.deps.db.clone(), self.deps.quarantine.clone(), cfg)
        {
            Ok(value) => Arc::new(value),
            Err(error) => {
                self.message = Some((format!("Cannot start protection: {error:#}"), false));
                return;
            }
        };
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        match blue_scan::watch(engine, roots, debounce, stop_rx) {
            Ok(()) => {
                self.watcher_stop = Some(stop_tx);
                self.realtime = true;
            }
            Err(error) => {
                self.watcher_stop = None;
                self.realtime = false;
                self.message = Some((format!("Cannot start protection: {error:#}"), false));
            }
        }
    }

    fn toggle_dns(&mut self, on: bool) {
        if self.dns_routed && self.dns_unit_installed {
            if !on {
                self.dns = true;
                self.message = Some((
                    "System DNS is routed through Blue. Use setup-system-dns.sh disable so NetworkManager is restored before the resolver stops."
                        .into(),
                    false,
                ));
                return;
            }
            match set_user_unit("blue-dns.service", true) {
                Ok(()) => {
                    self.dns = true;
                    self.message = Some(("System DNS shield started".into(), true));
                }
                Err(error) => {
                    self.dns = false;
                    self.message = Some((format!("DNS service failed: {error:#}"), false));
                }
            }
            return;
        }
        if !on {
            if let Some(stop) = self.dns_stop.take() {
                let _ = stop.send(true);
            }
            self.dns = false;
            return;
        }
        let mut blocklist = blue_dns::Blocklist::new();
        let lists = blue_core::config::expand_tilde(&self.deps.config.feeds.lists_dir);
        if let Err(error) = blocklist.load_dir(&lists) {
            self.message = Some((format!("Cannot load filter lists: {error:#}"), false));
            return;
        }
        if blocklist.is_empty() {
            self.message = Some((
                "Update filter lists before enabling DNS Shield".into(),
                false,
            ));
            return;
        }
        let bind = match self.deps.config.dns.bind.parse() {
            Ok(value) => value,
            Err(error) => {
                self.message = Some((format!("Invalid DNS bind address: {error}"), false));
                return;
            }
        };
        let mut upstreams = Vec::new();
        for value in &self.deps.config.dns.upstreams {
            match value.parse() {
                Ok(address) => upstreams.push(address),
                Err(error) => {
                    self.message = Some((format!("Invalid DNS upstream {value}: {error}"), false));
                    return;
                }
            }
        }
        let block_response = if self.deps.config.dns.block_response == "zero" {
            blue_dns::BlockResponse::Zero
        } else {
            blue_dns::BlockResponse::NxDomain
        };
        let cfg = blue_dns::DnsConfig {
            bind,
            upstreams,
            block_response,
        };
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        self.dns_stop = Some(stop_tx);
        self.dns = true;
        let tx = self.tx.clone();
        let stats = self.dns_stats.clone();
        std::thread::spawn(move || {
            let result = tokio::runtime::Runtime::new()
                .context("starting DNS runtime")
                .and_then(|rt| {
                    rt.block_on(blue_dns::run_with_stats(
                        cfg,
                        Arc::new(blocklist),
                        stats,
                        stop_rx,
                    ))
                })
                .map_err(|error| error.to_string());
            let _ = tx.send(JobResult::DnsStopped(result));
        });
    }

    fn toggle_kill_switch(&mut self) {
        let on = !self.deps.db.kill_switch();
        match self.deps.db.set_kill_switch(on) {
            Ok(()) => {
                self.message = Some((
                    if on {
                        "Emergency pause enabled — detection continues, automatic actions stopped"
                    } else {
                        "Automatic security actions resumed"
                    }
                    .into(),
                    !on,
                ));
                self.refresh();
            }
            Err(error) => self.message = Some((error.to_string(), false)),
        }
    }

    fn acknowledge(&mut self, id: i64) {
        if let Err(error) = self.deps.db.acknowledge_finding(id, blue_core::now_ms()) {
            self.message = Some((error.to_string(), false));
        }
        self.refresh();
    }

    fn sidebar(&mut self, root: &mut egui::Ui) {
        shell::sidebar(self, root);
    }

    fn header(&mut self, ui: &mut egui::Ui, title: &str, subtitle: &str) {
        shell::header(self, ui, title, subtitle);
    }
}

impl eframe::App for BlueApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.process_jobs();
        if self.last_refresh.elapsed() > Duration::from_secs(5) {
            self.refresh();
            self.refresh_firewall();
        }
        self.sidebar(ui);
        shell::workspace(self, ui);
        let focused = ui.input(|input| input.focused);
        let interval = if focused || !self.jobs.is_empty() {
            Duration::from_millis(500)
        } else {
            Duration::from_secs(2)
        };
        ui.ctx().request_repaint_after(interval);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(stop) = self.watcher_stop.take() {
            let _ = stop.send(true);
        }
        if let Some(stop) = self.dns_stop.take() {
            let _ = stop.send(true);
        }
    }
}

fn scan_tree(deps: &AppDeps, path: &Path) -> Result<ScanSummary> {
    if !path.exists() {
        anyhow::bail!("{} does not exist", path.display());
    }
    let engine = ScanEngine::new(
        deps.db.clone(),
        deps.quarantine.clone(),
        ScanConfig::from_config(&deps.config),
    )?;
    let mut summary = ScanSummary::default();
    let walker = walkdir::WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_bulk_build_dir(entry.path()));
    for entry in walker {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => {
                summary.errors += 1;
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        match engine.scan_path(entry.path()) {
            Ok(outcome) => {
                summary.files += 1;
                if outcome.tier == Tier::Candidate {
                    summary.candidates += 1;
                }
                if outcome.tier >= Tier::Corroborated {
                    summary.threats += 1;
                }
                if outcome.quarantined.is_some() {
                    summary.quarantined += 1;
                }
                if outcome.containment_error.is_some() {
                    summary.containment_failures += 1;
                }
            }
            Err(_) => summary.errors += 1,
        }
    }
    Ok(summary)
}

fn is_bulk_build_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| matches!(n, ".git" | "node_modules" | "target" | ".cache"))
}

fn surface(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(18))
        .show(ui, add);
}

fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title)
            .font(shell::display_font(22.0))
            .color(TEXT),
    );
    ui.add(egui::Label::new(RichText::new(subtitle).size(14.0).color(MUTED)).wrap());
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn tier_badge(ui: &mut egui::Ui, tier: Tier) {
    let color = match tier {
        Tier::Observed => MUTED,
        Tier::Candidate => AMBER,
        Tier::Corroborated | Tier::Confirmed => RED,
    };
    Frame::new()
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            28,
        ))
        .stroke(Stroke::new(1.0, color))
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("T{}", tier.as_i64()))
                    .size(10.0)
                    .strong()
                    .color(color),
            );
        });
}

fn empty_state(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(28.0);
        shield(ui, 38.0, MUTED);
        ui.add_space(8.0);
        ui.label(
            RichText::new(title)
                .font(shell::display_font(22.0))
                .color(TEXT),
        );
        ui.add(egui::Label::new(RichText::new(subtitle).size(14.0).color(MUTED)).wrap());
        ui.add_space(28.0);
    });
}

fn shield(ui: &mut egui::Ui, size: f32, color: Color32) {
    theme::icon(ui, theme::Icon::Overview, size, color);
}

fn extension_path() -> PathBuf {
    if let Some(path) = option_env!("BLUE_EXTENSION_DIR").map(PathBuf::from) {
        return path;
    }
    let data_home = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if let Some(path) =
        user_extension_path(data_home.as_deref(), home.as_deref()).filter(|path| path.is_dir())
    {
        return path;
    }
    let installed = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("../share/epimetheus-blue/browser-extension");
    if installed.exists() {
        installed
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../browser-extension")
    }
}

fn user_extension_path(data_home: Option<&Path>, home: Option<&Path>) -> Option<PathBuf> {
    data_home
        .filter(|path| path.is_absolute())
        .map(Path::to_path_buf)
        .or_else(|| {
            home.filter(|path| path.is_absolute())
                .map(|path| path.join(".local/share"))
        })
        .map(|path| path.join("epimetheus-blue/browser-extension"))
}

fn script_plan_command(script: &Path) -> String {
    let quoted = script.to_string_lossy().replace('\'', "'\\''");
    format!("'{quoted}' plan")
}

fn user_unit_exists(name: &str) -> bool {
    std::process::Command::new("systemctl")
        .args([
            "--user",
            "list-unit-files",
            name,
            "--no-legend",
            "--no-pager",
        ])
        .output()
        .ok()
        .is_some_and(|output| output.status.success() && !output.stdout.is_empty())
}

fn user_unit_active(name: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", name])
        .status()
        .ok()
        .is_some_and(|status| status.success())
}

fn set_user_unit(name: &str, on: bool) -> Result<()> {
    if !user_unit_exists(name) {
        anyhow::bail!("{name} is not installed; run scripts/install-local.sh first");
    }
    let verb = if on { "enable" } else { "disable" };
    let output = std::process::Command::new("systemctl")
        .args(["--user", verb, "--now", name])
        .output()
        .with_context(|| format!("running systemctl --user {verb}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        anyhow::bail!(
            "{}",
            if detail.is_empty() {
                "systemctl failed"
            } else {
                &detail
            }
        );
    }
    Ok(())
}

fn system_dns_uses_loopback() -> bool {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .is_some_and(|text| {
            text.lines().any(|line| {
                let line = line.trim();
                line == "nameserver 127.0.0.1" || line == "nameserver ::1"
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{
        glow_compatibility_command, preferred_renderer, script_plan_command, user_extension_path,
    };
    use std::ffi::{OsStr, OsString};
    use std::path::{Path, PathBuf};

    #[test]
    fn wgpu_is_preferred_unless_glow_is_requested() {
        for preference in [None, Some("wgpu"), Some("unknown")] {
            assert!(matches!(
                preferred_renderer(preference),
                eframe::Renderer::Wgpu
            ));
        }
        for preference in [Some("glow"), Some("GLOW")] {
            assert!(matches!(
                preferred_renderer(preference),
                eframe::Renderer::Glow
            ));
        }
    }

    #[test]
    fn compatibility_restart_preserves_program_and_arguments() {
        let arguments = vec![
            OsString::from("gui"),
            OsString::from("--config=Blue Data.toml"),
        ];
        let command =
            glow_compatibility_command(Path::new("/opt/Blue App/blue"), arguments.clone());
        assert_eq!(command.get_program(), OsStr::new("/opt/Blue App/blue"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            arguments
                .iter()
                .map(OsString::as_os_str)
                .collect::<Vec<_>>()
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == OsStr::new("BLUE_RENDERER") && value == Some(OsStr::new("glow"))
        }));
    }

    #[test]
    fn extension_assets_honor_absolute_xdg_data_home() {
        assert_eq!(
            user_extension_path(
                Some(Path::new("/custom/data")),
                Some(Path::new("/home/demo"))
            ),
            Some(PathBuf::from(
                "/custom/data/epimetheus-blue/browser-extension"
            ))
        );
    }

    #[test]
    fn invalid_xdg_data_home_falls_back_to_absolute_home() {
        for data_home in [None, Some(Path::new("")), Some(Path::new("relative/data"))] {
            assert_eq!(
                user_extension_path(data_home, Some(Path::new("/home/demo"))),
                Some(PathBuf::from(
                    "/home/demo/.local/share/epimetheus-blue/browser-extension"
                ))
            );
        }
        assert_eq!(user_extension_path(None, None), None);
        assert_eq!(
            user_extension_path(None, Some(Path::new("relative/home"))),
            None
        );
    }

    #[test]
    fn plan_commands_quote_spaces_and_shell_metacharacters() {
        assert_eq!(
            script_plan_command(Path::new("/tmp/Blue Data/setup.sh")),
            "'/tmp/Blue Data/setup.sh' plan"
        );
        assert_eq!(
            script_plan_command(Path::new("/tmp/a'b;$x.sh")),
            "'/tmp/a'\\''b;$x.sh' plan"
        );
    }
}
