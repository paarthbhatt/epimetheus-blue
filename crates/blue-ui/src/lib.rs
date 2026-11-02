//! Native Epimetheus Blue control center.
//!
//! This is an actual Wayland/X11 application built with egui/eframe. There is
//! no web server, browser shell, Electron runtime, or embedded web view.

use anyhow::{Context, Result};
use blue_core::{Config, Counts, Dataset, Db, Event, Finding, Quarantine, Quarantined, Tier};
use blue_feeds::{Feeds, FeedsConfig, SyncReport};
use blue_guard::{Guard, GuardConfig, GuardReport};
use blue_scan::{ScanConfig, ScanEngine};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Layout, RichText, Stroke, Vec2,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

const BG: Color32 = Color32::from_rgb(8, 13, 23);
const PANEL: Color32 = Color32::from_rgb(14, 22, 36);
const PANEL_HOVER: Color32 = Color32::from_rgb(20, 31, 49);
const BORDER: Color32 = Color32::from_rgb(37, 51, 72);
const TEXT: Color32 = Color32::from_rgb(229, 235, 244);
const MUTED: Color32 = Color32::from_rgb(139, 153, 175);
const GREEN: Color32 = Color32::from_rgb(62, 207, 142);
const AMBER: Color32 = Color32::from_rgb(245, 178, 67);
const RED: Color32 = Color32::from_rgb(244, 95, 105);
const BLUE: Color32 = Color32::from_rgb(88, 166, 255);

#[derive(Clone)]
pub struct AppDeps {
    pub config: Config,
    pub db: Arc<Db>,
    pub quarantine: Arc<Quarantine>,
}

/// Open the native control center and block until its window closes.
pub fn run(deps: AppDeps) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Epimetheus Blue")
            .with_app_id("epimetheus-blue")
            .with_active(true)
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 620.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Epimetheus Blue",
        options,
        Box::new(move |cc| Ok(Box::new(BlueApp::new(cc, deps)))),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Scanner,
    Integrity,
    Network,
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
    findings: Vec<Finding>,
    quarantine: Vec<Quarantined>,
    datasets: Vec<Dataset>,
}

impl Snapshot {
    fn load(db: &Db) -> Result<Snapshot> {
        Ok(Snapshot {
            counts: db.counts()?,
            events: db.recent_events(60)?,
            findings: db.list_findings(250, false)?,
            quarantine: db.list_quarantine(false)?,
            datasets: db.list_datasets()?,
        })
    }

    fn empty() -> Snapshot {
        Snapshot {
            counts: Counts::default(),
            events: Vec::new(),
            findings: Vec::new(),
            quarantine: Vec::new(),
            datasets: Vec::new(),
        }
    }
}

enum JobResult {
    Scan(Result<ScanSummary, String>),
    Guard(Result<GuardReport, String>),
    Network(Result<blue_net::NetReport, String>),
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
    errors: usize,
}

struct BlueApp {
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
    reputation_status: Option<blue_reputation::ReputationStatus>,
    reputation_result: Option<blue_reputation::ReputationResult>,
    reputation_path: String,
    reputation_online: bool,
    cleanup_report: Option<blue_cleanup::CleanupReport>,
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
        configure_style(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel();
        let scan_path = deps
            .config
            .roots()
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."))
            .to_string_lossy()
            .into_owned();
        let snapshot = Snapshot::load(&deps.db).unwrap_or_else(|_| Snapshot::empty());
        let watch_unit_installed = user_unit_exists("blue-watch.service");
        let guard_unit_installed = user_unit_exists("blue-guard.timer");
        let feed_unit_installed = user_unit_exists("blue-feeds.timer");
        let net_unit_installed = user_unit_exists("blue-net.timer");
        let reputation_unit_installed = user_unit_exists("blue-reputation.timer");
        let dns_unit_installed = user_unit_exists("blue-dns.service");
        let dns_routed = system_dns_uses_loopback();
        let reputation_path = scan_path.clone();
        BlueApp {
            deps,
            page: Page::Overview,
            snapshot,
            last_refresh: Instant::now(),
            refresh_error: None,
            tx,
            rx,
            jobs: HashSet::new(),
            message: None,
            scan_path,
            last_scan: None,
            last_guard: None,
            last_net: None,
            reputation_status: None,
            reputation_result: None,
            reputation_path,
            reputation_online: false,
            cleanup_report: None,
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
        if self.last_service_refresh.elapsed() > Duration::from_secs(15) {
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
                                    "Scan complete: {} files, {} threat(s), {} quarantined",
                                    summary.files, summary.threats, summary.quarantined
                                ),
                                true,
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
                            let candidate_ids = report
                                .candidates
                                .iter()
                                .map(|candidate| candidate.id.clone())
                                .collect::<HashSet<_>>();
                            self.cleanup_selected
                                .retain(|id| candidate_ids.contains(id));
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
                            self.cleanup_selected.clear();
                            self.cleanup_confirmation.clear();
                            self.run_cleanup_scan();
                        }
                        Err(error) => self.message = Some((error, false)),
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
        if !self.jobs.insert("cleanup-scan") {
            return;
        }
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
        if !self.jobs.insert("cleanup-apply") {
            return;
        }
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
        egui::Panel::left("sidebar")
            .exact_size(218.0)
            .frame(
                Frame::new()
                    .fill(PANEL)
                    .inner_margin(egui::Margin::same(18)),
            )
            .show(root, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    shield(ui, 32.0, GREEN);
                    ui.vertical(|ui| {
                        ui.label(RichText::new("EPIMETHEUS").size(11.0).color(MUTED).strong());
                        ui.label(RichText::new("BLUE").size(20.0).color(TEXT).strong());
                    });
                });
                ui.add_space(26.0);
                for (page, icon, name) in [
                    (Page::Overview, "◈", "Overview"),
                    (Page::Scanner, "⌕", "Scanner"),
                    (Page::Integrity, "⌁", "Integrity"),
                    (Page::Network, "⇄", "Network"),
                    (Page::Reputation, "#", "Reputation"),
                    (Page::Cleanup, "◫", "Cleanup"),
                    (Page::Quarantine, "◇", "Quarantine"),
                    (Page::Filters, "≋", "Filters"),
                    (Page::Browser, "◎", "Browser Shield"),
                    (Page::Settings, "⚙", "Settings"),
                ] {
                    let selected = self.page == page;
                    let response = ui.add_sized(
                        [182.0, 38.0],
                        egui::Button::new(
                            RichText::new(format!("  {icon}   {name}"))
                                .size(14.0)
                                .color(if selected { TEXT } else { MUTED }),
                        )
                        .fill(if selected {
                            PANEL_HOVER
                        } else {
                            Color32::TRANSPARENT
                        })
                        .stroke(if selected {
                            Stroke::new(1.0, BORDER)
                        } else {
                            Stroke::NONE
                        })
                        .corner_radius(8.0),
                    );
                    if response.clicked() {
                        self.page = page;
                    }
                    ui.add_space(3.0);
                }

                ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
                    let paused = self.deps.db.kill_switch();
                    ui.label(
                        RichText::new(if paused {
                            "● ACTIONS PAUSED"
                        } else {
                            "● SYSTEM READY"
                        })
                        .size(11.0)
                        .color(if paused { AMBER } else { GREEN }),
                    );
                    ui.add_space(8.0);
                    ui.separator();
                });
            });
    }

    fn header(&mut self, ui: &mut egui::Ui, title: &str, subtitle: &str) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(title).size(26.0).strong().color(TEXT));
                ui.label(RichText::new(subtitle).size(13.0).color(MUTED));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let paused = self.deps.db.kill_switch();
                if ui
                    .add(
                        egui::Button::new(if paused {
                            "Resume actions"
                        } else {
                            "Emergency pause"
                        })
                        .fill(if paused {
                            GREEN
                        } else {
                            Color32::from_rgb(64, 30, 36)
                        })
                        .stroke(Stroke::new(1.0, if paused { GREEN } else { RED }))
                        .corner_radius(8.0),
                    )
                    .clicked()
                {
                    self.toggle_kill_switch();
                }
            });
        });
        ui.add_space(18.0);
        if let Some((message, good)) = &self.message {
            Frame::new()
                .fill(if *good {
                    Color32::from_rgb(14, 48, 40)
                } else {
                    Color32::from_rgb(57, 30, 35)
                })
                .stroke(Stroke::new(1.0, if *good { GREEN } else { RED }))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::symmetric(12, 9))
                .show(ui, |ui| {
                    ui.label(RichText::new(message).color(TEXT));
                });
            ui.add_space(12.0);
        }
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Security overview",
            "One honest view of what is protected and what needs attention.",
        );
        let clamd_socket = blue_core::config::expand_tilde(&self.deps.config.scan.clamav.socket);
        if !clamd_socket.exists() {
            Frame::new()
                .fill(Color32::from_rgb(54, 40, 17))
                .stroke(Stroke::new(1.0, AMBER))
                .corner_radius(8.0)
                .inner_margin(egui::Margin::symmetric(12, 9))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(
                            "DEGRADED · ClamAV is unavailable; YARA-X protection remains active",
                        )
                        .color(AMBER)
                        .strong(),
                    );
                });
            ui.add_space(12.0);
        }
        ui.columns(4, |columns| {
            stat_card(
                &mut columns[0],
                "FILES SCANNED",
                self.snapshot.counts.artifacts,
                BLUE,
            );
            stat_card(
                &mut columns[1],
                "ACTIVE FINDINGS",
                self.snapshot.counts.findings,
                AMBER,
            );
            stat_card(
                &mut columns[2],
                "QUARANTINED",
                self.snapshot.counts.quarantined,
                RED,
            );
            let blocked = self.snapshot.counts.blocked + self.dns_stats.snapshot().blocked as i64;
            stat_card(&mut columns[3], "BLOCKED REQUESTS", blocked, GREEN);
        });
        ui.add_space(18.0);
        ui.columns(2, |columns| {
            surface(&mut columns[0], |ui| {
                section_title(
                    ui,
                    "Protection controls",
                    "Services run only while enabled.",
                );
                ui.add_space(12.0);
                if protection_row(
                    ui,
                    "Realtime file protection",
                    "Watch configured folders and scan changed files",
                    &mut self.realtime,
                ) {
                    self.toggle_realtime(self.realtime);
                }
                ui.separator();
                if protection_row(
                    ui,
                    "DNS ad & malware shield",
                    if self.dns_routed {
                        "System DNS is routed through the local shield"
                    } else {
                        "Local resolver only — system DNS setup is not enabled"
                    },
                    &mut self.dns,
                ) {
                    self.toggle_dns(self.dns);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("Integrity guard").strong().color(TEXT));
                        ui.label(
                            RichText::new("Check startup paths and sensitive files").color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                !self.jobs.contains("guard"),
                                egui::Button::new("Run check"),
                            )
                            .clicked()
                        {
                            self.run_guard();
                        }
                    });
                });
            });
            surface(&mut columns[1], |ui| {
                section_title(
                    ui,
                    "Recent activity",
                    "Latest security events on this device.",
                );
                ui.add_space(8.0);
                if self.snapshot.events.is_empty() {
                    empty_state(
                        ui,
                        "No activity yet",
                        "Run a scan or integrity check to start the timeline.",
                    );
                } else {
                    for event in self.snapshot.events.iter().take(7) {
                        event_row(ui, event);
                    }
                }
            });
        });
    }

    fn scanner(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Scanner",
            "Scan a file or folder. Nothing is deleted automatically.",
        );
        surface(ui, |ui| {
            section_title(
                ui,
                "Scan target",
                "Paths are expanded locally; no file is uploaded.",
            );
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let edit = egui::TextEdit::singleline(&mut self.scan_path)
                    .hint_text("~/Downloads or /path/to/file")
                    .desired_width(f32::INFINITY);
                ui.add_sized([ui.available_width() - 122.0, 36.0], edit);
                if ui
                    .add_enabled(!self.jobs.contains("scan"), egui::Button::new("Scan now"))
                    .clicked()
                {
                    self.start_scan();
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.small_button("Downloads").clicked() {
                    self.scan_path = "~/Downloads".into();
                }
                if ui.small_button("Home").clicked() {
                    self.scan_path = "~".into();
                }
                if self.jobs.contains("scan") {
                    ui.spinner();
                    ui.label(RichText::new("Scanning…").color(MUTED));
                }
            });
        });
        ui.add_space(18.0);
        surface(ui, |ui| {
            section_title(
                ui,
                "Last result",
                "Verdicts remain tiered: observed, candidate, corroborated, confirmed.",
            );
            ui.add_space(12.0);
            match &self.last_scan {
                Some(s) => {
                    ui.columns(5, |c| {
                        mini_stat(&mut c[0], "Files", s.files);
                        mini_stat(&mut c[1], "Candidates", s.candidates);
                        mini_stat(&mut c[2], "Threats", s.threats);
                        mini_stat(&mut c[3], "Quarantined", s.quarantined);
                        mini_stat(&mut c[4], "Errors", s.errors);
                    });
                }
                None => empty_state(
                    ui,
                    "No scan in this session",
                    "Choose a target and select Scan now.",
                ),
            }
        });
    }

    fn integrity(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Integrity guard",
            "Detect changes to startup paths, shell files, SSH keys and system units.",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.jobs.contains("guard"),
                    egui::Button::new("Run integrity check"),
                )
                .clicked()
            {
                self.run_guard();
            }
            if self.jobs.contains("guard") {
                ui.spinner();
            }
            if let Some(report) = &self.last_guard {
                ui.label(
                    RichText::new(if report.baseline {
                        "Baseline established — this is not a clean bill of health"
                    } else {
                        "Compared with previous baseline"
                    })
                    .color(MUTED),
                );
            }
        });
        ui.add_space(16.0);
        let findings = self.snapshot.findings.clone();
        surface(ui, |ui| {
            section_title(
                ui,
                "Unreviewed findings",
                "Every filesystem change is T1 until independently corroborated.",
            );
            ui.add_space(8.0);
            if findings.is_empty() {
                empty_state(
                    ui,
                    "No unreviewed changes",
                    "Run a check to compare with the stored baseline.",
                );
            } else {
                egui::ScrollArea::vertical()
                    .max_height(470.0)
                    .show(ui, |ui| {
                        for finding in &findings {
                            finding_row(ui, finding, |id| self.acknowledge(id));
                        }
                    });
            }
        });
    }

    fn network(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Network observer",
            "Read-only egress inventory. New does not mean malicious.",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.jobs.contains("network"),
                    egui::Button::new("Observe connections"),
                )
                .clicked()
            {
                self.run_network();
            }
            if self.jobs.contains("network") {
                ui.spinner();
            }
            ui.label(
                RichText::new("No firewall rules are changed by this component.").color(MUTED),
            );
        });
        ui.add_space(16.0);
        surface(ui, |ui| {
            section_title(
                ui,
                "Current public destinations",
                "Private, loopback, multicast and link-local addresses are excluded by default.",
            );
            ui.add_space(8.0);
            match &self.last_net {
                None => empty_state(
                    ui,
                    "No observation in this session",
                    "The first run creates a baseline and does not claim destinations are safe.",
                ),
                Some(report) if report.connections.is_empty() => empty_state(
                    ui,
                    "No public connections observed",
                    "Only established TCP and connected UDP sockets are included.",
                ),
                Some(report) => {
                    egui::ScrollArea::vertical()
                        .max_height(490.0)
                        .show(ui, |ui| {
                            for connection in &report.connections {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(&connection.protocol).monospace().color(BLUE),
                                    );
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new(
                                                connection
                                                    .process
                                                    .as_deref()
                                                    .unwrap_or("unknown process"),
                                            )
                                            .color(TEXT)
                                            .strong(),
                                        );
                                        ui.label(
                                            RichText::new(connection.remote.to_string())
                                                .monospace()
                                                .color(MUTED),
                                        );
                                    });
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        ui.label(
                                            RichText::new(&connection.state)
                                                .size(11.0)
                                                .color(MUTED),
                                        );
                                    });
                                });
                                ui.separator();
                            }
                        });
                }
            }
        });
    }

    fn reputation(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Hash reputation",
            "Exact local IOC matches by default; VirusTotal is explicit, hash-only and opt-in.",
        );
        if self.reputation_status.is_none() {
            self.refresh_reputation_status();
        }
        ui.columns(2, |columns| {
            surface(&mut columns[0], |ui| {
                section_title(ui, "Local SHA-256 index", "Files never leave this laptop.");
                ui.add_space(12.0);
                let status = self.reputation_status.unwrap_or_default();
                ui.label(
                    RichText::new(status.local_hashes.to_string())
                        .size(28.0)
                        .strong()
                        .color(TEXT),
                );
                ui.label(
                    RichText::new(format!("hashes from {} source(s)", status.local_sources))
                        .color(MUTED),
                );
                ui.add_space(10.0);
                if ui
                    .add_enabled(
                        !self.jobs.contains("reputation-sync"),
                        egui::Button::new("Update hash feeds"),
                    )
                    .clicked()
                {
                    self.sync_reputation();
                }
            });
            surface(&mut columns[1], |ui| {
                section_title(
                    ui,
                    "VirusTotal",
                    "Only the SHA-256 is sent; files are never uploaded.",
                );
                ui.add_space(12.0);
                let enabled = self.deps.config.reputation.virustotal_enabled;
                ui.label(
                    RichText::new(if enabled { "ENABLED" } else { "DISABLED" })
                        .color(if enabled { GREEN } else { MUTED })
                        .strong(),
                );
                ui.label(
                    RichText::new(format!(
                        "API key environment: {}",
                        self.deps.config.reputation.virustotal_api_key_env
                    ))
                    .monospace()
                    .color(MUTED),
                );
                ui.add_enabled_ui(enabled, |ui| {
                    ui.checkbox(
                        &mut self.reputation_online,
                        "Use online hash lookup for this check",
                    );
                });
            });
        });
        ui.add_space(16.0);
        surface(ui, |ui| {
            section_title(
                ui,
                "Check one file",
                "Local lookup is always performed first.",
            );
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 125.0, 36.0],
                    egui::TextEdit::singleline(&mut self.reputation_path)
                        .hint_text("/path/to/file"),
                );
                if ui
                    .add_enabled(
                        !self.jobs.contains("reputation-check"),
                        egui::Button::new("Check hash"),
                    )
                    .clicked()
                {
                    self.check_reputation();
                }
            });
            if let Some(result) = &self.reputation_result {
                ui.add_space(12.0);
                ui.label(RichText::new(&result.sha256).monospace().color(BLUE));
                ui.label(
                    RichText::new(format!(
                        "Local: {}",
                        result.local_match.as_deref().unwrap_or("not listed")
                    ))
                    .color(TEXT),
                );
                if let Some(vt) = &result.virustotal {
                    ui.label(
                        RichText::new(format!(
                            "VirusTotal: {} · malicious {} · suspicious {} · harmless {}",
                            vt.verdict, vt.malicious, vt.suspicious, vt.harmless
                        ))
                        .color(if vt.malicious > 0 {
                            AMBER
                        } else {
                            MUTED
                        }),
                    );
                }
            }
        });
    }

    fn cleanup(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Cleanup & performance",
            "Analyze first. Nothing is selected automatically and every deletion requires an exact phrase.",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.jobs.contains("cleanup-scan") && !self.jobs.contains("cleanup-apply"),
                    egui::Button::new("Analyze storage"),
                )
                .clicked()
            {
                self.run_cleanup_scan();
            }
            if self.jobs.contains("cleanup-scan") {
                ui.spinner();
                ui.label(RichText::new("Scanning bounded cleanup locations…").color(MUTED));
            }
            ui.label(
                RichText::new("EFI, backups, snapshots and partial downloads are protected.")
                    .color(MUTED),
            );
        });
        ui.add_space(14.0);

        if let Some(performance) = &self.cleanup_performance {
            ui.columns(3, |columns| {
                stat_card(
                    &mut columns[0],
                    "MEMORY AVAILABLE MiB",
                    (performance.memory_available_bytes / (1024 * 1024)) as i64,
                    GREEN,
                );
                stat_card(
                    &mut columns[1],
                    "MEMORY USED MiB",
                    ((performance
                        .memory_total_bytes
                        .saturating_sub(performance.memory_available_bytes))
                        / (1024 * 1024)) as i64,
                    AMBER,
                );
                stat_card(
                    &mut columns[2],
                    "PROCESSES",
                    performance.process_count as i64,
                    BLUE,
                );
            });
            ui.add_space(14.0);
        }

        let Some(report) = self.cleanup_report.clone() else {
            surface(ui, |ui| {
                empty_state(
                    ui,
                    "No cleanup analysis yet",
                    "Select Analyze storage. The analysis itself is read-only.",
                );
            });
            return;
        };

        ui.columns(3, |columns| {
            cleanup_summary_card(
                &mut columns[0],
                "SAFE / REBUILDABLE",
                report.safe_bytes,
                GREEN,
            );
            cleanup_summary_card(
                &mut columns[1],
                "REVIEW REQUIRED",
                report.review_bytes,
                AMBER,
            );
            cleanup_summary_unknown_card(&mut columns[2], "PROTECTED / LIST ONLY", RED);
        });
        ui.add_space(14.0);

        surface(ui, |ui| {
            section_title(
                ui,
                "Cleanup candidates",
                "Select only what you reviewed. Protected and elevated items cannot be selected here.",
            );
            ui.add_space(8.0);
            egui::ScrollArea::vertical()
                .max_height(350.0)
                .show(ui, |ui| {
                    for candidate in &report.candidates {
                        let selectable = candidate.supported
                            && !candidate.requires_root
                            && candidate.risk != blue_cleanup::CleanupRisk::Protected;
                        let mut selected = self.cleanup_selected.contains(&candidate.id);
                        ui.horizontal(|ui| {
                            let response =
                                ui.add_enabled(selectable, egui::Checkbox::new(&mut selected, ""));
                            if response.changed() {
                                if selected {
                                    self.cleanup_selected.insert(candidate.id.clone());
                                } else {
                                    self.cleanup_selected.remove(&candidate.id);
                                }
                                self.cleanup_confirmation.clear();
                            }
                            cleanup_risk_badge(ui, candidate.risk);
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&candidate.label).color(TEXT).strong());
                                ui.label(RichText::new(&candidate.reason).size(11.0).color(MUTED));
                                if let Some(path) = &candidate.path {
                                    ui.label(
                                        RichText::new(path.to_string_lossy())
                                            .size(10.0)
                                            .monospace()
                                            .color(MUTED),
                                    );
                                }
                                if let Some(warning) = &candidate.warning {
                                    ui.label(RichText::new(warning).size(10.0).color(AMBER));
                                }
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(
                                    RichText::new(
                                        if candidate.risk == blue_cleanup::CleanupRisk::Protected
                                            && candidate.bytes == 0
                                        {
                                            "not sized".to_owned()
                                        } else {
                                            format_bytes(candidate.bytes)
                                        },
                                    )
                                    .monospace()
                                    .color(if selectable {
                                        TEXT
                                    } else {
                                        MUTED
                                    }),
                                );
                                if !selectable {
                                    ui.label(
                                        RichText::new("LIST ONLY").size(9.0).strong().color(RED),
                                    );
                                }
                            });
                        });
                        ui.separator();
                    }
                });
        });

        ui.add_space(14.0);
        let selected = report
            .candidates
            .iter()
            .filter(|candidate| self.cleanup_selected.contains(&candidate.id))
            .cloned()
            .collect::<Vec<_>>();
        surface(ui, |ui| {
            section_title(
                ui,
                "Explicit approval",
                "The engine rescans and revalidates every selected path before deletion.",
            );
            if selected.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Nothing selected — this is the default.").color(GREEN));
            } else {
                let required = blue_cleanup::CleanupEngine::required_confirmation(&selected);
                let selected_bytes = selected
                    .iter()
                    .fold(0u64, |total, item| total.saturating_add(item.bytes));
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "{} item(s), {} estimated. Type exactly:",
                        selected.len(),
                        format_bytes(selected_bytes)
                    ))
                    .color(TEXT),
                );
                ui.label(RichText::new(&required).monospace().strong().color(AMBER));
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [ui.available_width() - 145.0, 34.0],
                        egui::TextEdit::singleline(&mut self.cleanup_confirmation)
                            .hint_text("confirmation phrase"),
                    );
                    if ui
                        .add_enabled(
                            self.cleanup_confirmation == required
                                && !self.jobs.contains("cleanup-apply"),
                            egui::Button::new("Delete selected")
                                .fill(Color32::from_rgb(64, 30, 36))
                                .stroke(Stroke::new(1.0, RED)),
                        )
                        .clicked()
                    {
                        self.apply_cleanup();
                    }
                });
            }
            ui.add_space(8.0);
            let setup_dir = extension_path()
                .parent()
                .map(|path| path.join("scripts"))
                .unwrap_or_else(|| PathBuf::from("scripts"));
            if ui.button("Copy system cleanup plan command").clicked() {
                ui.ctx().copy_text(format!(
                    "{} plan",
                    setup_dir.join("cleanup-system.sh").display()
                ));
                self.message = Some(("Read-only system cleanup plan command copied".into(), true));
            }
        });

        if let Some(performance) = &self.cleanup_performance {
            ui.add_space(14.0);
            surface(ui, |ui| {
                section_title(
                    ui,
                    "Largest resident processes",
                    "Observation only — Blue does not kill applications from Cleanup.",
                );
                for process in &performance.top_memory {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&process.name).color(TEXT));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format_bytes(process.rss_bytes))
                                    .monospace()
                                    .color(MUTED),
                            );
                            ui.label(
                                RichText::new(format!("PID {}", process.pid))
                                    .size(10.0)
                                    .color(MUTED),
                            );
                        });
                    });
                    ui.separator();
                }
            });
        }
    }

    fn quarantine(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Quarantine",
            "Held files are inert and restorable. Blue never auto-deletes them.",
        );
        let items = self.snapshot.quarantine.clone();
        surface(ui, |ui| {
            if items.is_empty() {
                empty_state(
                    ui,
                    "Quarantine is empty",
                    "Corroborated files will appear here with their evidence.",
                );
                return;
            }
            egui::ScrollArea::vertical()
                .max_height(520.0)
                .show(ui, |ui| {
                    for item in &items {
                        ui.horizontal(|ui| {
                            tier_badge(ui, item.tier);
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&item.original_path).color(TEXT).strong());
                                ui.label(RichText::new(&item.reason).size(12.0).color(MUTED));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add_enabled(
                                        !self.jobs.contains("restore"),
                                        egui::Button::new("Restore"),
                                    )
                                    .clicked()
                                {
                                    self.restore(item.id);
                                }
                                ui.label(RichText::new(format!("#{}", item.id)).color(MUTED));
                            });
                        });
                        ui.separator();
                    }
                });
        });
    }

    fn filters(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Filter feeds",
            "Versioned domain lists for ads, trackers and known malware infrastructure.",
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.jobs.contains("feeds"),
                    egui::Button::new("Update filters"),
                )
                .clicked()
            {
                self.sync_feeds();
            }
            if self.jobs.contains("feeds") {
                ui.spinner();
                ui.label(RichText::new("Downloading and validating…").color(MUTED));
            }
        });
        ui.add_space(16.0);
        let datasets = self.snapshot.datasets.clone();
        surface(ui, |ui| {
            section_title(
                ui,
                "Installed datasets",
                "A failed or undersized download never replaces a working list.",
            );
            ui.add_space(8.0);
            if datasets.is_empty() {
                empty_state(
                    ui,
                    "No filter datasets installed",
                    "Select Update filters to fetch the configured sources.",
                );
            } else {
                for dataset in datasets.iter().filter(|d| d.active) {
                    ui.horizontal(|ui| {
                        shield(ui, 24.0, GREEN);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&dataset.name).strong().color(TEXT));
                            ui.label(
                                RichText::new(format!(
                                    "version {} · {} KiB",
                                    dataset.version,
                                    dataset.size.unwrap_or(0) / 1024
                                ))
                                .color(MUTED),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(RichText::new("ACTIVE").size(11.0).color(GREEN).strong());
                            if ui
                                .add_enabled(
                                    !self.jobs.contains("rollback"),
                                    egui::Button::new("Rollback"),
                                )
                                .clicked()
                            {
                                self.rollback_feed(dataset.name.clone());
                            }
                        });
                    });
                    ui.separator();
                }
            }
        });
    }

    fn browser(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Browser Shield",
            "The native companion for Chromium and Brave search protection.",
        );
        ui.columns(2, |columns| {
            surface(&mut columns[0], |ui| {
                section_title(
                    ui,
                    "Blue Search Guard",
                    "Ad cleanup and malicious-domain blocking inside search results.",
                );
                ui.add_space(14.0);
                for text in [
                    "Removes sponsored search-result cards",
                    "Warns before opening suspicious links",
                    "Blocks known ad and tracker requests",
                    "Checks search links against the desktop domain feed",
                    "Keeps settings in the browser profile",
                ] {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("✓").color(GREEN).strong());
                        ui.label(RichText::new(text).color(TEXT));
                    });
                    ui.add_space(6.0);
                }
            });
            surface(&mut columns[1], |ui| {
                section_title(
                    ui,
                    "Install unpacked",
                    "No browser-store account or remote code.",
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new("1. Open chromium://extensions or brave://extensions")
                        .color(TEXT),
                );
                ui.label(RichText::new("2. Enable Developer mode").color(TEXT));
                ui.label(RichText::new("3. Select Load unpacked").color(TEXT));
                ui.add_space(8.0);
                let path = extension_path();
                ui.label(
                    RichText::new(path.to_string_lossy())
                        .monospace()
                        .color(BLUE),
                );
                if ui.button("Copy extension path").clicked() {
                    ui.ctx().copy_text(path.to_string_lossy().into_owned());
                    self.message = Some(("Extension path copied".into(), true));
                }
            });
        });
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        self.header(
            ui,
            "Settings",
            "Configuration remains plain TOML and local to this device.",
        );
        surface(ui, |ui| {
            section_title(
                ui,
                "Background services",
                "Optional user services continue after this window closes.",
            );
            ui.add_space(8.0);
            if protection_row(
                ui,
                "Integrity checks every 15 minutes",
                "Runs blue-guard.timer as your user",
                &mut self.guard_timer,
            ) {
                match set_user_unit("blue-guard.timer", self.guard_timer) {
                    Ok(()) => self.message = Some(("Integrity schedule updated".into(), true)),
                    Err(error) => {
                        self.guard_timer = !self.guard_timer;
                        self.message = Some((format!("Timer control failed: {error:#}"), false));
                    }
                }
            }
            ui.separator();
            if protection_row(
                ui,
                "Observe new egress every 5 minutes",
                "Read-only connection inventory; no firewall enforcement",
                &mut self.net_timer,
            ) {
                match set_user_unit("blue-net.timer", self.net_timer) {
                    Ok(()) => {
                        self.message = Some(("Network observation schedule updated".into(), true))
                    }
                    Err(error) => {
                        self.net_timer = !self.net_timer;
                        self.message = Some((format!("Timer control failed: {error:#}"), false));
                    }
                }
            }
            ui.separator();
            if protection_row(
                ui,
                "Daily malicious-hash feed updates",
                "Exact SHA-256 IOCs remain local",
                &mut self.reputation_timer,
            ) {
                match set_user_unit("blue-reputation.timer", self.reputation_timer) {
                    Ok(()) => self.message = Some(("Hash feed schedule updated".into(), true)),
                    Err(error) => {
                        self.reputation_timer = !self.reputation_timer;
                        self.message = Some((format!("Timer control failed: {error:#}"), false));
                    }
                }
            }
            ui.separator();
            if protection_row(
                ui,
                "Daily filter updates",
                "Runs blue-feeds.timer as your user",
                &mut self.feed_timer,
            ) {
                match set_user_unit("blue-feeds.timer", self.feed_timer) {
                    Ok(()) => self.message = Some(("Filter update schedule updated".into(), true)),
                    Err(error) => {
                        self.feed_timer = !self.feed_timer;
                        self.message = Some((format!("Timer control failed: {error:#}"), false));
                    }
                }
            }
            ui.add_space(16.0);
            section_title(
                ui,
                "Paths and policy",
                "Read from the layered TOML configuration.",
            );
            ui.add_space(8.0);
            for (label, value) in [
                (
                    "State directory",
                    self.deps.config.state_dir().display().to_string(),
                ),
                ("Database", self.deps.config.db_path().display().to_string()),
                ("DNS bind", self.deps.config.dns.bind.clone()),
                (
                    "System DNS route",
                    if self.dns_routed {
                        "Loopback resolver active"
                    } else {
                        "Not configured (safe default)"
                    }
                    .into(),
                ),
                ("Guard interval", "15 minutes (systemd timer)".into()),
                (
                    "Full package drift audit",
                    if self.deps.config.guard.watch_packages {
                        "Enabled"
                    } else {
                        "Opt-in (disabled)"
                    }
                    .into(),
                ),
                (
                    "Quarantine threshold",
                    "T2 corroborated (fixed safety policy)".into(),
                ),
            ] {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(label).color(MUTED).strong());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(value).monospace().color(TEXT));
                    });
                });
                ui.separator();
            }
            ui.add_space(8.0);
            section_title(
                ui,
                "Confirmed system setup",
                "These plans are read-only until you run their explicit confirmation command.",
            );
            let setup_dir = extension_path()
                .parent()
                .map(|path| path.join("scripts"))
                .unwrap_or_else(|| PathBuf::from("scripts"));
            for (label, script) in [
                ("ClamAV", setup_dir.join("setup-clamav.sh")),
                ("System DNS", setup_dir.join("setup-system-dns.sh")),
            ] {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(label).color(MUTED).strong());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.small_button("Copy plan command").clicked() {
                            ui.ctx().copy_text(format!("{} plan", script.display()));
                            self.message = Some((format!("{label} plan command copied"), true));
                        }
                    });
                });
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "This app is a native executable. It opens no listening HTTP port and contains no web view.",
                )
                .color(GREEN),
            );
        });
        if let Some(error) = &self.refresh_error {
            ui.add_space(12.0);
            ui.colored_label(RED, format!("State refresh failed: {error}"));
        }
    }
}

impl eframe::App for BlueApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.process_jobs();
        if self.last_refresh.elapsed() > Duration::from_secs(2) {
            self.refresh();
        }
        self.sidebar(ui);
        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG).inner_margin(egui::Margin::same(28)))
            .show(ui, |ui| match self.page {
                Page::Overview => self.overview(ui),
                Page::Scanner => self.scanner(ui),
                Page::Integrity => self.integrity(ui),
                Page::Network => self.network(ui),
                Page::Reputation => self.reputation(ui),
                Page::Cleanup => {
                    egui::ScrollArea::vertical()
                        .id_salt("cleanup-page")
                        .show(ui, |ui| self.cleanup(ui));
                }
                Page::Quarantine => self.quarantine(ui),
                Page::Filters => self.filters(ui),
                Page::Browser => self.browser(ui),
                Page::Settings => {
                    egui::ScrollArea::vertical()
                        .id_salt("settings-page")
                        .show(ui, |ui| self.settings(ui));
                }
            });
        ui.ctx().request_repaint_after(Duration::from_millis(500));
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

fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = Color32::from_rgb(10, 17, 29);
    style.visuals.widgets.inactive.bg_fill = PANEL_HOVER;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(27, 41, 63);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(32, 49, 74);
    style.visuals.selection.bg_fill = Color32::from_rgb(34, 89, 75);
    style.spacing.item_spacing = Vec2::new(8.0, 8.0);
    style.spacing.button_padding = Vec2::new(14.0, 8.0);
    ctx.set_global_style(style);
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
    ui.label(RichText::new(title).size(16.0).strong().color(TEXT));
    ui.label(RichText::new(subtitle).size(12.0).color(MUTED));
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: i64, color: Color32) {
    surface(ui, |ui| {
        ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(value.to_string())
                    .size(27.0)
                    .strong()
                    .color(TEXT),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new("●").color(color));
            });
        });
    });
}

fn cleanup_summary_card(ui: &mut egui::Ui, label: &str, bytes: u64, color: Color32) {
    surface(ui, |ui| {
        ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format_bytes(bytes))
                    .size(24.0)
                    .strong()
                    .color(TEXT),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new("●").color(color));
            });
        });
    });
}

fn cleanup_summary_unknown_card(ui: &mut egui::Ui, label: &str, color: Color32) {
    surface(ui, |ui| {
        ui.label(RichText::new(label).size(10.0).strong().color(MUTED));
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("not enumerated")
                    .size(18.0)
                    .strong()
                    .color(TEXT),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new("●").color(color));
            });
        });
    });
}

fn cleanup_risk_badge(ui: &mut egui::Ui, risk: blue_cleanup::CleanupRisk) {
    let (label, color) = match risk {
        blue_cleanup::CleanupRisk::Safe => ("SAFE", GREEN),
        blue_cleanup::CleanupRisk::Review => ("REVIEW", AMBER),
        blue_cleanup::CleanupRisk::Protected => ("PROTECTED", RED),
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
            ui.label(RichText::new(label).size(9.0).strong().color(color));
        });
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

fn mini_stat(ui: &mut egui::Ui, label: &str, value: usize) {
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new(value.to_string())
                .size(24.0)
                .strong()
                .color(TEXT),
        );
        ui.label(RichText::new(label).size(11.0).color(MUTED));
    });
}

fn protection_row(ui: &mut egui::Ui, title: &str, subtitle: &str, value: &mut bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).strong().color(TEXT));
            ui.label(RichText::new(subtitle).color(MUTED));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let label = if *value { "ON" } else { "OFF" };
            changed = ui.toggle_value(value, label).changed();
        });
    });
    changed
}

fn event_row(ui: &mut egui::Ui, event: &Event) {
    let color = match event.level.as_str() {
        "error" => RED,
        "warn" => AMBER,
        "notice" => BLUE,
        _ => GREEN,
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new("●").size(9.0).color(color));
        ui.vertical(|ui| {
            ui.label(
                RichText::new(event.subject.as_deref().unwrap_or(&event.kind))
                    .size(12.0)
                    .color(TEXT),
            );
            ui.label(RichText::new(&event.kind).size(10.0).color(MUTED));
        });
    });
    ui.add_space(4.0);
}

fn finding_row(ui: &mut egui::Ui, finding: &Finding, mut acknowledge: impl FnMut(i64)) {
    ui.horizontal(|ui| {
        tier_badge(ui, finding.tier);
        ui.vertical(|ui| {
            ui.label(RichText::new(&finding.subject).color(TEXT).strong());
            ui.label(
                RichText::new(format!("{} · {}", finding.kind, finding.detail))
                    .size(11.0)
                    .color(MUTED),
            );
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button("Acknowledge").clicked() {
                acknowledge(finding.id);
            }
        });
    });
    ui.separator();
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
        ui.label(RichText::new(title).strong().color(TEXT));
        ui.label(RichText::new(subtitle).size(12.0).color(MUTED));
        ui.add_space(28.0);
    });
}

fn shield(ui: &mut egui::Ui, size: f32, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let c = rect.center();
    let points = vec![
        egui::pos2(c.x, rect.top() + 3.0),
        egui::pos2(rect.right() - 4.0, rect.top() + size * 0.28),
        egui::pos2(rect.right() - 7.0, rect.bottom() - size * 0.25),
        egui::pos2(c.x, rect.bottom() - 2.0),
        egui::pos2(rect.left() + 7.0, rect.bottom() - size * 0.25),
        egui::pos2(rect.left() + 4.0, rect.top() + size * 0.28),
    ];
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 28),
        Stroke::new(1.5, color),
    ));
    ui.painter().text(
        c,
        egui::Align2::CENTER_CENTER,
        "✓",
        FontId::proportional(size * 0.38),
        color,
    );
}

fn extension_path() -> PathBuf {
    if let Some(path) = option_env!("BLUE_EXTENSION_DIR").map(PathBuf::from) {
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
