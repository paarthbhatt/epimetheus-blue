//! Recursive inotify watcher feeding the scan engine.
//!
//! Events are coalesced per path inside a debounce window: editors write the
//! same file several times in quick succession, and there is no value in
//! scanning every intermediate state.

use crate::{ScanEngine, ScanOutcome};
use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_QUEUED_EVENTS: usize = 1024;
const MAX_PENDING_PATHS: usize = 1024;
const MAX_SCAN_BATCH: usize = 32;
const IDLE_WAIT: Duration = Duration::from_secs(1);
const ALERT_SPACING: Duration = Duration::from_secs(10);
const ALERT_REPEAT_AFTER: Duration = Duration::from_secs(10 * 60);
const MAX_ALERT_HISTORY: usize = 512;
const MAX_NOTIFICATION_FIELD_BYTES: usize = 256;
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);

enum WatchEvent {
    Path(PathBuf),
    Error(notify::Error),
    Rescan,
}

fn event_channel() -> (SyncSender<WatchEvent>, Receiver<WatchEvent>) {
    std::sync::mpsc::sync_channel(MAX_QUEUED_EVENTS)
}

/// Start a background watcher for `roots`.
///
/// Returns once the watcher is registered; scans happen on the watcher thread.
/// The thread stops when `stop` becomes `true`.
pub fn watch(
    engine: Arc<ScanEngine>,
    roots: Vec<PathBuf>,
    debounce_ms: u64,
    stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let (tx, rx) = event_channel();
    let event_engine = engine.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        match event {
            Ok(event) => {
                if event.need_rescan() && tx.send(WatchEvent::Rescan).is_err() {
                    return;
                }
                // Ignore our own file reads before they can occupy queue space.
                if !matches!(event.kind, notify::EventKind::Access(_)) {
                    for path in event.paths {
                        if !event_engine.is_excluded(&path)
                            && tx.send(WatchEvent::Path(path)).is_err()
                        {
                            return;
                        }
                    }
                }
            }
            Err(error) => {
                let _ = tx.send(WatchEvent::Error(error));
            }
        }
    })
    .context("creating file watcher")?;

    // Drain bounded callbacks before registering roots: registration itself can
    // otherwise wait behind a callback blocked on a full event queue. The single
    // handoff slot retains the watcher for the lifetime of the consumer loop.
    let (watcher_tx, watcher_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("blue-scan-watch".into())
        .spawn(move || {
            let _watcher_keeper = watcher_rx;
            run(engine, rx, debounce_ms, stop);
        })
        .context("spawning scan watcher thread")?;

    let mut watched = 0usize;
    for root in &roots {
        match watcher.watch(root, RecursiveMode::Recursive) {
            Ok(()) => watched += 1,
            Err(e) => tracing::warn!(
                root = %root.display(),
                error = %e,
                "cannot watch scan root"
            ),
        }
    }
    if watched == 0 {
        anyhow::bail!("no scan roots could be watched");
    }

    watcher_tx
        .send(watcher)
        .map_err(|_| anyhow::anyhow!("scan watcher stopped during root registration"))?;
    Ok(())
}

fn run(
    engine: Arc<ScanEngine>,
    rx: Receiver<WatchEvent>,
    debounce_ms: u64,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let debounce = Duration::from_millis(debounce_ms.max(1));
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut alerts = ThreatAlerts::default();
    let mut last_overflow_warning: Option<Instant> = None;

    loop {
        if should_stop(&stop) {
            tracing::debug!("scan watcher stopping");
            break;
        }

        let now = Instant::now();
        if let Some(notification) = alerts.next_notification(now) {
            send_notification(&notification);
        }
        let wait = next_wait(&pending, debounce, &alerts, Instant::now());
        if pending.len() >= MAX_PENDING_PATHS {
            // Backpressure, never eviction: let queued paths finish their
            // debounce before accepting another path into the bounded map.
            std::thread::sleep(wait);
        } else {
            match rx.recv_timeout(wait) {
                Ok(WatchEvent::Path(path)) => queue(&engine, &mut pending, path),
                Ok(WatchEvent::Error(error)) => {
                    tracing::warn!(%error, "file watcher reported an error");
                }
                Ok(WatchEvent::Rescan) => {
                    let now = Instant::now();
                    if last_overflow_warning.is_none_or(|last| {
                        now.saturating_duration_since(last) >= Duration::from_secs(60)
                    }) {
                        tracing::warn!(
                            "file events overflowed; coverage is incomplete until a fresh scan"
                        );
                        let payload = r#"{"status":"degraded","reason":"file event overflow; a fresh scan is required"}"#;
                        if let Err(error) = engine.db.event(
                            "scan.watch",
                            "warn",
                            None,
                            payload,
                            blue_core::now_ms(),
                        ) {
                            tracing::warn!(%error, "could not record file watcher degradation");
                        }
                        last_overflow_warning = Some(now);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        let now = Instant::now();
        let mut ready: Vec<_> = pending
            .iter()
            .filter(|(_, last)| now.saturating_duration_since(**last) >= debounce)
            .map(|(path, last)| (path.clone(), *last))
            .collect();
        ready.sort_by_key(|(_, last)| *last);
        ready.truncate(MAX_SCAN_BATCH);

        for (path, _) in ready {
            if should_stop(&stop) {
                return;
            }
            pending.remove(&path);
            match engine.scan_path(&path) {
                Ok(outcome) => {
                    alerts.record(&outcome, Instant::now());
                    if let Some(notification) = alerts.next_notification(Instant::now()) {
                        send_notification(&notification);
                    }
                }
                Err(e) => {
                    // A single unreadable or vanished file never stops the watcher.
                    tracing::warn!(path = %path.display(), error = %e, "scan failed");
                }
            }
        }
    }
}

fn next_wait(
    pending: &HashMap<PathBuf, Instant>,
    debounce: Duration,
    alerts: &ThreatAlerts,
    now: Instant,
) -> Duration {
    let file_wait = pending
        .values()
        .map(|last| debounce.saturating_sub(now.saturating_duration_since(*last)))
        .min()
        .unwrap_or(IDLE_WAIT);
    let alert_wait = alerts.wait(now).unwrap_or(IDLE_WAIT);
    file_wait.min(alert_wait).min(IDLE_WAIT)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AlertKind {
    Quarantined,
    Failed,
    Paused,
}

impl AlertKind {
    fn from_outcome(outcome: &ScanOutcome) -> Self {
        if outcome.quarantined.is_some() {
            Self::Quarantined
        } else if outcome.containment_error.is_some() {
            Self::Failed
        } else {
            Self::Paused
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Quarantined => "Threat quarantined",
            Self::Failed => "Threat detected: containment failed",
            Self::Paused => "Threat detected: containment paused",
        }
    }

    fn priority(self) -> u8 {
        match self {
            Self::Quarantined => 0,
            Self::Paused => 1,
            Self::Failed => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct AlertKey {
    path: PathBuf,
    sha256: String,
    tier: i64,
    kind: AlertKind,
}

struct Notification {
    title: &'static str,
    body: String,
}

struct AlertBatch {
    notification: Notification,
    kind: AlertKind,
    quarantined: usize,
    failed: usize,
    paused: usize,
}

impl AlertBatch {
    fn add(&mut self, kind: AlertKind) {
        let count = match kind {
            AlertKind::Quarantined => &mut self.quarantined,
            AlertKind::Failed => &mut self.failed,
            AlertKind::Paused => &mut self.paused,
        };
        *count = count.saturating_add(1);
    }

    fn notification(mut self) -> Notification {
        let total = self
            .quarantined
            .saturating_add(self.failed)
            .saturating_add(self.paused);
        if total > 1 {
            self.notification.title = "Threat detections";
            self.notification.body.push_str(&format!(
                "\n{total} detections: {} quarantined, {} containment failed, {} paused. Review Blue for all records.",
                self.quarantined, self.failed, self.paused
            ));
        }
        self.notification
    }
}

/// Alert deduplication never suppresses scanning, evidence or quarantine. Bursts
/// become a bounded summary, with an uncontained threat as the representative.
#[derive(Default)]
struct ThreatAlerts {
    recent: HashMap<AlertKey, Instant>,
    last_sent: Option<Instant>,
    pending: Option<AlertBatch>,
}

impl ThreatAlerts {
    fn record(&mut self, outcome: &ScanOutcome, now: Instant) {
        if !outcome.tier.may_quarantine() {
            return;
        }
        self.recent
            .retain(|_, last| now.saturating_duration_since(*last) < ALERT_REPEAT_AFTER);
        let kind = AlertKind::from_outcome(outcome);
        let key = AlertKey {
            path: outcome.path.clone(),
            sha256: outcome.sha256.clone(),
            tier: outcome.tier.as_i64(),
            kind,
        };
        if self.recent.contains_key(&key) {
            return;
        }
        if self.recent.len() >= MAX_ALERT_HISTORY {
            if let Some(oldest) = self
                .recent
                .iter()
                .min_by_key(|(_, last)| **last)
                .map(|(key, _)| key.clone())
            {
                self.recent.remove(&oldest);
            }
        }
        self.recent.insert(key, now);
        let notification = threat_notification(outcome, kind);
        let batch = self.pending.get_or_insert_with(|| AlertBatch {
            notification: Notification {
                title: notification.title,
                body: notification.body.clone(),
            },
            kind,
            quarantined: 0,
            failed: 0,
            paused: 0,
        });
        if kind.priority() > batch.kind.priority() {
            batch.notification = notification;
            batch.kind = kind;
        }
        batch.add(kind);
    }

    fn wait(&self, now: Instant) -> Option<Duration> {
        self.pending.as_ref()?;
        Some(self.last_sent.map_or(Duration::ZERO, |last| {
            ALERT_SPACING.saturating_sub(now.saturating_duration_since(last))
        }))
    }

    fn next_notification(&mut self, now: Instant) -> Option<Notification> {
        if self.wait(now)? != Duration::ZERO {
            return None;
        }
        let notification = self.pending.take()?.notification();
        self.last_sent = Some(now);
        Some(notification)
    }
}

fn threat_notification(outcome: &ScanOutcome, kind: AlertKind) -> Notification {
    let path = notification_field(&outcome.path.to_string_lossy());
    let status = match kind {
        AlertKind::Quarantined => format!("Quarantine item #{}", outcome.quarantined.unwrap()),
        AlertKind::Failed => format!(
            "File was not safely contained. Review Blue.\n{}",
            notification_field(outcome.containment_error.as_deref().unwrap())
        ),
        AlertKind::Paused => "Automatic containment was emergency-paused; the detected file was left in place. Review Blue for current status.".into(),
    };
    Notification {
        title: kind.title(),
        body: format!("{path}\n{status}"),
    }
}

/// Paths/errors are untrusted notification text: cap UTF-8 bytes, strip control
/// and bidi formatting, and escape markup accepted by desktop notification UIs.
fn notification_field(value: &str) -> String {
    let mut text = String::new();
    for character in value.chars().filter(|character| {
        !character.is_control()
            && !matches!(character, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) {
        let mut buffer = [0; 4];
        let escaped = match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&apos;",
            _ => character.encode_utf8(&mut buffer),
        };
        if text.len() + escaped.len() > MAX_NOTIFICATION_FIELD_BYTES {
            break;
        }
        text.push_str(escaped);
    }
    text
}

/// One helper at a time, with bounded lifetime and no inherited stdio. Missing
/// notification support never changes a verdict or blocks scanning indefinitely.
fn send_notification(notification: &Notification) {
    let child = Command::new("/usr/bin/notify-send")
        .args([
            "--app-name=Epimetheus Blue",
            "--urgency=critical",
            "--icon=security-high",
            "--expire-time=15000",
            "--",
            notification.title,
            &notification.body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            tracing::debug!(%error, "desktop notification unavailable");
            return;
        }
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    tracing::debug!(%status, "desktop notification failed");
                }
                return;
            }
            Ok(None) if start.elapsed() < NOTIFICATION_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                tracing::debug!("desktop notification timed out or could not be reaped");
                return;
            }
        }
    }
}

fn should_stop(stop: &tokio::sync::watch::Receiver<bool>) -> bool {
    // Initial true is also a stop request. A dropped sender ends the watcher.
    *stop.borrow() || stop.has_changed().is_err()
}

fn queue(engine: &ScanEngine, pending: &mut HashMap<PathBuf, Instant>, path: PathBuf) {
    if engine.is_excluded(&path) {
        return;
    }
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {
            debug_assert!(pending.len() < MAX_PENDING_PATHS || pending.contains_key(&path));
            pending.insert(path, Instant::now());
        }
        // Directories, sockets and paths deleted before we looked are not
        // scannable; drop them without noise.
        Ok(_) => {}
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blue_core::Tier;

    fn outcome(tier: Tier, kind: AlertKind) -> ScanOutcome {
        ScanOutcome {
            path: PathBuf::from("threat-fixture"),
            sha256: "a".repeat(64),
            artifact_id: 1,
            tier,
            results: Vec::new(),
            quarantined: (kind == AlertKind::Quarantined).then_some(7),
            containment_error: (kind == AlertKind::Failed)
                .then(|| "read-only fixture filesystem".into()),
        }
    }

    #[test]
    fn observed_and_candidate_outcomes_never_alert() {
        let now = Instant::now();
        let mut alerts = ThreatAlerts::default();
        for tier in [Tier::Observed, Tier::Candidate] {
            for kind in [AlertKind::Quarantined, AlertKind::Failed, AlertKind::Paused] {
                alerts.record(&outcome(tier, kind), now);
            }
        }
        assert!(alerts.next_notification(now).is_none());
        assert!(alerts.pending.is_none());
        assert!(alerts.recent.is_empty());
    }

    #[test]
    fn t2_and_t3_alert_for_each_containment_state() {
        let now = Instant::now();
        for tier in [Tier::Corroborated, Tier::Confirmed] {
            for kind in [AlertKind::Quarantined, AlertKind::Failed, AlertKind::Paused] {
                let mut alerts = ThreatAlerts::default();
                alerts.record(&outcome(tier, kind), now);
                let notification = alerts.next_notification(now).unwrap();
                assert_eq!(notification.title, kind.title());
                match kind {
                    AlertKind::Quarantined => assert!(notification.body.contains("item #7")),
                    AlertKind::Failed => {
                        assert!(notification.body.contains("not safely contained"));
                        assert!(notification.body.contains("read-only fixture"));
                    }
                    AlertKind::Paused => {
                        assert!(notification.body.contains("emergency-paused"));
                        assert!(notification.body.contains("left in place"));
                    }
                }
            }
        }
    }

    #[test]
    fn repeated_threat_alerts_are_deduplicated_then_expire() {
        let now = Instant::now();
        let threat = outcome(Tier::Corroborated, AlertKind::Failed);
        let mut alerts = ThreatAlerts::default();
        alerts.record(&threat, now);
        assert!(alerts.next_notification(now).is_some());
        alerts.record(&threat, now + ALERT_SPACING);
        assert!(alerts.next_notification(now + ALERT_SPACING).is_none());
        alerts.record(&threat, now + ALERT_REPEAT_AFTER);
        assert!(alerts.next_notification(now + ALERT_REPEAT_AFTER).is_some());
    }

    #[test]
    fn changed_content_path_or_containment_state_is_not_a_duplicate() {
        let now = Instant::now();
        let mut threat = outcome(Tier::Corroborated, AlertKind::Paused);
        let mut alerts = ThreatAlerts::default();
        alerts.record(&threat, now);
        assert!(alerts.next_notification(now).is_some());
        threat.containment_error = Some("fixture failure".into());
        alerts.record(&threat, now + ALERT_SPACING);
        assert_eq!(
            alerts.next_notification(now + ALERT_SPACING).unwrap().title,
            AlertKind::Failed.title()
        );
        threat.sha256 = "b".repeat(64);
        alerts.record(&threat, now + ALERT_SPACING * 2);
        assert!(alerts.next_notification(now + ALERT_SPACING * 2).is_some());
        threat.path = PathBuf::from("second-threat-fixture");
        alerts.record(&threat, now + ALERT_SPACING * 3);
        assert!(alerts.next_notification(now + ALERT_SPACING * 3).is_some());
        threat.containment_error = None;
        threat.quarantined = Some(8);
        alerts.record(&threat, now + ALERT_SPACING * 4);
        assert_eq!(
            alerts
                .next_notification(now + ALERT_SPACING * 4)
                .unwrap()
                .title,
            AlertKind::Quarantined.title()
        );
        threat.tier = Tier::Confirmed;
        alerts.record(&threat, now + ALERT_SPACING * 5);
        assert!(alerts.next_notification(now + ALERT_SPACING * 5).is_some());
    }

    #[test]
    fn bursts_are_rate_limited_and_summarized_without_losing_uncontained_states() {
        let now = Instant::now();
        let mut alerts = ThreatAlerts::default();
        alerts.record(&outcome(Tier::Corroborated, AlertKind::Quarantined), now);
        assert!(alerts.next_notification(now).is_some());
        alerts.record(&outcome(Tier::Corroborated, AlertKind::Paused), now);
        alerts.record(&outcome(Tier::Corroborated, AlertKind::Failed), now);
        alerts.record(&outcome(Tier::Corroborated, AlertKind::Failed), now);
        assert!(alerts.next_notification(now).is_none());
        assert!(alerts.next_notification(now + ALERT_SPACING / 2).is_none());
        let notification = alerts.next_notification(now + ALERT_SPACING).unwrap();
        assert_eq!(notification.title, "Threat detections");
        assert!(notification.body.contains("not safely contained"));
        assert!(notification.body.contains("2 detections"));
        assert!(notification.body.contains("1 containment failed, 1 paused"));
        assert!(alerts.next_notification(now + ALERT_SPACING).is_none());
    }

    #[test]
    fn alert_history_and_burst_notification_text_are_bounded() {
        let now = Instant::now();
        let mut alerts = ThreatAlerts::default();
        for index in 0..MAX_ALERT_HISTORY + 20 {
            let mut threat = outcome(Tier::Corroborated, AlertKind::Failed);
            threat.path = PathBuf::from(format!("threat-fixture-{index}"));
            alerts.record(&threat, now);
            assert!(alerts.recent.len() <= MAX_ALERT_HISTORY);
        }
        let notification = alerts.next_notification(now).unwrap();
        assert!(notification
            .body
            .contains(&format!("{} detections", MAX_ALERT_HISTORY + 20)));
        assert!(notification.body.len() <= 1024);
    }

    #[test]
    fn notification_fields_escape_markup_strip_controls_and_cap_utf8_bytes() {
        let field = notification_field("<b>\"&'\u{202e}\n\0>");
        assert_eq!(field, "&lt;b&gt;&quot;&amp;&apos;&gt;");
        let unicode = notification_field(&"🛡".repeat(1000));
        assert!(unicode.len() <= MAX_NOTIFICATION_FIELD_BYTES);
        assert!(unicode.chars().all(|character| character == '🛡'));
        let mut threat = outcome(Tier::Corroborated, AlertKind::Failed);
        threat.path = PathBuf::from("<path>\u{202e}\n".repeat(1000));
        threat.containment_error = Some("<error>\u{202e}\n".repeat(1000));
        let notification = threat_notification(&threat, AlertKind::Failed);
        assert!(notification.body.len() <= 1024);
        assert!(!notification.body.contains('<'));
        assert!(!notification.body.contains('\u{202e}'));
    }

    #[test]
    fn idle_wait_is_one_second_and_active_wait_tracks_the_debounce_deadline() {
        let now = Instant::now();
        let mut pending = HashMap::new();
        let alerts = ThreatAlerts::default();
        let debounce = Duration::from_millis(500);
        assert_eq!(next_wait(&pending, debounce, &alerts, now), IDLE_WAIT);
        pending.insert(PathBuf::from("fixture"), now);
        assert_eq!(next_wait(&pending, debounce, &alerts, now), debounce);
        assert_eq!(
            next_wait(
                &pending,
                debounce,
                &alerts,
                now + Duration::from_millis(200)
            ),
            Duration::from_millis(300)
        );
        assert_eq!(
            next_wait(&pending, debounce, &alerts, now + debounce),
            Duration::ZERO
        );
    }

    #[test]
    fn pending_summary_deadline_is_included_in_waiting() {
        let now = Instant::now();
        let mut alerts = ThreatAlerts::default();
        alerts.record(&outcome(Tier::Corroborated, AlertKind::Quarantined), now);
        assert!(alerts.next_notification(now).is_some());
        alerts.record(&outcome(Tier::Corroborated, AlertKind::Failed), now);
        assert_eq!(
            next_wait(
                &HashMap::new(),
                Duration::from_millis(500),
                &alerts,
                now + ALERT_SPACING - Duration::from_millis(100)
            ),
            Duration::from_millis(100)
        );
    }

    #[test]
    fn initial_stop_and_dropped_sender_stop_the_watcher() {
        let (tx, rx) = tokio::sync::watch::channel(true);
        assert!(should_stop(&rx));
        tx.send(false).unwrap();
        assert!(!should_stop(&rx));
        drop(tx);
        assert!(should_stop(&rx));
    }

    #[test]
    fn event_channel_is_bounded_and_retains_a_backpressured_message() {
        let (tx, rx) = event_channel();
        for index in 0..MAX_QUEUED_EVENTS {
            assert!(tx
                .send(WatchEvent::Path(PathBuf::from(format!("fixture-{index}"))))
                .is_ok());
        }
        let message = WatchEvent::Path(PathBuf::from("backpressured-fixture"));
        let retained = match tx.try_send(message) {
            Err(std::sync::mpsc::TrySendError::Full(message)) => message,
            _ => panic!("the watcher event queue must not grow past its limit"),
        };
        assert!(rx.recv().is_ok());
        assert!(tx.send(retained).is_ok());
        for _ in 1..MAX_QUEUED_EVENTS {
            assert!(rx.recv().is_ok());
        }
        match rx.recv().unwrap() {
            WatchEvent::Path(path) => assert_eq!(path, PathBuf::from("backpressured-fixture")),
            _ => panic!("the backpressured path must remain available"),
        }
    }
}
