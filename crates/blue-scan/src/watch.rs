//! Recursive inotify watcher feeding the scan engine.
//!
//! Events are coalesced per path inside a debounce window: editors write the
//! same file several times in quick succession, and there is no value in
//! scanning every intermediate state.

use crate::ScanEngine;
use anyhow::{Context, Result};
use notify::{RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(tx).context("creating file watcher")?;

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

    std::thread::Builder::new()
        .name("blue-scan-watch".into())
        .spawn(move || {
            // The watcher must outlive the loop: dropping it closes the event
            // channel and silently stops watching.
            let _watcher = watcher;
            run(engine, rx, debounce_ms, stop);
        })
        .context("spawning scan watcher thread")?;
    Ok(())
}

fn run(
    engine: Arc<ScanEngine>,
    rx: Receiver<notify::Result<notify::Event>>,
    debounce_ms: u64,
    stop: tokio::sync::watch::Receiver<bool>,
) {
    let debounce = Duration::from_millis(debounce_ms.max(1));
    // Wake often enough to notice the stop flag and to flush due paths.
    let tick = Duration::from_millis(50).min(debounce);
    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();

    loop {
        if should_stop(&stop) {
            tracing::debug!("scan watcher stopping");
            break;
        }

        match rx.recv_timeout(tick) {
            Ok(Ok(event)) => {
                // Reading a file to scan it produces an OPEN event. Reacting to
                // access events would make the scanner rescan forever.
                if !matches!(event.kind, notify::EventKind::Access(_)) {
                    for path in event.paths {
                        queue(&engine, &mut pending, path);
                    }
                }
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "file watcher reported an error"),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();
        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, last)| now.duration_since(**last) >= debounce)
            .map(|(path, _)| path.clone())
            .collect();

        for path in ready {
            pending.remove(&path);
            if let Err(e) = engine.scan_path(&path) {
                // A single unreadable or vanished file never stops the watcher.
                tracing::warn!(path = %path.display(), error = %e, "scan failed");
            }
        }
    }
}

fn should_stop(stop: &tokio::sync::watch::Receiver<bool>) -> bool {
    match stop.has_changed() {
        // The sender was dropped; nobody can ask us to keep running.
        Ok(changed) => changed && *stop.borrow(),
        Err(_) => true,
    }
}

fn queue(engine: &ScanEngine, pending: &mut HashMap<PathBuf, Instant>, path: PathBuf) {
    if engine.is_excluded(&path) {
        return;
    }
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {
            pending.insert(path, Instant::now());
        }
        // Directories, sockets and paths deleted before we looked are not
        // scannable; drop them without noise.
        Ok(_) => {}
        Err(_) => {}
    }
}
