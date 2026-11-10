# Scoped automatic protection

The user selected scoped helpers, conservative quiet triage, the Public inbound
firewall baseline, and no change to system DNS routing.

- Keep the GUI and file watcher unprivileged. The watcher can write its state
  directory and approved default scan roots, Downloads and tmp, for containment.
  Custom roots need a reviewed matching service drop-in. Do not grant sudo ALL.
- Quarantine remains gated on T2+ evidence and emergency pause. Failed or paused
  containment retains detections and can alert, with bounded notification rates.
- New observations receive a persisted assessment and reason automatically.
  Routine complete HTTPS endpoint novelty may be informational, never trusted or
  certified benign. Unresolved persistence/unusual observations stay available
  for investigation. Raw evidence and acknowledgements are not erased.
- `blue review` assesses the existing backlog. Back up its database first.
- Keep continuous watching; integrity checks every 15 minutes, network inventory
  every 5 minutes, and feed maintenance daily. Full package audits stay opt-in.
- Root access is limited to fixed firewall and separately approved maintenance
  helpers. Firewall staging retains its 60-second rollback before confirmation.
- Cleanup is not automatic: exact typed approval and fresh path validation remain
  mandatory. Full failures and receipts stay visible in the local UI; persisted
  failure summaries omit private paths. Restricted size estimates are partial.

This is configured-folder, Defender-inspired protection, not kernel-wide on-access
coverage or Defender-equivalent detection. A connected browser bridge is a
read-only snapshot, not a protection-health certificate.

## Verified deployment, 2026-11-07

- Updated the installed user app, companion assets and service definitions.
- Public firewall staged, HTTPS/DNS connectivity checked, then confirmed and
  enabled for boot. Blue DNS remains disabled; NetworkManager owns DNS routing.
- Watcher, guard/network timers and daily feed timers are enabled and active.
  Its mount namespace now makes only Downloads, tmp and Blue state writable.
- Backed up the database privately before initial automatic assessment: 1,010
  records assessed, 946 informational, 64 unresolved, 50 pending groups. Records
  and acknowledgements were retained; later counts can grow normally.
- Automatic containment passed a harmless EICAR watcher test; that exact generated
  test was restored and removed. Three reviewed cleanup fixture deletions passed.
- 285 Rust tests, strict workspace Clippy, nine popup tests and four isolated
  installer tests passed. User confirmed reloading the updated extension.
- Watcher sample: about 34 MiB memory; this is a sample, not a performance benchmark.

Do not confuse this local deployment with a new published release. Protected and
root-owned cleanup remains restricted; do not weaken path/ownership/approval gates.
