# Epimetheus Blue

A personal security suite for one Arch Linux workstation. It combines malware
scanning, reversible quarantine, startup-path integrity checks, DNS ad/tracker
blocking, filter updates, and a browser search companion.

The control center is a **native Wayland/X11 executable** built in Rust. There
is no local website, HTTP API, Electron shell, or embedded web view.

## What works

| Protection | Implementation |
|---|---|
| Native control center | `blue` with no arguments opens the desktop app |
| Malware scanning | YARA-X in process plus optional ClamAV over its Unix socket |
| Realtime protection | inotify watches configured folders; systemd user service available |
| Quarantine | T2 gate, inert storage, byte-identical restore, never auto-delete |
| Integrity guard | Baselines and diffs startup paths, shell files, SSH keys and system units |
| Package drift | Opt-in bounded `pacman -Qkk` audit; unavailable checks degrade instead of failing |
| DNS shield | Suffix-safe blocklists and a local forwarding resolver |
| Encrypted DNS | Certificate-validated DNS-over-TLS upstream support with no plaintext fallback |
| Filter feeds | Download, validate, atomically activate, retain previous, roll back |
| Hash reputation | Local exact SHA-256 IOC feeds plus opt-in hash-only VirusTotal queries |
| Egress observer | Read-only procfs baseline and one-time alerts for new public destinations |
| Storage cleanup | Risk-classified scan, explicit item selection and typed confirmation; no automatic deletion |
| Browser/search shield | Chromium/Brave MV3 extension with a read-only native desktop bridge |

## Native app

```bash
cargo build --release
./target/release/blue
```

The app provides:

- protection toggles and an emergency automatic-action pause;
- file/folder scanning;
- integrity findings with acknowledgement;
- read-only network destination baselining;
- local and optional online hash reputation;
- quarantine restore;
- feed update and rollback;
- DNS Shield controls and live blocked-query counts;
- browser extension installation guidance;
- a Cleanup tab that separates safe caches, review-required artifacts and protected system data;
- background-service schedules.

### Install in the desktop launcher

```bash
./scripts/install-local.sh
```

This installs the binary to `~/.local/bin`, adds **Epimetheus Blue** to the
desktop launcher, copies the browser extension, and installs—but does not enable—
the user services. Nothing asks for root or changes the machine resolver.

Optional always-on protection:

```bash
systemctl --user enable --now \
  blue-watch.service blue-guard.timer blue-feeds.timer \
  blue-net.timer blue-reputation.timer
```

The same controls are available under **Settings** in the app after installation.

## Browser/search extension

The companion is in [`browser-extension/`](browser-extension/) and the packaged
archive is `dist/epimetheus-blue-search-guard-0.4.0.zip`.

For Chromium or Brave:

1. Open `chromium://extensions` or `brave://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose `browser-extension/` (or the installed path shown by the native app).

Its browser action includes a search box and provider picker. Typing
`blue <query>` in the address bar also searches with the selected provider and
optional strict safe search. Settings stay in the browser profile; the extension
contains no analytics or remote code.

The installed native-messaging host is read-only. On supported search pages it
checks visible result domains against the full local domain feed without trying
to import tens of thousands of domains into Chromium's limited DNR quota.

## CLI

The GUI is the default, while every important operation remains scriptable:

```bash
blue                         # native control center
blue scan ~/Downloads       # one-off scan
blue watch                  # realtime watcher in the foreground
blue guard                  # integrity/persistence check
blue network                # observe public egress; never changes firewall rules
blue feeds sync             # update domain filters
blue feeds ls               # list active local lists
blue feeds rollback NAME    # restore previous list version
blue reputation sync        # update local malicious SHA-256 feeds
blue reputation check FILE  # local exact-hash check
blue reputation check FILE --online # opt-in hash-only VT check when configured
blue cleanup scan           # read-only inventory; selects nothing
blue cleanup performance    # memory pressure + top resident processes
blue cleanup phrase --id ID # exact phrase for reviewed IDs
blue cleanup apply --id ID --confirm 'EXACT PHRASE'
blue dns                    # local DNS sinkhole
blue quarantine ls          # held files
blue quarantine restore ID  # safe restore; refuses overwrite
blue drill                  # EICAR detect → quarantine → restore proof
blue verify                 # detector/config/state self-check
```

State lives under `~/.local/share/blue`. Configuration layers are:

1. built-in defaults;
2. `/etc/blue/config.toml`;
3. sorted `/etc/blue/conf.d/*.toml` drop-ins;
4. `~/.config/blue/config.toml`;
5. sorted `~/.config/blue/conf.d/*.toml` drop-ins;
6. the file passed with `--config`.

Later files override individual TOML fields rather than replacing whole sections.
Unknown keys are errors so a typo cannot silently disable protection.

## ClamAV

ClamAV is optional but recommended. Review the exact plan, then use the
confirmation-gated installer:

```bash
~/.local/share/epimetheus-blue/scripts/setup-clamav.sh plan
~/.local/share/epimetheus-blue/scripts/setup-clamav.sh install --confirm-package-install
```

Without `clamd`, Blue reports `DEGRADED` and continues with YARA-X. It does not
block file opens or pretend full coverage exists.

## System-wide DNS

The normal installer never changes NetworkManager or grants capabilities. The
separate setup transaction backs up the active connection, verifies the local
resolver before switching, and restores NetworkManager before stopping it:

```bash
~/.local/share/epimetheus-blue/scripts/setup-system-dns.sh plan
~/.local/share/epimetheus-blue/scripts/setup-system-dns.sh enable --confirm-network-change
~/.local/share/epimetheus-blue/scripts/setup-system-dns.sh disable
```

On networks with private DNS, the setup preserves those servers as upstreams
instead of silently substituting public DoT and breaking internal names.

## Optional VirusTotal

Files are never uploaded. To permit explicit hash-only lookups, add a user
drop-in with `virustotal_enabled = true`, export the API key through the named
environment variable, and use `blue reputation check FILE --online`.

```toml
# ~/.config/blue/conf.d/70-virustotal.toml
[reputation]
virustotal_enabled = true
virustotal_query_on_scan = false
```

```bash
export VIRUSTOTAL_API_KEY='…'
blue reputation check /path/to/file --online
```

## Cleanup safety model

The **Cleanup** tab never deletes during analysis and never selects an item for
you. Candidates are grouped into:

- **Safe** — narrowly allowlisted, reproducible caches;
- **Review** — trash, old installers, `target`, `node_modules`, browser/app
  caches and similar data whose loss has a cost even if it can be rebuilt;
- **Protected** — EFI, snapshots, backups, partial downloads, active workspace
  roots and application sandboxes. Blue lists these but refuses direct deletion.

Applying selected user-owned candidates requires an exact phrase generated for
that selection, followed by a fresh rescan and path/type/symlink validation.
System-managed cleanup has a separate read-only plan and confirmation-gated
owner-tool script:

```bash
~/.local/share/epimetheus-blue/scripts/cleanup-system.sh plan
```

Snapshot pruning and Docker image pruning use separate confirmations. EFI and
arbitrary backup deletion are never implemented by Blue.

## Security model

1. A single weak signal is T1 **candidate**, not an infection.
2. Quarantine requires T2 corroboration or a strong named signature.
3. Nothing is deleted automatically. The only destructive call outside the
   quarantine move fallback removes the drill's own harmless EICAR file.
4. Integrity changes remain T1; startup drift is important but is not malware
   proof by itself.
5. Failed detectors and feeds are visible degradation, not silent success.
6. DNS uses blocking—not TLS interception. No root CA is installed.
7. Network monitoring is observe-and-suggest only; no default-deny firewall is
   hidden behind a toggle.
8. Browser native messaging is read-only and capped per request.
9. Cleanup is scan-first, never preselected, exact-confirmation-gated and
   allowlist-based; protected paths are visible but not executable actions.

## Verification

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
./scripts/check-invariants.sh
./target/debug/blue drill
node browser-extension/scripts/validate.mjs
```

The browser extension has also been loaded in a clean headless Chromium profile
to validate its manifest, permissions, content-script matches and DNR ruleset.

Read [`docs/DESIGN.md`](docs/DESIGN.md) for the threat model, evidence tiers,
failure modes and deliberate non-goals.
