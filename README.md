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
| Filter feeds | Download, validate, atomically activate, retain previous, roll back |
| Browser/search shield | Chromium/Brave MV3 extension: search-ad cleanup, tracking-link removal, domain rules |

## Native app

```bash
cargo build --release
./target/release/blue
```

The app provides:

- protection toggles and an emergency automatic-action pause;
- file/folder scanning;
- integrity findings with acknowledgement;
- quarantine restore;
- feed update and rollback;
- DNS Shield controls and live blocked-query counts;
- browser extension installation guidance;
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
  blue-watch.service blue-guard.timer blue-feeds.timer
```

The same controls are available under **Settings** in the app after installation.

## Browser/search extension

The companion is in [`browser-extension/`](browser-extension/) and the packaged
archive is `dist/epimetheus-blue-search-guard-0.2.0.zip`.

For Chromium or Brave:

1. Open `chromium://extensions` or `brave://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose `browser-extension/` (or the installed path shown by the native app).

Its browser action includes a search box and provider picker. Typing
`blue <query>` in the address bar also searches with the selected provider and
optional strict safe search. Settings stay in the browser profile; the extension
contains no analytics or remote code.

## CLI

The GUI is the default, while every important operation remains scriptable:

```bash
blue                         # native control center
blue scan ~/Downloads       # one-off scan
blue watch                  # realtime watcher in the foreground
blue guard                  # integrity/persistence check
blue feeds sync             # update domain filters
blue feeds ls               # list active local lists
blue feeds rollback NAME    # restore previous list version
blue dns                    # local DNS sinkhole
blue quarantine ls          # held files
blue quarantine restore ID  # safe restore; refuses overwrite
blue drill                  # EICAR detect → quarantine → restore proof
blue verify                 # detector/config/state self-check
```

State lives under `~/.local/share/blue`. Configuration layers are:

1. built-in defaults;
2. `/etc/blue/config.toml`;
3. `~/.config/blue/config.toml`;
4. the file passed with `--config`.

Later files override individual TOML fields rather than replacing whole sections.
Unknown keys are errors so a typo cannot silently disable protection.

## ClamAV

ClamAV is optional but recommended:

```bash
sudo pacman -S clamav
sudo systemctl enable --now clamav-daemon clamav-freshclam
```

Without `clamd`, Blue reports `DEGRADED` and continues with YARA-X. It does not
block file opens or pretend full coverage exists.

## Security model

1. A single weak signal is T1 **candidate**, not an infection.
2. Quarantine requires T2 corroboration or a strong named signature.
3. Nothing is deleted automatically. The only destructive call outside the
   quarantine move fallback removes the drill's own harmless EICAR file.
4. Integrity changes remain T1; startup drift is important but is not malware
   proof by itself.
5. Failed detectors and feeds are visible degradation, not silent success.
6. DNS uses blocking—not TLS interception. No root CA is installed.

## Verification

```bash
cargo test --workspace
./scripts/check-invariants.sh
./target/debug/blue drill
node browser-extension/scripts/validate.mjs
```

The browser extension has also been loaded in a clean headless Chromium profile
to validate its manifest, permissions, content-script matches and DNR ruleset.

Read [`docs/DESIGN.md`](docs/DESIGN.md) for the threat model, evidence tiers,
failure modes and deliberate non-goals.
