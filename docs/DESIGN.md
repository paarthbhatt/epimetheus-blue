# Epimetheus Blue — Design

**Status:** draft for review · **Date:** 2026-11-02 · **Scope:** one Arch Linux
workstation (Ryoku / Hyprland), single user.

---

## 1. Goals

1. Catch commodity malware that lands on this machine — downloaded binaries,
   droppers in `~/Downloads`, scripts in `/tmp`, malicious npm/pip install hooks —
   close to the moment it appears.
2. Tell me when something on disk or in my startup path changes without my
   knowledge.
3. Remove advertising, tracking and known-malicious domains from the network path
   for every application on the box, without breaking TLS.
4. Make all three share one state model, one native control center, one update mechanism, and
   one honest severity vocabulary.
5. Never lose data, never wedge the desktop, never lie about coverage.

### Explicit non-goals

- **Not a detection engine.** No new signatures, no classifier training, no
  heuristics invented here. We integrate ClamAV, YARA-X and public feeds.
- **Not a kernel module or eBPF agent.** User space only. No `CAP_SYS_ADMIN`
  services running permanently if it can be avoided.
- **Not a TLS interception proxy.** DNS sinkholing and browser-side filtering
  only. We will never install a root CA or MITM HTTPS.
- **Not multi-user, not multi-host, not a business product.** One machine.
- **Not a Windows/macOS port.** Seams are left clean, but not exercised.
- **Not automatic remediation of the OS.** No self-updating kernel, no automatic
  package downgrades, no edits to system files without an explicit operator verb.

---

## 2. Threat model

### Assets

| Asset | Why it matters |
|---|---|
| User documents, keys, source trees | Loss or exfiltration is the actual harm |
| SSH keys, GPG keys, browser profile, password manager DB | Credential theft enables everything else |
| Shell/desktop startup path | Persistence is how malware survives reboot |
| The resolver | A poisoned resolver redirects everything else |
| Availability of the workstation | A security tool that bricks the box gets removed, and then there is no tool |

### Adversaries considered

| Adversary | Capability | We help by |
|---|---|---|
| Commodity malware / infostealer | Known samples, packed binaries, script droppers | Signature + YARA scanning on write, quarantine |
| Malicious dependency | Runs `postinstall` / `setup.py`, writes to home, opens a socket | On-write scan of the resulting artifacts, persistence audit, egress visibility |
| Adware / tracking SDK | Bundled with an installer or a site | DNS sinkhole with tracker lists |
| Opportunistic phishing payload | User downloads and runs a file | Scan-before-open on Downloads, hash reputation |
| Someone with an existing shell on the box | Already past our perimeter | Integrity monitoring on startup path; we detect, we do not eject |

### Adversaries explicitly **not** in scope

- A targeted attacker with kernel-level access or physical access.
- A supply-chain compromise of the compiler, the kernel, or Arch's mirrors.
- Firmware/bootkit-level persistence.
- A user who deliberately disables the tool.

Saying this out loud is the point. A personal suite that implies it stops a
targeted intruder is worse than no suite, because it changes behaviour without
changing risk.

### Trust boundaries

```
 [ untrusted: network, downloaded files, package scripts ]
                          |
             (1) resolver  ---- sinkhole decision, no decryption
                          |
 [ user session: browser, editors, shells ]
                          |
             (2) watcher   ---- read-only observation of file events
                          |
 [ blue-core: policy, verdicts, SQLite ]
                          |
             (3) responder ---- only writable surface: quarantine dir
                          |
 [ quarantine: chmod 000, manifest, restorable ]
```

The responder is the only component allowed to *move* user data, and it may only
move into the quarantine store. Nothing may delete.

---

## 3. Architecture

One artifact, one database, several service modes.

### 3.1 Single binary, multiple roles

Decision (**ADR-1**): ship **one** Rust binary, `blue`, which opens a native app
by default and dispatches CLI subcommands. The alternative — separate binaries — multiplies packaging,
version-skew and unit-file surface for no benefit at this scale.

```text
blue               # native Wayland/X11 security control center
blue watch         # long-running: file watcher + scan pipeline
blue dns           # long-running: local sinkhole resolver
blue guard         # long-running: FIM + persistence audit
blue feeds sync    # oneshot, timer-driven
blue scan <path>   # ad-hoc scan
blue quarantine {ls,show,restore,export}
blue verify        # self-check: DB, feeds, detectors, units
blue drill         # end-to-end EICAR detection self-test
```

### 3.2 Crate layout

```text
blue/
├── Cargo.toml                  # workspace
├── crates/
│   ├── blue-bin/               # clap dispatch, service wiring, signal handling
│   ├── blue-core/              # config, sqlite, events, verdict policy, quarantine
│   ├── blue-scan/              # inotify watcher, clamd client, yara-x engine, queue
│   ├── blue-dns/               # UDP resolver, blocklist parser, suffix matcher
│   ├── blue-guard/             # hashing, FIM, persistence inventory, pacman drift
│   ├── blue-feeds/             # fetch, verify, activate, rollback datasets
│   ├── blue-reputation/        # local SHA-256 index + opt-in VT hash lookup
│   ├── blue-net/               # read-only procfs egress observer
│   ├── blue-native-host/       # bounded read-only browser messaging
│   ├── blue-cleanup/           # risk-classified storage/performance inventory
│   └── blue-ui/                # native eframe/egui Wayland/X11 application
├── browser-extension/          # Chromium/Brave MV3 search companion
├── packaging/                  # desktop entry and systemd user units
└── docs/
```

### 3.3 Process and privilege model

| Service | User | Privileges | Rationale |
|---|---|---|---|
| native app | logged-in user | normal user access | Controls scanning, guard, feeds and quarantine directly; no HTTP listener |
| `blue-watch.service` | logged-in user | normal user read access | Reads configured user paths; quarantine is its only data-moving operation |
| `blue-dns` | logged-in user | port 53 requires one-time external capability/setup | Resolver is never silently privileged by the installer |
| `blue-guard.timer` | logged-in user | read access to configured startup paths | Read-only by design |
| `blue-feeds.timer` | logged-in user | network egress | Downloads and validates DNS datasets |
| `blue-net.timer` | logged-in user | read-only procfs access | Observes the user's connected sockets; never edits firewall state |
| `blue-reputation.timer` | logged-in user | network egress | Downloads exact SHA-256 IOC lists; no samples |
| browser native host | browser-launched user process | stdin/stdout only | Read-only status, findings and bounded domain checks |

**No service runs as root.** Where root would normally be required:

- Port 53 → `AmbientCapabilities=CAP_NET_BIND_SERVICE`.
- Reading other users' files → out of scope; single-user machine, the scanner is
  a member of the user's group or runs as the user in "user scope" mode.
- Moving system files → **not supported**. System paths are report-only.

This is a deliberate reduction in capability. Root-level remediation is where
homebrew AV products destroy machines.

### 3.4 Data flow — file write

```text
inotify CLOSE_WRITE / MOVED_TO
   │  (debounce 500 ms, coalesce by inode)
   ▼
queue (bounded, 10k, disk-backed spool for overflow)
   │
   ├─ dedupe: (dev, inode, size, mtime) cache → skip unchanged
   │
   ├─ prefilter: extension allowlist, size cap, magic-byte sniff
   │      → skip media/fonts unless configured otherwise
   ▼
  clamd INSTREAM  ──┐
  yara-x scan     ──┤→ DetectorResults { name, rule, offset, severity_hint }
  hash reputation ──┘        (optional, opt-in, hash-only)
   ▼
 verdict policy (§6)  → tier T0..T3
   ▼
 T0/T1: review queue, no action
 T2/T3: quarantine + native-app entry
   ▼
 event row + evidence row (matched bytes, detector, timestamps, file hash)
```

### 3.5 Data flow — DNS query

```text
app → configured loopback UDP port
   │
   ├─ blocklist match (reversed-label map)
   │     → NXDOMAIN or 0.0.0.0 per policy, log {client, qname, list, action}
   └─ miss → forward over UDP to a configured upstream (2 s timeout)
```

Blocklist matching is **suffix-based**: `ads.example.com` blocks
`x.ads.example.com` but not `example.com`. Allowlist always wins over blocklist.
The matcher retains first-list-wins attribution for diagnostics. The current UI
shows aggregate live counts; a per-list query ledger is future work.

### 3.6 Data flow — integrity and persistence

```text
blue-guard (every 15 min + on-demand)
   ├─ hash watched set (systemd user units, ~/.config/autostart, crontab,
   │   shell rc files, ~/.ssh/authorized_keys, /etc/ld.so.preload, pacman db)
   ├─ diff against last snapshot → {added, removed, modified}
   ├─ classify: expected (package upgrade) vs unexplained
   └─ publish integrity events
```

Persistence inventory is a *first-class detector*, not an afterthought. It is
cheap, it survives anti-virus evasion, and it produces the highest-signal alerts
on a developer workstation ("something added a systemd user unit I did not write").

---

## 4. Component detail

### 4.1 `blue-core`

- Config: layered TOML — `/etc/blue/config.toml`, `~/.config/blue/config.toml`,
  CLI overrides. Unknown keys are a hard error (no silent typos).
- State: SQLite via `rusqlite` (bundled), WAL mode, single writer.
- State communication: direct shared handles inside the native process; SQLite is the durable path.
- Verdict policy: pure function over `(detector results, context) → Tier`.
  Unit-testable, no I/O. This is the most important 200 lines in the project.
- Quarantine: one retained object per event at `items/<id>/payload`, mode `000`,
  with original path/mode and hash recorded. Restore refuses to overwrite.
- Kill switch: one atomic flag in the DB and a file; all responders check it
  before acting.

### 4.2 `blue-scan`

- Watcher: `notify` over inotify, recursive only on configured roots, with
  per-path debounce and self-generated access events ignored.
- Scan path is synchronous and deliberately small; the native app moves full
  directory scans to a worker thread so the UI stays responsive.
- ClamAV: `clamd` over a Unix socket via the `INSTREAM` protocol,
  *not* spawning `clamscan` per file —
  process startup would dominate.
- YARA: `yara-x` (pure-Rust YARA, verified available at 1.22.x) compiled rules
  loaded once, hot-reloaded on dataset activation, scan with a scan timeout and
  `max_rule_scan` guard.
- Prefilter: exclusion globs and a 512 MiB default size cap. Oversized files are
  skipped without spending the same I/O budget hashing them first.
- Realtime desktop notifications are best-effort and only emitted after a T2+
  verdict actually enters quarantine; candidates never interrupt the user.

### 4.3 `blue-dns`

- Resolver: a small Tokio UDP sinkhole/forwarder. It parses only the first DNS
  question and never panics on malformed datagrams.
- Blocklists accept hosts, bare-domain and common Adblock anchor formats, then use
  exact label-boundary suffix matching. Allowlists always win.
- Upstreams support UDP and certificate-validated DNS-over-TLS (RFC 7858). A
  selected DoT endpoint never falls back to plaintext. The current campus network
  blocks port 853, so confirmed system setup preserves its internal UDP DNS.
- Bind conflicts and permission errors are returned visibly to the native app.

### 4.4 `blue-guard`

- FIM: SHA-256 hashes in a bounded JSON inventory persisted in SQLite meta state.
- Persistence inventory: systemd user+system units, drop-ins, timers, cron/at,
  XDG autostart, `~/.config/hypr` exec lines, shell rc, `~/.ssh/authorized_keys`,
  `/etc/ld.so.preload`, `/etc/pacman.conf` hooks, browser native-messaging hosts.
- Package drift: run bounded `pacman -Qkk` directly (never through a shell), parse
  warnings/altered summaries, and degrade visibly on timeout or command failure.
- Baseline discipline: the first run creates a baseline and says so. It does not
  claim the machine is clean — it claims the machine is *known*.

### 4.5 `blue-feeds`

- Sources: configured plain-text DNS hosts/domain blocklists. ClamAV keeps using
  its own `freshclam`; Blue does not impersonate that updater.
- Pipeline: `fetch → size-limit → structural validation → hash → stage → activate → record`.
- Every activation writes a dataset row (source, version, hash, size, timestamp).
- Rollback: `blue feeds rollback <dataset>` reactivates the previous row. A bad
  blocklist that breaks the internet must be a 5-second fix.
- No dataset is vendored in git. Licenses differ per list; each source entry
  records its license and fetch URL.

### 4.6 `blue-ui` and browser companion

- `eframe`/`egui` renders a native Wayland/X11 window. It contains no web view,
  web server, or loopback HTTP API.
- Long-running work executes off the UI thread. State is refreshed from SQLite;
  mutating verbs call the same Rust policy/quarantine APIs as the CLI.
- The Chromium/Brave Manifest V3 companion is deliberately separate. It removes
  sponsored search cards, strips tracking parameters, provides safe-search
  shortcuts and applies conservative DNR domain rules. It loads no remote code.
- A read-only native-messaging host batches visible search-result domains against
  the full desktop blocklist. The list is not copied into DNR because browser
  quota is smaller than the local dataset.

### 4.7 `blue-reputation`

- Loads exact SHA-256 IOCs from validated local feeds; MD5/SHA-1 are ignored.
- Local matches are high-confidence hash signals and participate in the same T2
  quarantine gate as the other detectors.
- VirusTotal is opt-in, hash-only, environment-keyed and cached. No file upload
  endpoint exists in the implementation. Explicit online checks are the default;
  automatic scan queries remain off.

### 4.8 `blue-net`

- Parses the logged-in user's established TCP and connected UDP sockets from
  procfs and best-effort maps socket inodes to process names.
- The first run establishes a public-destination baseline. Later new destinations
  are T1 observations worded as new, never as malicious.
- No packet capture, nftables mutation, process kill, or default-deny mode exists.

### 4.9 `blue-cleanup`

- Inventory and execution are separate. Scans never select or delete anything.
- Candidates are **Safe** (narrow reproducible caches), **Review** (trash,
  downloads and build artifacts with a real recovery cost), or **Protected**
  (EFI, snapshots, backups, partial downloads and application sandboxes).
- User-owned deletion requires explicit IDs plus an exact generated phrase, then
  a fresh rescan, candidate-ID resolution, file-type, symlink and mount checks.
- System-owned cleanup uses a separate owner-tool plan and distinct confirmation
  gates. EFI and arbitrary backups have no deletion implementation.
- Performance diagnostics are observation-only: memory availability, swap,
  process count and top resident processes. Blue never kills an application from
  the Cleanup page.

---

## 5. Data model

```sql
-- Detected artifact, one row per (path, hash) observation
CREATE TABLE artifacts (
  id            INTEGER PRIMARY KEY,
  path          TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  size          INTEGER NOT NULL,
  mtime         INTEGER NOT NULL,
  first_seen    INTEGER NOT NULL,
  last_seen     INTEGER NOT NULL,
  verdict_tier  INTEGER NOT NULL DEFAULT 0,   -- 0..3
  verdict_state TEXT NOT NULL DEFAULT 'open'  -- open|quarantined|restored|dismissed
);

-- One detector's output. Never merged; corroboration is computed, not stored away.
CREATE TABLE evidence (
  id            INTEGER PRIMARY KEY,
  artifact_id   INTEGER REFERENCES artifacts(id),
  detector      TEXT NOT NULL,   -- clamav|yara|hashrep|integrity|persistence
  signature     TEXT,
  severity_hint TEXT,
  detail_json   TEXT,
  created_at    INTEGER NOT NULL
);

CREATE TABLE events (
  id         INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  kind       TEXT NOT NULL,      -- scan|dns|integrity|persistence|feed|system
  level      TEXT NOT NULL,      -- info|notice|warn|error
  subject    TEXT,
  payload    TEXT NOT NULL
);

CREATE TABLE quarantine (
  id           INTEGER PRIMARY KEY,
  artifact_id  INTEGER REFERENCES artifacts(id),
  object_path  TEXT NOT NULL,    -- objects/<sha256>
  original_path TEXT NOT NULL,
  original_mode INTEGER,
  original_uid  INTEGER,
  original_mtime INTEGER,
  reason       TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  restored_at  INTEGER
);

CREATE TABLE dns_queries (
  id        INTEGER PRIMARY KEY,
  ts        INTEGER NOT NULL,
  client    TEXT NOT NULL,
  qname     TEXT NOT NULL,
  qtype     TEXT,
  action    TEXT NOT NULL,       -- allowed|cached|blocked|upstream_error
  list_name TEXT,
  latency_ms INTEGER
);

CREATE TABLE snapshots (
  id         INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  kind       TEXT NOT NULL,      -- fim|persistence|packages
  entry_count INTEGER NOT NULL,
  digest     TEXT NOT NULL
);

CREATE TABLE snapshot_entries (
  snapshot_id INTEGER REFERENCES snapshots(id),
  key         TEXT NOT NULL,     -- path or inventory key
  hash        TEXT,
  meta        TEXT
);

CREATE TABLE datasets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,      -- clamav|yara-core|dns-ads|dns-trackers
  version    TEXT NOT NULL,
  source_url TEXT,
  license    TEXT,
  sha256     TEXT NOT NULL,
  size       INTEGER,
  activated_at INTEGER,
  active     INTEGER NOT NULL DEFAULT 1
);
```

Retention: `dns_queries` 30 days, `events` 90 days, `evidence` and `quarantine`
until explicitly resolved. A nightly job enforces it.

---

## 6. Evidence and verdict policy

This section is the reason the project exists in this shape. It borrows the
fail-closed discipline of the Red platform: **a cheap signal must never wear the
costume of a confirmed finding.**

| Tier | Name | Requires | Permitted action |
|---|---|---|---|
| T0 | Observed | A file event, a DNS query, a snapshot diff | Log only |
| T1 | Candidate | One signal: a YARA rule match, a low-confidence hash hit, an unexplained persistence entry | Review queue, no file action |
| T2 | Corroborated | ClamAV signature match, **or** two independent weak signals agreeing on the same artifact, **or** a hash on a high-confidence reputation list | Quarantine + notify |
| T3 | Confirmed | T2 plus reproducible evidence: matched offset/bytes retained, a clean re-scan of the quarantined object confirms the same verdict | Quarantine + notify + "confirmed" label in UI |

Rules:

- **Never auto-delete.** No code path calls `remove_file` on user data. A unit
  test asserts this by scanning the workspace for `remove_file` outside the
  quarantine module.
- **Never auto-disconnect the network** or kill a process. Those are operator
  verbs with explicit confirmation.
- **Quarantine is reversible.** `blue quarantine restore <id>` puts the file back
  at its original path with its original mode, then marks state `restored`.
- **False positives are first-class.** Dismissing a verdict requires a reason,
  which is stored and fed back into a user allowlist (hash-pinned, never
  path-pinned).

---

## 7. Failure modes

| Failure | Behaviour | Why |
|---|---|---|
| `clamd` unavailable | Scanner enters `DEGRADED`, YARA-only scanning continues, native app shows the state | Partial coverage beats blocked files and an uninstalled tool |
| YARA rules fail to compile | Activate previous dataset automatically, keep the failure visible | A broken rule set must not take the pipeline down |
| Blocklist breaks a site | Allowlist entry, one-command rollback to previous dataset | The resolver is on the critical path of everything |
| Port 53 taken or denied | Refuse cleanly and show the bind error | Never race another resolver or hide missing privilege |
| DB locked / corrupt | Operation fails visibly in the UI; no clean claim is shown | Silent loss is worse than an explicit failed operation |
| Kill switch engaged | Scans and evidence continue; quarantine is suppressed | A reversible automatic-action pause |
| Disk full | Quarantine refuses new objects, emits error, never partial-copies | A truncated quarantine object is worse than none |

**Fail-open principle:** the scanner never blocks a file open. fanotify
permission events (`FAN_OPEN_PERM`) are explicitly not used, because a blocking
scanner on a developer workstation is a self-inflicted denial of service.

---

## 8. Performance budget

Measured on this machine (16 threads, 15 GiB).

| Metric | Target |
|---|---|
| Idle RSS, all services | < 120 MiB total |
| RSS during full scan | < 400 MiB |
| Blocklist memory @ 500k domains | < 150 MiB |
| DNS blocklist lookup p99 | < 1 ms |
| Time from `CLOSE_WRITE` to verdict (1 MiB file) | < 1 s |
| Full scan of `~/Downloads` (10 GiB) | < 10 min |
| Boot impact | services start concurrently, do not block login |
| CPU when idle | < 1 % average |

These remain budgets, not yet automated release gates. Functional tests are the
current release gate; benchmark automation is future work.

---

## 9. Configuration

```toml
[general]
state_dir = "~/.local/share/blue"
log_level = "info"

[scan]
roots = ["~/Downloads", "~/Documents", "~/Projects", "~/tmp", "/tmp"]
exclude_globs = ["**/node_modules/**", "**/.git/objects/**", "**/*.iso"]
max_file_size_mb = 512
debounce_ms = 500
# fanotify is documented but disabled: it needs CAP_SYS_ADMIN and can block opens.
mode = "inotify"

[scan.clamav]
socket = "/run/clamav/clamd.ctl"
required = false          # degrade rather than fail closed

[scan.yara]
rule_dirs = ["~/.local/share/blue/rules"]
timeout_ms = 5000

[dns]
bind = "127.0.0.1:53"
upstreams = ["1.1.1.1:53", "9.9.9.9:53"]
block_response = "nxdomain"   # or "zero"

[feeds]
lists_dir = "~/.local/share/blue/lists"

[[feeds.sources]]
name = "stevenblack"
url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
license = "MIT"

[guard]
watch_paths = [
  "~/.config/systemd/user",
  "~/.config/autostart",
  "~/.ssh/authorized_keys",
  "/etc/ld.so.preload",
  "/etc/systemd/system",
]
# Full pacman -Qkk is resource-heavy; enable only for explicit/manual audits.
watch_packages = false

```

---

## 10. Operations

### Units

```text
blue-watch.service       optional always-on realtime watcher
blue-guard.timer         15-minute read-only integrity check
blue-feeds.timer         daily filter update with randomized delay
```

All units:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
MemoryMax=512M
TasksMax=64
```

Units are installed but not enabled automatically. The native app or an explicit
`systemctl --user enable --now ...` controls them.

### Packaging

`scripts/install-local.sh` installs the native binary, desktop entry, browser
extension and systemd user units without root. A distro `PKGBUILD` is future work.
ClamAV remains a distro package and `freshclam` remains its own updater.

### Bootstrap order

```bash
scripts/setup-clamav.sh plan
scripts/setup-clamav.sh install --confirm-package-install
blue verify             # DB, units, feeds, detectors
blue feeds sync
blue reputation sync
blue network            # establish read-only egress baseline
blue drill              # end-to-end proof the pipeline works
blue scan ~/Downloads
```

`blue drill` writes the EICAR test string to a controlled state path, waits for
the verdict, asserts T2, quarantines it, restores it, and deletes it. This is the
single most important command in the suite: it proves the wiring without touching
a real sample.

---

## 11. Decisions

| # | Decision | Alternatives rejected |
|---|---|---|
| ADR-1 | One binary, many subcommands | Five binaries — version skew, five unit files, no gain |
| ADR-2 | inotify by default, fanotify documented but off | fanotify — needs `CAP_SYS_ADMIN`, permission events block opens |
| ADR-3 | `yara-x` embedded engine, not the `yara` CLI | shelling out per file — process spawn dominates scan time |
| ADR-4 | `clamd` over Unix socket, not `clamscan` per file | per-file process — same reason |
| ADR-5 | Minimal Tokio UDP/DoT resolver, not Unbound/Blocky | external daemon — loses in-process controls; full DNS stack is YAGNI for a sinkhole |
| ADR-6 | Quarantine only, delete never | auto-delete — irreversible, and the usual cause of data loss |
| ADR-7 | DNS sinkhole, no TLS interception | MITM proxy — breaks cert validation, bigger attack surface |
| ADR-8 | Native eframe/egui app, no loopback HTTP | web dashboard/Electron — unnecessary listener/runtime for one local user |
| ADR-9 | Separate MV3 browser companion | TLS MITM or all-page DOM inspection — excessive privilege and breakage |
| ADR-10 | Local exact-hash IOC feed; VirusTotal hash-only and explicit | automatic file uploads — unacceptable privacy boundary |
| ADR-11 | Read-only egress baselining | default-deny firewall — breakage and lockout risk exceeds personal value |
| ADR-12 | Read-only bounded browser native host | copying the full feed into DNR — browser quota and update churn |
| ADR-13 | Scan-first allowlisted cleanup with typed confirmation | generic “clean everything” commands — data-loss and TOCTOU risk |

---

## 12. Delivery plan

| Phase | Deliverable | Acceptance |
|---|---|---|
| 0 | `blue-core`, scanning, quarantine, EICAR drill | complete |
| 1 | DNS suffix sinkhole and blocklist matcher | complete |
| 2 | Watcher, integrity/persistence guard, package drift | complete |
| 3 | Native control center, versioned feeds, systemd user timers | complete |
| 4 | Chromium/Brave search companion | complete |
| 5 | DoT, local/optional VT reputation, egress observer, native browser bridge | complete |
| 6 | Risk-classified cleanup and performance inventory | complete |
| System activation | ClamAV package and NetworkManager loopback DNS | confirmation-gated, not silently applied |

Phase 0 is designed to be useful on day one and dangerous to nothing.

---

## 13. Acceptance drills

Each is a scripted, repeatable test. If a drill fails, the release is not done.

1. **EICAR end-to-end** — detect → T2 → quarantine → restore → byte-identical.
2. **No-delete invariant** — grep the workspace for destructive calls outside
   `blue-core::quarantine`; assert zero.
3. **Degraded mode** — stop `clamd`, write a file, assert YARA still scans, UI
   shows `DEGRADED`, file remains accessible.
4. **Kill switch** — engage, write a suspicious file, assert no quarantine, no
   notification, event still logged.
5. **Resolver conflict** — occupy `:53`, start `blue dns`, assert clean refusal.
6. **Blocklist rollback** — activate a broken list, rollback, assert resolution
   restored in under 5 s.
7. **Persistence injection** — add a systemd user unit, assert a T1 persistence
   event within one guard interval.
8. **Restart resilience** — kill all services mid-scan, restart, assert no
   duplicate quarantines and no lost events.
9. **Extension validation** — manifest parses, scripts pass syntax checks, static
   rule IDs are unique and Chromium accepts the unpacked extension.

---

## 14. Open questions

1. **Blocklist providers.** Which lists to ship as defaults is a licensing and
   taste decision. Every source must record its license and fetch URL; none are
   vendored.
2. **System-path scanning.** Report-only, or allow quarantine with an explicit
   per-action confirmation? Current design: report-only.
3. **Name.** `Epimetheus Blue` is a working title that pairs with the Red work.
   Renaming costs a `sed` today and a migration later.

---

## 15. What success looks like

Not "zero infections". Success is:

- A downloaded binary is scanned before I run it, and I know the result.
- A tracker domain is blocked, and I can name the list that blocked it.
- Something adds a startup entry, and I hear about it within 15 minutes.
- When a detector breaks, I see `DEGRADED` instead of believing I am covered.
- Nothing the tool did is irreversible.

---

## 16. Implementation status

Built on 2026-11-03. `blue drill` passes end to end; the resolver and browser
extension have live smoke tests. The current workspace test count is recorded in
the release summary rather than hard-coded here.

| Component | State |
|---|---|
| `blue-core` (config, SQLite, verdict, quarantine) | implemented |
| `blue-scan` (YARA-X, clamd, watcher) | implemented |
| `blue-dns` (suffix blocklist, UDP + authenticated DoT) | implemented |
| `blue-ui` (native Wayland/X11 app, kill switch) | implemented |
| `blue-guard` (FIM, persistence audit, package drift) | implemented |
| `blue-feeds` (validated dataset sync, rollback) | implemented |
| `blue-reputation` (local SHA-256 + optional VT hash lookup) | implemented |
| `blue-net` (read-only egress baseline) | implemented |
| `blue-native-host` (read-only browser bridge) | implemented |
| `blue-cleanup` (risk inventory, explicit user-owned apply, performance snapshot) | implemented |
| Chromium/Brave MV3 search companion | implemented, stable extension ID |
| systemd user units + desktop entry | implemented |
| reversible ClamAV and NetworkManager setup | implemented; privileged apply awaits confirmation |

### Deviations from the design above

These are deliberate and cheap to reverse. Listed so the doc does not drift.

1. **Quarantine layout is `items/<id>/payload`, not `objects/<sha256>`.** Content
   addressing would force a decision about what to do with a second file that has
   the same hash — and every answer except "keep both" involves deleting one.
   The hash is still recorded on every record.
2. **Default state dir is `~/.local/share/blue`.** Running as the logged-in user
   keeps one-machine ownership simple; hardened user units isolate background jobs.
3. **YARA-X is built with `default-features = false`.** The default feature set
   pulls in parsers and modules that the current plain-string rules do not use.
   YARA-X core still brings its own runtime; this switch trims optional modules,
   not the entire dependency graph. Re-enable only what a future dataset needs.
4. **DoT is available but the current campus network blocks port 853.** The
   reversible system setup therefore preserves its private DNS servers as UDP
   upstreams instead of breaking internal names or silently downgrading DoT.
5. **`blue scan` has no `--json` yet.** It prints a table and a summary line;
   SQLite is the durable machine-readable state.
6. **Oversized files are recorded as T0 with no hash and no row**, rather than
   hashing 512 MiB just to skip it. Visible in the per-file output.

### Verified behaviours worth keeping

- Suffix matching blocks `x.ads.example.com` and not `notads.example.com`.
- A ClamAV hit alone reaches T2; a single low-confidence YARA hit stays at T1.
- Kill switch on: verdict recorded, nothing moved.
- A local exact SHA-256 IOC produces a high-confidence hash signal; VT remains off
  unless both configuration and an explicit online check permit it.
- Egress observation reports new destinations once and never edits nftables.
- The browser native host has no mutating message type.
- Restore refuses to overwrite a file that reappeared at the original path.
- Stopping `clamd` degrades the scanner instead of failing closed.
