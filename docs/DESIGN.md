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
4. Make all three share one state model, one dashboard, one update mechanism, and
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

Decision (**ADR-1**): ship **one** Rust binary, `blue`, which dispatches on a
subcommand. The alternative — five separate binaries — multiplies packaging,
version-skew and unit-file surface for no benefit at this scale.

```text
blue daemon        # long-running: event bus, policy, HTTP API, embedded UI
blue scanner       # long-running: file watcher + scan pipeline
blue dns           # long-running: local sinkhole resolver
blue guard         # long-running: FIM + persistence audit
blue feeds sync    # oneshot, timer-driven
blue scan <path>   # ad-hoc scan
blue quarantine {ls,show,restore,export}
blue verify        # self-check: DB, feeds, detectors, units
blue drill eicar   # end-to-end detection self-test
```

### 3.2 Crate layout

```text
blue/
├── Cargo.toml                  # workspace
├── crates/
│   ├── blue-bin/               # clap dispatch, service wiring, signal handling
│   ├── blue-core/              # config, sqlite, events, verdict policy, quarantine
│   ├── blue-scan/              # inotify watcher, clamd client, yara-x engine, queue
│   ├── blue-dns/               # hickory resolver, blocklist compiler, matcher
│   ├── blue-guard/             # hashing, FIM, persistence inventory, pacman drift
│   ├── blue-feeds/             # fetch, verify, activate, rollback datasets
│   └── blue-http/              # axum router, SSE stream, rust-embed UI assets
├── assets/                     # dashboard (vanilla HTML/JS, no build step)
├── config/                     # default TOML, example overrides
├── packaging/                  # PKGBUILD, systemd units, sysusers, tmpfiles
└── docs/
```

### 3.3 Process and privilege model

| Service | User | Privileges | Rationale |
|---|---|---|---|
| `blue-daemon` | `blue` (system user) | none beyond its own state dir | Owns DB and API; reachable only on loopback |
| `blue-scanner` | `blue-scanner` (system user), member of `blue` group | `CAP_DAC_READ_SEARCH` **optional**, only if system paths are watched | Reads user files to scan them; never writes outside quarantine |
| `blue-dns` | `blue-dns` | bind 127.0.0.1:53 only | No root after bind if port 53 is granted via capability |
| `blue-guard` | `blue-guard` | read access to startup paths | Read-only by design |
| `blue-feeds` | `blue` | network egress only | Downloads and verifies datasets |

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
 T2/T3: quarantine + notify + dashboard entry
   ▼
 event row + evidence row (matched bytes, detector, timestamps, file hash)
```

### 3.5 Data flow — DNS query

```text
app → 127.0.0.1:53
   │
   ├─ cache hit (LRU, 4096 entries, TTL-aware)
   ├─ blocklist match (suffix trie / FST set)
   │     → NXDOMAIN or 0.0.0.0 per policy, log {client, qname, list, action}
   └─ miss → forward over DoT to configured upstream
                → cache, log latency/outcome
```

Blocklist matching is **suffix-based**: `ads.example.com` blocks
`x.ads.example.com` but not `example.com`. Allowlist always wins over blocklist.
Per-list attribution is stored so the dashboard can answer *which list* blocked
something, not just that something was blocked.

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
- Event bus: in-process `tokio::broadcast`; persistence is the durable path.
- Verdict policy: pure function over `(detector results, context) → Tier`.
  Unit-testable, no I/O. This is the most important 200 lines in the project.
- Quarantine: content-addressed store, `objects/<sha256>`, manifests in DB, a
  `chmod 000` copy under `links/`. Restore replays metadata.
- Kill switch: one atomic flag in the DB and a file; all responders check it
  before acting.

### 4.2 `blue-scan`

- Watcher: `notify` crate over inotify. Recursive watches only on configured
  roots (`~/Downloads`, `~/Documents`, `~/tmp`, `/tmp`, `~/Projects`), capped at
  `max_user_watches`; refuses to start with a clear message if the cap is too low
  and prints the exact `sysctl` to set.
- Concurrency: 4 scan workers by default, bounded channel, per-file timeout
  (30 s), total scan budget per batch.
- ClamAV: persistent `clamd` over Unix socket via the clamd protocol
  (`INSTREAM`, `clamav-client` crate), *not* spawning `clamscan` per file —
  process startup would dominate.
- YARA: `yara-x` (pure-Rust YARA, verified available at 1.22.x) compiled rules
  loaded once, hot-reloaded on dataset activation, scan with a scan timeout and
  `max_rule_scan` guard.
- Prefilter: size cap (default 512 MiB), extension allow/deny lists, ELF/PE/script
  sniffing, skip if the hash is in the known-clean cache and the file is unchanged.
- Backpressure: when the queue exceeds 80 %, emit a `SCANNER_OVERLOADED` event and
  degrade to scheduled-only scanning rather than dropping silently.

### 4.3 `blue-dns`

- Resolver: `hickory-server` with a custom authority that consults the blocklist
  before forwarding.
- Blocklist compile: fetch plain-text hosts/domain lists → normalize → dedupe →
  build a suffix matcher. Target: 500k domains in under 2 s, under 150 MB RSS,
  p99 lookup under 1 ms. If those numbers miss, fall back to a sorted-array
  binary search before considering anything exotic.
- Upstreams: DoT by default (Cloudflare/Quad9), configurable; never plaintext
  unless explicitly set.
- Conflict handling: on startup, if `:53` is bound, refuse and print who holds it
  (`ss -lunp`). Do not fight `systemd-resolved`; document the exact disable steps.
- Client identification: per-source-IP counters, later per-interface names, so LAN
  promotion is a config change rather than a rewrite.

### 4.4 `blue-guard`

- FIM: BLAKE3 hashes, snapshot table, diff, classification.
- Persistence inventory: systemd user+system units, drop-ins, timers, cron/at,
  XDG autostart, `~/.config/hypr` exec lines, shell rc, `~/.ssh/authorized_keys`,
  `/etc/ld.so.preload`, `/etc/pacman.conf` hooks, browser native-messaging hosts.
- Package drift: compare `pacman -Qkk` output and file ownership against the last
  known-good snapshot; flag files owned by a package but modified, and files in
  system paths owned by no package.
- Baseline discipline: the first run creates a baseline and says so. It does not
  claim the machine is clean — it claims the machine is *known*.

### 4.5 `blue-feeds`

- Sources: `freshclam` for ClamAV; project-pinned YARA rule sets; DNS blocklists
  (ads, trackers, malware C2) from public providers.
- Pipeline: `fetch → hash → verify → stage → compile → activate → record`.
- Every activation writes a dataset row (source, version, hash, size, timestamp).
- Rollback: `blue feeds rollback <dataset>` reactivates the previous row. A bad
  blocklist that breaks the internet must be a 5-second fix.
- No dataset is vendored in git. Licenses differ per list; each source entry
  records its license and fetch URL.

### 4.6 `blue-http`

- `axum`, bound to `127.0.0.1:8471` only, bearer token from a root-owned file.
- Endpoints: `/api/events`, `/api/verdicts`, `/api/quarantine`,
  `/api/dns/stats`, `/api/integrity`, `/api/feeds`, `/api/health`,
  `/api/killswitch`, plus an SSE stream for the dashboard.
- UI: embedded static assets, no Node toolchain, no CDN. Works offline.
- Read-only by default; the few mutating verbs (`restore`, `killswitch`,
  `feeds rollback`) require a confirmation token minted per-session.

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
| `clamd` unavailable | Scanner enters `DEGRADED`, YARA-only scanning continues, dashboard shows the state | Partial coverage beats blocked files and an uninstalled tool |
| YARA rules fail to compile | Activate previous dataset automatically, keep the failure visible | A broken rule set must not take the pipeline down |
| Queue overflows | Coalesce, drop oldest low-priority work, emit `SCANNER_OVERLOADED` | Silent loss is the thing we must not do |
| Blocklist breaks a site | Allowlist entry, one-command rollback to previous dataset | The resolver is on the critical path of everything |
| Port 53 taken | Refuse to start, name the holder, print remediation | Never race another resolver |
| DB locked / corrupt | Read-only mode, UI shows the error, scanner spools to disk | Lose diagnosis, not events |
| Kill switch engaged | All responders stop within one event-loop tick; watchers keep observing | A one-action panic button |
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
| DNS lookup p99, cache miss | < 2 ms added latency |
| DNS lookup p99, cache hit | < 0.2 ms |
| Time from `CLOSE_WRITE` to verdict (1 MiB file) | < 1 s |
| Full scan of `~/Downloads` (10 GiB) | < 10 min |
| Boot impact | services start concurrently, do not block login |
| CPU when idle | < 1 % average |

Budgets are enforced by a `blue bench` command so regressions are visible, not
discovered.

---

## 9. Configuration

```toml
[general]
state_dir = "/var/lib/blue"
kill_switch = false
log_level = "info"

[scan]
roots = ["~/Downloads", "~/Documents", "~/Projects", "~/tmp", "/tmp"]
exclude_globs = ["**/node_modules/**", "**/.git/objects/**", "**/*.iso"]
max_file_size_mb = 512
workers = 4
debounce_ms = 500
# fanotify is documented but disabled: it needs CAP_SYS_ADMIN and can block opens.
mode = "inotify"

[scan.clamav]
socket = "/run/clamav/clamd.ctl"
required = false          # degrade rather than fail closed

[scan.yara]
rule_sets = ["core", "webshells", "ransomware"]
timeout_ms = 5000

[verdict]
quarantine_at = "T2"      # or "T3" for a more conservative posture
notify_at = "T2"

[dns]
bind = "127.0.0.1:53"
upstreams = ["tls://1.1.1.1:853", "tls://9.9.9.9:853"]
block_response = "nxdomain"   # or "zero"
lists = ["ads", "trackers", "malware"]
allowlist = ["*.local", "*.internal", "github.com"]

[guard]
interval_minutes = 15
watch_paths = [
  "~/.config/systemd/user",
  "~/.config/autostart",
  "~/.ssh/authorized_keys",
  "/etc/ld.so.preload",
  "/etc/systemd/system",
]
watch_packages = true

[http]
bind = "127.0.0.1:8471"
```

---

## 10. Operations

### Units

```text
blue-daemon.service      After=network.target
blue-scanner.service     After=blue-daemon.service clamav-daemon.service
blue-dns.service         After=blue-daemon.service, Wants=network-online.target
blue-guard.service       After=blue-daemon.service
blue-feeds.timer         hourly; oneshot service
```

All units:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
MemoryMax=300M
TasksMax=64
```

Acceptance: `systemd-analyze security` score below 2.0 exposure for each unit.

### Packaging

`PKGBUILD` + `sysusers.d` + `tmpfiles.d`. ClamAV and `clamav-daemon` remain distro
packages; we depend on them rather than vendoring. `freshclam` stays the system
updater; `blue-feeds` orchestrates and records it, it does not replace it.

### Bootstrap order

```bash
pacman -S clamav yara   # or rely on yara-x, see ADR-3
systemctl enable --now clamav-daemon clamav-freshclam
blue verify             # DB, units, feeds, detectors
blue feeds sync
blue drill eicar        # end-to-end proof the pipeline works
blue scan ~/Downloads
```

`blue drill eicar` writes the EICAR test string to a temp watched path, waits for
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
| ADR-5 | hickory-based resolver, not Unbound/Blocky | external daemon — loses per-list attribution and unified state |
| ADR-6 | Quarantine only, delete never | auto-delete — irreversible, and the usual cause of data loss |
| ADR-7 | DNS sinkhole, no TLS interception | MITM proxy — breaks cert validation, bigger attack surface |
| ADR-8 | Loopback HTTP + bearer token, no auth stack | full auth — single-user box, not worth the surface |

---

## 12. Delivery plan

| Phase | Deliverable | Acceptance |
|---|---|---|
| 0 | `blue-core` skeleton, config, SQLite, `blue scan`, `blue drill eicar` | EICAR detected, quarantined, restored; zero root daemons |
| 1 | `blue-dns` with three lists, dashboard DNS tab | 500k domains compile < 2 s, p99 < 1 ms, rollback works |
| 2 | `blue-scanner` watcher, `blue-guard` FIM + persistence | Write to `~/Downloads` → verdict < 1 s; injected systemd unit alert |
| 3 | `blue-http` dashboard, notifications, `blue feeds` timer | One screen answers "what happened this week" |
| 4 | Optional: hash-only VirusTotal, egress observer, browser companion | Opt-in, offline-safe, no file uploads by default |

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
7. **False-positive path** — dismiss a verdict with a reason, assert the hash is
   allowlisted and a re-scan does not re-alert.
8. **Persistence injection** — add a systemd user unit, assert a T1 persistence
   event within one guard interval.
9. **Restart resilience** — kill all services mid-scan, restart, assert no
   duplicate quarantines and no lost events.
10. **Hardening** — `systemd-analyze security` below threshold for every unit.

---

## 14. Open questions

1. **Hash reputation backend.** VirusTotal is the obvious choice but sends hashes
   to a third party. Opt-in, hash-only (never upload files), or skip entirely and
   rely on local signals? Default posture in this design: skip, stub the seam.
2. **Blocklist providers.** Which lists to ship as defaults is a licensing and
   taste decision. Every source must record its license and fetch URL; none are
   vendored.
3. **Notifications.** Desktop notifications via `notify-send` are trivial, but a
   noisy security tool trains the user to dismiss it. Proposal: one digest per
   day plus immediate alerts only at T3.
4. **System-path scanning.** Report-only, or allow quarantine with an explicit
   per-action confirmation? Current design: report-only.
5. **Name.** `Epimetheus Blue` is a working title that pairs with the Red work.
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

Built and verified on 2026-11-02: 52 tests, `blue drill` passing end to end,
dashboard and resolver smoke-tested live.

| Component | State |
|---|---|
| `blue-core` (config, SQLite, verdict, quarantine) | implemented |
| `blue-scan` (YARA-X, clamd, watcher, queue) | implemented |
| `blue-dns` (suffix blocklist, UDP sinkhole/forwarder) | implemented |
| `blue-http` (API, dashboard, kill switch) | implemented |
| `blue-guard` (FIM, persistence audit) | not started |
| `blue-feeds` (dataset sync, rollback) | not started |
| systemd units, PKGBUILD | template unit only |

### Deviations from the design above

These are deliberate and cheap to reverse. Listed so the doc does not drift.

1. **Quarantine layout is `items/<id>/payload`, not `objects/<sha256>`.** Content
   addressing would force a decision about what to do with a second file that has
   the same hash — and every answer except "keep both" involves deleting one.
   The hash is still recorded on every record.
2. **Default state dir is `~/.local/share/blue`.** The design assumed a system
   user and `/var/lib/blue`. Running unprivileged was the safer first step; the
   `blue@.service` template documents the hardened system install.
3. **YARA-X is built with `default-features = false`.** The default feature set
   pulls in the full module ecosystem (including a WebAssembly runtime) for rules
   that only use plain strings. Re-enable module features when a dataset needs them.
4. **DNS upstreams are plaintext UDP in this build.** DoT is the documented next
   step; the config already carries upstream addresses, so no API change.
5. **`blue scan` has no `--json` yet.** It prints a table and a summary line; the
   API serves JSON for programmatic use.
6. **Oversized files are recorded as T0 with no hash and no row**, rather than
   hashing 512 MiB just to skip it. Visible in the per-file output.

### Verified behaviours worth keeping

- Suffix matching blocks `x.ads.example.com` and not `notads.example.com`.
- A ClamAV hit alone reaches T2; a single low-confidence YARA hit stays at T1.
- Kill switch on: verdict recorded, nothing moved.
- Restore refuses to overwrite a file that reappeared at the original path.
- Stopping `clamd` degrades the scanner instead of failing closed.

