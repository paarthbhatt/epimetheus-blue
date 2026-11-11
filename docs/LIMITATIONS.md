# Known limitations — experimental v0.6.0

Epimetheus Blue is personal tooling for one Arch Linux workstation, not a
Microsoft Defender replacement or an independently audited endpoint product.
No malware-detection parity, comprehensive coverage, or compromise-prevention
guarantee is claimed. Keep backups and other security controls.

## Detection and recovery

- inotify scanning reacts to file events; it does **not** block file opens or
  execution. A file can run before a verdict. Only configured, readable paths
  are covered; exclusions, timeouts, and the default 512 MiB file-size cap limit
  scanning. A skipped file is not a clean file.
- YARA-X uses the configured rules and selected engine modules, not every YARA
  capability. ClamAV is optional and separately maintained. An unavailable
  `clamd` means degraded, YARA-only coverage, not a successful full scan.
- T1 is a candidate, not an infection. T2 permits quarantine, but signatures
  and feeds can produce false positives and miss threats. Integrity and egress
  baselines describe observed state; a first baseline does not certify it clean.
- User-space observation cannot reliably defend against root/kernel compromise
  or an attacker who can alter the user's state. It is not a multi-user EDR,
  packet capture system, or process containment tool.
- Quarantine is local storage, not encryption or a sandbox. Other copies may
  remain. Restore refuses overwrite but can reintroduce dangerous executable
  content; restore only after review. Recovery depends on intact stored data.

## Optional network features

- **DNS is off after normal installation unless explicitly configured and
  started.** System resolver routing is a separate, confirmed setup operation;
  installing the app or firewall does not change it. A running local resolver
  does not force applications to use it. Browser DoH, VPN/private resolvers,
  direct IP connections, and other bypasses may evade domain blocking.
- Domain feeds are incomplete and may break legitimate names. DoT validates
  certificates and does not fall back to plaintext when selected; UDP upstreams
  remain plaintext. Port 53 permissions, resolver conflicts, and blocked DoT
  ports can prevent operation. Private-network upstreams need explicit review.
- VirusTotal is optional, disabled by default, and **SHA-256 hash-only**; files
  are not uploaded. Explicit online checks require configuration and credentials;
  automatic scan queries require a separate opt-in. Hash queries still disclose
  a file identifier to a third party and are subject to its terms/rate limits.
  Unknown, unavailable, or cached reputation is not a clean verdict.
- The egress observer is best-effort procfs observation of visible connected
  sockets, not continuous traffic inspection or an outbound application firewall.

## Optional firewall

The separately installed, root-owned helper changes only
`table inet epimetheus_blue`. Public/Private profiles filter stateful IPv4/IPv6
**host incoming** traffic; Private adds bounded discovery, not blanket LAN trust.
Installation alone does not apply a policy. Apply is staged with a **60-second
rollback timer armed before mutation**; failure to arm it prevents application.
Explicit confirmation is required to keep the new policy. Closing the GUI or
authorizing Apply is not confirmation; only confirmed policy may persist.

Forwarded traffic, Docker/container published ports using forwarding, and output
paths are **not filtered by Blue**. Foreign firewall/VPN/container tables remain
unchanged and can independently affect connectivity. Rollback or runtime errors
are possible: keep a local recovery path and check reported errors rather than
assuming a timer guarantees access. See [FIREWALL.md](FIREWALL.md).

## Caches and status

- VirusTotal results have a configurable TTL (default 168 hours). The browser
  native host caches its domain list, including a load error, for that host
  process's lifetime; feed changes may require a new host process.
- Browser `connected` status means the bridge can read local state, not that
  scanners, DNS, or firewall enforcement are healthy. Counts and findings are
  stored observations. Firewall status is a helper-published snapshot, **not a
  live nftables probe**, and may be stale after changes by other tools.
- Feed structural checks and recorded hashes do not establish source correctness
  or independent review. Check update failures, timestamps, disabled/degraded
  services, and pending/error states. `blue verify` is a local self-check, not a
  certificate that the machine is protected or uncompromised.

## Manual cleanup can lose data

Analysis selects and deletes nothing. Applying explicitly selected items is
destructive, not quarantine: typed confirmation and path checks are safeguards,
not backups or an undo guarantee. Even a “Safe” cache can have recovery costs;
review-required artifacts, trash, and browser/app caches may contain useful data
or session state. Owner-tool cleanup, snapshot pruning, and container image
pruning can remove recovery options. Protected paths are not permission to
delete them manually. Review exact targets, back up important data, and never
test cleanup against production data.

## Package and runtime boundaries

The target is a single-user Arch Linux session. Other distributions,
architectures, multi-user setups, and server deployments are not a validated
compatibility matrix. The native GUI needs Wayland/X11, usable OpenGL, and the
matching system libraries/drivers. Background units require a systemd user
session and are installed but not enabled automatically. Firewall activation
also requires nftables, systemd, Polkit, and an authentication agent.

ClamAV signatures are not bundled or updated by Blue; `freshclam` remains separate.
The optional bounded `pacman -Qkk` audit can be slow, time out, or be unavailable;
it reports drift, not malware proof or automatic package repair. The workspace and
locked dependency graph require Rust 1.95 or newer; use the toolchain recorded for
the exact revision. Browser support is the Chromium/Brave MV3 companion, not every
browser or page layout.

Do not assume an experimental archive/local install provides distro support,
automatic upgrades, reproducible builds, or signed artifacts. Disable separately
configured system DNS before replacing its capability-bearing binary, following
the setup script's rollback procedure. Performance budgets in design docs and
synthetic functional tests are not hardware-wide performance or security promises.
