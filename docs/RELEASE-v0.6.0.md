# v0.6.0 — experimental release

**Experimental prerelease for current Arch Linux x86_64.** This is not
Microsoft Defender-equivalent or independently audited security software.
Use a non-critical test machine first.

## Highlights

- Premium native instrument frame: beveled armor shield with depth-aware
  picking for functional Files/DNS/Integrity layer inspection, inset material
  theming, grouped navigation and brief interruptible transitions. All motion
  is finite, interruptible and has reduced-motion fallbacks.
- Conservative automatic triage for stored observations: every new finding is
  assessed on write with a persisted classification and reason, and grouped
  occurrences replace the raw "899 findings" backlog view. Routine HTTPS
  endpoint novelty may read as informational — never trusted, benign or
  acknowledged. Persistence and unusual observations stay needs-investigation.
  `blue review` assesses the existing backlog explicitly. Evidence, verdicts
  and acknowledgement timestamps are never modified.
- Realtime threat alerts now cover failed and emergency-paused containment, not
  only successful quarantine, with bounded dedup/aggregation. Detected threats
  retain their evidence even when a containment attempt fails or an event write
  fails.
- The sandboxed watcher can now write only its state directory plus the
  default watched folders (`Downloads`, `tmp`) so containment actually works;
  the rest of HOME stays read-only. Custom roots require a reviewed service
  drop-in. No sudo-all access is granted anywhere.
- Cleanup fixes: user-owned interior symlinks (for example `node_modules/.bin`
  links) no longer trigger a false ownership refusal, repeated permission
  diagnostics collapse into one partial-totals note, per-candidate failure
  receipts stay visible in the UI, and the installer replaces a running
  executable atomically.
- Resource discipline: watcher event/pending queues are bounded with
  backpressure, idle polling became deadline-based waits, long-lived reputation
  engines notice updated feed indexes at most once a minute, and the UI slows
  its repaint cadence when idle.
- Browser companion popup refresh: grouped "groups needing attention" counts,
  explicit read-only bridge wording, bundled IBM Plex fonts, and nine popup
  regression tests.

## Defaults and boundaries

Normal installation neither activates the firewall nor enables background
services. DNS stays off unless explicitly configured and started; system DNS
routing requires separate confirmation. VirusTotal and automatic online scan
queries are off by default; no file upload is implemented. ClamAV is optional
and missing coverage is degraded rather than a full-protection claim.

Automatic review never certifies a record as safe, never trusts an endpoint,
and never acknowledges evidence on your behalf. Cleanup remains fully manual:
explicit selection plus an exact typed confirmation, revalidated against a
fresh inventory before any deletion. The firewall keeps its staged apply,
60-second rollback and exact confirmation phrases.

The firewall does not filter output or forwarding, including container
published ports using forwarded paths, and does not replace foreign rules.
Status and caches are local snapshots, not independent live protection checks.
Runtime, package, detector, privacy, and cleanup limits are documented in
[LIMITATIONS.md](LIMITATIONS.md); review [FIREWALL.md](FIREWALL.md) before
activation. See [AUTONOMOUS-PROTECTION.md](AUTONOMOUS-PROTECTION.md) for the
scoped-helper and triage decisions.

## Tests and validation record

Repository tests cover the firewall policy/client boundary and staged
rollback, quarantine tier gating and containment-failure retention, triage
migration and grouping semantics, cleanup approval gates and interior-symlink
preflight, grouped UI presentation, and the extension's read-only bridge.
The optional netns harness exercises real nftables against synthetic traffic
only in an isolated, unprivileged user/network namespace. Neither simulated
tests nor that harness establish safety on every host, detection parity, or an
independent audit.

Validation on Arch Linux with Rust 1.99.1 (minimum locked dependency MSRV 1.95):

| Validation | Tagged-commit result |
|---|---|
| Rust workspace build, fmt, tests, clippy | PASS — see `BUILD_INFO.txt` for counts |
| Invariant script and browser validator/popup tests | PASS |
| Shell/desktop-entry/systemd packaging checks | PASS |
| Isolated installer tests (live atomic replacement) | PASS |
| makepkg build/check/package from the frozen source | PASS |
| Rootless firewall netns harness | Not rerun — veth module unavailable on the running kernel; firewall code unchanged since the v0.5.0 PASS |
| Harmless EICAR detect/quarantine/restore drill | PASS |

GitHub-hosted CI did not execute for this tag (account billing lock); no
passing GitHub CI result is claimed. Local results are recorded in
`BUILD_INFO.txt`.

No privileged host installation, activation, nftables mutation, or resolver
change is required for these checks. Performance targets are not benchmark
results.

## Downloads and provenance

Asset contents, verification and the publish procedure are documented in
[RELEASES.md](RELEASES.md).

| Item | Value |
|---|---|
| Tag / exact source commit | `v0.6.0`; see release `BUILD_INFO.txt` |
| Source archive | `epimetheus-blue-0.6.0-source.tar.gz` |
| Native archive | `epimetheus-blue-0.6.0-linux-x86_64.tar.gz` |
| Arch binary package | `epimetheus-blue-0.6.0-1-x86_64.pkg.tar.zst` — unsigned |
| Arch build recipe | `PKGBUILD`, `.SRCINFO`, and source package |
| Browser companion | `epimetheus-blue-search-guard-0.5.0.zip` |
| Checksums | `SHA256SUMS` — unsigned |
| Build/validation record | `BUILD_INFO.txt` |

Checksums help detect mismatches; they are not signatures, an audit, or proof
of reproducible builds. Report vulnerabilities [privately](../SECURITY.md).
