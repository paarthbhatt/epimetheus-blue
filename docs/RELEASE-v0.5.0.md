# v0.5.0 — experimental release

**Experimental prerelease for current Arch Linux x86_64.** This is not
Microsoft Defender-equivalent or independently audited security software.
Use a non-critical test machine first.

## Highlights

- Optional Public/Private stateful IPv4/IPv6 host-incoming firewall, explicit
  port/CIDR exceptions, and native GUI/CLI planning and controls.
- A separately installed root-owned, fixed-verb helper validates bounded policy
  input and changes only `table inet epimetheus_blue`. Apply arms a 60-second
  rollback timer before mutation; unconfirmed changes restore the previous owned
  table or remove it if previously absent. Only confirmed policy may persist.
- The native Wayland/X11 control center brings together YARA-X/optional ClamAV
  scanning, T2-gated quarantine and restore, startup integrity checks, feed
  activation/rollback, and read-only egress observation.
- Configurable domain blocking and certificate-validated DoT, local SHA-256
  reputation plus optional hash-only VirusTotal, and a read-only Chromium/Brave
  search companion remain available.
- Risk-classified cleanup inventory, explicit item selection/typed confirmation,
  and read-only performance diagnostics. Cleanup is manual and can lose data;
  it is not an automatic optimization or reversible quarantine action.

## Defaults and boundaries

Normal installation neither activates the firewall nor enables background
services. DNS stays off unless explicitly configured and started; system DNS
routing requires separate confirmation. VirusTotal and automatic online scan
queries are off by default; no file upload is implemented. ClamAV is optional
and missing coverage is degraded rather than a full-protection claim.

The firewall does not filter output or forwarding, including container published
ports using forwarded paths, and does not replace foreign rules. Status and
caches are local snapshots, not independent live protection checks. Runtime,
package, detector, privacy, and cleanup limits are documented in
[LIMITATIONS.md](LIMITATIONS.md); review [FIREWALL.md](FIREWALL.md) before activation.

## Tests and validation record

Repository tests cover policy rendering/input validation, the fixed client
boundary, helper state/ownership checks, staged confirmation, simulated rollback
and command failures, and preservation of foreign tables. The optional netns
harness exercises real nftables against synthetic traffic only in an isolated,
unprivileged user/network namespace. Neither simulated tests nor that harness
establish safety on every host, detection parity, or an independent audit.

Validation on Arch Linux with Rust 1.99.1 (minimum locked dependency MSRV 1.95):

| Validation | Tagged-commit result |
|---|---|
| Rust workspace build, fmt, tests, clippy | PASS — 185 tests |
| Invariant script and browser validator | PASS |
| Shell/Polkit XML/offline systemd packaging checks | PASS |
| Rootless firewall netns harness | PASS — isolated synthetic traffic only |

No privileged host installation, activation, nftables mutation, or resolver
change is required for these checks. Performance targets are not benchmark results.

## Downloads and provenance

| Item | Value |
|---|---|
| Tag / exact source commit | `v0.5.0`; see release `BUILD_INFO.txt` |
| Source archive | `epimetheus-blue-0.5.0-source.tar.gz` |
| Native archive | `epimetheus-blue-0.5.0-linux-x86_64.tar.gz` |
| Arch binary package | `epimetheus-blue-0.5.0-1-x86_64.pkg.tar.zst` — unsigned |
| Arch build recipe | `PKGBUILD`, `.SRCINFO`, and source package |
| Browser companion | `epimetheus-blue-search-guard-0.4.0.zip` |
| Checksums | `SHA256SUMS` — unsigned |
| Build/validation record | `BUILD_INFO.txt` |

Checksums help detect mismatches; they are not signatures, an audit, or proof of
reproducible builds. Report vulnerabilities [privately](../SECURITY.md).
