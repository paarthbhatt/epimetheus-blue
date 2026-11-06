# Installing Epimetheus Blue 0.5.0

Choose **one** method: a prebuilt user-local archive, a source-built Arch package
managed by pacman, or a user-local source build. None silently enables protection
services or changes firewall/DNS settings.
Never run Cargo, makepkg, or the user-local installer as root.

## Verify the release before building

Release packaging is not complete until tag `v0.5.0` is frozen, its exact release
source asset is hashed, and the checksum in `packaging/PKGBUILD` and
`packaging/.SRCINFO` is finalized. An all-zero SHA-256 is a deliberately failing
placeholder, **not** a valid release checksum. Do not use `--skipinteg`, replace
it with `SKIP`, or disable tests to get past a release blocker.

Use the finalized Arch source package, `epimetheus-blue-0.5.0-1.src.tar.gz`,
and the release's `SHA256SUMS`. The checksum manifest
cover that source package and the exact `epimetheus-blue-0.5.0-source.tar.gz` asset
downloaded from:

```text
https://github.com/paarthbhatt/epimetheus-blue/releases/download/v0.5.0/epimetheus-blue-0.5.0-source.tar.gz
```

With the release artifacts and checksum files in the same directory:

```bash
sha256sum --ignore-missing --check SHA256SUMS
```

The v0.5.0 checksum manifest is **unsigned**. Checksums detect corruption and
substitution against that manifest, not independent author authentication.
Stop on a mismatch. Security-sensitive testers should review and build source;
neither these checksums nor a GitHub download constitute an independent audit.

A SHA-256 in a PKGBUILD checks source integrity, not author identity. Review the
recipe before building. There is no signed pacman repository or AUR listing yet.

## Prebuilt user-local archive

For current Arch Linux x86_64, download the Linux archive and `SHA256SUMS`, verify
the checksum, then run:

```bash
tar -xzf epimetheus-blue-0.5.0-linux-x86_64.tar.gz
cd epimetheus-blue-0.5.0
./scripts/install-release.sh
~/.local/bin/blue
```

No Rust compiler or sudo is needed. The archive contains tested executables, the
extension, user units and optional setup scripts. It enables no services and
makes no firewall/DNS changes. See uninstall instructions below before starting.

### Maintainer: freeze source before publishing

The release source asset is a deterministic archive of the release tree, with an
`epimetheus-blue-0.5.0/` prefix. It excludes `packaging/PKGBUILD` and
`packaging/.SRCINFO` so the source checksum cannot reference itself. Keep that
asset immutable once published.

Hash the exact asset fetched from the URL above, replace the placeholder in
the packaging recipe, then regenerate metadata and create the Arch source
package from `packaging/`:

```bash
makepkg --printsrcinfo > .SRCINFO
makepkg --verifysource
makepkg --allsource
```

`--allsource` includes the verified source asset for a self-contained source
package; it does not vendor Rust crates, so Cargo still needs network access or
a populated dependency cache during `prepare()`. Publish the checksum manifest
and clearly state whether signatures are provided. Future signing keys and all
credentials must remain outside the source tree and package.

Publish the finalized recipe as the separate Arch source package after freezing
the release source asset; do not move the tag or replace the asset merely to
insert a checksum. Creating a source package does not publish a release or
submit anything to the AUR.

## Option A: source-built Arch package

Use an up-to-date Arch Linux **x86_64** environment with `base-devel`, a Rust
toolchain providing Cargo/Rust **1.95 or newer**, and `pkgconf`. The workspace
MSRV and locked Cranelift/Wasmtime dependencies require Rust 1.95. Test
dependencies are `nodejs` and `desktop-file-utils`. Use a clean build environment
when preparing a release.

Extract the verified Arch source package into a fresh directory and review its
recipe:

```bash
tar -xf epimetheus-blue-0.5.0-1.src.tar.gz
cd epimetheus-blue
less PKGBUILD
makepkg --verifysource
makepkg -si
```

`makepkg -si` builds from source, runs `check()`, then installs the resulting
package. Its `-s` and `-i` steps may invoke sudo/pacman to install missing build
dependencies and the package; compilation itself remains unprivileged. To
build without installing anything, supply the dependencies separately and use
`makepkg` without `-s` or `-i`.

The recipe fetches Cargo dependencies with `--locked`, then builds and tests
the **whole workspace** with `--locked --offline`. It also checks shell syntax,
the browser extension's stable ID and assets, and the desktop entry. Cargo's
crate downloads are pinned by `Cargo.lock`; the upstream archive is pinned by
the finalized PKGBUILD checksum. No locally built binaries are used as sources.

### Package layout and guarantees

| Installed path | Purpose |
|---|---|
| `/usr/bin/blue` | Native app and CLI, `root:root`, mode `0755` |
| `/usr/bin/blue-native-host` → `blue` | Filename-selected, read-only browser host |
| `/usr/lib/epimetheus-blue/blue-firewall-helper` | Regular root-owned helper, mode `0755`; never a link into a user checkout |
| `/usr/share/epimetheus-blue/browser-extension/` | Unpacked browser companion |
| `/usr/share/epimetheus-blue/scripts/` | Optional, explicitly invoked setup/cleanup scripts |
| `/usr/lib/systemd/user/blue-*.service`, `blue-*.timer` | User units; service `ExecStart` uses `/usr/bin/blue` |
| `/usr/lib/systemd/system/blue-firewall.service` | Optional root firewall boot unit, not enabled by installation |
| `/usr/share/polkit-1/actions/com.epimetheus.blue.firewall.policy` | Administrator authorization for the exact installed helper path |
| `/usr/share/applications/epimetheus-blue.desktop` | Desktop launcher using `/usr/bin/blue` |
| `/etc/{chromium,brave}/native-messaging-hosts/com.epimetheus.blue.json` | Root-owned browser-host registration, restricted to the stable extension ID |
| `/usr/share/doc/epimetheus-blue/` | Installed documentation |

The build sets `BLUE_EXTENSION_DIR` to
`/usr/share/epimetheus-blue/browser-extension`, so the app never depends on the
builder's source checkout to locate these assets. The host manifest must point
to **`/usr/bin/blue-native-host`**, not plain `blue`: the binary recognizes the
alias from its filename before the browser's origin arguments reach the CLI.

There is no package install/remove script or enablement preset. Installation
does not start/enable a service, grant setuid/file capabilities, apply firewall
rules, create a default firewall policy, edit browser profiles, or change
NetworkManager, `/etc/resolv.conf`, or DNS. Distribution hooks may refresh
desktop/systemd definitions; existing service enablement is not reset. An
already-running or enabled service remains an administrator/user responsibility.

Launch the app from the desktop launcher or run `/usr/bin/blue` as your normal
desktop user. It creates its private state on first use, not during packaging.

## Option B: user-local installation

Extract the verified upstream source archive into a separate build directory.
Use the same Rust/native-library requirements as the Arch build above. From
its `epimetheus-blue-0.5.0/` root, as your desktop user:

```bash
cargo test --workspace --locked
./scripts/install-local.sh
```

The script builds with `cargo build --release --locked` and installs:

- `~/.local/bin/blue` and the `blue-native-host` → `blue` symlink;
- `${XDG_DATA_HOME:-$HOME/.local/share}/epimetheus-blue/` assets and an inert optional
  firewall installation bundle;
- a user desktop entry, Chromium/Brave native-host manifests, and user units
  under `${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/`.

It uses no sudo, enables no services, and does not alter system DNS or firewall
rules. It reloads user unit definitions and optionally refreshes the desktop
database. Add `~/.local/bin` to your PATH if needed. The previous browser
extension directory is retained as `browser-extension.previous` for manual
rollback. The root firewall helper is **not** installed by this method; follow
[`FIREWALL.md`](FIREWALL.md) only if you want that optional module.

### Switching methods

Do not keep overlapping installations active. User-local binaries can shadow
`/usr/bin/blue`, and user unit/desktop files and native-host manifests take
precedence over package files. Check `type -a blue` and
`systemctl --user cat blue-watch.service` to see what will actually run.

Before switching, restore any system-DNS transaction using the **old**
installation's `setup-system-dns.sh disable` command. Stop/disable the user
services you opted into, then move only the old install artifacts to a backup
outside their active search paths. Keep Blue's configuration, database, feeds,
quarantine, and DNS recovery backups. Do not rerun `install-firewall.sh` over
pacman-managed helper/policy files; a prior
`/etc/systemd/system/blue-firewall.service` also overrides the package unit and
must be reviewed separately.

## Optional modules — explicit opt-in only

- **Background protection:** run Blue once to initialize user state, then opt
  in through the app's Settings or:

  ```bash
  systemctl --user daemon-reload
  systemctl --user enable --now \
    blue-watch.service blue-guard.timer blue-feeds.timer \
    blue-net.timer blue-reputation.timer
  ```

  Feed/reputation timers use outbound networking. Online VirusTotal queries
  remain a separate opt-in; do not put API keys in the package or system units.
  User units currently assume `~/.local/share/blue`; custom state paths need
  matching user-owned sandbox overrides.

- **ClamAV:** optional `clamav` dependency and a reachable clamd Unix socket.
  Inspect `/usr/share/epimetheus-blue/scripts/setup-clamav.sh plan` for the Arch
  package, or the corresponding user-local script. Its separately confirmed
  install mode can install ClamAV and enable discovered ClamAV services; that
  action is not part of installing Blue. Without clamd, YARA-X remains available
  and Blue reports degraded coverage.

- **Browser companion:** manually load
  `/usr/share/epimetheus-blue/browser-extension/` through **Load unpacked** in
  `chromium://extensions` or `brave://extensions`. For the user-local method,
  use its installed extension directory instead. The stable ID is
  `alfkkfmnmngogkkaenefploocfbdooji`. A stale per-user native-host manifest can
  override the package registration and show “Desktop: Disconnected”.

- **Firewall:** the Arch package already installs the helper, policy and inert
  root unit. Optional runtime dependencies are `nftables`, `polkit`, a reachable
  systemd system manager, and a desktop Polkit authentication agent. Skip the
  separate file-copy installer when using the package. Follow
  [`FIREWALL.md`](FIREWALL.md) to review, apply, explicitly confirm, and separately
  opt into boot persistence. No rules become active merely because the helper
  is present.

- **DNS Shield:** the local resolver and user unit are included, but port 53
  capability and resolver routing are not configured. **Current integration
  limitation:** `setup-system-dns.sh` hard-codes `~/.local/bin/blue`, while the
  package unit runs `/usr/bin/blue`. Do not use its enable mode with the package,
  create a symlink to bypass its checks, or manually grant capabilities as an
  installation step. Package-aware, upgrade-safe DNS activation needs a
  separate fix. With a user-local installation, review its `plan` and use its
  confirmation-gated enable/disable transaction. Restore DNS **before**
  replacing/removing that binary; replacing it can discard its file capability
  and leave the system pointing at an unavailable resolver.

- **Cleanup:** analysis is read-only and deletion requires explicit selection
  and confirmation. The optional `cleanup-system.sh plan` is separate from
  installation; neither package installation nor removal runs cleanup.

## Uninstall, rollback, and retained data

Back up configuration and state before changing versions. Defaults are
`~/.config/blue/` and `~/.local/share/blue/` (including quarantine, database,
feeds, and system-DNS recovery backups); also retain any custom state path and
browser-profile extension settings. Global configuration under `/etc/blue/`
and confirmed firewall state under `/etc/epimetheus-blue/firewall/` are not
shipped as package defaults and are not purged by package hooks.

1. If you previously enabled system-wide DNS through the user-local setup,
   run that installation's `setup-system-dns.sh disable` **first**, and verify
   connectivity. Do not delete its active recovery backup. Package removal
   never performs this restoration for you.
2. Stop/disable only Blue user services/timers you enabled. Include
   `blue-dns.service` only after DNS is restored. Timers and running services
   are not silently stopped by a Blue removal hook.
3. Decide explicitly whether to keep live Blue firewall rules. If removing
   them, use the client's authorized **Disable** operation while the helper is
   still installed, verify status, and separately disable boot persistence.
   Stopping/disabling `blue-firewall.service` alone does **not** remove live
   rules. Do not remove the helper while a staged policy/rollback is pending.
4. For the Arch package, remove it with `sudo pacman -R epimetheus-blue` only
   after the decisions above. No Blue removal hook flushes nftables, resets DNS,
   deletes user data, or deletes saved firewall policy. Live rules can persist
   until explicitly disabled or the host reboots; removal also removes the
   helper needed to manage them. Review boot-enable symlinks yourself.
5. For user-local installs, move/remove only the known installer artifacts
   after inspecting them: binaries, native-host symlink/manifests, desktop
   entry, user units, and application assets. Do not recursively remove
   `~/.local/share/blue` or `~/.config/blue`; those are your data, not installer
   artifacts. A separately installed root firewall bundle needs its own
   administrator-reviewed removal and is not undone by deleting local assets.

Modified package native-host manifests are marked as pacman backup files; review
any `.pacsave`/`.pacnew` files rather than deleting them blindly. Remove the
unpacked extension through the browser UI if wanted; package removal does not
erase browser settings. Reload user unit definitions after manually removing
user-local units.

For an Arch rollback, keep the previous verified source package and locally
built `.pkg.tar.zst`; reinstall the previous local package with:

```bash
sudo pacman -U /path/to/previous-package.pkg.tar.zst
```

If retaining a user-local install, rebuild from the previous verified source
and use the retained extension assets
as appropriate. Stop affected optional modules first, preserve the backup, and
check configuration/database compatibility before opening older code. Binary
rollback is not a promise that an older release understands newer state; never
delete quarantine or reset a firewall to make a downgrade appear successful.
