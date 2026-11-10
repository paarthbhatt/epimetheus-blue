#!/usr/bin/env bash
# Install the native app and browser companion for the current user.
# No root access, resolver changes, service enablement, or browser-profile edits
# happen here.
set -euo pipefail

die() {
  printf 'install-local: %s\n' "$*" >&2
  return 1
}

root="$(cd "$(dirname "$0")/.." && pwd -P)"
[[ -n "${HOME:-}" && "$HOME" == /* ]] || die 'HOME must be an absolute path'
((EUID != 0)) || die 'run this installer as the desktop user, never as root'

prefix="${XDG_DATA_HOME:-$HOME/.local/share}"
bindir="$HOME/.local/bin"
appdir="$prefix/epimetheus-blue"
unitdir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
chromium_host_dir="$HOME/.config/chromium/NativeMessagingHosts"
brave_host_dir="$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
extension_id_file="$root/browser-extension/EXTENSION_ID"
native_host_path="$bindir/blue-native-host"
native_manifest='com.epimetheus.blue.json'
active_dns_backup="$HOME/.local/share/blue/system-dns-backup/active"

[[ -f "$extension_id_file" ]] \
  || die "missing stable browser extension ID: $extension_id_file"
extension_id="$(<"$extension_id_file")"
[[ "$extension_id" =~ ^[a-p]{32}$ ]] \
  || die 'browser-extension/EXTENSION_ID must contain one 32-character Chromium ID (a-p)'
[[ "$native_host_path" == /* ]] || die 'native messaging host path is not absolute'
if [[ -e "$active_dns_backup" || -L "$active_dns_backup" ]]; then
  die "system DNS routing is active; run scripts/setup-system-dns.sh disable before replacing the capability-bearing binary"
fi
if printf '%s' "$native_host_path" | LC_ALL=C grep -q '[[:cntrl:]]'; then
  die 'native messaging host path contains a control character'
fi

# JSON basic-string escaping for the one path interpolated below. The extension
# ID has already been constrained to Chromium's a-p alphabet.
native_host_json="${native_host_path//\\/\\\\}"
native_host_json="${native_host_json//\"/\\\"}"

write_native_manifest() {
  local destination_dir="$1"
  local destination="$destination_dir/$native_manifest"
  local temporary

  temporary="$(mktemp "$destination_dir/.${native_manifest}.XXXXXX")"
  cat > "$temporary" <<EOF
{
  "name": "com.epimetheus.blue",
  "description": "Epimetheus Blue native browser host",
  "path": "$native_host_json",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$extension_id/"
  ]
}
EOF
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$destination"
}

cd "$root"
case "${1:-}" in
  '') cargo build --release --locked ;;
  --from-binary)
    [[ $# == 1 ]] || die '--from-binary accepts no extra arguments'
    [[ -x target/release/blue && -x target/release/blue-firewall-helper ]] \
      || die 'release binaries missing; use the complete release archive'
    ;;
  *) die 'usage: install-local.sh [--from-binary]' ;;
esac

install -d \
  "$bindir" \
  "$appdir" \
  "$prefix/applications" \
  "$unitdir" \
  "$HOME/.local/share/blue" \
  "$chromium_host_dir" \
  "$brave_host_dir"
# Replace the executable atomically while the old watcher keeps running.
# Truncating a live executable can fail with ETXTBSY and interrupt installation.
binary_stage="$(mktemp "$bindir/.blue-install.XXXXXX")"
install -m 0755 target/release/blue "$binary_stage"
mv -f -- "$binary_stage" "$bindir/blue"
if [[ -L "$native_host_path" ]]; then
  [[ "$(readlink "$native_host_path")" == 'blue' ]] \
    || die "refusing to replace unrelated native host symlink: $native_host_path"
elif [[ -e "$native_host_path" ]]; then
  die "refusing to replace existing native host path: $native_host_path"
else
  ln -s -- blue "$native_host_path"
fi

# Replace the extension as a directory without mixing old and new releases.
# The last installed release remains available for manual rollback.
stage="$appdir/browser-extension.new.$$"
archive="$appdir/browser-extension.previous"
mkdir -p "$stage"
cp -a browser-extension/. "$stage/"
if [[ -d "$appdir/browser-extension" ]]; then
  if [[ -d "$archive" ]]; then
    mv "$archive" "$archive.$(date +%s)"
  fi
  mv "$appdir/browser-extension" "$archive"
fi
mv "$stage" "$appdir/browser-extension"
install -d "$appdir/scripts"
install -m 0755 scripts/setup-system-dns.sh "$appdir/scripts/setup-system-dns.sh"
install -m 0755 scripts/setup-clamav.sh "$appdir/scripts/setup-clamav.sh"
install -m 0755 scripts/cleanup-system.sh "$appdir/scripts/cleanup-system.sh"

# Optional privileged bundle: copied locally, never installed as root or enabled.
firewall_bundle="$appdir/firewall-install"
install -d "$firewall_bundle/target/release" "$firewall_bundle/packaging" "$firewall_bundle/scripts"
install -m 0755 target/release/blue-firewall-helper "$firewall_bundle/target/release/blue-firewall-helper"
install -m 0755 scripts/install-firewall.sh "$firewall_bundle/scripts/install-firewall.sh"
install -m 0644 packaging/blue-firewall.service "$firewall_bundle/packaging/blue-firewall.service"
install -m 0644 packaging/com.epimetheus.blue.firewall.policy "$firewall_bundle/packaging/com.epimetheus.blue.firewall.policy"

write_native_manifest "$chromium_host_dir"
write_native_manifest "$brave_host_dir"

sed "s|^Exec=blue$|Exec=$bindir/blue|" \
  packaging/epimetheus-blue.desktop \
  > "$prefix/applications/epimetheus-blue.desktop"
chmod 0644 "$prefix/applications/epimetheus-blue.desktop"
install -m 0644 packaging/blue-watch.service "$unitdir/blue-watch.service"
install -m 0644 packaging/blue-dns.service "$unitdir/blue-dns.service"
install -m 0644 packaging/blue-guard.service "$unitdir/blue-guard.service"
install -m 0644 packaging/blue-guard.timer "$unitdir/blue-guard.timer"
install -m 0644 packaging/blue-feeds.service "$unitdir/blue-feeds.service"
install -m 0644 packaging/blue-feeds.timer "$unitdir/blue-feeds.timer"
install -m 0644 packaging/blue-net.service "$unitdir/blue-net.service"
install -m 0644 packaging/blue-net.timer "$unitdir/blue-net.timer"
install -m 0644 packaging/blue-reputation.service "$unitdir/blue-reputation.service"
install -m 0644 packaging/blue-reputation.timer "$unitdir/blue-reputation.timer"

systemctl --user daemon-reload >/dev/null 2>&1 || true

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$prefix/applications" >/dev/null 2>&1 || true
fi

cat <<EOF
Epimetheus Blue installed.

Native app:
  $bindir/blue
  or launch “Epimetheus Blue” from your desktop launcher.

Browser extension:
  $appdir/browser-extension
  Load it unpacked from chrome://extensions or brave://extensions.

Native browser host:
  $native_host_path
  Registered for Chromium and Brave as com.epimetheus.blue.

Optional always-on protection (not enabled automatically):
  systemctl --user enable --now blue-watch.service blue-guard.timer blue-feeds.timer blue-net.timer blue-reputation.timer

DNS Shield note:
  blue-dns.service is installed but not started or enabled. Binding port 53 and
  changing NetworkManager are intentionally separate, confirmed operations:
  $root/scripts/setup-system-dns.sh plan

ClamAV setup plan:
  $appdir/scripts/setup-clamav.sh plan

System cleanup plan (read-only):
  $appdir/scripts/cleanup-system.sh plan

Optional firewall installer plan (no live rules applied):
  $appdir/firewall-install/scripts/install-firewall.sh plan
EOF
