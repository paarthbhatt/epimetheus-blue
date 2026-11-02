#!/usr/bin/env bash
# Install the native app and browser companion for the current user.
# No root access, resolver changes, or browser-profile edits happen here.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
prefix="${XDG_DATA_HOME:-$HOME/.local/share}"
bindir="$HOME/.local/bin"
appdir="$prefix/epimetheus-blue"
unitdir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

cd "$root"
cargo build --release --locked

install -d "$bindir" "$appdir" "$prefix/applications" "$unitdir" "$HOME/.local/share/blue"
install -m 0755 target/release/blue "$bindir/blue"

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

sed "s|^Exec=blue$|Exec=$bindir/blue|" \
  packaging/epimetheus-blue.desktop \
  > "$prefix/applications/epimetheus-blue.desktop"
chmod 0644 "$prefix/applications/epimetheus-blue.desktop"
install -m 0644 packaging/blue-watch.service "$unitdir/blue-watch.service"
install -m 0644 packaging/blue-guard.service "$unitdir/blue-guard.service"
install -m 0644 packaging/blue-guard.timer "$unitdir/blue-guard.timer"
install -m 0644 packaging/blue-feeds.service "$unitdir/blue-feeds.service"
install -m 0644 packaging/blue-feeds.timer "$unitdir/blue-feeds.timer"

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
  Load it unpacked from chromium://extensions or brave://extensions.

Optional always-on protection (not enabled automatically):
  systemctl --user enable --now blue-watch.service blue-guard.timer blue-feeds.timer

DNS Shield note:
  Binding port 53 and changing the machine resolver are intentionally NOT done
  by this installer. The app will explain if elevated setup is needed.
EOF
