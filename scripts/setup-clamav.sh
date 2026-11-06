#!/usr/bin/env bash
# Install and connect Arch Linux's packaged ClamAV without rewriting any
# distribution-owned ClamAV configuration.
set -Eeuo pipefail

export LC_ALL=C
umask 077

default_socket='/run/clamav/clamd.ctl'
clamav_partial="${HOME:-}/.config/blue/conf.d/60-clamav.toml"
blue_path=''
temporary_config=''

declare -a CLAMAV_UNITS=()
declare -a FRESHCLAM_UNITS=()
declare -a FRESHCLAM_ONCE_UNITS=()
declare -a DAEMON_UNITS=()
declare -a OTHER_CLAMAV_UNITS=()
declare -a CLAMD_SOCKETS=()
declare -a STOPPED_FRESHCLAM_UNITS=()

die() {
  printf 'setup-clamav: %s\n' "$*" >&2
  return 1
}

usage() {
  cat <<'EOF'
Usage:
  setup-clamav.sh status
  setup-clamav.sh plan
  setup-clamav.sh install --confirm-package-install

install uses Arch's clamav package, discovers the service names actually
installed by that package, and enables only discovered freshclam/clamd daemon
units. It never edits /etc/clamav or /etc/clamd configuration files.
EOF
}

finish_on_exit() {
  local status=$?
  local unit
  trap - EXIT
  set +e
  for unit in "${STOPPED_FRESHCLAM_UNITS[@]}"; do
    sudo systemctl start "$unit" >/dev/null 2>&1 \
      || printf 'setup-clamav: WARNING: could not restart %s after failure\n' "$unit" >&2
  done
  if [[ -n "$temporary_config" && (-e "$temporary_config" || -L "$temporary_config") ]]; then
    rm -f -- "$temporary_config"
  fi
  exit "$status"
}
trap finish_on_exit EXIT

require_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 \
      || die "required command not found: $command_name"
  done
}

os_release_value() {
  local wanted="$1"
  local key value
  [[ -r /etc/os-release ]] || return 1
  while IFS='=' read -r key value; do
    [[ "$key" == "$wanted" ]] || continue
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    printf '%s' "$value"
    return 0
  done < /etc/os-release
  return 1
}

check_arch_platform() {
  local os_id os_like
  os_id="$(os_release_value ID 2>/dev/null || true)"
  os_like="$(os_release_value ID_LIKE 2>/dev/null || true)"
  [[ "$os_id" == 'arch' || " $os_like " == *' arch '* ]] \
    || die "this installer supports Arch/pacman only (detected ID=${os_id:-unknown})"
  command -v pacman >/dev/null 2>&1 || die 'pacman is required on this Arch system'
}

locate_blue() {
  if [[ -x "$HOME/.local/bin/blue" && ! -L "$HOME/.local/bin/blue" ]]; then
    blue_path="$HOME/.local/bin/blue"
  elif command -v blue >/dev/null 2>&1; then
    blue_path="$(command -v blue)"
  else
    return 1
  fi
  [[ "$blue_path" == /* && -x "$blue_path" ]]
}

discover_clamav_units() {
  local output unit
  local -A seen=()
  CLAMAV_UNITS=()
  FRESHCLAM_UNITS=()
  FRESHCLAM_ONCE_UNITS=()
  DAEMON_UNITS=()
  OTHER_CLAMAV_UNITS=()

  output="$(systemctl list-unit-files --type=service --no-legend --no-pager 'clamav*.service' 2>/dev/null || true)"
  while read -r unit _; do
    [[ -n "$unit" ]] || continue
    [[ "$unit" =~ ^clamav[[:alnum:]_.@-]*\.service$ ]] || continue
    [[ -z "${seen[$unit]+present}" ]] || continue
    seen[$unit]=1
    CLAMAV_UNITS+=("$unit")
    case "$unit" in
      *freshclam*once*) FRESHCLAM_ONCE_UNITS+=("$unit") ;;
      *freshclam*) FRESHCLAM_UNITS+=("$unit") ;;
      *daemon*|*clamd*) DAEMON_UNITS+=("$unit") ;;
      *) OTHER_CLAMAV_UNITS+=("$unit") ;;
    esac
  done <<< "$output"
}

print_discovered_units() {
  local unit
  if ((${#CLAMAV_UNITS[@]} == 0)); then
    printf '  (no clamav*.service units discovered)\n'
    return
  fi
  for unit in "${FRESHCLAM_UNITS[@]}"; do
    printf '  %s (freshclam updater)\n' "$unit"
  done
  for unit in "${DAEMON_UNITS[@]}"; do
    printf '  %s (clamd daemon)\n' "$unit"
  done
  for unit in "${OTHER_CLAMAV_UNITS[@]}"; do
    printf '  %s (not auto-enabled)\n' "$unit"
  done
  for unit in "${FRESHCLAM_ONCE_UNITS[@]}"; do
    printf '  %s (one-shot; disabled when using the background updater)\n' "$unit"
  done
}

definitions_present() {
  local main_present=0 daily_present=0 path
  for path in /var/lib/clamav/main.cvd /var/lib/clamav/main.cld; do
    [[ -s "$path" ]] && main_present=1
  done
  for path in /var/lib/clamav/daily.cvd /var/lib/clamav/daily.cld; do
    [[ -s "$path" ]] && daily_present=1
  done
  ((main_present == 1 && daily_present == 1))
}

discover_clamd_sockets() {
  local candidate
  local -A seen=()
  local -a known=(
    '/run/clamav/clamd.ctl'
    '/run/clamav/clamd.sock'
    '/run/clamd/clamd.sock'
    '/run/clamd.scan/clamd.sock'
  )
  CLAMD_SOCKETS=()

  for candidate in "${known[@]}"; do
    if [[ -S "$candidate" && -z "${seen[$candidate]+present}" ]]; then
      seen[$candidate]=1
      CLAMD_SOCKETS+=("$candidate")
    fi
  done
  if [[ -d /run ]]; then
    while IFS= read -r -d '' candidate; do
      [[ -z "${seen[$candidate]+present}" ]] || continue
      seen[$candidate]=1
      CLAMD_SOCKETS+=("$candidate")
    done < <(
      find /run -xdev -maxdepth 4 -type s \
        \( -name 'clamd*.sock' -o -name 'clamd*.ctl' \) \
        -print0 2>/dev/null
    )
  fi
}

select_clamd_socket() {
  local candidate
  for candidate in "${CLAMD_SOCKETS[@]}"; do
    if [[ "$candidate" == "$default_socket" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  if ((${#CLAMD_SOCKETS[@]} == 1)); then
    printf '%s' "${CLAMD_SOCKETS[0]}"
    return 0
  fi
  if ((${#CLAMD_SOCKETS[@]} == 0)); then
    return 1
  fi
  printf 'setup-clamav: multiple non-default clamd sockets found; refusing to guess:\n' >&2
  printf '  %s\n' "${CLAMD_SOCKETS[@]}" >&2
  return 1
}

wait_for_clamd_socket() {
  local attempt=0 selected
  while ((attempt < 40)); do
    discover_clamd_sockets
    if selected="$(select_clamd_socket)"; then
      printf '%s' "$selected"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.25
  done
  return 1
}

unique_sibling_path() {
  local base="$1"
  local candidate="$base.$(date +%Y%m%dT%H%M%S)-$$"
  local counter=0
  while [[ -e "$candidate" || -L "$candidate" ]]; do
    counter=$((counter + 1))
    candidate="$base.$(date +%Y%m%dT%H%M%S)-$$-$counter"
  done
  printf '%s' "$candidate"
}

write_clamav_partial() {
  local socket_path="$1"
  local escaped backup
  if printf '%s' "$socket_path" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die 'discovered clamd socket path contains a control character'
  fi
  if [[ -L "$clamav_partial" || -d "$clamav_partial" ]]; then
    die "refusing to replace non-regular config partial: $clamav_partial"
  elif [[ -e "$clamav_partial" && ! -f "$clamav_partial" ]]; then
    die "refusing to replace unsupported config partial file type: $clamav_partial"
  fi

  escaped="${socket_path//\\/\\\\}"
  escaped="${escaped//\"/\\\"}"
  install -d -m 0700 "$(dirname "$clamav_partial")"
  temporary_config="$(mktemp "$(dirname "$clamav_partial")/.clamav.toml.XXXXXXXX")"
  {
    printf '# Generated by setup-clamav.sh; /etc ClamAV config is package-owned.\n'
    printf '[scan.clamav]\n'
    printf 'socket = "%s"\n' "$escaped"
  } > "$temporary_config"
  chmod 0600 "$temporary_config"

  if [[ -f "$clamav_partial" ]] && cmp -s -- "$temporary_config" "$clamav_partial"; then
    rm -f -- "$temporary_config"
    temporary_config=''
    printf 'Blue ClamAV partial already matches %s.\n' "$socket_path"
    return
  fi
  if [[ -f "$clamav_partial" ]]; then
    backup="$(unique_sibling_path "$clamav_partial.previous")"
    cp -p -- "$clamav_partial" "$backup"
    printf 'Preserved previous Blue ClamAV partial at %s\n' "$backup"
  fi
  mv -f -- "$temporary_config" "$clamav_partial"
  temporary_config=''
  printf 'Wrote %s for socket %s\n' "$clamav_partial" "$socket_path"
}

print_plan() {
  local package_state database_state socket_path
  check_arch_platform
  require_commands systemctl
  discover_clamav_units
  if pacman -Q clamav >/dev/null 2>&1; then package_state='installed'; else package_state='not installed'; fi
  if definitions_present; then database_state='present'; else database_state='missing/incomplete'; fi
  discover_clamd_sockets

  printf 'Platform: Arch/pacman\n'
  printf 'Package: clamav (%s)\n' "$package_state"
  printf 'Signature database: %s\n' "$database_state"
  printf 'Discovered clamav*.service units:\n'
  print_discovered_units
  printf 'Discovered clamd sockets:\n'
  if ((${#CLAMD_SOCKETS[@]})); then
    printf '  %s\n' "${CLAMD_SOCKETS[@]}"
  else
    printf '  (none)\n'
  fi
  if socket_path="$(select_clamd_socket 2>/dev/null)"; then
    if [[ "$socket_path" == "$default_socket" ]]; then
      printf 'Blue config partial: unnecessary (default socket %s)\n' "$default_socket"
    else
      printf 'Blue config partial: %s -> %s\n' "$clamav_partial" "$socket_path"
    fi
  else
    printf 'Blue config partial: decided after clamd starts and its socket is discovered\n'
  fi
  cat <<'EOF'

Confirmed install will run:
  sudo pacman -S --needed clamav
It will run freshclam only when the main/daily database is missing, enable and
start only discovered freshclam/daemon units, then run `blue verify` and
`blue drill`. No /etc ClamAV configuration file will be edited by this script.
EOF
}

print_status() {
  local os_id package_state database_state unit active enabled socket_path
  os_id="$(os_release_value ID 2>/dev/null || true)"
  printf 'ClamAV setup status\n'
  printf '  OS ID: %s\n' "${os_id:-unknown}"
  if command -v pacman >/dev/null 2>&1 && pacman -Q clamav >/dev/null 2>&1; then
    package_state='installed'
  else
    package_state='not installed'
  fi
  printf '  package: %s\n' "$package_state"
  if definitions_present; then database_state='present'; else database_state='missing/incomplete'; fi
  printf '  signature database: %s\n' "$database_state"

  if command -v systemctl >/dev/null 2>&1; then
    discover_clamav_units
    printf '  units:\n'
    if ((${#CLAMAV_UNITS[@]} == 0)); then
      printf '    (none)\n'
    fi
    for unit in "${CLAMAV_UNITS[@]}"; do
      if systemctl is-active --quiet "$unit"; then active='active'; else active='inactive'; fi
      enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
      printf '    %s: %s, %s\n' "$unit" "$active" "${enabled:-unknown}"
    done
  else
    printf '  units: systemctl unavailable\n'
  fi

  discover_clamd_sockets
  printf '  clamd sockets:\n'
  if ((${#CLAMD_SOCKETS[@]})); then
    printf '    %s\n' "${CLAMD_SOCKETS[@]}"
  else
    printf '    (none)\n'
  fi
  if socket_path="$(select_clamd_socket 2>/dev/null)"; then
    printf '  selected socket: %s\n' "$socket_path"
  fi
  if [[ -f "$clamav_partial" && ! -L "$clamav_partial" ]]; then
    printf '  Blue partial: %s\n' "$clamav_partial"
  elif [[ -e "$clamav_partial" || -L "$clamav_partial" ]]; then
    printf '  Blue partial: unsafe non-regular path (%s)\n' "$clamav_partial"
  else
    printf '  Blue partial: none\n'
  fi
}

install_clamav() {
  local unit socket_path
  check_arch_platform
  require_commands sudo systemctl
  locate_blue || die 'install Blue first; ~/.local/bin/blue is required for verification'

  printf 'Package to install: clamav\n'
  discover_clamav_units
  printf 'Currently discovered clamav*.service units:\n'
  print_discovered_units
  printf 'Running: sudo pacman -S --needed clamav\n'
  sudo pacman -S --needed clamav

  discover_clamav_units
  printf 'Units installed by the package:\n'
  print_discovered_units
  ((${#DAEMON_UNITS[@]} > 0)) \
    || die 'no clamav daemon service was discovered; no service was auto-enabled'

  # Two freshclam processes race for the same log/database lock at boot.
  if ((${#FRESHCLAM_UNITS[@]} > 0)); then
    for unit in "${FRESHCLAM_ONCE_UNITS[@]}"; do
      printf 'Disabling conflicting one-shot updater: %s\n' "$unit"
      sudo systemctl disable --now "$unit"
    done
  fi

  if ! definitions_present; then
    require_commands freshclam
    # A pre-existing updater daemon holds freshclam's lock. Stop only a
    # discovered updater temporarily; every such unit is enabled/started below.
    for unit in "${FRESHCLAM_UNITS[@]}"; do
      if systemctl is-active --quiet "$unit"; then
        printf 'Temporarily stopping %s for the initial signature download.\n' "$unit"
        sudo systemctl stop "$unit"
        STOPPED_FRESHCLAM_UNITS+=("$unit")
      fi
    done
    printf 'Signature database is missing/incomplete; running sudo freshclam.\n'
    sudo freshclam
    definitions_present || die 'freshclam completed but main/daily definitions are still missing'
  else
    printf 'Signature database already present; freshclam command not needed.\n'
  fi

  for unit in "${FRESHCLAM_UNITS[@]}"; do
    printf 'Enabling discovered updater unit: %s\n' "$unit"
    sudo systemctl enable --now "$unit"
  done
  STOPPED_FRESHCLAM_UNITS=()
  for unit in "${DAEMON_UNITS[@]}"; do
    printf 'Enabling discovered daemon unit: %s\n' "$unit"
    sudo systemctl enable --now "$unit"
  done

  socket_path="$(wait_for_clamd_socket)" \
    || die 'clamd started without a discoverable socket under /run'
  printf 'Discovered clamd socket: %s\n' "$socket_path"
  if [[ "$socket_path" != "$default_socket" ]]; then
    write_clamav_partial "$socket_path"
  else
    printf 'Socket matches Blue default; no user config partial was written.\n'
  fi

  printf 'Running Blue verification: %s verify\n' "$blue_path"
  "$blue_path" verify
  printf 'Running Blue end-to-end drill: %s drill\n' "$blue_path"
  "$blue_path" drill
}

[[ -n "${HOME:-}" && "$HOME" == /* ]] || die 'HOME must be an absolute path'
((EUID != 0)) || die 'run this script as the desktop user, never as root'

action="${1:-}"
[[ -n "$action" ]] || { usage >&2; exit 2; }
shift

confirm_package_install=0
while (($#)); do
  case "$1" in
    --confirm-package-install) confirm_package_install=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

case "$action" in
  status)
    ((confirm_package_install == 0)) || die 'status accepts no options'
    print_status
    ;;
  plan)
    ((confirm_package_install == 0)) || die 'plan accepts no options'
    print_plan
    ;;
  install)
    ((confirm_package_install == 1)) \
      || die 'install requires --confirm-package-install (run plan first)'
    install_clamav
    ;;
  -h|--help|help)
    ((confirm_package_install == 0)) || die 'help accepts no options'
    usage
    ;;
  *)
    usage >&2
    die "unknown command: $action"
    ;;
esac
