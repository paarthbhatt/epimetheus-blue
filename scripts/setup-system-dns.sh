#!/usr/bin/env bash
# Safely route one NetworkManager connection through the unprivileged Blue DNS
# user service. Privileged and network-changing work is confirmation-gated.
set -Eeuo pipefail

export LC_ALL=C
umask 077

service_name='blue-dns.service'
blue_path="${HOME:-}/.local/bin/blue"
dns_config="${HOME:-}/.config/blue/dns.toml"
dns_dropin="${HOME:-}/.config/blue/conf.d/90-system-dns.toml"
backup_root="${HOME:-}/.local/share/blue/system-dns-backup"
active_backup="$backup_root/active"

rollback_armed=0
backup_ready=0
backup_dir=''
pending_backup=''
temporary_config=''
temporary_dropin=''
config_installed=0
capability_added=0
nm_change_attempted=0

ACTIVE_UUID=''
ACTIVE_NAME=''
ACTIVE_DEVICE=''
CAP_SPEC=''
declare -a ACTIVE_UUIDS=()
declare -a ACTIVE_NAMES=()
declare -a ACTIVE_DEVICES=()
declare -a DNS_UPSTREAMS=()

die() {
  printf 'setup-system-dns: %s\n' "$*" >&2
  return 1
}

usage() {
  cat <<'EOF'
Usage:
  setup-system-dns.sh status
  setup-system-dns.sh plan
  setup-system-dns.sh enable --confirm-network-change
  setup-system-dns.sh disable [--remove-capability]

enable enables and starts blue-dns.service before making the persistent
NetworkManager change. The confirmation flag is mandatory because the active
profile is reactivated.

disable restores the exact saved NetworkManager DNS properties, reactivates the
profile, and then stops/disables the user service. The Blue binary keeps its
port-53 file capability unless --remove-capability is explicitly supplied.
EOF
}

require_commands() {
  local command_name
  for command_name in "$@"; do
    command -v "$command_name" >/dev/null 2>&1 \
      || die "required command not found: $command_name"
  done
}

refresh_active_connections() {
  local output uuid devices name effective_ipv4 effective_ipv6
  ACTIVE_UUIDS=()
  ACTIVE_NAMES=()
  ACTIVE_DEVICES=()

  output="$(nmcli -g UUID connection show --active)" || return 1
  while IFS= read -r uuid; do
    [[ -n "$uuid" ]] || continue
    if [[ ! "$uuid" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
      printf 'setup-system-dns: refusing unexpected active connection UUID %q\n' "$uuid" >&2
      return 1
    fi
    devices="$(nmcli -g GENERAL.DEVICES connection show uuid "$uuid")" || return 1
    [[ "$devices" == 'lo' ]] && continue
    # NetworkManager commonly exposes active bridge profiles (for example
    # docker0) which do not contribute DNS. They are not resolver candidates.
    effective_ipv4="$(nmcli -g IP4.DNS device show "$devices")" || return 1
    effective_ipv6="$(nmcli -g IP6.DNS device show "$devices")" || return 1
    [[ -n "$effective_ipv4" || -n "$effective_ipv6" ]] || continue
    name="$(nmcli -g connection.id connection show uuid "$uuid")" || return 1
    ACTIVE_UUIDS+=("$uuid")
    ACTIVE_NAMES+=("$name")
    ACTIVE_DEVICES+=("$devices")
  done <<< "$output"
}

print_active_candidates() {
  local index
  if ((${#ACTIVE_UUIDS[@]} == 0)); then
    printf '  (none)\n'
    return
  fi
  for index in "${!ACTIVE_UUIDS[@]}"; do
    printf '  name=%q uuid=%s device=%q\n' \
      "${ACTIVE_NAMES[$index]}" \
      "${ACTIVE_UUIDS[$index]}" \
      "${ACTIVE_DEVICES[$index]}"
  done
}

select_single_active_connection() {
  refresh_active_connections || return 1
  if ((${#ACTIVE_UUIDS[@]} != 1)); then
    printf 'setup-system-dns: expected exactly one active DNS-bearing NetworkManager connection excluding lo; found %d\n' \
      "${#ACTIVE_UUIDS[@]}" >&2
    print_active_candidates >&2
    return 1
  fi
  ACTIVE_UUID="${ACTIVE_UUIDS[0]}"
  ACTIVE_NAME="${ACTIVE_NAMES[0]}"
  ACTIVE_DEVICE="${ACTIVE_DEVICES[0]}"
}

normalise_effective_dns() {
  local ipv4_raw="$1"
  local ipv6_raw="$2"
  python3 - "$ipv4_raw" "$ipv6_raw" <<'PY'
import ipaddress
import re
import sys

seen = set()
endpoints = []
invalid = []

for text in sys.argv[1:]:
    for token in re.split(r"\s+\|\s+|[,\s]+", text.strip()):
        if not token or token == "--":
            continue
        if "%" in token:
            invalid.append(f"{token} (scoped IPv6 is not supported by Blue)")
            continue
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            invalid.append(token)
            continue
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            invalid.append(f"{token} (unsafe recursive/invalid upstream)")
            continue
        if address.is_link_local:
            invalid.append(f"{token} (link-local upstream needs an unsupported scope ID)")
            continue
        endpoint = f"[{address}]:53" if address.version == 6 else f"{address}:53"
        if endpoint not in seen:
            seen.add(endpoint)
            endpoints.append(endpoint)

if invalid:
    print("setup-system-dns: unusable NetworkManager DNS value(s): " + ", ".join(invalid), file=sys.stderr)
if not endpoints:
    print(
        "setup-system-dns: no usable effective NetworkManager DNS servers; "
        "refusing to substitute public DNS and risk breaking internal names",
        file=sys.stderr,
    )
    raise SystemExit(1)

print("\n".join(endpoints))
PY
}

load_effective_upstreams() {
  local ipv4_raw ipv6_raw normalised
  ipv4_raw="$(nmcli -g IP4.DNS device show "$ACTIVE_DEVICE")" || return 1
  ipv6_raw="$(nmcli -g IP6.DNS device show "$ACTIVE_DEVICE")" || return 1
  normalised="$(normalise_effective_dns "$ipv4_raw" "$ipv6_raw")" || return 1
  mapfile -t DNS_UPSTREAMS <<< "$normalised"
  ((${#DNS_UPSTREAMS[@]} > 0))
}

read_capability_spec() {
  local output
  output="$(getcap "$blue_path" 2>/dev/null)" || return 1
  if [[ -z "$output" ]]; then
    CAP_SPEC=''
    return 0
  fi
  if [[ "$output" != "$blue_path "* ]]; then
    printf 'setup-system-dns: could not safely parse getcap output: %q\n' "$output" >&2
    return 1
  fi
  CAP_SPEC="${output#"$blue_path "}"
}

capability_allows_bind() {
  [[ "$CAP_SPEC" == *cap_net_bind_service* && "$CAP_SPEC" == *'=ep'* ]]
}

capability_is_bind_only() {
  [[ "$CAP_SPEC" == 'cap_net_bind_service=ep' ]]
}

write_resolv_summary() {
  local destination="$1"
  {
    printf 'captured-at=%s\n' "$(date --iso-8601=seconds)"
    if [[ -L /etc/resolv.conf ]]; then
      printf 'symlink-target=%s\n' "$(readlink /etc/resolv.conf)"
    else
      printf 'symlink-target=(not a symlink)\n'
    fi
    if [[ -e /etc/resolv.conf ]]; then
      stat -c 'mode=%a owner=%U group=%G inode=%i' /etc/resolv.conf
      awk '
        /^[[:space:]]*(nameserver|search|domain|options)[[:space:]]/ {
          sub(/^[[:space:]]+/, "")
          print
        }
      ' /etc/resolv.conf
    else
      printf 'state=missing\n'
    fi
  } > "$destination"
}

prepare_backup() {
  local field filename

  if [[ -L "$backup_root" || (-e "$backup_root" && ! -d "$backup_root") ]]; then
    die "backup root is not a real directory: $backup_root"
  fi
  install -d -m 0700 "$backup_root"
  if [[ -e "$active_backup" || -L "$active_backup" ]]; then
    die "an active DNS backup already exists; run '$0 status' or '$0 disable' first"
  fi

  pending_backup="$(mktemp -d "$backup_root/.pending.XXXXXXXX")"
  printf '%s\n' '1' > "$pending_backup/format-version"
  printf '%s\n' "$(date --iso-8601=seconds)" > "$pending_backup/captured-at"
  printf '%s\n' "$ACTIVE_UUID" > "$pending_backup/connection-uuid"
  printf '%s\n' "$ACTIVE_DEVICE" > "$pending_backup/connection-device"
  printf '%s\n' "$blue_path" > "$pending_backup/blue-path"
  printf '%s\n' "$CAP_SPEC" > "$pending_backup/blue-capabilities"

  nmcli -g connection.id connection show uuid "$ACTIVE_UUID" \
    > "$pending_backup/connection-name"
  for field in \
    ipv4.dns \
    ipv4.ignore-auto-dns \
    ipv6.dns \
    ipv6.ignore-auto-dns; do
    filename="${field//./-}"
    nmcli -g "$field" connection show uuid "$ACTIVE_UUID" \
      > "$pending_backup/$filename"
  done
  nmcli -g IP4.DNS device show "$ACTIVE_DEVICE" \
    > "$pending_backup/effective-ipv4-dns"
  nmcli -g IP6.DNS device show "$ACTIVE_DEVICE" \
    > "$pending_backup/effective-ipv6-dns"
  write_resolv_summary "$pending_backup/resolv.conf.summary"

  if [[ -L "$dns_config" || -d "$dns_config" ]]; then
    die "refusing to replace non-regular DNS config: $dns_config"
  elif [[ -f "$dns_config" ]]; then
    printf '%s\n' 'yes' > "$pending_backup/dns-config-existed"
    cp -p -- "$dns_config" "$pending_backup/dns.toml.previous"
  elif [[ -e "$dns_config" ]]; then
    die "refusing to replace unsupported DNS config file type: $dns_config"
  else
    printf '%s\n' 'no' > "$pending_backup/dns-config-existed"
  fi

  if [[ -d "$dns_dropin" && ! -L "$dns_dropin" ]]; then
    die "refusing to replace DNS drop-in directory: $dns_dropin"
  elif [[ -e "$dns_dropin" || -L "$dns_dropin" ]]; then
    if [[ -f "$dns_dropin" || -L "$dns_dropin" ]]; then
      printf '%s\n' 'yes' > "$pending_backup/dns-dropin-existed"
      cp -a -- "$dns_dropin" "$pending_backup/dns-dropin.previous"
    else
      die "refusing to replace unsupported DNS drop-in file type: $dns_dropin"
    fi
  else
    printf '%s\n' 'no' > "$pending_backup/dns-dropin-existed"
  fi

  mv -- "$pending_backup" "$active_backup"
  pending_backup=''
  backup_dir="$active_backup"
  backup_ready=1
}

write_dns_partial() {
  local upstream comma
  install -d -m 0700 "$(dirname "$dns_config")"
  temporary_config="$(mktemp "$(dirname "$dns_config")/.dns.toml.XXXXXXXX")"
  {
    cat <<'EOF'
# Generated by setup-system-dns.sh.
#
# Blue currently has no split-DNS routing. The original NetworkManager DNS
# servers are therefore kept as UDP upstreams so private and split-horizon names
# continue to resolve. Public DoT servers are intentionally not appended; edit
# this partial only after confirming that doing so cannot bypass internal DNS.

[dns]
bind = "127.0.0.1:53"
upstreams = [
EOF
    for upstream in "${DNS_UPSTREAMS[@]}"; do
      comma=','
      printf '  "%s"%s\n' "$upstream" "$comma"
    done
    printf ']\n'
  } > "$temporary_config"
  chmod 0600 "$temporary_config"
  mv -f -- "$temporary_config" "$dns_config"
  temporary_config=''
  config_installed=1

  install -d -m 0700 "$(dirname "$dns_dropin")"
  temporary_dropin="$(dirname "$dns_dropin")/.90-system-dns.toml.$$"
  [[ ! -e "$temporary_dropin" && ! -L "$temporary_dropin" ]] \
    || die "temporary DNS drop-in path already exists: $temporary_dropin"
  ln -s -- '../dns.toml' "$temporary_dropin"
  mv -Tf -- "$temporary_dropin" "$dns_dropin"
  temporary_dropin=''
}

verify_direct_dns() {
  python3 <<'PY'
import secrets
import socket
import struct

query_id = secrets.randbelow(65536)
labels = b"example.com".split(b".")
question = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.connect(("127.0.0.1", 53))
    sock.send(packet)
    response = sock.recv(4096)

if len(response) < 12:
    raise SystemExit("direct DNS verification returned a truncated packet")
response_id, flags = struct.unpack("!HH", response[:4])
if response_id != query_id:
    raise SystemExit("direct DNS verification returned a mismatched query ID")
if not flags & 0x8000:
    raise SystemExit("direct DNS verification did not receive a response packet")
print("direct DNS query to 127.0.0.1:53: OK")
PY
}

dns_value_for_nmcli() {
  local value
  value="$(<"$1")"
  value="${value// | /,}"
  printf '%s' "$value"
}

validate_backup() {
  local required
  if [[ ! -d "$backup_dir" || -L "$backup_dir" ]]; then
    die "active backup is missing or unsafe: $backup_dir"
    return 1
  fi
  for required in \
    format-version \
    connection-uuid \
    connection-name \
    ipv4-dns \
    ipv4-ignore-auto-dns \
    ipv6-dns \
    ipv6-ignore-auto-dns \
    dns-config-existed \
    dns-dropin-existed; do
    if [[ ! -f "$backup_dir/$required" || -L "$backup_dir/$required" ]]; then
      die "backup file is missing or unsafe: $backup_dir/$required"
      return 1
    fi
  done
  if [[ "$(<"$backup_dir/format-version")" != '1' ]]; then
    die 'unsupported DNS backup format'
    return 1
  fi
}

restore_connection_from_backup() {
  local uuid ipv4_dns ipv4_ignore ipv6_dns ipv6_ignore
  validate_backup || return 1
  uuid="$(<"$backup_dir/connection-uuid")"
  if [[ ! "$uuid" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]]; then
    die 'backup contains an invalid connection UUID'
    return 1
  fi
  ipv4_dns="$(dns_value_for_nmcli "$backup_dir/ipv4-dns")"
  ipv4_ignore="$(<"$backup_dir/ipv4-ignore-auto-dns")"
  ipv6_dns="$(dns_value_for_nmcli "$backup_dir/ipv6-dns")"
  ipv6_ignore="$(<"$backup_dir/ipv6-ignore-auto-dns")"

  nmcli connection modify uuid "$uuid" \
    ipv4.dns "$ipv4_dns" \
    ipv4.ignore-auto-dns "$ipv4_ignore" \
    ipv6.dns "$ipv6_dns" \
    ipv6.ignore-auto-dns "$ipv6_ignore" || return 1
  nmcli connection up uuid "$uuid" || return 1
}

unique_backup_path() {
  local stem="$1"
  local candidate="$backup_dir/$stem-$(date +%Y%m%dT%H%M%S)-$$"
  local counter=0
  while [[ -e "$candidate" || -L "$candidate" ]]; do
    counter=$((counter + 1))
    candidate="$backup_dir/$stem-$(date +%Y%m%dT%H%M%S)-$$-$counter"
  done
  printf '%s' "$candidate"
}

restore_user_dns_config() {
  local existed dropin_existed preserved temporary target
  validate_backup || return 1

  if [[ -e "$dns_config" || -L "$dns_config" ]]; then
    if [[ -d "$dns_config" && ! -L "$dns_config" ]]; then
      die "refusing to replace DNS config directory: $dns_config"
      return 1
    fi
    preserved="$(unique_backup_path 'dns.toml.at-restore')"
    cp -a -- "$dns_config" "$preserved" || return 1
  fi
  if [[ -e "$dns_dropin" || -L "$dns_dropin" ]]; then
    if [[ -d "$dns_dropin" && ! -L "$dns_dropin" ]]; then
      die "refusing to replace DNS drop-in directory: $dns_dropin"
      return 1
    fi
    preserved="$(unique_backup_path 'dns-dropin.at-restore')"
    cp -a -- "$dns_dropin" "$preserved" || return 1
  fi

  existed="$(<"$backup_dir/dns-config-existed")"
  case "$existed" in
    yes)
      if [[ ! -f "$backup_dir/dns.toml.previous" || -L "$backup_dir/dns.toml.previous" ]]; then
        die 'previous DNS config is missing from backup'
        return 1
      fi
      install -d -m 0700 "$(dirname "$dns_config")" || return 1
      temporary="$(mktemp "$(dirname "$dns_config")/.dns.restore.XXXXXXXX")" || return 1
      cp -p -- "$backup_dir/dns.toml.previous" "$temporary" || return 1
      mv -f -- "$temporary" "$dns_config" || return 1
      ;;
    no)
      if [[ -e "$dns_config" || -L "$dns_config" ]]; then
        rm -f -- "$dns_config" || return 1
      fi
      ;;
    *)
      die 'invalid dns-config-existed marker in backup'
      return 1
      ;;
  esac

  dropin_existed="$(<"$backup_dir/dns-dropin-existed")"
  case "$dropin_existed" in
    yes)
      if [[ ! -e "$backup_dir/dns-dropin.previous" && ! -L "$backup_dir/dns-dropin.previous" ]]; then
        die 'previous DNS drop-in is missing from backup'
        return 1
      fi
      install -d -m 0700 "$(dirname "$dns_dropin")" || return 1
      if [[ -L "$backup_dir/dns-dropin.previous" ]]; then
        target="$(readlink "$backup_dir/dns-dropin.previous")" || return 1
        temporary_dropin="$(dirname "$dns_dropin")/.dns-dropin.restore.$$"
        [[ ! -e "$temporary_dropin" && ! -L "$temporary_dropin" ]] || return 1
        ln -s -- "$target" "$temporary_dropin" || return 1
      elif [[ -f "$backup_dir/dns-dropin.previous" ]]; then
        temporary_dropin="$(mktemp "$(dirname "$dns_dropin")/.dns-dropin.restore.XXXXXXXX")" || return 1
        cp -p -- "$backup_dir/dns-dropin.previous" "$temporary_dropin" || return 1
      else
        die 'previous DNS drop-in has an unsupported file type'
        return 1
      fi
      mv -Tf -- "$temporary_dropin" "$dns_dropin" || return 1
      temporary_dropin=''
      ;;
    no)
      if [[ -e "$dns_dropin" || -L "$dns_dropin" ]]; then
        rm -f -- "$dns_dropin" || return 1
      fi
      ;;
    *)
      die 'invalid dns-dropin-existed marker in backup'
      return 1
      ;;
  esac
  config_installed=0
}

archive_active_backup() {
  local label="$1"
  local destination counter=0
  destination="$backup_root/$label-$(date +%Y%m%dT%H%M%S)-$$"
  while [[ -e "$destination" || -L "$destination" ]]; do
    counter=$((counter + 1))
    destination="$backup_root/$label-$(date +%Y%m%dT%H%M%S)-$$-$counter"
  done
  mv -- "$active_backup" "$destination" || return 1
  backup_ready=0
  backup_dir=''
  printf '%s\n' "$destination"
}

preserve_pending_backup() {
  local destination
  [[ -n "$pending_backup" && -d "$pending_backup" ]] || return 0
  destination="$backup_root/failed-pending-$(date +%Y%m%dT%H%M%S)-$$"
  mv -- "$pending_backup" "$destination" 2>/dev/null || true
  pending_backup=''
}

rollback_enable() {
  local failed=0 archived
  printf 'setup-system-dns: enable failed; attempting rollback\n' >&2

  if ((nm_change_attempted)); then
    if ! restore_connection_from_backup; then
      printf 'setup-system-dns: WARNING: NetworkManager restore failed; backup remains at %s\n' "$backup_dir" >&2
      failed=1
    fi
  fi

  if ! systemctl --user disable --now "$service_name"; then
    printf 'setup-system-dns: WARNING: could not disable/stop %s\n' "$service_name" >&2
    failed=1
  fi

  if ((config_installed)) && ((backup_ready)); then
    if ! restore_user_dns_config; then
      printf 'setup-system-dns: WARNING: could not restore the prior DNS partial\n' >&2
      failed=1
    fi
  fi

  if ((capability_added)); then
    if ! sudo setcap -r "$blue_path"; then
      printf 'setup-system-dns: WARNING: could not remove the newly added file capability\n' >&2
      failed=1
    fi
  fi

  preserve_pending_backup
  if ((backup_ready)) && ((failed == 0)); then
    printf '%s\n' "$(date --iso-8601=seconds)" > "$backup_dir/rolled-back-at"
    if archived="$(archive_active_backup 'rolled-back')"; then
      printf 'setup-system-dns: rollback complete; record preserved at %s\n' "$archived" >&2
    else
      printf 'setup-system-dns: WARNING: rollback succeeded but its record could not be archived\n' >&2
    fi
  elif ((backup_ready)); then
    printf 'setup-system-dns: incomplete rollback; recovery data remains at %s\n' "$backup_dir" >&2
  fi
}

finish_on_exit() {
  local status=$?
  trap - EXIT
  set +e
  if ((rollback_armed)); then
    rollback_enable
  fi
  if [[ -n "$temporary_config" && (-e "$temporary_config" || -L "$temporary_config") ]]; then
    rm -f -- "$temporary_config"
  fi
  if [[ -n "$temporary_dropin" && (-e "$temporary_dropin" || -L "$temporary_dropin") ]]; then
    rm -f -- "$temporary_dropin"
  fi
  exit "$status"
}
trap finish_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

print_plan() {
  local property value upstream
  require_commands nmcli python3 systemctl getcap setcap sudo
  [[ -x "$blue_path" && ! -L "$blue_path" ]] \
    || die "installed Blue binary is missing, non-executable, or a symlink: $blue_path"
  select_single_active_connection
  load_effective_upstreams

  printf 'NetworkManager connection:\n'
  printf '  name=%q\n  uuid=%s\n  device=%q\n' "$ACTIVE_NAME" "$ACTIVE_UUID" "$ACTIVE_DEVICE"
  printf 'Saved properties:\n'
  for property in ipv4.dns ipv4.ignore-auto-dns ipv6.dns ipv6.ignore-auto-dns; do
    value="$(nmcli -g "$property" connection show uuid "$ACTIVE_UUID")"
    printf '  %s=%q\n' "$property" "$value"
  done
  printf 'Blue UDP upstreams (preserved from the active connection):\n'
  for upstream in "${DNS_UPSTREAMS[@]}"; do
    printf '  %s\n' "$upstream"
  done
  cat <<EOF

Confirmed enable will:
  1. Save separate recovery files below $active_backup.
  2. Write $dns_config and link it into the user conf.d directory, without
     adding public DNS/DoT fallbacks.
  3. Run: sudo setcap cap_net_bind_service=+ep $blue_path
  4. Enable and start $service_name and verify a direct DNS reply.
  5. Set IPv4 DNS to 127.0.0.1, clear IPv6 DNS bypasses, set both
     ignore-auto-dns properties, and reactivate the selected profile.

Any enable failure triggers restoration and stops the user service.
No change has been made. To continue:
  $0 enable --confirm-network-change
EOF
}

print_status() {
  local state enabled connection_name
  printf 'Blue DNS setup status\n'
  printf '  binary: %s\n' "$blue_path"
  if command -v getcap >/dev/null 2>&1 && [[ -e "$blue_path" ]]; then
    if read_capability_spec; then
      printf '  file capabilities: %s\n' "${CAP_SPEC:-(none)}"
    else
      printf '  file capabilities: unreadable\n'
    fi
  else
    printf '  file capabilities: unavailable\n'
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user is-active --quiet "$service_name"; then state='active'; else state='inactive'; fi
    enabled="$(systemctl --user is-enabled "$service_name" 2>/dev/null || true)"
    printf '  service: %s; enablement: %s\n' "$state" "${enabled:-unknown}"
  else
    printf '  service: systemctl unavailable\n'
  fi

  if [[ -d "$active_backup" && ! -L "$active_backup" ]]; then
    connection_name='(unreadable)'
    if [[ -f "$active_backup/connection-name" && ! -L "$active_backup/connection-name" ]]; then
      connection_name="$(<"$active_backup/connection-name")"
    fi
    printf '  active recovery backup: %s\n' "$active_backup"
    printf '  backed-up connection: %q\n' "$connection_name"
  elif [[ -e "$active_backup" || -L "$active_backup" ]]; then
    printf '  active recovery backup: unsafe path (%s)\n' "$active_backup"
  else
    printf '  active recovery backup: none\n'
  fi

  if command -v nmcli >/dev/null 2>&1; then
    if refresh_active_connections; then
      printf '  active DNS-bearing NetworkManager connections excluding lo: %d\n' "${#ACTIVE_UUIDS[@]}"
      print_active_candidates
    else
      printf '  active NetworkManager connections: query failed\n'
    fi
  else
    printf '  NetworkManager: nmcli unavailable\n'
  fi
}

enable_dns() {
  local current archived
  require_commands nmcli python3 systemctl getcap setcap sudo
  [[ -x "$blue_path" && ! -L "$blue_path" ]] \
    || die "installed Blue binary is missing, non-executable, or a symlink: $blue_path"
  select_single_active_connection
  load_effective_upstreams
  read_capability_spec
  if [[ -n "$CAP_SPEC" ]] && ! capability_allows_bind; then
    die "refusing to replace unrelated file capabilities on $blue_path: $CAP_SPEC"
  fi
  if systemctl --user is-active --quiet "$service_name"; then
    die "$service_name is already active; disable the prior setup before enabling"
  fi
  if systemctl --user is-enabled --quiet "$service_name"; then
    die "$service_name is already enabled; disable the prior setup before enabling"
  fi

  rollback_armed=1
  prepare_backup
  write_dns_partial

  if ! capability_allows_bind; then
    sudo setcap cap_net_bind_service=+ep "$blue_path"
    capability_added=1
    read_capability_spec
    capability_allows_bind \
      || die 'cap_net_bind_service was not present after setcap'
  fi

  systemctl --user daemon-reload
  systemctl --user enable --now "$service_name"
  systemctl --user is-active --quiet "$service_name" \
    || die "$service_name did not become active"
  verify_direct_dns

  nm_change_attempted=1
  nmcli connection modify uuid "$ACTIVE_UUID" \
    ipv4.dns '127.0.0.1' \
    ipv4.ignore-auto-dns yes \
    ipv6.dns '' \
    ipv6.ignore-auto-dns yes
  nmcli connection up uuid "$ACTIVE_UUID"

  current="$(nmcli -g ipv4.dns connection show uuid "$ACTIVE_UUID")"
  [[ "$current" == '127.0.0.1' ]] || die 'NetworkManager did not retain IPv4 loopback DNS'
  current="$(nmcli -g ipv4.ignore-auto-dns connection show uuid "$ACTIVE_UUID")"
  [[ "$current" == 'yes' ]] || die 'NetworkManager did not retain ipv4.ignore-auto-dns=yes'
  current="$(nmcli -g ipv6.dns connection show uuid "$ACTIVE_UUID")"
  [[ -z "$current" ]] || die 'NetworkManager retained an IPv6 DNS bypass'
  current="$(nmcli -g ipv6.ignore-auto-dns connection show uuid "$ACTIVE_UUID")"
  [[ "$current" == 'yes' ]] || die 'NetworkManager did not retain ipv6.ignore-auto-dns=yes'
  systemctl --user is-active --quiet "$service_name" \
    || die "$service_name stopped after NetworkManager reactivation"
  verify_direct_dns

  printf '%s\n' "$(date --iso-8601=seconds)" > "$backup_dir/enabled-at"
  rollback_armed=0
  archived="$backup_dir"
  cat <<EOF
Blue DNS is active for connection $(printf '%q' "$ACTIVE_NAME").
Recovery data: $archived
The service is enabled so persistent loopback DNS remains safe across reboot.
Use '$0 disable' before reinstalling Blue or changing the selected connection.
EOF
}

disable_dns() {
  local archived
  require_commands nmcli systemctl
  backup_dir="$active_backup"
  backup_ready=1
  validate_backup

  # Restore and reactivate the real upstream profile before stopping the local
  # resolver, so a successful disable never leaves a loopback DNS black hole.
  restore_connection_from_backup
  systemctl --user disable --now "$service_name"
  restore_user_dns_config

  if ((remove_capability)); then
    require_commands getcap setcap sudo
    [[ -f "$blue_path" && ! -L "$blue_path" ]] \
      || die "installed Blue binary is missing or unsafe: $blue_path"
    read_capability_spec
    if [[ -z "$CAP_SPEC" ]]; then
      printf 'Port-53 file capability is already absent.\n'
    elif capability_is_bind_only; then
      sudo setcap -r "$blue_path"
    else
      die "refusing to remove capability because other capabilities are present: $CAP_SPEC"
    fi
  fi

  printf '%s\n' "$(date --iso-8601=seconds)" > "$backup_dir/disabled-at"
  archived="$(archive_active_backup 'restored')"
  printf 'Original NetworkManager DNS settings restored; recovery record: %s\n' "$archived"
  if ((!remove_capability)); then
    printf 'The cap_net_bind_service file capability was retained.\n'
  fi
}

[[ -n "${HOME:-}" && "$HOME" == /* ]] || die 'HOME must be an absolute path'
((EUID != 0)) || die 'run this script as the desktop user, never as root'

action="${1:-}"
[[ -n "$action" ]] || { usage >&2; exit 2; }
shift

confirm_network_change=0
remove_capability=0
while (($#)); do
  case "$1" in
    --confirm-network-change) confirm_network_change=1 ;;
    --remove-capability) remove_capability=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

case "$action" in
  status)
    ((confirm_network_change == 0 && remove_capability == 0)) \
      || die 'status accepts no options'
    print_status
    ;;
  plan)
    ((confirm_network_change == 0 && remove_capability == 0)) \
      || die 'plan accepts no options'
    print_plan
    ;;
  enable)
    ((remove_capability == 0)) || die '--remove-capability is valid only with disable'
    ((confirm_network_change == 1)) \
      || die 'enable requires --confirm-network-change (run plan first)'
    enable_dns
    ;;
  disable)
    ((confirm_network_change == 0)) \
      || die '--confirm-network-change is valid only with enable'
    disable_dns
    ;;
  -h|--help|help)
    ((confirm_network_change == 0 && remove_capability == 0)) \
      || die 'help accepts no options'
    usage
    ;;
  *)
    usage >&2
    die "unknown command: $action"
    ;;
esac
