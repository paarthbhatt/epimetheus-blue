#!/usr/bin/env bash
# Optional privileged packaging only. Never enable a service or apply rules.
set -euo pipefail
export LC_ALL=C
umask 077

die() {
  printf 'install-firewall: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  install-firewall.sh plan
  install-firewall.sh install --confirm-firewall-install

plan is read-only. Build blue-firewall-helper as the desktop user first.
install uses sudo to copy root-owned files and reload systemd definitions;
it never runs the helper, starts/enables services, or changes firewall/DNS rules.
EOF
}

mode="${1:-plan}"
case "$mode" in
  plan)
    (($# <= 1)) || die 'plan takes no additional arguments'
    ;;
  install)
    [[ $# == 2 && "$2" == '--confirm-firewall-install' ]] \
      || die 'install requires exactly --confirm-firewall-install'
    ((EUID != 0)) || die 'run as the desktop user; this installer uses sudo'
    ;;
  -h|--help)
    (($# == 1)) || die 'help takes no additional arguments'
    usage
    exit 0
    ;;
  *)
    usage >&2
    die "unknown mode: $mode"
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
helper_source="$root/target/release/blue-firewall-helper"
policy_source="$root/packaging/com.epimetheus.blue.firewall.policy"
service_source="$root/packaging/blue-firewall.service"

show_plan() {
  cat <<EOF
Optional firewall installation plan (no changes made):
  Build separately, without sudo:
    cargo build --release --locked --package blue-firewall-helper

  Copy $helper_source
    -> /usr/lib/epimetheus-blue/blue-firewall-helper (root:root, 0755, regular file)
  Copy $policy_source
    -> /usr/share/polkit-1/actions/com.epimetheus.blue.firewall.policy (root:root, 0644)
  Copy $service_source
    -> /etc/systemd/system/blue-firewall.service (root:root, 0644)
  Initialize root:root directories:
    /usr/lib/epimetheus-blue          0755
    /etc/epimetheus-blue              0755
    /etc/epimetheus-blue/firewall     0700
    /run/epimetheus-blue              0755 (for readable sanitized status)
  Reload systemd unit definitions only. Preserve existing policy/state files.
  Do not enable/start/stop services, run the helper, or create an initial policy.
  Do not modify the GUI, capabilities, global nftables rules, or DNS settings.

Prerequisites (availability checks only):
EOF
}

check_prerequisites() {
  local missing=0 tool polkit_load
  for tool in nft systemctl systemd-run pkexec pkaction sudo; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '  %s: available\n' "$tool"
    else
      printf '  %s: missing\n' "$tool"
      missing=1
    fi
  done

  if [[ -d /run/systemd/system ]] \
    && command -v systemctl >/dev/null 2>&1 \
    && systemctl --system show --property=Version --value >/dev/null 2>&1; then
    printf '  systemd system manager: reachable\n'
    polkit_load="$(systemctl --system show --property=LoadState --value polkit.service 2>/dev/null || true)"
    if [[ "$polkit_load" == 'loaded' ]]; then
      printf '  polkit.service: available (activation state unchanged)\n'
    else
      printf '  polkit.service: unavailable\n'
      missing=1
    fi
  else
    printf '  systemd system manager: unavailable\n'
    missing=1
  fi
  return "$missing"
}

show_plan
check_prerequisites || die 'install the missing prerequisites yourself; no packages were installed'
[[ "$mode" == 'install' ]] || exit 0

# No compilation, downloads, or execution of the user-built helper as root.
for source in "$helper_source" "$policy_source" "$service_source"; do
  [[ -f "$source" && -r "$source" && ! -L "$source" ]] \
    || die "source must be a readable regular file, not a symlink: $source"
done
[[ -x "$helper_source" ]] || die 'build the standalone release helper before installing'
[[ -x /usr/bin/sudo && -x /usr/bin/env && -x /usr/bin/bash ]] \
  || die 'this installer requires sudo, env, and bash under /usr/bin'

# Only this fixed, confirmation-gated operation is privileged. Sanitize the
# root environment; execute only the fixed installation fragment below, never
# the compiler or the source helper.
/usr/bin/sudo -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
  /usr/bin/bash --noprofile --norc -s -- \
  "$helper_source" "$policy_source" "$service_source" <<'ROOT_INSTALL'
set -euo pipefail
umask 077
((EUID == 0)) || exit 1

fail() {
  printf 'install-firewall: %s\n' "$*" >&2
  exit 1
}

for tool in install stat mktemp mv rm systemctl; do
  command -v "$tool" >/dev/null 2>&1 || fail "required system command missing: $tool"
done

secure_owner_and_mode() {
  local path="$1" owner permissions
  owner="$(stat -c '%u:%g' -- "$path")"
  permissions="$(stat -c '%a' -- "$path")"
  [[ "$owner" == '0:0' ]] || fail "refusing non-root-owned destination: $path"
  (( (8#$permissions & 0022) == 0 )) \
    || fail "refusing group/other-writable destination: $path"
}

secure_directory_chain() {
  local directory="$1"
  while :; do
    [[ -d "$directory" && ! -L "$directory" ]] \
      || fail "destination directory must exist and not be a symlink: $directory"
    secure_owner_and_mode "$directory"
    [[ "$directory" != '/' ]] || break
    directory="${directory%/*}"
    [[ -n "$directory" ]] || directory='/'
  done
}

prepare_directory() {
  local directory="$1" permissions="$2"
  secure_directory_chain "${directory%/*}"
  if [[ -e "$directory" || -L "$directory" ]]; then
    secure_directory_chain "$directory"
  fi
  install -d -o root -g root -m "$permissions" -- "$directory"
  secure_directory_chain "$directory"
}

# Validate distribution-owned parents; do not repair/chown unsafe trees.
for directory in /usr/lib /usr/share/polkit-1/actions /etc/systemd/system /etc /run; do
  secure_directory_chain "$directory"
done
prepare_directory /usr/lib/epimetheus-blue 0755
prepare_directory /etc/epimetheus-blue 0755
prepare_directory /etc/epimetheus-blue/firewall 0700
prepare_directory /run/epimetheus-blue 0755

declare -a staged_files=() destinations=()
cleanup() {
  if ((${#staged_files[@]})); then
    rm -f -- "${staged_files[@]}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stage_file() {
  local source="$1" destination="$2" permissions="$3" temporary
  [[ -f "$source" && -r "$source" && ! -L "$source" ]] \
    || fail "source is no longer a regular file: $source"
  [[ ! -L "$destination" ]] || fail "refusing destination symlink: $destination"
  if [[ -e "$destination" ]]; then
    [[ -f "$destination" ]] || fail "refusing non-file destination: $destination"
    secure_owner_and_mode "$destination"
  fi
  temporary="$(mktemp "${destination%/*}/.${destination##*/}.XXXXXX")"
  staged_files+=("$temporary")
  destinations+=("$destination")
  install -T -o root -g root -m "$permissions" -- "$source" "$temporary"
  secure_owner_and_mode "$temporary"
}

# Stage regular copies inside secure, root-owned parents, then rename them.
# Never link a privileged executable back into the user-writable source tree.
stage_file "$1" /usr/lib/epimetheus-blue/blue-firewall-helper 0755
stage_file "$2" /usr/share/polkit-1/actions/com.epimetheus.blue.firewall.policy 0644
stage_file "$3" /etc/systemd/system/blue-firewall.service 0644
IFS= read -r -N 4 magic < "${staged_files[0]}" || fail 'helper is not an ELF executable'
[[ "$magic" == $'\177ELF' ]] || fail 'helper must be the standalone compiled ELF executable'
for ((index = 0; index < ${#staged_files[@]}; index++)); do
  mv -fT -- "${staged_files[index]}" "${destinations[index]}"
done

# Register definitions, but do not enable, start, restart, stop, or run boot.
systemctl --system daemon-reload
ROOT_INSTALL

cat <<'EOF'
Privileged firewall components installed. Service enablement is unchanged.
No firewall rules or DNS settings were changed; no initial policy was saved.
The GUI remains rootless. Apply and confirm a policy separately, then opt in
to boot persistence if wanted. See docs/FIREWALL.md before activation.
EOF
