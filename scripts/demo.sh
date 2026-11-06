#!/usr/bin/env bash
# Offline, disposable demonstration. Never scans or cleans the user's files.
# Blue's database/rule writes and its harmless EICAR drill stay in our temp HOME.
set -euo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage: scripts/demo.sh

Inspect configuration and a firewall draft, then run the harmless EICAR drill.
Network providers are disabled. No firewall, DNS, service or cleanup is applied.
All state is temporary and removed on exit; the real HOME is never used.

Environment: BLUE_BIN=/path/to/blue  TMPDIR=/path/to/temporary-directory
USAGE
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi
if (( $# != 0 )); then
    usage >&2
    exit 2
fi

if ! blue_bin="$(command -v -- "${BLUE_BIN:-blue}")"; then
    echo 'blue is not installed; set BLUE_BIN to a tested Blue executable.' >&2
    exit 1
fi
if [[ $blue_bin != /* ]]; then
    blue_bin="$(cd -- "$(dirname -- "$blue_bin")" && pwd -P)/$(basename -- "$blue_bin")"
fi
if [[ ! -f $blue_bin || ! -x $blue_bin ]]; then
    echo 'BLUE_BIN must name an executable file.' >&2
    exit 1
fi

temp_base="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
demo_dir="$(mktemp -d "$temp_base/blue-demo.XXXXXXXX")"
readonly demo_dir temp_base

cleanup_demo() {
    local status=$?
    trap - EXIT
    # Only the unique directory we created; never a caller-supplied scan target.
    if [[ $demo_dir == "$temp_base"/blue-demo.* && -d $demo_dir && ! -L $demo_dir ]]; then
        rm -rf -- "$demo_dir"
    fi
    exit "$status"
}
trap cleanup_demo EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

demo_home="$demo_dir/home"
state_dir="$demo_home/.local/share/blue"
config="$demo_dir/config.toml"
mkdir -p -- "$demo_home/.config/blue" "$state_dir/lists" "$state_dir/hash-feeds" \
    "$demo_dir/cache" "$demo_dir/runtime" "$demo_dir/tmp"

# Override every path/provider that could otherwise come from system config.
# Tilde paths resolve against the isolated HOME, not the real user's home.
cat > "$config" <<'TOML'
[general]
state_dir = "~/.local/share/blue"
log_level = "error"

[scan]
roots = []
exclude_globs = []
max_file_size_mb = 1
debounce_ms = 500
mode = "inotify"

[scan.clamav]
socket = "~/no-clamd.sock"
required = false

[scan.yara]
rule_paths = []
rule_dirs = []
timeout_ms = 5000

[dns]
bind = "127.0.0.1:0"
upstreams = []
block_response = "nxdomain"

[guard]
watch_paths = []
watch_packages = false

[feeds]
lists_dir = "~/.local/share/blue/lists"
sources = []

[reputation]
local_dir = "~/.local/share/blue/hash-feeds"
sources = []
virustotal_enabled = false
virustotal_query_on_scan = false
virustotal_api_key_env = "BLUE_DEMO_UNUSED_KEY"
virustotal_api_key_file = "~/.config/blue/no-api-key"
virustotal_min_malicious = 3
cache_hours = 168

[network]
ignore_private = true
interval_minutes = 5
max_connections = 100

[cleanup]
scan_roots = []
download_age_days = 30
build_artifact_depth = 1
max_candidates = 100
TOML

run_blue() {
    # Do not inherit credentials, display sockets, proxies or the user session.
    env -i HOME="$demo_home" XDG_CONFIG_HOME="$demo_home/.config" \
        XDG_DATA_HOME="$demo_home/.local/share" XDG_CACHE_HOME="$demo_dir/cache" \
        XDG_RUNTIME_DIR="$demo_dir/runtime" TMPDIR="$demo_dir/tmp" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$demo_dir/no-user-bus" \
        PATH=/usr/bin:/bin LANG=C.UTF-8 \
        "$blue_bin" --config "$config" --state-dir "$state_dir" "$@"
}

echo 'DEMO STATE — offline; firewall NOT activated; no live cleanup.'
echo 'Only the disposable EICAR fixture is quarantined/restored/removed.'
echo 'ClamAV is deliberately unavailable; the shipped YARA-X rules are used.'
run_blue verify
run_blue reputation status
run_blue firewall plan --profile public
run_blue drill
echo 'Demo passed. Temporary fixture and state are removed on exit.'
