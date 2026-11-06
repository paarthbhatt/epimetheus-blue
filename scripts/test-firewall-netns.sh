#!/usr/bin/env bash
# Real nft enforcement, only in an unprivileged disposable user/network namespace.
# Exit 77 means SKIP. No installed helper, service, mounts, DNS, or host nft calls.
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "$0")/.." && pwd)"
skip() { echo "SKIP: $*"; exit 77; }
[[ $# == 0 ]] || { echo "Usage: $0" >&2; exit 1; }
(( EUID != 0 )) || skip "run as an ordinary user (no sudo)"
for tool in unshare ip nft python3 cargo rustc readlink; do
    command -v "$tool" >/dev/null || skip "missing $tool"
done

tmp_base="${TMPDIR:-/tmp/opencode}"
[[ -d "$tmp_base" ]] || tmp_base=/tmp
work="$(mktemp -d "$tmp_base/blue-firewall-netns.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
if ! unshare --user --map-root-user --net -- true 2>"$work/unshare.err"; then
    skip "user/network namespaces unavailable: $(<"$work/unshare.err")"
fi

# Compile the production renderer, offline, without changing workspace files.
cargo build --offline --locked --quiet --manifest-path "$root/Cargo.toml" \
    --package blue-firewall --target-dir "$work/target"
cat >"$work/render.rs" <<'RS'
use blue_firewall::{FirewallPolicy, FirewallProfile, InboundRule, Protocol};

fn main() {
    let mut policy = FirewallPolicy::new(FirewallProfile::Public);
    if std::env::args().nth(1).as_deref() == Some("exception") {
        policy.inbound.push(InboundRule {
            name: "Namespace UDP probe".into(),
            protocol: Protocol::Udp,
            port: 42424,
            source: Some("192.0.2.0/24".into()),
        });
    }
    print!("{}", policy.render_nft().expect("production policy must render"));
}
RS
rustc --edition=2021 "$work/render.rs" \
    --extern "blue_firewall=$work/target/debug/libblue_firewall.rlib" \
    -L "dependency=$work/target/debug/deps" -o "$work/render"
"$work/render" >"$work/public.nft"
"$work/render" exception >"$work/exception.nft"

# The helper verifies BOTH namespaces and the uid map before any ip/nft call.
status=0
unshare --user --map-root-user --net -- python3 \
    "$root/tests/firewall/netns.py" "$EUID" \
    "$(readlink /proc/self/ns/user)" "$(readlink /proc/self/ns/net)" \
    "$work/public.nft" "$work/exception.nft" 2>"$work/test.err" || status=$?
if (( status != 0 )) && [[ $(<"$work/test.err") == unshare:* ]]; then
    skip "user/network namespaces unavailable: $(<"$work/test.err")"
fi
cat "$work/test.err" >&2
exit "$status"
