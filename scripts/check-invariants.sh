#!/usr/bin/env bash
# Invariant: nothing in the suite deletes user data.
#
# The drill is allowed exactly one remove_file, and only for its own EICAR
# artifact. Everything else must quarantine and restore.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

status=0

echo "== destructive calls outside quarantine =="
if grep -rn --include='*.rs' -E '\bremove_file\b|\bremove_dir_all\b' crates \
   | grep -v 'allowed-delete' \
   | grep -v 'quarantine.rs'; then
    echo "FAIL: found a destructive call that is not part of quarantine or the drill"
    status=1
else
    echo "ok: none"
fi

echo "== quarantine module =="
if grep -q 'fn store' crates/blue-core/src/quarantine.rs; then
    echo "ok: store/restore present"
else
    echo "FAIL: quarantine module looks wrong"
    status=1
fi

echo "== tier gate =="
if grep -q 'may_quarantine' crates/blue-core/src/model.rs; then
    echo "ok: quarantine is gated on T2"
else
    echo "FAIL: tier gate missing"
    status=1
fi

exit "$status"
