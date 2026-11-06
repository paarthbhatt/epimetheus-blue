#!/usr/bin/env bash
# Run only after verifying the release archive checksum. No sudo or compilation.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
exec "$root/scripts/install-local.sh" --from-binary "$@"
