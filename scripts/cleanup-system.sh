#!/usr/bin/env bash
# Confirmation-gated owner-tool cleanup for system-managed data. This script
# never touches EFI files, arbitrary backups, projects, or personal downloads.
set -Eeuo pipefail

export LC_ALL=C
umask 077

die() {
  printf 'cleanup-system: %s\n' "$*" >&2
  return 1
}

usage() {
  cat <<'EOF'
Usage:
  cleanup-system.sh status
  cleanup-system.sh plan
  sudo cleanup-system.sh apply --confirm-system-cleanup
  sudo cleanup-system.sh snapshots --keep N --confirm-snapshot-prune
  cleanup-system.sh docker-plan
  cleanup-system.sh docker-prune --confirm-docker-prune

`apply` keeps one cached version of each pacman package, caps the journal at
14 days/400 MiB, and clears reproducible debtap indexes. It never touches EFI,
snapshots, backups, projects, Downloads, containers, or personal files.

Snapshot pruning is separate because rollback history is not a cache. Docker
image pruning is separate because images may be expensive to re-download.
EOF
}

human_size() {
  local output
  output="$(du -sh -- "$1" 2>/dev/null | awk 'NR==1 {print $1}' || true)"
  printf '%s' "${output:-unreadable}"
}

print_status() {
  printf 'Filesystem:\n'
  df -h / /efi 2>/dev/null || df -h /
  printf '\nCandidates and protected data:\n'
  printf '  pacman cache: %s\n' "$(human_size /var/cache/pacman/pkg)"
  local journal_usage
  journal_usage="$(journalctl --disk-usage 2>/dev/null || true)"
  printf '  journal: %s\n' "${journal_usage:-unreadable}"
  printf '  debtap indexes: %s\n' "$(human_size /var/cache/debtap)"
  printf '  snapshots (protected; logical size may double-count shared blocks): %s\n' "$(human_size /.snapshots)"
  printf '  EFI (protected; never deleted here): %s\n' "$(human_size /efi)"
  printf '  Ryoku backups (protected; never deleted here): %s\n' "$(human_size /var/backups/ryoku)"
}

print_plan() {
  print_status
  printf '\nDry-run details:\n'
  if command -v paccache >/dev/null 2>&1; then
    if ! timeout 20s paccache -d -k1 2>/dev/null; then
      printf '  paccache dry run exceeded 20 seconds or could not complete\n'
    fi
  else
    printf '  paccache unavailable; pacman cache step would be skipped\n'
  fi
  cat <<'EOF'

Confirmed apply performs only:
  paccache -rk1
  journalctl --vacuum-size=400M
  journalctl --vacuum-time=14d
  delete regular files directly under /var/cache/debtap

No change has been made. EFI, snapshots and backups remain protected.
EOF
}

apply_system_cleanup() {
  ((EUID == 0)) || die 'apply must run through sudo/root after reviewing plan'
  printf 'Before:\n'
  df -h / | tail -1
  if command -v paccache >/dev/null 2>&1; then
    paccache -rk1
  else
    printf 'paccache unavailable; skipping pacman cache\n' >&2
  fi
  journalctl --vacuum-size=400M
  journalctl --vacuum-time=14d
  if [[ -d /var/cache/debtap && ! -L /var/cache/debtap ]]; then
    find /var/cache/debtap -xdev -mindepth 1 -maxdepth 1 -type f -delete
  fi
  printf 'After:\n'
  df -h / | tail -1
}

prune_snapshots() {
  local keep="$1"
  ((EUID == 0)) || die 'snapshot pruning must run through sudo/root'
  [[ "$keep" =~ ^[1-9][0-9]*$ ]] || die '--keep must be a positive integer'
  ((keep >= 2 && keep <= 50)) || die '--keep must be between 2 and 50'
  command -v snapper >/dev/null 2>&1 || die 'snapper is not installed'
  printf 'Snapshots before:\n'
  snapper -c root list
  snapper -c root set-config "NUMBER_LIMIT=$keep" "NUMBER_LIMIT_IMPORTANT=$keep" NUMBER_CLEANUP=yes
  snapper -c root cleanup number
  printf 'Snapshots after:\n'
  snapper -c root list
  systemctl start limine-snapper-sync.service 2>/dev/null || true
}

docker_plan() {
  command -v docker >/dev/null 2>&1 || die 'docker is not installed'
  docker system df
  printf '\nNo change made. Confirmed prune removes unused images only; containers and volumes are not selected.\n'
}

docker_prune() {
  command -v docker >/dev/null 2>&1 || die 'docker is not installed'
  docker image prune -a -f
}

action="${1:-}"
[[ -n "$action" ]] || { usage >&2; exit 2; }
shift

confirm_system=0
confirm_snapshots=0
confirm_docker=0
keep=''
while (($#)); do
  case "$1" in
    --confirm-system-cleanup) confirm_system=1 ;;
    --confirm-snapshot-prune) confirm_snapshots=1 ;;
    --confirm-docker-prune) confirm_docker=1 ;;
    --keep)
      shift
      (($#)) || die '--keep requires a value'
      keep="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

case "$action" in
  status)
    ((confirm_system == 0 && confirm_snapshots == 0 && confirm_docker == 0)) && [[ -z "$keep" ]] \
      || die 'status accepts no options'
    print_status
    ;;
  plan)
    ((confirm_system == 0 && confirm_snapshots == 0 && confirm_docker == 0)) && [[ -z "$keep" ]] \
      || die 'plan accepts no options'
    print_plan
    ;;
  apply)
    ((confirm_snapshots == 0 && confirm_docker == 0)) && [[ -z "$keep" ]] \
      || die 'apply accepts only --confirm-system-cleanup'
    ((confirm_system == 1)) || die 'apply requires --confirm-system-cleanup'
    apply_system_cleanup
    ;;
  snapshots)
    ((confirm_system == 0 && confirm_docker == 0)) \
      || die 'snapshots accepts only --keep and --confirm-snapshot-prune'
    ((confirm_snapshots == 1)) || die 'snapshots requires --confirm-snapshot-prune'
    [[ -n "$keep" ]] || die 'snapshots requires --keep N'
    prune_snapshots "$keep"
    ;;
  docker-plan)
    ((confirm_system == 0 && confirm_snapshots == 0 && confirm_docker == 0)) && [[ -z "$keep" ]] \
      || die 'docker-plan accepts no options'
    docker_plan
    ;;
  docker-prune)
    ((confirm_system == 0 && confirm_snapshots == 0)) && [[ -z "$keep" ]] \
      || die 'docker-prune accepts only --confirm-docker-prune'
    ((confirm_docker == 1)) || die 'docker-prune requires --confirm-docker-prune'
    docker_prune
    ;;
  -h|--help|help) usage ;;
  *) usage >&2; die "unknown command: $action" ;;
esac
