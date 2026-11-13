#!/usr/bin/env bash
# Run on Ansible. Keep IPID read-back; replace only the redundant ZMap stage.
set -euo pipefail
revision=372f2890cf534dc3988eedeb360c09ac6d56caea
failed=0
for entry in sa:southamerica-east1 af:africa-south1 as:asia-east2 au:australia-southeast1; do
  site=${entry%%:*}
  region=${entry#*:}
  printf '\n=== %s: reuse original ZMap backup ===\n' "$site"
  if gcloud compute ssh "ansible@ipid-gc-$region-icmp" \
    --project=jmuecke-ipid-imc-2026-10 \
    --zone="$region-a" \
    --ssh-key-file="$HOME/.ssh/id_ed25519" \
    --command="sudo /bin/bash -s -- $site $revision" <<'REMOTE'
set -euo pipefail
site=$1
revision=$2
case "$site" in sa|af|as|au) ;; *) exit 1 ;; esac
test "$revision" = 372f2890cf534dc3988eedeb360c09ac6d56caea
repo=/mnt/data01/ipid-measure
sudo -H -u aweis git -C "$repo" fetch origin "$revision"
directory="/var/lib/ipid-recovery-tools/$revision"
install -d -m 0755 "$directory"
temporary=$(mktemp)
trap 'rm -f -- "$temporary"' EXIT
sudo -H -u aweis git -C "$repo" show "$revision:scripts/backup-interrupted-geo.py" > "$temporary"
install -m 0644 "$temporary" "$directory/backup-interrupted-geo.py"
tool="$directory/backup-interrupted-geo.py"

case "$site" in
  sa) original=/var/log/ipid-recovery/sa-20261113T140459479575969Z.log ;;
  af) original=/var/log/ipid-recovery/af-20261113T140508329972360Z.log ;;
  as) original=/var/log/ipid-recovery/as-20261113T140519645544993Z.log ;;
  au) original=/var/log/ipid-recovery/au-20261113T140531140535507Z.log ;;
esac
test -f "$original"
if grep -Fq 'BACKUP VERIFIED; originals unchanged.' "$original"; then
  echo 'Original backup already complete; no change.'
  tail -n 1 "$original"
  exit 0
fi
for previous in /var/log/ipid-recovery/"$site"-zmap-reference-*.log /var/log/ipid-recovery/"$site"-metadata-finish-*.log; do
  [ -f "$previous" ] || continue
  if grep -Fq 'BACKUP VERIFIED; originals unchanged.' "$previous"; then
    echo 'Backup continuation already complete; no repeat.'
    tail -n 1 "$previous"
    exit 0
  fi
done

active=$(python3 - "$site" "$tool" <<'CHECK'
from pathlib import Path
import sys
site, tool = sys.argv[1:]
active = []
for proc in Path('/proc').glob('[0-9]*'):
    try:
        args = (proc / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
        if proc.stat().st_uid != 0 or tool not in args or '--site' not in args:
            continue
        if args[args.index('--site') + 1] == site and '--handoff-zmap-from-log' in args:
            active.append(proc.name)
    except (OSError, ValueError, IndexError):
        continue
print(' '.join(active))
CHECK
)
if [ -n "$active" ]; then
  printf 'Existing handoff retained, PID(s): %s\n' "$active"
  exit 0
fi
umask 077
log="/var/log/ipid-recovery/$site-zmap-reference-$(date -u +%Y%m%dT%H%M%S%NZ).log"
nohup python3 -u "$tool" --site "$site" --handoff-zmap-from-log "$original" \
  > "$log" 2>&1 < /dev/null &
pid=$!
printf '%s\n' "$pid" > "$log.pid"
sleep 2
if ! kill -0 "$pid" 2>/dev/null; then
  cat "$log"
  if grep -Eq 'BACKUP VERIFIED; originals unchanged.|Original backup already completed' "$log"; then exit 0; fi
  exit 1
fi
printf 'Guarded handoff started, PID=%s\nLog: %s\n' "$pid" "$log"
tail -n 4 "$log"
REMOTE
  then :; else failed=$((failed+1)); echo "Step failed for $site; inspect output before retrying."; fi
done
test "$failed" -eq 0
