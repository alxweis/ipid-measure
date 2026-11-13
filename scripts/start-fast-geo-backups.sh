#!/usr/bin/env bash
set -euo pipefail
revision=${1:?Pass the reviewed 40-character commit SHA}
failed=0
for entry in sa:southamerica-east1 af:africa-south1 as:asia-east2 au:australia-southeast1; do
  site=${entry%%:*}
  region=${entry#*:}
  printf '\n=== %s: S3-Upload beschleunigen ===\n' "$site"
  if gcloud compute ssh "ansible@ipid-gc-$region-icmp" \
    --project=jmuecke-ipid-imc-2026-10 --zone="$region-a" \
    --ssh-key-file="$HOME/.ssh/id_ed25519" \
    --command="sudo /bin/bash -s -- $site $revision" <<'REMOTE'
set -euo pipefail
site=$1
revision=$2
case "$site" in sa|af|as|au) ;; *) exit 1 ;; esac
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
state=$(systemctl show measurement-ipid.service -p ActiveState --value)
case "$state" in inactive|failed) ;; *) echo "Messdienst aktiv: $state; nichts umgestellt."; exit 1 ;; esac
repo=/mnt/data01/ipid-measure
sudo -H -u aweis git -C "$repo" fetch origin "$revision"
tools="/var/lib/ipid-recovery-tools/$revision"
install -d -m 0755 "$tools"
/usr/bin/python3 - "$revision" "$tools" <<'INSTALL'
from pathlib import Path
import subprocess
import sys
revision, destination = sys.argv[1], Path(sys.argv[2])
if destination.is_symlink() or destination.resolve() != destination:
    raise SystemExit('Unerwarteter Werkzeugpfad; keine Änderung.')
for name in ('backup-interrupted-geo.py', 'accelerate-geo-backup.py'):
    data = subprocess.run(
        ['sudo', '-H', '-u', 'aweis', 'git', '-C', '/mnt/data01/ipid-measure',
         'show', revision + ':scripts/' + name],
        check=True, capture_output=True,
    ).stdout
    path = destination / name
    if path.exists():
        if path.is_symlink() or path.read_bytes() != data:
            raise SystemExit('Abweichende Werkzeugdatei; nichts überschrieben.')
    else:
        with path.open('xb') as stream:
            stream.write(data)
INSTALL
umask 077
install -d -m 0700 /var/log/ipid-recovery
stamp=$(date -u +%Y%m%dT%H%M%S%NZ)
log="/var/log/ipid-recovery/fast-$site-$stamp.log"
nohup /usr/bin/python3 -u "$tools/accelerate-geo-backup.py" --site "$site" \
  > "$log" 2>&1 < /dev/null &
pid=$!
printf '%s\n' "$pid" > "$log.pid"
sleep 2
if kill -0 "$pid" 2>/dev/null; then
  printf 'Beschleunigung gestartet: PID=%s\nLog: %s\n' "$pid" "$log"
  tail -n 4 "$log"
else
  wait "$pid"
  cat "$log"
fi
REMOTE
  then :; else failed=$((failed + 1)); echo "Start für $site fehlgeschlagen; andere Standorte werden geprüft."; fi
done
printf '\nFehlgeschlagene Starts: %s\n' "$failed"
[ "$failed" -eq 0 ]
