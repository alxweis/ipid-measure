# Preserve the interrupted geographic RT measurements

The November 13, 2026 automatic upgrade log on the South America VM explicitly
includes `systemctl restart ... measurement-ipid.service ...`. The retained RT
files must not be declared complete or replaced by a fresh attempt while recovery
is being assessed.

This tool is the preservation stage, **not a scanner resume implementation**.
It sends no probes, changes no scientific settings, and never publishes a
`measurement-complete.json`, workflow completion, or controller retry marker.

## Admission and contents

`scripts/backup-interrupted-geo.py --site sa` runs as root on one of the four
affected VMs. It accepts only the known campaign and retained measurement IDs.
The measurement service must be stopped/failed and no controller or scanner may
be running. The tool holds the same `.runner.lock` flock as `run-continental`.
Do not stop a running measurement to use it.

The backup preserves:

* the original `ipid.pq` and effective `ipid.snapshot.yaml`;
* `state.json`, including the original target and measurement IDs;
* the original ZMap Parquet and snapshot, without repeating discovery;
* a small, PID-filtered export of the scanner's final journal messages.

It checks the retained file's opening/closing Parquet magic. This is not a full
Parquet page/schema validation; that is a separate recovery admission check.

## Destination and verification

Objects are written below:

```
s3://netds3o:aweis/ipid-2/raw/recovery/geo-full-20261107-r1/<site>/icmp/<old-rt-id>/
```

Each source has a `sha256-<digest>/<filename>` key. An existing object is read
and verified rather than overwritten. After upload the tool streams the entire
object back through SHA256 and compares both its size and hash with the local
source. It checks that local sources did not change during the operation.
S3 commands use the measurement user's existing configuration; credentials are
not copied into the backup or printed.

Only after **all six sources** pass read-back verification is a separate
`receipts/sha256-<digest>/backup-verified.json` uploaded and itself read back and
verified. The receipt purpose is explicitly interrupted-RT preservation, not
measurement completion. A successful run ends with:

```
BACKUP VERIFIED; originals unchanged. Receipt: s3://.../backup-verified.json
```

Original files and controller state are never deleted, moved, truncated, or
marked complete. An interrupted/failed backup can be retried: already-uploaded
objects must still pass verification. A backup failure creates no verified
receipt, leaves originals intact, and must be investigated before resumption.

Content-addressed keys and the tool's refusal to overwrite are safeguards of
this tool, not S3 Object Lock or a guarantee against later administrative
deletion. Keep the original VM disks and the verified S3 copies through final
result verification. Upload plus full read-back can take hours; it uses network
traffic in both directions, without making a second bulk copy on the VM disk.

## Protect the service before running any recovery

Ubuntu documents per-service needrestart exclusions at
<https://discourse.ubuntu.com/t/needrestart-changes-in-ubuntu-24-04-service-restarts/44671>.
Install `/etc/needrestart/conf.d/99-ipid-measurement.conf` before upgrades/build
preparation, without restarting the measurement unit:

```perl
$nrconf{override_rc}{qr(^measurement-ipid\.service$)} = 0;
1;
```

This excludes this unit from needrestart-triggered restarts; it does not disable
updates or protect against explicit restarts, reboots, other package scripts,
disk failures, or administrative deletion. Never redeploy/restart the two
unaffected live measurements to apply this file.

## Remaining recovery limits

The old RT files contain successful targets, not a per-target completion ledger.
Their final strict-base terminal counters may allow reconstruction of a started
prefix in the ordered ZMap input, including unsuccessful attempts. This must be
validated against the actual closed-file row counts, original scanner version,
original target file, and final journal counters before a recovery can use it.
Rounded progress percentages are not an exact cursor.

In-flight probe state and samples that were never persisted cannot be recovered
from these files. Neither the backup receipt nor file existence grants permission
to silently treat an incomplete measurement as complete, to skip unknown targets,
or to retry all old failures as if they had never been probed. A recovery tool
must state exactly which population it preserves, retries, or leaves incomplete.

## Validation

Run `python3 scripts/test_backup_interrupted_geo.py` on Linux. Tests use an
isolated fake S3 process and exercise complete read-back, corrupt existing
objects, failed downloads, changed local sources, partial/unexpected source
state, preserved originals, publication ordering, and exclusive controller locks.
