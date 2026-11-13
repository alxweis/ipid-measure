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
* references to the already committed original ZMap Parquet and snapshot;
* a small, PID-filtered export of the scanner's final journal messages.

It checks the retained file's opening/closing Parquet magic. This is not a full
Parquet page/schema validation; that is a separate recovery admission check.

## Destination and verification

Objects are written below:

```
s3://netds3o:aweis/ipid-2/raw/recovery/geo-full-20261107-r1/<site>/icmp/<old-rt-id>/
```

Each newly backed-up source has a `sha256-<digest>/<filename>` key. An existing object is read
and verified rather than overwritten. After upload the tool streams the entire
object back through SHA256 and compares both its size and hash with the local
source. It checks that local sources did not change during the operation.
S3 commands use the measurement user's existing configuration; credentials are
not copied into the backup or printed.

ZMap is already published below the original raw campaign/site/zmap/measurement
directory. The tool reads its scoped `measurement-complete.json`, verifies its
identity and SHA256 evidence, checks both local and remote object sizes, and
hashes the small local snapshot. It does not upload or download the ZMap body.
The receipt binds those two original URIs and the completion-marker SHA256 in
`zmap_reference`. The RT resume admission independently hashes the entire local
target file and validates its population before probing. Missing/mismatched
original commits are errors, never an automatic duplicate-upload fallback.

Only after **all six sources** have the corresponding read-back/reference evidence is a separate
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

## Private metadata access and failed metadata-upload continuation

The original root-run tool created its private recovery-backup directories and
journal/receipt files without making them readable to the aweis uploader. With
a restrictive umask, s3cmd could fail on the frozen journal after all bulk data
had already passed full read-back. A final receipt would have had the same issue.

Prepare narrow Linux access/default ACLs on **only** recovery-backup and the
known measurement's metadata directory. The uploader gets traversal/read access,
not write access or world access; future root-created receipts inherit read
access even with umask 077. Original raw Parquet/snapshot/state permissions and
contents are untouched. The tool uses the existing libacl through ctypes, with
no package installation or running-process restart on measurement VMs.

Use --repair-metadata-access-only for the known site to repair existing small
metadata and future creation rights while its old backup process keeps running.
This mode takes no runner lock because it changes only these private metadata
ACLs, and it still refuses an active measurement service/controller. It never
stops a backup, downloads/uploads objects or changes scientific state.

For an already failed attempt, --continue-from-log /var/log/ipid-recovery/SITE-TIMESTAMP.log
holds the controller lock and requires the private root-owned original log. It
accepts only an unambiguous frozen journal and matching full read-back proofs
for IPID, its snapshot and the original state. It reuses the earlier bulk SHA256
proofs, checks current local/S3 bulk sizes and hashes the small metadata, then uploads/verifies
only missing journal metadata and a new six-file receipt. The receipt binds the
original verification log's digest. It refuses changed local originals, missing
or truncated remote objects, mismatched proofs, incomplete proof sets and
writable/untrusted logs; no automatic full bulk retry is attempted.

This reuses completed full read-backs from the same attempt; it does **not**
perform fresh full downloads or local rehashes of those bulk objects. The
receipt explicitly labels this scope. RT resume admission must independently
rehash current local bulk files before probing. As in the original tool,
content-addressed keys are not S3 Object Lock. A later administrative equal-size
overwrite is outside the size check's guarantee. Retain original disks and
copies; the completion line appears only after all six files have verified
proofs/references and the new receipt itself is uploaded and read back successfully.

## Skip the redundant ZMap stage in a currently running old backup

`--handoff-zmap-from-log /var/log/ipid-recovery/SITE-TIMESTAMP.log` checks the
original committed ZMap first, then repairs metadata ACLs and watches the trusted
old attempt. It leaves IPID upload/full read-back running until IPID, snapshot
and state have all printed their matching full verification proofs. Only then
does it freeze and validate the exact old backup PID/start-time/owner/argv and
its S3-only descendant tree before terminating that obsolete backup stage.
It does not signal measurement services, controllers or scanners. Unknown or
reused process identities are refused. A separate watch lock prevents duplicate
watchers; the controller lock is acquired only for final continuation.

If the original ZMap duplicate has already finished, the old backup is allowed
to finish its tiny metadata naturally. If that attempt already failed at the
journal upload, continuation reuses its proofs immediately. No original source
or existing S3 object is removed. A failed old attempt without the three required
proofs is refused; this mode never silently repeats the expensive IPID backup.

CI runs the preservation tests as root, requires POSIX ACL support, and uses a
real unprivileged nobody process to prove existing and future metadata are
readable but not writable. Local WSL1 may skip that one ACL test; CI may not.

