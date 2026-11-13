# Accelerate the retained November 13 Geo backups

`scripts/accelerate-geo-backup.py --site as` is an additive, bounded upload-only
handoff for the four known interrupted ICMP runs. Run it as root with
`backup-interrupted-geo.py` from commit
`925067f98b37380f96bc16380d2981e721010066` in the same directory. It does not
restart a measurement or modify the measurement checkout/configuration/state.

The tool uses a pinned official rclone v1.76.0 Linux amd64 archive, verified
against its GitHub release SHA256 digest. It downloads/extracts that binary
under `/var/lib/ipid-recovery-tools/fast-backup`; no package upgrade is run.
The existing `aweis` S3 credentials are read into child-process environment
variables, never printed, put in command arguments, or written to a new config.
The endpoint is restricted to the already configured ZIH S3 service.

`bash scripts/start-fast-geo-backups.sh <reviewed-commit-sha>` runs on the
Ansible VM and launches the four helpers in the background over SSH. It fetches
the pinned helpers into a separate root-owned tool directory without checking
out or overwriting measurement code. Logs are `/var/log/ipid-recovery/fast-<site>-*.log`.

## Transfer policy

* Eight 32 MiB parts concurrently, one file at a time: approximately 256 MiB
  multipart buffers, plus normal client overhead.
* Disable the additional whole-file MD5 metadata pre-read. Retain rclone's
  normal transfer checks and post-upload HEAD; do not use `--s3-no-head`.
* Do not perform any full-object read-back or a new whole-source SHA256 pass.
* Use `copyto`, immutable destinations and fresh `fast-<timestamp>-<uuid>`
  paths. Never use `sync`, `move`, deletion, or incomplete-upload cleanup.
* Preserve every local original and existing remote object/old incomplete part.
  Existing completed objects recorded in the old log are reused when their
  size matches. A mismatch aborts without overwriting.

Before interrupting an old backup, check the known source/state, inactive
measurement service, rclone credentials/connectivity, available RAM and a
256 MiB multipart test from RAM. The test data is retained too.

Read completed old multipart-part sizes and times from S3. If at least half
the RT object is already uploaded, retain that uploader until it completes.
When the previous rate is known, replace it only if the measured rclone test
(capped at a conservative 20 MB/s disk allowance) predicts at least a 40%
reduction and ten minutes saved. With no completed parts, replace only after
a successful test at >=5 MB/s. Unknown rates with existing progress are kept.
These are conservative estimates, not a guaranteed speed-up: RAM tests and
the production disk have different behavior and compete with current uploads.

For a retained uploader, poll until its completed RT object becomes visible,
then stop the old parent/read-back process and reuse the object. For a clear
replacement, the old upload is stopped, its completed parts remain, and rclone
starts the RT file at a separate destination. It does **not** import s3cmd's
multipart session. The stop operation checks PID start times, UID, command,
site and all descendants; unknown processes abort the handoff and continue
the old parent. Measurement services/probes are never signalled.

After the handoff, acquire the existing controller flock before reading the
sources for upload. Check file identity/size/mtime before and after each copy.
If any operation fails, preserve originals and report failure; do not publish
a success receipt. A failed replacement may require rerunning this helper or
another explicit backup action: it does not restart the old backup automatically.

## Completion and verification level

All six original sources are included: IPID Parquet/snapshot, ZMap
Parquet/snapshot, controller state, and original scanner journal. A unique
`backup-uploaded.json` records exact S3 URIs, sizes, source identities and the
original configuration binding. A reused RT object can remain at its original
`sha256-...` URI, referenced by the new receipt.

Successful completion says:

```
BACKUP UPLOADED; originals unchanged; size checks only. Receipt: s3://...
```

This is deliberately **not** `BACKUP VERIFIED`: it confirms successful client
upload and matching remote object sizes, not an independent full remote SHA256
read-back. It does not assert full Parquet validity or measurement completion.
No `measurement-complete.json`, controller success, or analysis job is forged.
The retained VM disks and separate S3 objects remain necessary during recovery.

## Tests

Run `sudo python3 scripts/test_accelerate_geo_backup.py` on Linux. Tests cover
real isolated process-tree handoffs and refusal of unknown children/PID reuse,
failed preflights, completed object reuse, source retention, conservative speed
decisions, failed uploads without success receipts and credential isolation.

Reference: https://rclone.org/s3/#multipart-uploads
