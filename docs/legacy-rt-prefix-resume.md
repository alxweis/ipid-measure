# Resume the four original interrupted Geo ICMP RT prefixes

This is a narrowly admitted recovery for `geo-full-20261107-r1`, sites `sa`,
`af`, `as`, and `au`. Do not apply it to Europe (already running FI-MASS), North
America (ICMP controller complete), TCP, UDP, OS, other campaigns or FI scans.
No default bandwidth, pacing, RTT, sample count, worker count or classification
threshold changes. Normal scanner calls do not activate this mode.

## What is preserved and what is lost

The original successful rows retain every IPID, send/receive timestamp and DF
sample. The original file is never truncated, renamed or removed. A new RT
measurement ID contains copies of those rows plus measurements of the untouched
tail of the original ordered ZMap population. Both source and new result need
local space until the new result is durably published. The ordinary controller
then uses that new ID for classification, FI-MASS and the remaining stages.

The original strict 4x4 RT worker uses one FIFO input channel and one terminal
outcome per target. Its final probe failures plus saved rows reconstruct the
started prefix. Reply drop counters are not target outcomes. This recovery
retains previously attempted failures in the coverage denominator; it does not
retry every address missing from the successful-row file. The final counters,
row counts and full target membership must all agree before any new probes.

Shutdown-related terminal outcomes (`interrupt` plus `limiter_stop`) numbered
4006, 4101, 3967 and 3967 for sa/af/as/au. Their partial samples and per-target
identities were not saved and cannot be restored. They remain unsuccessful.
The resumed dataset spans the interruption and a time gap; it must not be
reported as an uninterrupted scan. Reply/socket diagnostics cover the resumed
segment; successful/attempted/terminal probe totals are cumulative.

## Required safety admission

1. Complete the preservation script from PR #51. Require `BACKUP VERIFIED`,
   not merely an uploaded object or the presence of a local receipt file.
2. Keep the `needrestart` exclusion installed. Leave Europe and running
   measurements untouched; never redeploy the measurement VMs for this change.
3. Require an inactive/failed measurement service, no live scanner/controller,
   and the controller lock to be free. Do not kill an active backup blindly.
4. Allow enough local disk for the old source **and** the new complete result.
   Admission estimates the full result from saved bytes/rows and target rows,
   with 25% headroom and another 8 GiB reserve. The original 180 GB disks may
   require an online enlargement; do not delete the original to pass admission.
5. Build only `measure-ipid` and `run-continental`, and reapply the scanner's
   existing raw-socket capabilities. Package installation/upgrades are not
   part of recovery.

The scanner fetches the small receipt from its content-addressed S3 URI and
requires byte equality with the local receipt. It verifies the known retained
RT SHA256, all preserved local source hashes, the original S3 state/binding,
the unchanged effective configuration and exact ZMap input. Full Parquet scans
reject incomplete sample sequences, unknown/malformed/duplicate addresses and
saved successes outside the claimed started prefix. One IPv4 bitset bounds the
population-validation memory to 512 MiB plus readers/runtime; the temporary Go
memory budget is 2 GiB and is restored before normal probing.

The preservation receipt may reference the original committed ZMap objects
instead of a duplicate recovery upload. In that case admission independently
fetches the exact scoped completion marker, verifies its bound SHA256/identity
and matches both ZMap file hashes/sizes with the receipt. The full local target
hash and population checks still run. Legacy receipts with verified recovery
copies remain supported; uploaded-only IPID receipts are not accepted.

Admission requires local reads of the retained source and original targets.
It is not instantaneous and does not redownload the bulk S3 objects. There is
no guarantee of a particular admission duration or unchanged future coverage.

## Check before starting

Use the original effective snapshot and the exact published local receipt:

```bash
IPID_MEASURE_WORKSPACE="$workspace" ./bin/measure-ipid \
  --config "$workspace/ipid/raw/$old_id/ipid.snapshot.yaml" \
  --resume-from "$workspace/ipid/raw/$old_id" \
  --resume-backup "$receipt" --resume-site "$site" \
  --resume-binding "$binding" --check-resume
```

The check sends no probes and creates no measurement output. It prints admitted
saved/started/total counts and source evidence only after all checks pass. Do
not change the sampling configuration to make an admission error disappear.

## Start through the existing controller

Within the same campaign/site/workspace, add only:

```text
--retry-failed --resume-legacy-rt /absolute/path/to/backup-verified-TIMESTAMP.json
```

Never combine with `--retry-incomplete`. The controller preserves the original
step in `state.json` under `rt_recoveries`, chooses a new ID and fsyncs the
old/new mapping before invoking the scanner. The scanner admits and copies the
old results before receivers/workers start; then seeks the validated original
target file to the exact started-prefix boundary. The new `resume-evidence.json`
is uploaded and included in the raw completion evidence. No completion is
published until the tail and ordinary upload finish successfully.

If admission fails before output creation, correct the cause and reuse the
same explicit receipt. If a resumed output directory already exists without
durable completion, recovery refuses to overwrite or silently replace it.
Preserve that **additional** progress and reassess its checkpoint separately;
this PR is not a general arbitrary-crash checkpoint engine. Existing committed
new results are reused, including the normal verified cleanup-receipt path.

Other sites' UDP controllers require their own ordinary `--retry-failed` once
the local ICMP/TCP/UDP publications are ready. This RT recovery does not start
other VMs, reset ZMap, repeat finished protocol scans or restart the OS scan.
