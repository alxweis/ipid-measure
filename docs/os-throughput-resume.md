# Faster geographic OS scanning without repeating completed IPs

The geographic campaign can contain hundreds of millions of distinct IPs. A
DNS CHAOS pool of 1000 workers with a five-second timeout processes about
200 timeout-bound targets/s. Since the input fanout uses bounded queues, it
also limits how far zgrab2 and SNMP can run ahead. At 419954422 targets this is
roughly 24 days, despite free CPU and RAM.

## Resource profile for the current 8-CPU / 16-GiB OS VM

Keep all six modules and the existing timeouts. Start with these **explicit
operator settings**, not hidden overrides in the worker:

```yaml
zgrab2_senders: 10000
dns_chaos_workers: 10000
snmp_workers: 10000
go_memory_limit: 2147483648
```

The Go heap budget is 2 GiB. It is a soft runtime budget, not total process or
zgrab2-child RSS. The existing 10000-worker configuration maxima remain.
DNS timeout-bound capacity becomes nominally 2000 targets/s; SNMP's three-second
timeout permits nominally 3333/s. These are component capacities, **not an
end-to-end throughput guarantee**. TCP handshakes, networking and local resource
limits can become the next bottleneck. Measure actual `os: completed` deltas.
The zgrab2 counter counts module scans and must not replace the common completed
IP count when estimating campaign duration.

Before launching the worker, raise its shell's soft file limit to 65536 (the
current hard limit is 1048576). The scanner checks its actual Unix file limit,
conservative TCP/UDP descriptor requirements, and Linux ephemeral-port headroom
before sending probes. The observed 32768..60999 range permits 20000 configured
UDP workers plus headroom. Other processes and reserved/occupied ports can still
reduce actual availability. Do not change kernel networking limits blindly.

No deployed default, module, timeout, target count or scanner packet is changed
by this PR. Persist the chosen resource settings in the OS VM's infrastructure
configuration separately so a later deployment does not restore the old pool
sizes. Do not redeploy the 18 measurement VMs to change this OS-only profile.

## What is preserved

`--resume-incomplete` on `continental-os-worker` retains the closed old attempt
and starts a separate measurement ID. `measure-os --resume-from OLD_DIRECTORY`
copies its evidence rows and per-IP observations, rebuilds coverage from the
stored masks, and dispatches only targets absent from the completed-IP set.
This includes targets with **no evidence**, ambiguous targets, and unclassified
targets. Old banners/tags are copied, not reclassified. The original full union
remains the authoritative target population and final coverage denominator.

Import fails before any new probes if schema/classifier, modules, timeouts,
SNMP community or target binding differ; files must have valid Parquet footers.
Duplicate completed IPs, missing/duplicate evidence rows, invalid status/masks
and completed IPs outside the target input are rejected. Input and source checks
read Parquet in bounded batches. Two sparse IPv4 bitsets need at most 1 GiB
combined during import; only the completed-IP set remains for dispatch.

`os-resume.json` records source hashes, target hash, the old effective snapshot
and restored counts. It is published separately and referenced by an optional
`resume` field in `os/done.json`; the existing **four-entry** `files` contract
is preserved for the deployed analysis consumer. No analysis deployment is
needed just to consume this resumed scan.

A second resume requires a committed previous import. If interrupted during
import, the older source remains intact; do not treat the partly copied output
as a new checkpoint. Retain it for diagnosis and recover from the retained
source recorded in `scan.json` rather than erasing state.

After a resume, `completed` includes restored targets; `elapsed` measures the
new process lifetime. Use **new completion deltas** for speed/ETA calculations.
In-flight targets without a complete retained observation may be probed again.

## Operator recovery for an already running scan

1. Let all measurement VMs and the analysis worker continue. Keep the same
   campaign ID, union file and pinned `request.json`.
2. After this PR is merged, fetch/pin the new measurement revision on the OS VM.
   Build `make build-os build-continental-os-worker` **while the old scan is
   still running**. Building/replacing Go binaries does not alter the running
   Linux process. Preserve a copy of `config/os.yaml` and `scan.json`.
3. Apply only the explicit concurrency/heap settings above to `config/os.yaml`.
   Keep the old timeouts and all modules. The active process keeps its existing
   configuration until it exits.
4. From a second OS-VM shell, identify the single `measure-os` child for this
   campaign and send **SIGTERM to that child**. Do not Ctrl+C the outer worker:
   cancellation of its subprocess command can kill the child before it closes
   Parquet files. Wait for both scanner and old worker to exit naturally.
   An interrupted-scan error and an OS failure marker are expected here.
5. Verify the retained source before continuing (example workspace below):

```bash
cd /mnt/data01/ipid-measure
workspace=/mnt/data01/ipid-measure/continental/geo-full-20261107-r1/os
source_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$workspace/scan.json")
reference=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reference_zmap"])' "$workspace/request.json")

./bin/measure-os --config config/os.yaml \
  --zmap "$reference" --target-file "$workspace/targets.pq" \
  --record-target-status --resume-from "$workspace/os/raw/$source_id" \
  --check-resume
```

`--check-resume` creates no measurement and sends no probes. Full population
and evidence/observation consistency checks also run during the actual import.

6. In the original OS-worker Screen session, after it returned to the prompt:

```bash
cd /mnt/data01/ipid-measure
export PATH="/mnt/data01/bin:/snap/bin:$PATH"
ulimit -Sn 65536
make workflow-os-worker CAMPAIGN_ID=geo-full-20261107-r1 \
  ARGS="--s3-prefix s3://netds3o:aweis/ipid-2/analysis-workflow --poll-interval 2s --retry-failed --resume-incomplete"
```

`--retry-failed` archives only this OS job's existing failure marker and
requires that marker to exist. If no marker was published, inspect the old
worker's error and omit that flag rather than deleting data or fabricating
status. `--resume-incomplete` is mutually exclusive with `--retry-incomplete`,
which deliberately starts a fresh scan and does not reuse completed targets.

Expected logs include `restored N completed targets ... scanning remaining M`
with `N + M` equal to the original target count. Check actual completed-IP
throughput and socket/resource errors after startup. Keep every retained source
until the final OS result has been verified and published.

## Validation

Tests exercise exact evidence/observation preservation, no-evidence and ambiguous
targets, changed resource versus scientific settings, duplicate/missing records,
unclosed files, membership checks, interrupted scans and higher-concurrency
resumption, all-targets-already-complete recovery without launching scanners,
and retrying a failed publication without repeating probes. Unix admission
tests cover insufficient descriptor/port budgets.

Local synthetic benchmarks do not scan public networks. A one-million-target
import with 500000 retained observations took about 0.32 seconds on the local
test machine. A loopback DNS timeout benchmark improved from about 17420 to
49982 completions/s when increasing its pool from 100 to 1000 workers (5 ms
test timeout). These figures verify local mechanics and are **not** forecasts
for the production five-second, six-service Internet scan.
