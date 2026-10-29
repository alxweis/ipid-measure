# Six-site campaigns

This mode is additive. `make run-all-icmp`, `make run-all-tcp` and
`make run-all-udp` keep their existing script, OS scans and S3 workflow.
The new mode requires the companion continental worker in `ipid-analysis`.
Deploy the analysis change first. No VM or Ansible changes are included.

## Explicitly running without OS scans

OS scanning remains enabled unless explicitly disabled. After deploying the
optional-OS updates in **both repositories**, use:

```sh
# Existing single-protocol workflow; ICMP and UDP support the same option.
make run-all-tcp SKIP_OS=1
# Resume from an existing discovery with the same persisted OS policy.
make run-all-tcp ZMAP_ID=tcp-80_YYYY-MM-DD_HH-MM-SS SKIP_OS=1

# Geographic mode: all six sites must agree on this immutable campaign policy.
make run-all-eu CAMPAIGN_ID=round-without-os SKIP_OS=1
```

The underlying `run-all.sh`, `run-continental` and `publish-analysis-job`
commands also accept `--skip-os`. `SKIP_OS` accepts `0` (default) or `1`;
`--skip-os` cannot be combined with an OS measurement ID. Omitting the option
never means that a missing/failed OS scan is intentionally disabled.

The protocol workflow records `analysis-jobs/<zmap-id>/os-policy.json` locally
and in S3 **before** OS/IPID steps. It checks existing legacy manifests as well.
A restart must retain that mode; changing mode requires a new ZMap/campaign ID.
The final manifest omits the OS measurement ID and includes
`"os_status": "not_requested"`. The analysis request carries the same explicit
status and an empty OS prefix; no OS configuration file is required in this mode.
Measurement parameters, repeat counts and all non-OS analyses remain unchanged.

A geographic opt-out is persisted as `"os_mode": "disabled"` in `campaign.json`
and `os/not-requested.json` with status `not_requested`. Legacy descriptors
without `os_mode` still mean **enabled**. No discovery union/OS request is built,
and neither the analysis worker nor an accidentally started OS worker waits for
`os/request.json` or `os/done.json`. Each site's final non-OS analysis can start
after its own measurements, independently of other sites' discovery completion.
Site and campaign completion explicitly retain `not_requested`; they do not
fabricate OS completion or OS coverage/plots. All IPID/interprotocol work remains.

Normal measurement/analysis retries continue to apply with the original mode.
There is no OS scan/failure to retry for an opted-out campaign. Existing enabled
campaigns, including descriptors created before this option, keep their OS gates.

## Start a campaign

Build using the normal `make setcap` procedure. Keep the existing per-VM
interface, probe and S3 configuration in `config/*.yaml`. ZMap and IPID upload
destinations must end in `/zmap/` and `/ipid/` below the same raw root.
All six sites and the OS VM must use the same workflow prefix/raw root.
Use a **new explicit campaign ID for each round**; never infer a round from
wall-clock timestamps. Example, on the European VM:

```sh
export IPID_CAMPAIGN_ID=round-2026-10-26-a
make run-all-eu
```

Use `run-all-as`, `run-all-af`, `run-all-na`, `run-all-sa` and `run-all-au`
on the other VMs with that same campaign ID. `CAMPAIGN_ID=...` as a make
argument is equivalent. One kernel lease prevents concurrent runs of the same
site on a VM. Site codes describe vantage points, not a destination-IP filter.

On the **separate OS VM**, build the same repository and run:

```sh
export IPID_CAMPAIGN_ID=round-2026-10-26-a
make workflow-os-worker
```

This waits for this campaign's OS request, scans once and exits after successful
publication. `ARGS="--once"` only checks the queue once. The workflow prefix is
read from `config/ipid.yaml`, or explicitly from `IPID_ANALYSIS_S3_PREFIX` /
`--s3-prefix`. ZGrab2 and the existing six-service OS dependencies are required
on the OS VM. The analysis VM continues to run `make workflow-worker`.

## Ordering and dependencies

Each site performs three protocol-specific ZMap scans (ICMP, TCP/80,
UDP-DNS/53), publishes `discovery.json`, and immediately starts the regular
IPID workflows in ICMP → TCP → UDP order. Each protocol retains the existing
RT 4×4, Mass 4×25, five Mass reproducibility repeats and sampled fixed Base
4×4; TCP also retains its two connection measurements. RT/Mass target handoffs
use the existing verified request/response implementation.

After each protocol, an immutable normal manifest and a `strategy-jobs` request
allow the analysis worker to prepare its canonical RT+Mass merge. Only this
preliminary merge is needed for `strategies-ready.json`; it is **not final
analysis completion**. After all three protocols, the existing exclusive
interprotocol target selection and all four protocol groups × Base/Mass are
performed. Empty groups remain valid empty Parquet targets. The site then
publishes `final/request.json`; final analysis is asynchronous.

Independently, the analysis VM unions all 18 discoveries only after all six
site discovery markers exist. The OS VM scans that unique union once. A site's
three final analyses require that shared OS completion and its own complete
measurement workflow. Other sites' IPID workflows need not have finished.
Site completion also requires the site's interprotocol analysis. Campaign
completion requires all six site completions.

## Storage and provenance

The controller generates isolated configuration/checkpoints under
`continental/<campaign>/<site>/` locally. Original config files are unchanged.
Raw S3 layout is:

```text
<raw>/continental/<campaign>/<site>/zmap/<legacy-id>/...
<raw>/continental/<campaign>/<site>/ipid/<legacy-id>/...
<raw>/continental/<campaign>/os/shared-os/...
```

The control namespace is `<workflow>/continental/<campaign>/`, with an immutable
`campaign.json`, `sites/<site>/{discovery.json,strategy-jobs,analysis-jobs,jobs,
interprotocol-target-jobs,interprotocol-jobs,final}` and `os/{request,done,failed}.json`.
Measurement IDs and scientific Parquet schemas remain unchanged. Scope prevents
same-second IDs on different sites from colliding. Closed raw files/snapshots
have SHA-256 evidence in a `measurement-complete.json` published **after sync**.

The shared OS dataset is stored once, with its real scan ID, all 18 source
references, union checksum and explicit `shared-os-vm` vantage in completion
provenance. `os.pq` and legacy OS coverage retain their semantics. The optional
`os-observations.pq` adds one row for every target, including response-only and
nonresponding targets omitted from `os.pq`. Its response/evidence/tag masks use
bits 0–5 for SSH, SMB, HTTP, HTTPS, SNMP and DNS. The analysis worker reconstructs
each site's protocol coverage from this sidecar and its own ZMap set. A shared
OS vantage must not be described as a regional OS observation.

## Restart and failure recovery

Rerun the same command, campaign and unchanged configuration to resume.
Completed raw steps are adopted only after local files match their committed
size/SHA-256 evidence. A lost successful process response does not repeat the
measurement. Keep the local workspace: automatic recovery from disk loss is
outside this implementation. Configuration changes during a resumed round are
rejected; use a new campaign for intentional changes.

An uncertain **uncommitted** site attempt is retained and stops the run. After
inspection, `make run-all-eu ARGS="--retry-incomplete"` archives it locally and
starts that step with a new measurement ID. It never deletes S3 data or reuses
an identity whose old handoff might already be complete.

### Recovery from a ZMap upload failure

The `Destination S3 URI must end with '/'` error (s3cmd exit 64) occurs
after ZMap has closed its output but before the scoped raw completion marker
is created and uploaded. The central uploader now normalizes only the sync
destination to end in exactly one `/`. The source directory argument is
unchanged: its basename still produces
`<raw>/continental/<campaign>/<site>/zmap/<measurement-id>/...`.
Classic destinations already ending in `/` retain the same behavior.

The existing Geographic CLI cannot republish such an uncommitted ZMap result
without scanning again. A closed parquet file and snapshot alone are not the
durable, verified completion required by the runner; simply rerunning the
command stops at `uncommitted`. There is no publish-existing-only command.
Do not fabricate a completion marker or edit `state.json` to bypass this
check. No new recovery mechanism is introduced for this transport fix.

After updating to the fix, rebuild the measurement binaries (on each affected
measurement VM, `make setcap` rebuilds and reapplies their usual capabilities).
Retain the same campaign, site, configuration, OS policy and local workspace.
For the two failed No-OS test runs, the supported explicit restart is:

```sh
# On the EU VM:
make run-all-eu CAMPAIGN_ID=geo-test-200k SKIP_OS=1 ARGS="--retry-incomplete"
# On the AS VM:
make run-all-as CAMPAIGN_ID=geo-test-200k SKIP_OS=1 ARGS="--retry-incomplete"
```

This **does run ZMap again**, with a new measurement ID. The original local
directory is preserved byte-for-byte under
`continental/geo-test-200k/<site>/attempts/zmap-icmp-<old-measurement-id>/`.
Previously committed steps are still verified and adopted without reprobing.
The flag applies to any uncommitted step encountered, so inspect retained
attempts before using it later in a campaign. No S3 data, prior completion
markers or immutable campaign policy are deleted or rewritten. For this
first-discovery upload failure, no Analysis-worker retry is needed: the site's
three-protocol discovery event has not yet been published.

Analysis failures retain the existing explicit archive-and-retry procedure.
See the companion analysis guide for scoped request URIs. On the OS VM:

```sh
make workflow-os-worker ARGS="--retry-failed"
# If the scan itself was interrupted before its closed-file marker:
make workflow-os-worker ARGS="--retry-failed --retry-incomplete"
```

Only this campaign's terminal OS failure is archived/removed. Successful
markers and source data are preserved. If scanning completed but uploading
failed, retry uploads the verified closed local files without rescanning.
An OS failure does not prevent the other sites' critical IPID handoffs.

## Validation still required before a full campaign

Unit/integration tests use synthetic data and fake S3/measurement commands.
Run a small isolated real S3/FUSE campaign first, including all six sites, an
OS-worker restart and an analysis-worker restart. Then measure peak RAM,
scratch and critical-handoff latency with overlapping campaigns. No production
S3 objects or actual Internet scans are accessed by these tests. Increasing
background parallelism or changing probing/classification algorithms is not
part of this change.
