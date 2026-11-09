# Resource profiles for future Geo IPID phases

A running `measure-ipid` process reads its concurrency once. Do not interrupt a
large RT run merely to install this feature. Replacing the scanner executables
atomically and installing an optional workspace policy lets the **next** child
of the already-running Geo controller use a different worker count. The old
controller binary can continue running; it already exports
`IPID_MEASURE_WORKSPACE` and passes the effective workspace config to each child.

This is not IPID resume support and does not make an interrupted RT measurement
complete. `--retry-incomplete` archives an incomplete attempt and starts a new
attempt. It does not skip previously processed targets. ZMap does not need to be
repeated when its existing committed step/config binding is retained.

## Policy and phase selection

The optional file is `<workspace>/config/ipid-runtime.yaml`, for example:

```yaml
version: 1
workspace_binding: "<binding from this workspace's state.json>"
profiles:
  single-rt:
    number_of_inflight_probes: 5K
  single-fi:
    number_of_inflight_probes: 3K
```

These counts illustrate the format, not validated production recommendations or
automatic defaults. Every omitted profile retains the effective `ipid.yaml`
worker count. Without this file behavior is unchanged. An invalid policy fails
before output creation or probing, including invalid **unselected** profiles.
The only allowed resource field is `number_of_inflight_probes` (1 through 1M,
as in the normal IPID config); the upper validation limit is not a safe resource
budget for a measurement VM. Bandwidth, packet rate, timeouts, sampling, requests
per target, minimum reply rates, interfaces and memory limits cannot be changed
through this policy.

| Profile | Applies to |
| --- | --- |
| `single-rt` | Ordinary single-protocol RT, including RT base |
| `single-fi` | Ordinary single-protocol FI: Mass, repeats and FI base |
| `connection-rt` | TCP with established connections, RT |
| `connection-fi` | TCP with established connections, FI |
| `interprotocol-base` | Active interprotocol base |
| `interprotocol-mass` | Active interprotocol Mass |
| `local-reference-base` | Local-reference base |
| `local-reference-mass` | Local-reference Mass |

The binding prevents accidental use of a policy from a differently configured
workspace. Config paths must be the workspace's `config/ipid.yaml` or
`config/interprotocol.yaml`. Ad-hoc invocations without
`IPID_MEASURE_WORKSPACE` do not auto-discover policies. Each applied override
stores the effective worker count plus `runtime_resources` evidence in the
normal uploaded measurement snapshot: policy SHA-256, workspace binding, profile
and previous worker count. This also covers interprotocol/reference snapshots.

## Installing during an existing campaign

1. Preserve the source configs (`<repo>/config/ipid.yaml` and `zmap.yaml`),
   workspace state, cleanup receipts, raw directories and all S3 objects. Do not
   edit the source configs: they form the existing controller binding. Do not
   redeploy or restart the measurement service to enable future-phase profiles.
2. Check out the merged revision and build `cmd/measure-ipid` and
   `cmd/measure-interprotocol` to **new temporary executable paths on the same
   filesystem** as `bin/`. Before installation, verify ownership, executable
   permissions and the capabilities of the deployed originals (`getcap`).
   Apply the required existing capabilities/ownership to the replacements and
   use atomic rename to install them. Do not overwrite the running executable
   in place. Do not replace the active controller or the ZMap/OS executables.
3. Install the policy atomically, using the exact current `state.json` binding
   and only the profiles explicitly selected for this VM. The sidecar is kept
   when `Runner.Prepare` regenerates ordinary workspace configs, so a later
   legitimate controller retry still uses the chosen future-phase policy.
   Completed steps and cleanup receipts remain reusable without signature or
   binding edits. Do not replace an old committed step just to apply a profile.
4. Both scanners support `--check-runtime-resources`. Run this with the same
   workspace environment/config, a valid existing target file and the desired
   phase flags to validate a policy **without creating measurement output or
   sending probes**. Normal interface/capability validation still runs.
5. Verify the next child logs its selected profile and effective worker count.
   Existing scanners keep their old count. A phase that started before policy
   installation also keeps its old count; do not interrupt it just to catch up.

For example, a read-only single-protocol FI/Mass config check (run with the same
privileges/capabilities as the scanner) is:

```bash
IPID_MEASURE_WORKSPACE="$workspace" ./bin/measure-ipid \
  --config "$workspace/config/ipid.yaml" \
  --zmap "$zmap_id" --target-file "$existing_target_file" \
  --connection_count 4 --requests_per_connection 25 \
  --measurement_mode fixed-interval \
  --fixed_interval.request_interval 20ms \
  --fixed_interval.minimum_reply_rate 0.8 \
  --tcp.establish_connection false --analysis_workflow.enable false \
  --check-runtime-resources
```

`--check-runtime-resources` also accepts the normal interprotocol/reference flags
on `measure-interprotocol`. It never selects targets or publishes results.

## Choosing counts and rollback

Measure actual completed/started-IP rate over several minutes alongside CPU,
available RAM, capture drops, socket errors, timeouts and valid-probe fractions.
The per-second `+N` progress field is targets started, not necessarily completed;
wait for a steady in-flight population when comparing it. Under the observed
2K/RT profile, free CPU/RAM and consistently full in-flight capacity suggest
latency-bound work, but do not establish a speedup factor or unchanged coverage.

FI sends many more packets concurrently and may reach the existing bandwidth
limit earlier. Higher worker counts can increase pacing delays, change actual
inter-request timing and trigger target/network rate limits even if the nominal
FI interval is unchanged. Inspect stored send times and coverage on comparable
target populations; do not infer equivalent coverage from an overall fraction
alone. Do not claim that increasing from 2K to 5K guarantees 2.5x throughput.

Change one VM/profile at a time. Do not enable all eight profiles fleet-wide as a
side effect of installing the binaries. Keep bandwidth, timeouts, sample counts
and intervals fixed initially. There is no automatic resource admission or
adaptive live control in this feature. Rollback means atomically removing or
changing the sidecar for **future** children; it does not resize a running pool.

Decide separately whether restarting a particular long RT phase is worthwhile.
At progress `p` and sustained speedup `s`, a complete RT restart beats continuing
only when `s > 1/(1-p)`, ignoring installation/validation time. Use fresh progress
and a measured speedup. Preserve the incomplete attempt and record the change
in measurement methodology; this PR itself restarts no measurement.
