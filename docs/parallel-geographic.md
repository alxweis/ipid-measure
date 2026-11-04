# Protocol-specific geographic VMs

Deploy the companion ipid-analysis parallel queue support first. Existing
`run-all-{icmp,tcp,udp}` and `run-all-{eu,as,af,na,sa,au}` remain supported.
Use a new explicit campaign identity for the additive layout. Do not mix the
six-VM and protocol-specific controllers in one campaign.

On each of the 18 VMs, build with `make setcap` and configure the ordinary
ZMap/IPID YAML files, two assigned source addresses and the shared S3 roots.
For example:

```sh
make run-all-eu-icmp CAMPAIGN_ID=round-18
make run-all-eu-tcp CAMPAIGN_ID=round-18
make run-all-eu-udp CAMPAIGN_ID=round-18
```

The same suffixes exist for `as`, `af`, `na`, `sa`, and `au`. `ARGS` forwards
controller flags. Each command discovers and probes only its own protocol.
ICMP and TCP finish independently; UDP subsequently owns its continent's mixed
interprotocol measurements and needs permission/configuration to use all three
protocols. Each VM still needs both local source IPv4 addresses.

Raw measurement parameters, RT/Mass handoffs, five frozen-cohort repetitions,
fixed-base sampling and TCP connection measurements retain their definitions.
Every completed measurement also publishes a streaming analysis event. The
analysis worker prepares each discovery separately and dispatches the shared
OS scan only after all 18 prepared inputs are committed. Measurement VMs do not
wait for that scan. Use the normal separate OS VM and `make workflow-os-worker`
with the same campaign ID. Explicit `SKIP_OS=1` must match on all 18 VMs.

Local state/config copies live below `parallel/<campaign>/<site>/<protocol>/`.
Raw S3 paths retain `continental/<campaign>/<site>/{zmap,ipid}/<id>/`; normal
IDs include their protocol, so distinct protocol writers cannot collide.
Each writer owns only its `sites/<site>/protocols/<protocol>/` control queue.
The immutable `parallel.json` distinguishes this layout from six-VM campaigns.
Interprotocol control remains at `sites/<site>/interprotocol-*` and is UDP-owned.

Resume with the same command/configuration/workspace. Verified raw completion
markers are reused. Changed parameters fail rather than silently remeasure.
An uncommitted attempt requires `ARGS="--retry-incomplete"`, retaining the old
directory. Terminal controller failures require an explicit
`ARGS="--retry-failed"` (combine both flags for an interrupted measurement).
Inspect failures first; retries never erase successful raw objects.

The analysis stages, early core results, OS-only results and continent completion
have separate completion markers. A finished protocol measurement controller is
not final scientific completion. No cross-continent scientific aggregation is
introduced.

## Local interprotocol references

New parallel campaigns pin `local_references: true` in `parallel.json` and
publish `local-references.json` as the scheduler's completion dependency.
Deploy the companion reference consumer before starting a fresh campaign.
Do not upgrade an already started campaign from the foundation-only layout;
its immutable layout marker intentionally prevents changing its experiment.

After the three local protocol sweeps and their strategy merges, the UDP VM
downloads the original four target files plus six additive target files named
`reference-<icmp|tcp|udp>-<base|mass>-targets.pq`. Each reference population is
the deduplicated union of the original groups involving that protocol, split
into BASE (five deterministic strategies) and MASS (MULTI/RANDOM). No original
group is filtered or reclassified.

Before the eight existing interleaved measurements, it runs, in order:
ICMP BASE, TCP BASE, UDP BASE, ICMP MASS, TCP MASS, UDP MASS. These controls use
`measure-interprotocol --local-reference --protocols <one protocol>` and the
same UDP-VM configuration, two source IPv4 addresses, request-IPID indexing,
TCP flags/ports, zero retries and sampling rules as the interleaved probes.
BASE is RT-based 4x4; MASS is fixed-interval 4x25 with minimum reply rate 0.8.
Only the number of interleaved protocols changes. No probes run concurrently
on the UDP VM during this phase; the other continents remain independent.

Reference IDs are `interprotocol-<protocol>_<timestamp>_<sample>`, distinct from
all original single-protocol and mixed-group IDs. Under the usual local
`ipid/raw/<id>/` and raw S3 prefix they write `interprotocol.pq`,
`interprotocol.snapshot.yaml`, logs, target symlink and the existing raw commit
marker. A completed reference immediately publishes
`sites/<site>/reference-jobs/reference-<protocol>-<sample>/request.json` with
the raw identity and target size/hash. After all six, the UDP VM publishes
`sites/<site>/reference-comparison/request.json`. Existing per-step checkpoint
and explicit retry rules apply; a failed event upload does not repeat probes.
Empty cohorts produce valid empty measurements and analysis artifacts.

Each continent therefore adds six local measurements, with no changes to its
26 original IPID measurements or eight original interprotocol measurements.
