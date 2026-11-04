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
