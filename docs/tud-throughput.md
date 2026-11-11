# Standalone TUD throughput settings

`make run-all-{icmp,tcp,udp}` supports independent target concurrency for four
phases. Without options, every phase keeps `config/ipid.yaml` unchanged:

```bash
make run-all-icmp ARGS="--rt-inflight-probes 5K --fi-inflight-probes 2K"
make run-all-tcp ARGS="--rt-inflight-probes 4K --fi-inflight-probes 2K --connection-rt-inflight-probes 2K --connection-fi-inflight-probes 2K"
make run-all-udp ARGS="--rt-inflight-probes 4K --fi-inflight-probes 2K"
```

These are provisional starting profiles for 4-vCPU, 3.8-GiB TUD VMs, not a
validated speed or coverage guarantee. Run each command on its own protocol VM.
The FI setting covers Mass, random repeats and fixed base. Connection phases
never inherit the stateless setting. Values accept integers or integer K
suffixes and are validated before discovery. The standalone scanner also
accepts `--number_of_inflight_probes 5K`, validates it before creating output,
and records the effective value in its normal configuration snapshot.

The change does not modify packet rate/bandwidth caps, per-IP sample counts,
RTT deadlines, FI intervals, minimum reply rates or classifier rules. Higher
aggregate concurrency can nevertheless change network/rate-limiter behavior.
Monitor sustained completed IPs/s, valid probes, capture drops/socket errors,
capture age, CPU, available memory, and output growth during the actual run.
Low local packet loss alone does not prove unchanged end-to-end coverage.

## OS settings

The wrapper uses `config/os.yaml` without overriding its resource settings or
timeouts. A smaller starting profile than the 8-vCPU/15-GiB geographic OS VM is
appropriate on the 4-vCPU/3.8-GiB TUD VMs:

```yaml
zgrab2_senders: 10000
dns_chaos_workers: 5000
snmp_workers: 5000
connect_timeout: 3s
read_timeout: 5s
dns_chaos_timeout: 5s
snmp_timeout: 3s
go_memory_limit: 536870912
```

Keep all six service modules enabled. This is an unbenchmarked starting point;
it does not promise the geographic 20K profile's throughput. A Go heap target
is not an overall memory cap: ZGrab2, socket buffers, queues and page cache also
consume memory. Set `ulimit -Sn 131072` in the launching shell (hard limit must
permit it), and retain the existing socket/port preflight checks. To use the
20K geographic profile, provision and validate sufficient memory first.
Measure OS coverage as distinct IPs with a resolved OS / all scanned IPs;
evidence rows, generic vendor labels and ZGrab2 service successes are not this
metric. Conflicting evidence remains ambiguous.

## Full-scale prerequisites

Set `number_of_target_ip_addresses: null` in `config/zmap.yaml`. Use a current
built revision and retain required raw-socket capabilities after rebuilding.
The standalone queues are supported by the existing scheduled analysis worker,
but compete with the running Geo campaign for analysis resources. Keep TUD raw
and workflow objects outside the existing continental campaign namespace.

Standalone `run-all` retains local measurement inputs, and its RT/Mass handoffs
require `upload.delete_local: false`. The geographic controller's cleanup
receipts and automatic bulk cleanup do not apply to this shell wrapper. Do not
enable generic `delete_local` as a workaround: later stages need local files.
About 140 GiB free on ICMP/TCP is not a verified storage budget for discovery,
OS, a 65–100-GB ICMP RT file, Mass and other outputs. Establish enough local
capacity or a separately verified retention solution before a full run.

No change here is applied to an already-running geographic VM or worker.
