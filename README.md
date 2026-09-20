# ipid-measure

A high-throughput active-measurement toolkit for IPv4. It runs as a three-stage
pipeline:

1. **zmap** — discover responsive hosts (wraps the `zmap` scanner).
2. **os** — fingerprint their operating system from service banners
   (`zgrab2` + in-process DNS CHAOS and SNMP probes).
3. **ipid** — sample how each host selects its IP-ID field.

Each stage writes a Parquet file. `os` and `ipid` consume the host set produced
by a `zmap` run, referenced by that run's **measurement id**.

---

## Requirements

- Linux with `AF_PACKET` raw sockets.
- **Go >= 1.25**
- **libpcap headers** (the `ipid` capture path links libpcap via
  `gopacket/pcap`):
  ```bash
  sudo apt-get install libpcap-dev      # Debian/Ubuntu
  ```
- The **external scanners on `$PATH`**, used by the `os` and `zmap` stages:
  `zmap` and `zgrab2`. Install them from their upstream projects
  (github.com/zmap/{zmap,zgrab2}) so both are callable by name.
- For the `ipid` stage: **one interface with two source IPv4 addresses**.

---

## Build

```bash
make           # builds bin/measure-zmap, bin/measure-os, bin/measure-ipid
```

`make build-zmap` / `build-os` / `build-ipid` build a single binary.

The `zmap` and `ipid` binaries need raw-socket capabilities. Either run them as
root, or grant file capabilities once:

```bash
make setcap    # builds, then setcap cap_net_raw,cap_net_admin+ep on the binaries
```

> `go build` writes a fresh binary and drops file capabilities each time, so run
> `make setcap` (not a bare `make`) whenever you rebuild before measuring. The
> `make run-*` targets deliberately do **not** rebuild, so they keep the
> capabilities in place.

Other targets: `make vet`, `make test`, `make tidy`, `make clean`.

---

## Configure

Configs live in `config/`. Copy the templates and adapt them:

```bash
cp config/zmap.yaml.example config/zmap.yaml
cp config/os.yaml.example   config/os.yaml
cp config/ipid.yaml.example config/ipid.yaml
```

### zmap — `config/zmap.yaml`

| Key | Type | Description |
|---|---|---|
| `payload` | `icmp` \| `tcp` \| `udp-dns` | zmap probe module |
| `port` | uint16 / null | destination port; `null` for icmp, `53` for udp-dns |
| `probe_args` | string / null | dns probe args (udp-dns only), e.g. `A,www.example.com` |
| `number_of_target_ip_addresses` | scaled-int / null | stop after N responsive hosts; `null` = **entire IPv4 space**. Suffixes `K`, `M`, `G` |
| `bandwidth` | scaled-bits | send-rate cap, e.g. `30M` |
| `packets_per_second` | scaled-int | pps cap (set exactly one of bandwidth / pps) |
| `sender_threads` | scaled-int | zmap send threads (optional) |
| `interface.name` / `interface.ip` | string | egress interface and source IPv4 |
| `blacklist_file` | path / unset | zmap blocklist passed via `-b` (see [Blocklist](#blocklist)). Unset = zmap's built-in default |
| `log_to_file` | bool | also write `<run>/zmap.log` |
| `go_memory_limit` | scaled-int / null | Go heap target; TCP exact-IP deduplication automatically requires at least `768M` |
| `upload.*` | | optional S3 upload (see [Output](#output)) |

### os — `config/os.yaml`

| Key | Type | Description |
|---|---|---|
| `zmap` | measurement-id | zmap run to scan, e.g. `tcp-80_2026-06-03_00-13-06` (usually set via `--zmap`) |
| `modules.{ssh,smb,http,https,snmp,dns_chaos}` | bool | the six required OS-evidence services; all are scanned for every target |
| `zgrab2_senders` / `dns_chaos_workers` / `snmp_workers` | scaled-int | bounded concurrency for ZGrab2, DNS CHAOS, and SNMP |
| `connect_timeout` / `read_timeout` / `snmp_timeout` | duration | timeouts |
| `snmp_community` | string | SNMPv2c community |
| `log_to_file` | bool | also write `<run>/os.log` |
| `upload.*` | | optional S3 upload |

`zgrab2` is invoked by name from `$PATH`. DNS CHAOS and SNMP probes run in
process. The os stage does not bind a source interface (its scanners connect
out over the default route), so unlike `zmap` and `ipid` it takes no
`interface` config.

### ipid — `config/ipid.yaml`

| Key | Type | Description |
|---|---|---|
| `zmap` | measurement-id | zmap run providing the targets (usually set via `--zmap`) |
| `connection_count` | uint16 | connections (source-port slots) per target |
| `requests_per_connection` | uint16 | probes per connection |
| `measurement_mode` | `rt-based` \| `fixed-interval` | one-in-flight vs. burst-with-min-reply-rate |
| `fixed_interval.request_interval` | duration | gap between probes (fixed-interval) |
| `fixed_interval.minimum_reply_rate` | float 0-1 | drop if reply rate below this (fixed-interval) |
| `tcp.establish_connection` | bool | full handshake instead of stateless SYN (see below) |
| `tcp.request_flags` / `tcp.reply_flags` | flags / list | outbound TCP flags and accepted reply flags |
| `request_ip_ids` | list of uint16 | IP-ID values placed on outbound probes |
| `maximum_tolerated_rtt` | duration | per-probe RTT timeout |
| `bandwidth` / `packets_per_second` | scaled | send-rate cap |
| `number_of_inflight_probes` | scaled-int | in-flight concurrency |
| `interface.name` | string | the (single) egress interface |
| `interface.ip_a` | string | source IPv4 that **sends and receives** |
| `interface.ip_b` | string | second source IPv4 on the same interface that sends and receives |
| `log_to_file` | bool | also write `<run>/ipid.log` |
| `upload.*` | | optional S3 upload |
| `analysis_workflow.*` | | S3-only RT classification handoff used by every `run-all-*` sweep |

---

## Command-line flags

Every tool accepts `--config <path>` (default `config/<tool>.yaml`). The other
flags override the corresponding config value, which is how `scripts/run-all.sh`
drives one static config file per tool.

**measure-zmap**

| Flag | Description |
|---|---|
| `--payload icmp\|tcp\|udp-dns` | override `payload` |
| `--port <n>` | override `port` (`-1` keeps config) |
| `--probe-args "A,www.example.com"` | override dns `probe_args` |
| `--print-id` | print the run's measurement id to stdout on success |

The generated `zmap.pq` contains one deduplicated row per accepted responder.
For TCP SYN scans, both validated `synack` and `rst` responses are retained in
`REPLY_TYPE`; the first response per IP wins and the configured target count is
applied after this exact IP-level deduplication. ICMP errors are excluded.
UDP-DNS retains responses whose DNS
transaction ID and question match the probe, independently of DNS header flags.
ICMP scans retain only validated echo replies.

**measure-os**

| Flag | Description |
|---|---|
| `--zmap <id>` | override the `zmap` run id |
| `--zgrab2-senders` / `--dns-chaos-workers` / `--snmp-workers` | override scanner concurrency |
| `--connect-timeout` / `--read-timeout` / `--snmp-timeout` | override scanner timeouts |

Every ZMap target is scanned for SSH/22, SMB/445, HTTP/80, HTTPS/443, SNMP/161,
and DNS CHAOS `version.bind`/53. ZGrab2 handles the four TCP services in one
multimodule pass; bounded worker pools handle SNMP and DNS concurrently. SMB
session setup retains available NativeOS/NTLM evidence.

`os.pq` contains one row for every IP with at least one evidence string. Each
service has one nullable evidence column and one nullable canonical OS-tag
column. `OS_STATUS` is `resolved`, `ambiguous`, or `unclassified`; `OS_TAG` is
set only for a resolved row. Compatible service tags select the most specific
tag, while conflicting tags remain explicit as `ambiguous`. OS grouping is an
analysis operation and therefore is not stored in raw measurement data.

The Parquet columns are `IP_ADDR`, `OS_STATUS`, `OS_TAG`, the six nullable
`{SSH,SMB,HTTP,HTTPS,SNMP,DNS}_OS_TAG` columns, followed by the six nullable
evidence columns `SSH_SERVER_ID`, `SMB_NATIVE_OS`, `HTTP_SERVER`,
`HTTPS_SERVER`, `SNMP_SYS_DESCR`, and `DNS_VERSION_BIND`.

`os-coverage.json` has a paper-oriented `overview` and a lossless `detail`.
The overview reports unique responded/evidence/tagged/resolved IP counts and
their coverage relative to all ZMap targets, classification rates among evidence
targets, and per-service response/evidence/tag coverage and conditional rates.
The detail retains all absolute target, classification, service, and conflicting-
tag counters. Coverage values are fractions in `[0,1]`; multiply by 100 for a
percentage. The Parquet writer streams Snappy-compressed nullable columns in
bounded row groups.

The periodic `os: completed=...` log reports completed targets (including
targets without fingerprint evidence), current targets/s, pending merge rows,
per-scanner completion counts, heap size, and elapsed time.
See [Internet-wide OS scan profile](docs/os-scan-performance.md) for the
performance budget, module rationale, and production tuning thresholds.

**measure-ipid**

| Flag | Description |
|---|---|
| `--zmap <id>` | override the `zmap` run id |
| `--connection_count <n>` | override `connection_count` |
| `--requests_per_connection <n>` | override `requests_per_connection` |
| `--measurement_mode rt-based\|fixed-interval` | override `measurement_mode` |
| `--fixed_interval.request_interval <dur>` | override (e.g. `20ms`) |
| `--fixed_interval.minimum_reply_rate <float>` | override (0-1) |
| `--tcp.establish_connection true\|false` | override |
| `--target-file <path.pq>` | use an explicit ZMap-compatible parquet as targets |
| `--analysis_workflow.enable true\|false` | enable/disable the S3 classification handoff |

---

## Run a full measurement

The three stages are chained by the zmap **run id**: `measure-zmap` produces it,
`measure-os` / `measure-ipid` consume it via `--zmap`.

### Manually, one protocol

Each tool has a `make run-<tool>` wrapper that forwards `ARGS="..."` to the
binary (and, for `run-zmap`, refreshes the blocklist first). The binaries can
also be called directly — the wrappers do nothing more than that:

```bash
# 1. discover hosts, capture the run id
id=$(make run-zmap ARGS="--payload tcp --port 80 --print-id" | tail -n1)
#    equivalently: id=$(./bin/measure-zmap --payload tcp --port 80 --print-id | tail -n1)

# 2. fingerprint OS on those hosts
make run-os ARGS="--zmap $id"
#    equivalently: ./bin/measure-os --zmap "$id"

# 3. sample IP-ID behaviour on those hosts
make run-ipid ARGS="--zmap $id --measurement_mode rt-based"
#    equivalently: ./bin/measure-ipid --zmap "$id" --measurement_mode rt-based
```

Build first (`make build`, or `make setcap` for the raw-socket binaries); the
`run-*` targets do not rebuild. If you built with `make setcap`, no `sudo` is
needed; otherwise prefix each command with `sudo`. Complex `ARGS` containing
spaces inside a single value (e.g. dns `--probe-args`) are awkward to quote
through make — call the binary directly for those.

### Per-protocol sweeps

```bash
make run-all-icmp
make run-all-tcp
make run-all-udp
```

These wrap `scripts/run-all.sh [icmp|tcp|udp]`, which runs the complete campaign
end-to-end with no manual id juggling:

1. `make pull-blocklist` once, up front, to refresh the zmap blocklist (so every
   zmap run in the sweep shares one consistent list).
2. For each selected protocol: run `measure-zmap` (capturing its id), then
   `measure-os --zmap <id>`.
3. For each protocol, classify the stateless RT result via S3 and run the mass
   measurement only against the returned `UNCLASSIFIED` targets.
4. After every measurement for a protocol has succeeded, write
   `analysis-jobs/<zmap-id>/manifest.json` locally and publish it to the shared
   S3 prefix. Publishing `request.json` last starts automatic postprocessing on
   the analysis VM.

Build the binaries first (`make setcap` / `make build`); the sweep runs them
directly and does not rebuild. Edit the variables at the top of the script
(`RT_*`, `FI_*`, `DNS_PROBE`) to change the swept parameters. This is also what a
scheduler (cron / systemd timer) would invoke for a recurring campaign.

An interrupted sweep can reuse completed local ZMap and OS measurements instead
of repeating expensive scans:

```bash
# Reuse ZMap, then run OS and IPID.
make run-all-tcp ZMAP_ID=tcp-80_2026-07-28_01-59-44

# Reuse both ZMap and OS, then resume at IPID.
make run-all-tcp \
  ZMAP_ID=tcp-80_2026-07-28_01-59-44 \
  OS_ID=tcp-80_2026-07-29_01-04-50
```

The equivalent direct-script options are `--zmap-id ID` and `--os-id ID`.
`--os-id` requires `--zmap-id`. Resume mode accepts one protocol at a time and
verifies the measurement-id protocol, local parquet and snapshot files, and the
OS snapshot's ZMap reference before sending any probes. When ZMap is reused, the
blocklist is not refreshed because no ZMap scan will run.

### S3 analysis handoff

Every `run-all-*` sweep uses S3 as the only control and data channel between the
measurement and analysis VMs. Configure the same `analysis_workflow.s3_prefix`
on the measurement VM and `IPID_ANALYSIS_S3_PREFIX` for the analysis worker.
Both VMs need a working `s3cmd` configuration. `upload.enable` must be true and
`upload.delete_local` false for the RT runs.

For ICMP, TCP, and UDP-DNS the common order is:

1. ZMap and OS fingerprinting against the original ZMap result.
2. Stateless RT-based IPID measurement (4 x 4), followed by its normal S3 upload.
3. Upload `jobs/<rt-id>/request.json` and wait for either `done.json` or
   `failed.json`. The analysis worker stores `zmap_unclassified.pq` beside the
   RT measurement's `ipid.pq`; on success, download and SHA-256-verify it.
4. Stateless fixed-interval 4 x 25 only against `zmap_unclassified.pq`.
5. Stateless fixed-interval 4 x 4: ICMP and UDP-DNS use the original ZMap
   result; TCP uses the fixed-base target sample described below.

The 4 x 4 layout uses strict Base validation in both measurement modes. An
active target fails on a duplicate, an unsent or out-of-range request index,
incorrect reply flags or addresses/ports, a connection reset, or a late reply.
Only complete 16-reply results are saved, including direct 4 x 4 invocations.
Fixed-interval replies may arrive out of order. RT keeps the target registered
across all requests so replies to earlier requests remain attributable.
Completed results are frozen; packets without an active target are ignored.
TCP connection measurements acknowledge each accepted SYN-ACK with a separate
empty ACK, without waiting for the other connections' SYN-ACKs. The measurement
worker sends these ACKs, including while waiting between fixed-interval requests
or for outstanding handshakes. They use the shared rate limiter and packet/byte
counters, but do not occupy samples or advance the data-request sequence numbers.
The 4 x 4 layout still records four SYN-ACKs and twelve data acknowledgments.
TCP Base connection data replies require ACK and permit PSH as the only optional
flag. SYN-ACK flags remain exact; FIN, RST and unnegotiated control flags are not
accepted as data samples. An already answered sample aborts as `dup` before flag
validation, so later ACK/FIN/data packets cannot replace its SYN-ACK.
Contiguous server payload is acknowledged by the worker with a separate empty
ACK and by later requests; SYN-ACK payload is included in its acknowledgment.
Control ACKs use the client's next send sequence and consume no sample slots.
Invalid server sequences, payload gaps and overlaps abort as `tcp_seq`; there is
no server-data reassembly buffer. Fixed-interval pure ACK replies can still arrive
out of order, including delayed ACKs within the already observed server sequence
range. These changes apply only to strict Base reply validation.
Capture accepts IPv4 packets addressed to each receiver's local IP and MAC.
The outer IPv4 source is looked up before transport decoding. An unexpected IP
protocol from a registered target aborts an active Base measurement as `proto`;
for ICMP measurements, non-Echo-Reply ICMP messages also abort as `proto`.
ICMP errors from routers are not attributed through their quoted inner packet.
Malformed packets and fragments of the expected protocol remain excluded from
samples without a new immediate abort rule. Configured no-connection flag sets
are unchanged. The 4 x 25 Mass layout retains its existing loss tolerance and
duplicate handling. `replies[...]` counts packets; the new validation reasons
in `probes[...]` count each failed Base target once. Existing send-error counters
also include failures when sending TCP cleanup resets.

`capture[packets=... dropped=... errors=...]` accumulates kernel packet-socket
statistics across both receivers. Kernel packet totals include dropped packets;
`errors` counts statistics-read failures, so zero reported drops with errors does
not prove loss-free capture. Statistics are sampled approximately once per second
and once before each capture socket closes. After all workers and receivers stop,
`replies_final[...]`, `probes_final[...]` and `capture_final[...]` report the final
counters. Capture drops are not assigned to individual targets. The broader
filter can increase receive load and reveal additional Base aborts.

Receive-path diagnostics accompany the periodic and final counters automatically;
no test-run settings need to change. `receiver_diag` identifies receiver `0` as
IP A and `1` as IP B. It reports the actual kernel `SO_RCVBUF` value (including
Linux's accounting overhead), capture length, timestamp support, and per-socket
packet/drop totals. A buffer value of `-1` or `socket_errors>0` means a socket
option could not be queried. The diagnostic does not resize buffers.
`ready_ms` and `first_send_ms` are offsets from a common process-local epoch;
zero means not observed yet. `send_before_ready` compares the first send attempt
for that IP with the receiver's readiness. It is an observation, not a startup
barrier. Drop timestamps indicate when statistics reported drops, not their exact
occurrence time. Startup drops may include traffic queued before BPF attachment.

`receive_timing` samples the first and every subsequent 256th call at each site:
header/transport decoding, registry lookup, Base reply/failure lock waits, sender
lock waits, the send syscall, and the sender's Base probe-lock holding time.
Each timing reports observed samples, average/maximum microseconds and sampled
durations of at least 1 ms. These are cumulative sampled values, not full-run
worst-case bounds; short or rare stalls can be missed. The per-receiver `read`
timing includes normal idle waiting and read timeouts. `capture_age` measures
kernel timestamp to userspace read completion when kernel timestamps are enabled;
clock adjustments can distort it. `process` covers the complete decoder/validation
call, including waits. Timings overlap and must not be summed.

`receive_runtime` reports interval process CPU usage (100% is one CPU core),
process peak RSS in KiB, newly allocated MiB, GC count/pause deltas, GOMAXPROCS and
goroutine count. These cover the whole process, not just the receiver. Sampling
adds atomic counters and occasional clock reads; logging and resource collection
also have overhead. These diagnostics help identify bottlenecks but do not measure
VM-host contention or NIC/network loss. The `_final` variants are emitted after
workers and receivers stop. Validation, pacing, concurrency, capture filters and
sample timestamps are unchanged.

For TCP Base runs, `tcp_bad_flags[handshake:A=2 data:PA=3]` breaks down
`probes[bad_flags]` by the matched request's phase and received flag combination.
No-connection runs use `no_connection`; RT/FI is identified by the run's
`measurement_mode`. Counts are cumulative, once per failed target, and exclude
connection resets, non-TCP replies and Mass measurements. Flag letters use
`FSRPAUECN` order; `NONE` means no flags. Only nonzero counts are logged, with
`tcp_bad_flags_final[...]` emitted after receivers stop so the final counts
include failures since the last periodic snapshot. Reply acceptance is unchanged.

The stateless TCP fixed-base sample contains exactly
`min(N, max(ceil(10% * N), 1,000,000))` uniformly selected rows from the
original TCP `zmap.pq`. It is generated once per ZMap campaign and persisted as
`zmap/raw/<zmap-id>/zmap-fixed-base-sample.pq`; its seed and source/sample row
counts are recorded in `zmap-fixed-base-sample.json`.

Both TCP connection variants use one separate uniform sample filtered to
`REPLY_TYPE = synack`. The same size formula applies with N equal to the number
of SYN-ACK targets. `sample-zmap --reply-type synack` persists this sample as
`zmap/raw/<zmap-id>/zmap-connection-sample.pq` and records the filter, seed,
source, eligible and sampled counts in `zmap-connection-sample.json`. No eligible
targets causes an error; it never falls back to RST or unknown response types.
The analysis job uploads both artifacts and identifies this target in its manifest.
Deploy the corresponding ipid-analysis support before starting new TCP sweeps.
ICMP and UDP-DNS retain their full-ZMap fixed-base runs.

After the complete protocol sweep, the ZMap id is used as its analysis job id.
The protocol prefix in that id keeps the ICMP, TCP, and UDP-DNS VM jobs distinct.
The persistent manifest and request are stored below
`analysis-jobs/<zmap-id>/` both locally and in the configured S3 workflow
prefix. The existing analysis worker consumes these jobs sequentially, runs the
normal manifest-driven postprocessing, and publishes `done.json` or
`failed.json` plus `postprocess.log` in the same S3 directory.

The analysis worker uploads the target parquet to the RT measurement prefix
before publishing the completion marker under `jobs/<rt-id>/`; therefore
observing a valid `done.json` means the result is complete. A timeout, failure
marker, checksum mismatch, or missing result aborts the sweep before the
25-request measurement starts.

---

## Blocklist

Exempt bogon / opt-out prefixes: `measure-zmap` passes `blacklist_file`
(`config/zmap.yaml`) to zmap via `-b`. `make run-zmap` and the `run-all*` sweeps
refresh the blocklist before scanning (only the zmap stage consumes it). Options:

- **Own repo:** `make pull-blocklist BLOCKLIST_REPO=<url>` clones into
  `../active-measurements-blocklists/`; point `blacklist_file` at a file there.
  (The default `BLOCKLIST_REPO` is an internal netd-tud repo, not public.)
- **Local file:** set `blacklist_file` to any path, skip `pull-blocklist`.
- **zmap default:** leave `blacklist_file` unset.

---

## tcp.establish_connection

With `tcp.establish_connection: true`, `measure-ipid` performs a full TCP
handshake and therefore needs iptables rules that (1) bypass conntrack on the
scan port and (2) drop the kernel's outbound RSTs, so the tool can own the
connection. It installs and removes these rules automatically around the run
(invoking `iptables` needs root / `CAP_NET_ADMIN`).

`scripts/setup-iptables.sh <dst-port> <ip_a> [<ip_b>]` and
`scripts/teardown-iptables.sh <dst-port> <ip_a> [<ip_b>]` install/remove the same
rules standalone, if you prefer to manage them yourself.

After probing, the tool sends one RST+ACK on every successfully established TCP
connection. A reset releases peer state immediately without inviting the extra
packets of a graceful four-way close. These packets are rate-accounted but are
not added to the IP-ID result sequence.

---

## Output

Each stage writes to `<tool>/raw/<measurement-id>/`:

- `<tool>.pq` — the Parquet result,
- a snapshot of the effective config and, if `log_to_file`, a log.

If `upload.enable: true`, the run directory is synced to `upload.s3_destination`
with `s3cmd` (install `s3cmd` and configure `~/.s3cfg`; set `upload.enable: false`
to keep results local only).

---

## Scripts & make targets

| Command | Purpose |
|---|---|
| `make` / `make build` | build the three binaries |
| `make build-zmap` / `build-os` / `build-ipid` | build one binary |
| `make setcap` | build + apply `cap_net_raw,cap_net_admin+ep` (needs sudo) |
| `make run-zmap` / `run-os` / `run-ipid` | run a built binary with `ARGS="..."` (does not rebuild; `run-zmap` pulls the blocklist first) |
| `make run-all-icmp` / `run-all-tcp` / `run-all-udp` | sweep one protocol only |
| `make pull-blocklist` | clone/update the zmap blocklist |
| `make vet` / `test` / `tidy` / `clean` | Go housekeeping |
| `scripts/run-all.sh [icmp\|tcp\|udp]` | sweep script behind the `run-all*` targets |
| `scripts/setup-iptables.sh` / `teardown-iptables.sh` | standalone RST-drop rules for `establish_connection` mode (the tool installs/removes these itself; scripts are a manual escape hatch) |
