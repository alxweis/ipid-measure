# ipid

High-throughput active IP-ID measurement toolkit. Given a list of target IPv4
addresses (the output of a ZMap-style scan, stored as a Parquet file), it sends
a configurable burst of probes (ICMP echo, TCP, or UDP/DNS) to each target,
collects the replies, and records the observed IP identification field sequence
together with send/receive timestamps. It is built to stream hundreds of
millions of targets over multi-day runs.

## Architecture

Send and receive are fully decoupled. A global token-bucket rate limiter
governs the send rate (bandwidth and/or pps), and a flat pool of "prober"
goroutines pulls targets from a single shared channel — there is no per-worker
sharding of replies. Each prober registers its in-flight probe in a sharded
**inflight registry** keyed by the target IP, then sends and waits. Two
receiver goroutines (one per egress interface) capture replies with zero-copy
reads and a kernel BPF prefilter, decode the headers, look up the matching
probe in the registry, and atomically fill the corresponding sample slot. The
prober is woken by a one-shot `done` channel once its completion criterion is
satisfied (RT-based: one reply; FixedInterval: all replies or RTT elapsed).

This design has two important properties for very large measurements:

* **No silent reply loss.** There are no bounded per-worker reply channels and
  no non-blocking sends — every captured reply runs through the registry, and
  outcomes (matched / unmatched / rejected) are counted and logged.
* **Throughput is decoupled from RTT.** The old worker-per-RTT-slot model
  capped throughput at `WorkerCount / RTT`, which at 500 M targets and 2 s RTT
  meant days lost to timeouts. The new model is bounded by the configured
  bandwidth, with the concurrency knob only sized to cover `bandwidth × RTT`.

```
cmd/                entry points: measure-ipid, measure-os, measure-zmap
config/             example YAML configuration files
internal/           config loading, path/ID helpers, shared types, records
ipid/
  measurement/      dependency-free state + Run orchestration (composition root)
  worker/           prober pool, parquet target streaming, fast IPv4 parser
  probe/            Measure(), inflight registry, atomic sample state machine
  receiver/         zero-copy capture + DecodingLayerParser + registry fulfilment
  sender/           AF_PACKET raw sockets, global token-bucket rate limiter
  packet/           one-time raw packet templates + zero-alloc per-target patching
  payload/          protocol selection (icmp / tcp / udp-dns)
  ip,tcp,udp,dns,icmp,checksum,port,seqnum,reply,stats   protocol + support code
```

`ipid/measurement` is a dependency leaf: it imports no other `ipid/*` package
and holds only configuration, lifecycle signals, and the `Run` orchestration.
Each sub-package registers its setup/start behaviour into `measurement` through
hook variables in `init()`, and `cmd/measure-ipid` blank-imports the top-level
stages to trigger registration. This keeps the import graph acyclic.

## Build

Requires Go (>= 1.24.9) and the libpcap development headers:

```
sudo apt-get install libpcap-dev
make            # builds bin/measure-ipid, bin/measure-os, bin/measure-zmap
make vet
make test       # runs unit tests under -race
```

The binaries use AF_PACKET raw sockets, so run them as root or grant
`CAP_NET_RAW`:

```
sudo setcap cap_net_raw+ep ./bin/measure-ipid
```

## Configure

Copy an example and edit it:

```
cp config/ipid.yaml.example config/ipid.yaml
```

Key fields (see `config/ipid.yaml.example` for the full set):

* `zmap` — reference identifying the input scan
* `measurement_mode` — `rt-based` or `fixed-interval`
* `bandwidth` / `packets_per_second` — global send caps (token bucket); at
  least one must be > 0
* `concurrency` — size of the prober pool (default: `worker_count`). Pick big
  enough to cover `bandwidth × MaximumToleratedRTT`. 25 000 is reasonable at
  1 Gbit/s with 200 ms RTT.
* `maximum_tolerated_rtt` — late replies are rejected
* `interfaces` — the two egress interfaces

## Run

```
sudo ./bin/measure-ipid
```

Press Ctrl+C to stop gracefully: target feeding halts, the rate limiter is
released so all blocked sends exit, in-flight probes finish, and the buffered
parquet writer is fully flushed before exit. Once per second the run logs:

```
estimated_time_left=[1d04h32m] probed_ip_addresses=[12345678, 2.47%] \
valid_probes=[18432, 9876543/12345678=79.99%] sent_mbps=[842.31] sent_pps=[71250] \
replies[matched=98765 unmatched=123 rejected=4] concurrency=[25000]
```

`matched` is the number of replies that filled a sample. `unmatched` are
validly decoded replies that did not match an in-flight probe (typical for
late stragglers). `rejected` are replies that could not be decoded.
