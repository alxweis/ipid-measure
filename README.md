# ipid-measure

A high-throughput active-measurement toolkit for IPv4. It runs as a three-stage
pipeline:

1. **zmap** — discover responsive hosts (wraps the `zmap` scanner).
2. **os** — fingerprint their operating system from service banners
   (`zgrab2` + `zdns` + in-process SNMP).
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
  `zmap`, `zgrab2`, `zdns`. Install them from their upstream projects
  (github.com/zmap/{zmap,zgrab2,zdns}) so that `zmap`, `zgrab2` and `zdns` are
  callable by name.
- For the `ipid` stage: **one interface with two source IPv4 addresses**.

---

## Build

```bash
make           # builds bin/measure-zmap, bin/measure-os, bin/measure-ipid
```

The `zmap` and `ipid` binaries need raw-socket capabilities. Either run them as
root, or grant file capabilities once:

```bash
make setcap    # builds, then setcap cap_net_raw,cap_net_admin+ep on the binaries
```

> `go build` writes a fresh binary and drops file capabilities each time, so run
> `make setcap` (not a bare `make`) whenever you rebuild before measuring.

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
| `upload.*` | | optional S3 upload (see [Output](#output)) |

### os — `config/os.yaml`

| Key | Type | Description |
|---|---|---|
| `zmap` | measurement-id | zmap run to scan, e.g. `tcp-80_2026-06-03_00-13-06` (usually set via `--zmap`) |
| `modules.{ssh,smb,http,https,snmp,smtp,mssql,pop3,imap,ftp,telnet,dns_chaos}` | bool | enable each fingerprint module |
| `zgrab2_senders` / `zdns_threads` / `snmp_workers` | scaled-int | per-scanner concurrency |
| `interface.name` / `interface.ip` | string | egress interface and source IPv4 |
| `connect_timeout` / `read_timeout` / `snmp_timeout` | duration | timeouts |
| `snmp_community` | string | SNMPv2c community |
| `log_to_file` | bool | also write `<run>/os.log` |
| `upload.*` | | optional S3 upload |

`zgrab2` and `zdns` are invoked by name from `$PATH`.

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
| `interface.ip_b` | string | second source IPv4 on the same interface that **only receives** |
| `log_to_file` | bool | also write `<run>/ipid.log` |
| `upload.*` | | optional S3 upload |

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

**measure-os**

| Flag | Description |
|---|---|
| `--zmap <id>` | override the `zmap` run id |

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

---

## Run a full measurement

The three stages are chained by the zmap **run id**: `measure-zmap` produces it,
`measure-os` / `measure-ipid` consume it via `--zmap`.

### Manually, one protocol

```bash
# 1. discover hosts, capture the run id
id=$(./bin/measure-zmap --payload tcp --port 80 --print-id | tail -n1)

# 2. fingerprint OS on those hosts
./bin/measure-os --zmap "$id"

# 3. sample IP-ID behaviour on those hosts
./bin/measure-ipid --zmap "$id" --measurement_mode rt-based
```

(If you built with `make setcap`, no `sudo` is needed; otherwise prefix each
command with `sudo`.)

### The full sweep — `scripts/run-all.sh`

```bash
./scripts/run-all.sh
```

Runs the complete campaign end-to-end with no manual id juggling:

1. `make pull-blocklist` to refresh the zmap blocklist.
2. For each protocol `icmp`, `tcp-80`, `udp-dns-53`: run `measure-zmap` (capturing
   its id), then `measure-os --zmap <id>`.
3. For each protocol, sweep `measure-ipid` over `establish_connection`
   (`false`/`true` for tcp, `false` otherwise) x three mode/parameter
   combinations (one `rt-based`, two `fixed-interval`), threading the zmap id in
   via `--zmap`.

Edit the variables at the top of the script (`RT_*`, `FI_*`, `DNS_PROBE`) to
change the swept parameters. This is also the script a scheduler (cron / systemd
timer) would invoke for a recurring campaign.

---

## Blocklist

Exempt bogon / opt-out prefixes: `measure-zmap` passes `blacklist_file`
(`config/zmap.yaml`) to zmap via `-b`. Options:

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

---

## Output

Each stage writes to `<tool>/raw/<measurement-id>/`:

- `<tool>.pq` — the Parquet result,
- a snapshot of the effective config, run metadata, and (if `log_to_file`) a log.

If `upload.enable: true`, the run directory is synced to `upload.s3_destination`
with `s3cmd` (install `s3cmd` and configure `~/.s3cfg`; set `upload.enable: false`
to keep results local only).

---

## Scripts & make targets

| Command | Purpose |
|---|---|
| `make` / `make build` | build the three binaries |
| `make setcap` | build + apply `cap_net_raw,cap_net_admin+ep` (needs sudo) |
| `make pull-blocklist` | clone/update the zmap blocklist |
| `make vet` / `test` / `tidy` / `clean` | Go housekeeping |
| `scripts/run-all.sh` | full multi-protocol measurement sweep |
| `scripts/setup-iptables.sh` / `teardown-iptables.sh` | manage the RST-drop rules for `establish_connection` mode |

# TODO

- Add FIN-ACK Message to finalize connection