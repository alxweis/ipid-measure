# ipid-measure

## About

A high-throughput active measurement toolkit for IPv4: discover responsive hosts with **zmap**, fingerprint their operating system with **os**, and record their IP-ID selection behavior with **ipid**.

## Requirements

- Linux with `AF_PACKET` raw-socket support (root or `CAP_NET_RAW`)
- Go 1.22+
- External binaries on `$PATH` for the **os** tool: `zmap`, `zgrab2`, `zdns`

## Build

```bash
make
```

Produces `bin/measure-zmap`, `bin/measure-os`, `bin/measure-ipid`.

## Measure

Each tool reads its config from `config/<tool>.yaml` and writes its output under `<tool>/raw/<measurement-id>/`.
In `config/`, you can find the template configuration files marked with the `.yaml.example` extension.
Adapt them as needed and rename them to `.yaml`.

### zmap — host discovery

Wrapper around the `zmap` binary that streams `(saddr, timestamp)` tuples into a parquet file.

**Configure** (`config/zmap.yaml`):

| Key | Type | Description |
|---|---|---|
| `payload` | enum | `icmp`, `tcp`, `udp-dns` — selects the zmap probe module |
| `port` | uint16 / null | destination port; `null` for icmp, `53` for udp-dns |
| `number_of_target_ip_addresses` | scaled-int / null | stop after N responsive hosts; `null` = full IPv4 space. Suffixes `K`, `M`, `G` |
| `bandwidth` | scaled-bits / null | wire-rate cap (e.g. `30M` = 30 Mbps); `null` disables |
| `packets_per_second` | scaled-int / null | pps cap; `null` disables |
| `sender_threads` | scaled-int | zmap send-thread count |
| `interface.name` | string | egress interface (e.g. `eth0`) |
| `interface.ip` | string | source IPv4 |
| `dryrun` | bool | run zmap without sending packets (validation) |
| `blacklist_file` | path / null | optional blocklist; `null` = zmap default |
| `whitelist_file` | path / null | optional inclusion list |
| `log_to_file` | bool | also write logs to `<measurement_dir>/zmap.log` |

**Run:**

```bash
sudo ./bin/measure-zmap
```

### os — banner-based OS fingerprinting

Joins `zgrab2` (TCP banners), in-process SNMP probes, and `zdns` (DNS CHAOS-class). The configured `zmap` measurement is the input.

**Configure** (`config/os.yaml`):

| Key | Type | Description |
|---|---|---|
| `zmap` | measurement-id | id of the zmap run to scan (e.g. `tcp-80_2026-06-03_00-13-06`) |
| `modules.{ssh,smb,http,https,snmp,smtp,mssql,pop3,imap,ftp,telnet,dns_chaos}` | bool | enable per banner-grab module |
| `zgrab2_senders` | scaled-int | concurrent zgrab2 connections |
| `zdns_threads` | scaled-int | concurrent zdns resolvers |
| `snmp_workers` | scaled-int | in-process SNMP worker goroutines |
| `interface.name` | string | egress interface |
| `interface.ip` | string | source IPv4 |
| `connect_timeout` | duration | TCP connect timeout (`3s`) |
| `read_timeout` | duration | banner-read timeout |
| `snmp_timeout` | duration | per-target SNMP UDP timeout |
| `snmp_community` | string | SNMPv2c community string |
| `zgrab2_binary` | path / null | override zgrab2 binary path |
| `zdns_binary` | path / null | override zdns binary path |
| `log_to_file` | bool | also write logs to `<measurement_dir>/os.log` |

**Run:**

```bash
sudo ./bin/measure-os
```

### ipid — IP-ID behavior sampling

Sends `connection_count × requests_per_connection` requests per target across two source interfaces, records the IP-ID field of each reply. The configured `zmap` measurement is the input.

**Configure** (`config/ipid.yaml`):

| Key | Type | Description |
|---|---|---|
| `zmap` | measurement-id | id of the zmap run providing the targets |
| `connection_count` | uint16 | distinct connections (= source-port slots) per target |
| `requests_per_connection` | uint16 | probes per connection. Total probes per target = product of both |
| `measurement_mode` | enum | `rt-based` (one in flight at a time, accept on reply) or `fixed-interval` (burst, accept if reply-rate ≥ threshold) |
| `fixed_interval.request_interval` | duration | gap between probes in `fixed-interval` mode |
| `fixed_interval.minimum_reply_rate` | float | drop probe if received/total below this (0..1) |
| `tcp.establish_connection` | bool | full SYN→SYN-ACK→PSH-ACK handshake instead of stateless SYN |
| `tcp.request_flags` | TCP-flag string | flags to set on outbound TCP (e.g. `S` = SYN) |
| `tcp.reply_flags` | list of flag strings | accept any of these as a valid reply (e.g. `SA`, `RA`, `R`) |
| `request_ip_ids` | list of uint16 | IP-ID values placed on outbound packets (cycled by seqNum) |
| `maximum_tolerated_rtt` | duration | per-probe RTT timeout |
| `bandwidth` | scaled-bits / null | global send-rate cap |
| `packets_per_second` | scaled-int / null | global pps cap |
| `number_of_inflight_probes` | scaled-int | semaphore size for concurrent in-flight probes |
| `interfaces.a.name` / `interfaces.a.ip` | string | first egress interface and source IP |
| `interfaces.b.name` / `interfaces.b.ip` | string | second egress interface (used to vary L3 routing per seqNum) |
| `log_to_file` | bool | also write logs to `<measurement_dir>/ipid.log` |

**Run:**

```bash
sudo ./bin/measure-ipid
```

# TODO

- Add FIN-ACK Message to finalize connection
- Hide estimated_time_left until ready