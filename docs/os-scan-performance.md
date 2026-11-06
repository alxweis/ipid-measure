# Internet-wide OS scan profile

The OS pipeline scans six services for every ZMap target:

| Scanner | Services | Work per target |
|---|---|---:|
| ZGrab2 multimodule | SSH/22, SMB/445, HTTP/80, HTTPS/443 | four bounded connection attempts |
| in-process SNMP | `sysDescr.0` on UDP/161 | one request |
| in-process DNS CHAOS | `version.bind` TXT on UDP/53 | one request |

All three scanner implementations run concurrently. Fixed-size input and result
queues provide backpressure, scanner workers reuse buffers and sockets where the
protocol permits it, and the merger retains only the currently in-flight IPs.
Evidence is classified with ordered regular expressions from specific product
names to broad family terms. The writer emits Snappy-compressed Parquet row
groups without accumulating the target population in memory.

The configured Internet-wide defaults are:

- 5,000 ZGrab2 senders;
- 1-second connect and read timeouts;
- 3,000 SNMP workers with a 1-second timeout;
- 1,000 DNS CHAOS workers with an independent 1-second `dns_chaos_timeout`;
- a 384 MiB Go heap target.

These are the example configuration's defaults, not hardware-specific tuning.
The shared geographic worker and late OS enrichment use `config/os.yaml` for
scanner concurrency and timeouts without replacing them with a fixed profile.
They still own campaign target selection, per-target status, and uploads.
Older configurations that omit `dns_chaos_timeout` use `read_timeout` for DNS;
set it explicitly to keep slower TCP reads from extending DNS timeouts.
The effective timeout is recorded in `os.snapshot.yaml` and the scan log.

SMB session setup adds an exchange after successful negotiation and exposes
NativeOS/NTLM fields. HTTP and HTTPS retain only the `Server` response header.
DNS performs exactly one `version.bind` query. SNMP performs exactly one
`sysDescr.0` query.

## Production verification

The process reports completed targets, per-second progress, pending merge rows,
scanner-result counts, written rows, heap size, and goroutine count once per
second. The scanner-result counters should converge on the input target count;
the run fails if any target lacks one of the three scanner completions.

Performance acceptance uses a representative live-VM benchmark with the same
timeouts, file-descriptor limits, routing, and target mix as the campaign. The
new measurement is accepted when sustained targets per second and peak memory
are at least as good as the reference implementation while producing the
expected six-service coverage counters in `os-coverage.json`.
