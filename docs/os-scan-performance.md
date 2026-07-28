# Internet-wide OS scan profile

The OS pipeline is designed to finish approximately 300 million targets in
three to five days on the measurement host. That requires a sustained
throughput between 694 and 1,158 completed targets per second.

## Scan plan

| Tier | Modules | Coverage | Reason |
|---|---|---:|---|
| Core | SSH, SMB, HTTP, HTTPS, SNMP | 100% | Broadly deployed and the strongest direct OS, firmware, or appliance evidence |
| Secondary | SMTP, MSSQL, POP3, IMAP, FTP, Telnet, DNS CHAOS | Stable 1% | Useful on niche services, but too expensive and too sparse for exhaustive probing |

The sample is a deterministic hash of the IPv4 string. Repeated campaigns
therefore select the same secondary population. At 300 million targets, a 1%
sample still probes approximately 3 million addresses.

`SECONDARY_SAMPLED` in `os.pq` identifies retained rows that received the
secondary probes. This allows downstream analysis to separate exhaustive core
evidence from sampled secondary evidence.

## Runtime budget

The legacy 1-million-target ICMP run took 6h25m, or about 43 completed
targets/s, with ten exhaustive ZGrab2 modules, exhaustive DNS CHAOS, 1,000
ZGrab2 senders, and 3-second timeouts.

The optimized `run-all-*` profile uses:

- 5,000 ZGrab2 senders;
- 1-second connect and read timeouts;
- 3,000 SNMP workers with a 1-second timeout;
- 1,000 in-process DNS CHAOS workers with a 1-second timeout;
- a 1% secondary sample.

The ZGrab2 work per target falls from ten module attempts to approximately
`4 + 0.01 * 6 = 4.06`. Combined with five times the concurrency and the shorter
timeouts, the empirical baseline predicts roughly 700-1,600 targets/s after
allowing for non-linear kernel, network, and parsing overhead. SNMP has a
worst-case timeout capacity of about 3,000 targets/s. Sampled DNS performs only
about 6 million queries instead of 600 million. The in-process prober emits one
completion for every selected host, including timeouts, so DNS cannot leave
millions of merger entries pending at shutdown.

This is a performance target, not a hard real-time guarantee: remote filtering,
local file-descriptor limits, CPU, and network policy can change the observed
rate.

## Production verification

The OS process logs a line like:

```text
os: completed=1234567/300000000 (0.41% +912/s eta=90h12m...)
```

`completed` includes retained fingerprints and empty results, so it is the
correct progress counter. After the first 30-60 minutes:

- `>= 1,158/s` projects to at most 3 days;
- `>= 694/s` projects to at most 5 days;
- `< 694/s` misses the five-day budget.

The per-scanner counters show the bottleneck. If ZGrab2 trails, raise
`zgrab2_senders` toward 8K-10K after checking CPU, memory, file-descriptor, and
ephemeral-port headroom. If SNMP trails, raise `snmp_workers` toward 5K. If
resource limits prevent more concurrency, reduce `secondary_sample_rate` before
removing core modules.

Use `secondary_sample_rate: 1` only for a deliberately exhaustive smaller
campaign. It restores the legacy cost profile and is unsuitable for a
300-million-target run.
