package consts

import (
	"time"
)

const (
	TimestampFormat    = "2006-01-02_15-04-05"
	ZMapReadBufferSize = 10_000
	LogUpdateInterval  = 1 * time.Second
	DnsSuffix          = "example.com"
)

const (
	ZMapBinary                    = "zmap"
	ZMapOutputFields              = "saddr,timestamp-ts,timestamp-us"
	ZMapOutputFormat              = "csv"
	ZMapParquetWriteBatchSize     = 10_000
	ZMapStdoutReadBufferBytes     = 1 << 20
	ZMapParquetMaxRowsPerRowGroup = 2_000_000
	ZMapParquetPageBufferBytes    = 1 << 20
	ZMapShutdownGraceSeconds      = 5
)

// OS measurement constants. The OS module orchestrates two external tools
// (zgrab2 for TCP application-layer probes, zdns for DNS CHAOS queries) plus
// an in-process SNMP UDP worker pool. Defaults are conservative so a default
// run does not saturate a typical uplink.
const (
	// OSZGrab2Binary is the executable invoked as a subprocess for the
	// application-layer scans (HTTP, HTTPS, SSH, SMB, SMTP, MSSQL, POP3, IMAP,
	// FTP, Telnet).
	OSZGrab2Binary = "zgrab2"

	// OSZDNSBinary is the executable invoked for DNS CHAOS queries.
	OSZDNSBinary = "zdns"

	// OSDefaultZGrab2Senders is the default number of concurrent connections
	// the zgrab2 subprocess will maintain. Higher = more parallelism but more
	// open sockets and faster bandwidth burn. 1000 is a sane middle ground.
	OSDefaultZGrab2Senders = 1000

	// OSDefaultZDNSThreads is the default number of concurrent DNS workers.
	OSDefaultZDNSThreads = 1000

	// OSDefaultSNMPWorkers is the default number of in-process SNMP UDP
	// workers. SNMP is much cheaper per probe (1 UDP packet round trip),
	// so we can run many more in parallel than TCP-based modules.
	OSDefaultSNMPWorkers = 2000

	// OSDefaultConnectTimeout is the per-probe TCP connect timeout.
	OSDefaultConnectTimeout = 3 // seconds

	// OSDefaultReadTimeout is the per-probe read timeout once connected.
	OSDefaultReadTimeout = 3 // seconds

	// OSDefaultSNMPTimeout is the SNMP request timeout (UDP, no retransmits).
	OSDefaultSNMPTimeout = 2 // seconds

	// OSDefaultSNMPCommunity is the SNMP v2c community string used. "public"
	// is the de-facto default community on misconfigured devices, which is
	// exactly what we want to fingerprint anyway.
	OSDefaultSNMPCommunity = "public"

	// OSResultBufferSize bounds how many merged per-IP results can queue
	// ahead of the parquet writer. Each entry is small (~1 KiB max), so
	// 100k entries ≈ 100 MB of RAM headroom.
	OSResultBufferSize = 100_000

	// OSResultMergeWaitSeconds is how long we wait for the last few stragglers
	// from the three subprocesses to merge before declaring a target "done"
	// and giving up on missing service results. Per IP a result becomes
	// eligible for parquet write as soon as all three scanners have either
	// produced output for it or signalled their stream end.
	OSResultMergeWaitSeconds = 30

	// OSParquetWriteBatchSize, OSParquetMaxRowsPerRowGroup, OSParquetPageBufferBytes
	// mirror the zmap module's tuning. Snappy compression keeps the file
	// small while remaining cheap to read back.
	OSParquetWriteBatchSize     = 10_000
	OSParquetMaxRowsPerRowGroup = 2_000_000
	OSParquetPageBufferBytes    = 1 << 20
	OSStdoutReadBufferBytes     = 1 << 20

	// OSShutdownGraceSeconds is how long we give the external subprocesses
	// after SIGTERM before SIGKILL.
	OSShutdownGraceSeconds = 5
)
