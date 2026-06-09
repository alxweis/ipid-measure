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
// an in-process SNMP UDP worker pool.
const (
	// Default subprocess binary names. Looked up via PATH; user can override
	// with absolute paths via os.yaml.
	OSZGrab2Binary = "zgrab2"
	OSZDNSBinary   = "zdns"

	// OSResultBufferSize bounds how many merged per-IP results can queue
	// ahead of the parquet writer.
	OSResultBufferSize = 100_000

	// Parquet tuning, mirrors the zmap module.
	OSParquetWriteBatchSize     = 10_000
	OSParquetMaxRowsPerRowGroup = 2_000_000
	OSParquetPageBufferBytes    = 1 << 20
	OSStdoutReadBufferBytes     = 1 << 20

	// OSShutdownGraceSeconds is how long we give the external subprocesses
	// after SIGTERM before SIGKILL.
	OSShutdownGraceSeconds = 5
)
