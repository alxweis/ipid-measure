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

const (
	OSZGrab2Binary              = "zgrab2"
	OSZDNSBinary                = "zdns"
	OSResultBufferSize          = 100_000
	OSParquetWriteBatchSize     = 10_000
	OSParquetMaxRowsPerRowGroup = 2_000_000
	OSParquetPageBufferBytes    = 1 << 20
	OSStdoutReadBufferBytes     = 1 << 20
	OSShutdownGraceSeconds      = 5
)
