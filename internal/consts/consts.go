package consts

import (
	"time"
)

const (
	LogUpdateInterval = 1 * time.Second
)

// --- SPEEDUP ----------------------------------------------------------------

const (
	ZMapReadBufferSize        = 50_000
	ZMapParquetWriteBatchSize = 50_000
	ZMapStdoutReadBufferBytes = 4 << 20

	IPIDSaveChannelSize    = 1 << 18
	IPIDSaveFileBufferSize = 8 * 1024 * 1024

	SoSndBuf = 32 * 1024 * 1024
)
