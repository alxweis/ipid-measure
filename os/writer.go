package os

import (
	"bufio"
	"fmt"
	osstd "os"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"

	"github.com/alxweis/ipid-measure/internal/records"
)

const (
	ParquetWriteBatchSize     = 10_000
	ParquetMaxRowsPerRowGroup = 2_000_000
	ParquetPageBufferBytes    = 1 << 20
)

// Writer is the parquet sink for OS-fingerprint results. Behaves identically
// in spirit to zmap/writer.go: batched, snappy-compressed, single-writer.
type Writer struct {
	file     *osstd.File
	buffered *bufio.Writer
	pq       *parquet.GenericWriter[records.OSRecord]
	batch    []records.OSRecord
	written  uint64
	closed   bool
}

func NewWriter(outPath string) (*Writer, error) {
	f, err := osstd.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("create parquet: %w", err)
	}
	bw := bufio.NewWriterSize(f, ParquetPageBufferBytes)
	pq := parquet.NewGenericWriter[records.OSRecord](bw,
		parquet.Compression(&snappy.Codec{}),
		parquet.PageBufferSize(ParquetPageBufferBytes),
		parquet.MaxRowsPerRowGroup(ParquetMaxRowsPerRowGroup),
	)
	return &Writer{
		file:     f,
		buffered: bw,
		pq:       pq,
		batch:    make([]records.OSRecord, 0, ParquetWriteBatchSize),
	}, nil
}

// Append queues one record. Empty OS_NAME records are dropped silently --
// the run requirement is that os.pq only contains rows where an OS could
// be inferred.
func (w *Writer) Append(r records.OSRecord) error {
	if r.OSName == "" {
		return nil
	}
	w.batch = append(w.batch, r)
	if len(w.batch) >= ParquetWriteBatchSize {
		return w.flush()
	}
	return nil
}

func (w *Writer) flush() error {
	if len(w.batch) == 0 {
		return nil
	}
	if _, err := w.pq.Write(w.batch); err != nil {
		return fmt.Errorf("parquet write: %w", err)
	}
	w.written += uint64(len(w.batch))
	w.batch = w.batch[:0]
	return nil
}

func (w *Writer) Written() uint64 { return w.written }

func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	var firstErr error
	setErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	setErr(w.flush())
	setErr(w.pq.Close())
	setErr(w.buffered.Flush())
	setErr(w.file.Close())
	return firstErr
}
