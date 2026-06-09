package zmap

import (
	"bufio"
	"fmt"
	"os"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"

	"github.com/netd-tud/ipid-measure/internal/consts"
	"github.com/netd-tud/ipid-measure/internal/records"
)

// Writer is the parquet sink for ZMap results.
type Writer struct {
	file     *os.File
	buffered *bufio.Writer
	pq       *parquet.GenericWriter[records.ZMap]
	batch    []records.ZMap
	written  uint64
}

// NewWriter creates a parquet file at outPath.
func NewWriter(outPath string) (*Writer, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return nil, fmt.Errorf("create parquet: %w", err)
	}

	bw := bufio.NewWriterSize(f, consts.ZMapParquetPageBufferBytes)
	pq := parquet.NewGenericWriter[records.ZMap](bw,
		parquet.Compression(&snappy.Codec{}),
		parquet.PageBufferSize(consts.ZMapParquetPageBufferBytes),
		parquet.MaxRowsPerRowGroup(consts.ZMapParquetMaxRowsPerRowGroup),
	)

	return &Writer{
		file:     f,
		buffered: bw,
		pq:       pq,
		batch:    make([]records.ZMap, 0, consts.ZMapParquetWriteBatchSize),
	}, nil
}

// Append queues one record.
func (w *Writer) Append(r records.ZMap) error {
	w.batch = append(w.batch, r)
	if len(w.batch) >= consts.ZMapParquetWriteBatchSize {
		return w.flush()
	}
	return nil
}

// flush drains the current batch into the parquet writer.
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

// Written reports the total number of records appended and persisted so far.
func (w *Writer) Written() uint64 { return w.written }

// Close flushes any remaining records, finalises the parquet footer, flushes
// the buffered file writer and closes the underlying file.
func (w *Writer) Close() error {
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
