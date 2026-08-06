package zmapsample

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"

	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/records"
)

const (
	parquetMaxRowsPerRowGroup = 500_000
	parquetPageBufferBytes    = 1 << 20
)

type SampleStats struct {
	SourceRows int64
	SampleRows int64
	Seed       int64
}

// FixedBaseSampleSize returns min(total, max(ceil(total*percent/100), minimum)).
func FixedBaseSampleSize(total, minimum int64, percent int) int64 {
	if total <= 0 {
		return 0
	}
	percentageRows := (total*int64(percent) + 99) / 100
	requested := max(percentageRows, minimum)
	return min(requested, total)
}

// WriteUniformSample streams an exact-size uniform sample without holding the
// selected population in memory. Rows retain their original order.
func WriteUniformSample(inputPath, outputPath string, minimum int64, percent int, seed int64) (SampleStats, error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return SampleStats{}, fmt.Errorf("open source parquet: %w", err)
	}
	defer input.Close()

	reader := parquet.NewGenericReader[records.ZMap](input)
	defer reader.Close()

	total := reader.NumRows()
	wanted := FixedBaseSampleSize(total, minimum, percent)
	stats := SampleStats{SourceRows: total, SampleRows: wanted, Seed: seed}
	if total == 0 {
		return stats, fmt.Errorf("source parquet is empty")
	}

	temporary := outputPath + ".part"
	_ = os.Remove(temporary)
	output, err := os.Create(temporary)
	if err != nil {
		return stats, fmt.Errorf("create sampled parquet: %w", err)
	}
	buffered := bufio.NewWriterSize(output, parquetPageBufferBytes)
	writer := parquet.NewGenericWriter[records.ZMap](buffered,
		parquet.Compression(&snappy.Codec{}),
		parquet.PageBufferSize(parquetPageBufferBytes),
		parquet.MaxRowsPerRowGroup(parquetMaxRowsPerRowGroup),
	)
	keepTemporary := false
	defer func() {
		if !keepTemporary {
			_ = os.Remove(temporary)
		}
	}()

	closeOutput := func() error {
		var first error
		for _, closeErr := range []error{writer.Close(), buffered.Flush(), output.Close()} {
			if closeErr != nil && first == nil {
				first = closeErr
			}
		}
		return first
	}

	rng := rand.New(rand.NewSource(seed))
	remainingRows := total
	remainingWanted := wanted
	readBuffer := make([]records.ZMap, consts.ZMapReadBufferSize)
	writeBuffer := make([]records.ZMap, 0, consts.ZMapParquetWriteBatchSize)
	processed := int64(0)

	flush := func() error {
		if len(writeBuffer) == 0 {
			return nil
		}
		if _, err := writer.Write(writeBuffer); err != nil {
			return err
		}
		writeBuffer = writeBuffer[:0]
		return nil
	}

	for {
		count, readErr := reader.Read(readBuffer)
		for i := 0; i < count; i++ {
			take := remainingWanted == remainingRows
			if !take && remainingWanted > 0 {
				take = rng.Int63n(remainingRows) < remainingWanted
			}
			if take {
				writeBuffer = append(writeBuffer, readBuffer[i])
				if len(writeBuffer) >= consts.ZMapParquetWriteBatchSize {
					if err := flush(); err != nil {
						_ = closeOutput()
						return stats, fmt.Errorf("write sampled rows: %w", err)
					}
				}
				remainingWanted--
			}
			remainingRows--
			processed++
		}

		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				_ = closeOutput()
				return stats, fmt.Errorf("read source parquet: %w", readErr)
			}
			break
		}
		if count == 0 {
			break
		}
	}

	if processed != total || remainingWanted != 0 || remainingRows != 0 {
		_ = closeOutput()
		return stats, fmt.Errorf(
			"sample accounting mismatch: processed=%d/%d selected_remaining=%d rows_remaining=%d",
			processed, total, remainingWanted, remainingRows,
		)
	}
	if err := flush(); err != nil {
		_ = closeOutput()
		return stats, fmt.Errorf("write final sampled rows: %w", err)
	}
	if err := closeOutput(); err != nil {
		return stats, fmt.Errorf("close sampled parquet: %w", err)
	}
	if err := os.Rename(temporary, outputPath); err != nil {
		return stats, fmt.Errorf("publish sampled parquet: %w", err)
	}
	keepTemporary = true
	return stats, nil
}
