package zmap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
)

// Run executes a complete ZMap measurement.
func Run(c *config.ZMapConfig, m *paths.ZMapMeasurement) (uint64, error) {
	args, err := BuildArgs(c)
	if err != nil {
		return 0, fmt.Errorf("build args: %w", err)
	}
	log.Printf("zmap args: %v", args)

	// Cancel the whole run on Ctrl+C / SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner, err := Start(ctx, args)
	if err != nil {
		return 0, err
	}

	// Forward ZMap's stderr to our log.
	var stderrWg sync.WaitGroup
	stderrWg.Add(1)
	go func() {
		defer stderrWg.Done()
		drainStderr(runner.Stderr())
	}()

	writer, err := NewWriter(m.MeasurementFilePath)
	if err != nil {
		stop() // cancel ctx -> Runner shuts ZMap down
		_ = runner.Wait()
		stderrWg.Wait()
		return 0, err
	}

	var written atomic.Uint64

	parser := NewParser(runner.Stdout())
	parseErr := streamRows(ctx, parser, writer, &written)

	if parseErr != nil {
		stop() // unblock zmap if we stopped reading early
	}

	// Wait for ZMap to exit.
	zmapErr := runner.Wait()
	closeErr := writer.Close()

	stderrWg.Wait()

	total := written.Load()

	switch {
	case parseErr != nil && !errors.Is(parseErr, io.EOF) && !errors.Is(parseErr, context.Canceled):
		return total, fmt.Errorf("parse: %w", parseErr)
	case zmapErr != nil && ctx.Err() == nil:
		// ZMap died unexpectedly (not because we canceled)
		return total, fmt.Errorf("zmap exit: %w", zmapErr)
	case closeErr != nil:
		return total, fmt.Errorf("close parquet: %w", closeErr)
	}

	log.Printf("zmap: wrote %d records to %s", total, m.MeasurementFilePath)
	return total, nil
}

// streamRows pulls rows from the parser and appends them to the writer until
// io.EOF or context cancellation.
func streamRows(ctx context.Context, p *Parser, w *Writer, written *atomic.Uint64) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		row, err := p.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if err := w.Append(ToRecord(row)); err != nil {
			return err
		}
		written.Add(1)
	}
}

// drainStderr forwards ZMap's stderr to our own log, one line at a time.
func drainStderr(r io.Reader) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			log.Printf("zmap: %s", trimNewline(line))
		}
		if err != nil {
			return
		}
	}
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
