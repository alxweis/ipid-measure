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
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/paths"
)

// Run executes a complete ZMap measurement.
func Run(c *config.ZMapConfig, m *paths.ZMapMeasurement) (uint64, error) {
	args, err := BuildArgs(c)
	if err != nil {
		return 0, fmt.Errorf("build args: %w", err)
	}

	log.Printf("zmap args: %v", args)

	// Top-level context with interrupt handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			log.Printf("zmap: interrupt received, shutting down...")
			cancel()
		case <-ctx.Done():
		}
	}()

	runner, err := Start(ctx, args)
	if err != nil {
		return 0, err
	}

	// Drain stderr and forward to stderr of our own process.
	var stderrWg sync.WaitGroup
	stderrWg.Add(1)
	go func() {
		defer stderrWg.Done()
		drainStderr(runner.Stderr())
	}()

	writer, err := NewWriter(m.MeasurementFilePath)
	if err != nil {
		// Best effort: terminate the subprocess started.
		_ = runner.Shutdown()
		stderrWg.Wait()
		return 0, err
	}

	// Stats tick
	var written atomic.Uint64
	var duplicates atomic.Uint64
	statsDone := make(chan struct{})
	go reportStats(ctx, &written, &duplicates, statsDone)

	parser := NewParser(runner.Stdout())

	expectedUnique := 0
	if c.NumberOfTargetIPAddresses != nil {
		expectedUnique = int(*c.NumberOfTargetIPAddresses)
	}

	parseErr := streamRows(ctx, parser, writer, &written, &duplicates, expectedUnique)

	// Wait for zmap to exit.
	zmapErr := runner.Wait()

	// Flush parquet (always, even on error, so any captured rows survive).
	closeErr := writer.Close()

	// Stop stats logger and drain stderr fully.
	cancel()
	<-statsDone
	stderrWg.Wait()

	totalWritten := written.Load()
	totalDuplicates := duplicates.Load()

	// Error reporting
	switch {
	case parseErr != nil && !errors.Is(parseErr, io.EOF) && !errors.Is(parseErr, context.Canceled):
		return totalWritten, fmt.Errorf("parse: %w", parseErr)
	case zmapErr != nil && ctx.Err() == nil:
		// ZMap died unexpectedly (not because we cancelled)
		return totalWritten, fmt.Errorf("zmap exit: %w", zmapErr)
	case closeErr != nil:
		return totalWritten, fmt.Errorf("close parquet: %w", closeErr)
	}

	log.Printf("zmap: wrote %d unique records to %s (filtered %d duplicate responses)",
		totalWritten, m.MeasurementFilePath, totalDuplicates)
	return totalWritten, nil
}

// streamRows pulls rows from the parser and appends them to the writer until
// the parser returns io.EOF (zmap exited) or the context is cancelled.
func streamRows(
	ctx context.Context,
	p *Parser,
	w *Writer,
	written, duplicates *atomic.Uint64,
	expectedUnique int,
) error {
	initCap := 1 << 20
	if expectedUnique > initCap {
		initCap = expectedUnique
	}
	seen := make(map[[4]byte]struct{}, initCap)

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

		key, ok := parseIPv4Key(row.IPAddress)
		if !ok {
			// Malformed IP address -> skip silently
			continue
		}
		if _, dup := seen[key]; dup {
			duplicates.Add(1)
			continue
		}
		seen[key] = struct{}{}

		if err := w.Append(ToRecord(row)); err != nil {
			return err
		}
		written.Add(1)
	}
}

// parseIPv4Key turns a dotted-quad string into a [4]byte hashable key.
func parseIPv4Key(s string) ([4]byte, bool) {
	var ip [4]byte
	octet := 0
	val := 0
	hadDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if !hadDigit || octet >= 3 || val > 255 {
				return ip, false
			}
			ip[octet] = byte(val)
			octet++
			val = 0
			hadDigit = false
			continue
		}
		if c < '0' || c > '9' {
			return ip, false
		}
		val = val*10 + int(c-'0')
		if val > 255 {
			return ip, false
		}
		hadDigit = true
	}
	if octet != 3 || !hadDigit {
		return ip, false
	}
	ip[3] = byte(val)
	return ip, true
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

// reportStats prints written-count + per-second delta until ctx is cancelled.
func reportStats(ctx context.Context, written, duplicates *atomic.Uint64, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(consts.LogUpdateInterval)
	defer ticker.Stop()

	var last uint64
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := written.Load()
			dups := duplicates.Load()
			delta := cur - last
			last = cur
			elapsed := time.Since(start).Truncate(time.Second)
			log.Printf("zmap: unique=%d (+%d/s) duplicates=%d elapsed=%s",
				cur, delta, dups, elapsed)
		}
	}
}
