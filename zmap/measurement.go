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

	// Forward ZMap's stderr to our log, line by line.
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

// streamRows pulls rows from the parser, deduplicates by source IP, and appends  unique rows to the writer until
// io.EOF or context cancellation.
func streamRows(ctx context.Context, p *Parser, w *Writer, written *atomic.Uint64) error {
	dedup := newIPv4Dedup() // 512 MiB, full IPv4 uniqueness guarantee

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

		key, ok := parseIPv4(row.IPAddress)
		if !ok {
			continue // not a dotted-quad saddr; skip defensively
		}
		if dedup.seenOrAdd(key) {
			continue // already written
		}

		if err := w.Append(ToRecord(row)); err != nil {
			return err
		}
		written.Add(1)
	}
}

// ipv4Dedup is a 512 MiB bitmap over the entire IPv4 space.
type ipv4Dedup struct {
	bits []uint64
}

func newIPv4Dedup() *ipv4Dedup {
	// 2^32 bits / 64 bits-per-word = 2^26 words = 67,108,864 * 8 B = 512 MiB.
	return &ipv4Dedup{bits: make([]uint64, 1<<26)}
}

// seenOrAdd reports whether key was already recorded; if not, it records it.
func (d *ipv4Dedup) seenOrAdd(key uint32) bool {
	word := key >> 6
	mask := uint64(1) << (key & 63)
	if d.bits[word]&mask != 0 {
		return true
	}
	d.bits[word] |= mask
	return false
}

// parseIPv4 parses a dotted-quad string into a uint32 without allocating.
func parseIPv4(s string) (uint32, bool) {
	var ip, octet uint32
	var digits, parts int
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if digits == 0 {
				return 0, false
			}
			ip = ip<<8 | octet
			octet, digits = 0, 0
			parts++
			continue
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		octet = octet*10 + uint32(c-'0')
		if octet > 255 {
			return 0, false
		}
		digits++
	}
	if digits == 0 || parts != 3 {
		return 0, false
	}
	return ip<<8 | octet, true
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
