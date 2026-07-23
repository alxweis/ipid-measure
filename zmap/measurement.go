package zmap

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/types"
)

const (
	ipv4AddressCount           = uint64(1) << 32
	bitsPerDedupWord           = 64
	TCPDedupBitmapBytes        = ipv4AddressCount / 8
	TCPDedupGoMemoryLimitBytes = 768 << 20
)

type recordAppender interface {
	Append(records.ZMap) error
}

// ipv4Deduplicator is an exact, constant-size set for IPv4 addresses.
type ipv4Deduplicator struct {
	words        []uint64
	addressCount uint64
}

func newIPv4Deduplicator(addressCount uint64) *ipv4Deduplicator {
	wordCount := (addressCount + bitsPerDedupWord - 1) / bitsPerDedupWord
	return &ipv4Deduplicator{
		words:        make([]uint64, int(wordCount)),
		addressCount: addressCount,
	}
}

// Add records an IPv4 address and reports whether it was not present before.
func (d *ipv4Deduplicator) Add(address string) (bool, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() {
		return false, fmt.Errorf("invalid IPv4 address %q", address)
	}

	octets := ip.As4()
	value := uint64(binary.BigEndian.Uint32(octets[:]))
	if value >= d.addressCount {
		return false, fmt.Errorf("IPv4 address %q exceeds deduplicator capacity", address)
	}

	word := value / bitsPerDedupWord
	mask := uint64(1) << (value % bitsPerDedupWord)
	if d.words[word]&mask != 0 {
		return false, nil
	}
	d.words[word] |= mask
	return true, nil
}

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

	var (
		deduplicator *ipv4Deduplicator
		targetLimit  uint64
	)
	if c.Payload == types.PayloadTCP {
		deduplicator = newIPv4Deduplicator(ipv4AddressCount)
		if c.NumberOfTargetIPAddresses != nil {
			targetLimit = uint64(*c.NumberOfTargetIPAddresses)
		}
		log.Printf(
			"zmap: deduplicating TCP responders by IP address (%d MiB bitmap)",
			TCPDedupBitmapBytes>>20,
		)
	}

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

	parser := NewParser(runner.Stdout(), UsesJSONOutput(c))
	parseErr := streamRows(
		ctx,
		parser,
		writer,
		&written,
		deduplicator,
		targetLimit,
		stop,
	)

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
// io.EOF, context cancellation, or the unique target limit is reached.
func streamRows(
	ctx context.Context,
	p *Parser,
	w recordAppender,
	written *atomic.Uint64,
	deduplicator *ipv4Deduplicator,
	targetLimit uint64,
	stop context.CancelFunc,
) error {
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

		if deduplicator != nil {
			first, err := deduplicator.Add(row.IPAddress)
			if err != nil {
				return err
			}
			if !first {
				continue
			}
		}

		if err := w.Append(ToRecord(row)); err != nil {
			return err
		}
		total := written.Add(1)
		if targetLimit > 0 && total >= targetLimit {
			stop()
			return nil
		}
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
