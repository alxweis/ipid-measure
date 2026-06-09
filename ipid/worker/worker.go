package worker

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/packet"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

// In the new architecture there is no per-worker reply channel and no per-IP
// hash routing of replies — replies are matched to probes via the shared
// inflight registry inside the probe package. A "worker" here is therefore
// simply one of N prober goroutines, all consuming from a single target
// channel. N is Config.Concurrency and may be very large (tens of thousands).
//
// Throughput is bounded by the global rate limiter in the sender package, not
// by the size of this pool: the pool size only needs to be big enough to cover
// bandwidth * RTT (Little's law).

// targets is the single shared input channel feeding the prober pool. Its size
// is small (one batch's worth) because backpressure flows naturally back to
// the parquet streaming reader.
var targets chan net.IP

// StartAll spawns Concurrency prober goroutines. Registered into
// measurement.StartWorkers.
func StartAll() {
	concurrency := measurement.Config.Concurrency
	// Channel buffer: enough to keep all probers busy through one parquet read
	// batch, but bounded so a stalled writer eventually back-pressures here.
	targets = make(chan net.IP, concurrency*2)

	for i := uint64(0); i < concurrency; i++ {
		measurement.WorkerWg.Add(1)
		go proberLoop()
	}
}

// CloseTargets closes the shared input channel, signalling end-of-stream.
// Registered into measurement.CloseTargetChans.
func CloseTargets() {
	close(targets)
}

// proberLoop is one prober goroutine. It owns a reusable packet scratch buffer
// (allocated once) and runs probe.Measure on each target until the channel is
// closed or shutdown is requested.
func proberLoop() {
	defer measurement.WorkerWg.Done()

	scratch := make([]packet.Packet, measurement.RequestCount)

	for {
		select {
		case <-measurement.StopSignal:
			return
		case target, ok := <-targets:
			if !ok {
				return
			}
			probe.Measure(target, scratch)
		}
	}
}

// StreamZMapToWorkers streams the ZMap parquet file and feeds every target into
// the shared input channel. Registered into measurement.StreamTargets.
//
// IP parsing avoidance: the parquet column is a dotted-quad string. We parse it
// into a fresh net.IP per row (this is unavoidable for the format) but reuse
// no per-row state otherwise. At 500M rows, this is one short-lived 4-byte
// allocation per row — small and easily handled by the GC.
func StreamZMapToWorkers() error {
	file, err := os.Open(measurement.Paths.ZMapLinkPath)
	if err != nil {
		return fmt.Errorf("open zmap parquet: %w", err)
	}
	defer file.Close()

	reader := parquet.NewGenericReader[records.ZMap](file)
	defer reader.Close()

	// Record the total target count so the stats logger can compute progress.
	atomic.StoreInt64(&stats.NumberOfTargetIPAddresses, reader.NumRows())

	buffer := make([]records.ZMap, consts.ZMapReadBufferSize)

	for {
		// Stop streaming promptly if a shutdown was requested.
		select {
		case <-measurement.StopSignal:
			return nil
		default:
		}

		count, err := reader.Read(buffer)

		for i := 0; i < count; i++ {
			ip4 := parseIPv4Fast(buffer[i].IPAddress)
			if ip4 == nil {
				continue
			}
			select {
			case targets <- ip4:
			case <-measurement.StopSignal:
				return nil
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read parquet: %w", err)
		}
		if count == 0 {
			return nil
		}
	}
}

// parseIPv4Fast parses a dotted-quad string into a 4-byte net.IP without the
// general-purpose net.ParseIP path (which probes for IPv6 first, allocates a
// 16-byte slice, and runs a state machine). At 500M targets this is a worthy
// hot-path optimisation. Returns nil for malformed input.
func parseIPv4Fast(s string) net.IP {
	var ip [4]byte
	octet := 0
	val := 0
	hadDigit := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if !hadDigit || octet >= 3 || val > 255 {
				return nil
			}
			ip[octet] = byte(val)
			octet++
			val = 0
			hadDigit = false
			continue
		}
		if c < '0' || c > '9' {
			return nil
		}
		val = val*10 + int(c-'0')
		if val > 255 {
			return nil
		}
		hadDigit = true
	}
	if octet != 3 || !hadDigit {
		return nil
	}
	ip[3] = byte(val)
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).To4()
}

func init() {
	measurement.StartWorkers = StartAll
	measurement.CloseTargetChans = CloseTargets
	measurement.StreamTargets = StreamZMapToWorkers
}
