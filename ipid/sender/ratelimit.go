package sender

import (
	"math"
	"sync"
	"time"

	"github.com/alxweis/ipid-measure/ipid/measurement"
)

// RateLimiter throttles the global send rate by bytes (bandwidth) and optionally
// by packets per second. It is the primary throttle of the new architecture:
// throughput is bounded here, not by the size of the prober pool. A single
// shared limiter governs both senders together so the overall bandwidth/pps cap
// is enforced regardless of how many goroutines call Send concurrently.
type RateLimiter struct {
	mu sync.Mutex

	// bytes per second capacity; 0 means unlimited bytes
	bytesPerSecond float64
	// packets per second capacity; 0 means unlimited packets
	packetsPerSecond float64

	// burst sizes (capacity of each bucket)
	burstBytes   float64
	burstPackets float64

	// available tokens
	availBytes   float64
	availPackets float64

	// done is closed by Stop. Acquire selects on it during its sleep so a
	// shutdown unblocks every waiter immediately rather than waiting out the
	// timed sleep.
	done    chan struct{}
	stopped bool
	last    time.Time
}

// Limiter is the process-wide rate limiter, owned by the sender package. It is
// initialised by Setup before any goroutine starts.
var Limiter *RateLimiter

// newRateLimiter constructs a limiter from configured bandwidth (bits/s) and
// pps. burstDuration controls how much send can burst above the long-run rate;
// 100ms is the standard ZMap-class default and avoids both starvation (too
// small) and unbounded bursts (too large).
func newRateLimiter(bandwidthBitsPerSecond, packetsPerSecond int, burstDuration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		bytesPerSecond:   float64(bandwidthBitsPerSecond) / 8.0,
		packetsPerSecond: float64(packetsPerSecond),
		last:             time.Now(),
		done:             make(chan struct{}),
	}
	burstSec := burstDuration.Seconds()
	rl.burstBytes = rl.bytesPerSecond * burstSec
	rl.burstPackets = rl.packetsPerSecond * burstSec
	// Start half-full so the first probes do not see an empty bucket.
	rl.availBytes = rl.burstBytes / 2
	rl.availPackets = rl.burstPackets / 2
	return rl
}

// refill adds tokens since the last refill, capped at the burst size. Caller
// must hold rl.mu.
func (rl *RateLimiter) refill(now time.Time) {
	elapsed := now.Sub(rl.last).Seconds()
	if elapsed <= 0 {
		return
	}
	rl.last = now
	if rl.bytesPerSecond > 0 {
		rl.availBytes += elapsed * rl.bytesPerSecond
		if rl.availBytes > rl.burstBytes {
			rl.availBytes = rl.burstBytes
		}
	}
	if rl.packetsPerSecond > 0 {
		rl.availPackets += elapsed * rl.packetsPerSecond
		if rl.availPackets > rl.burstPackets {
			rl.availPackets = rl.burstPackets
		}
	}
}

// Acquire blocks until the requested byte and packet budget is available, or
// the limiter is stopped. It MUST NOT silently undercount: if the bucket is too
// small ever to satisfy a request (frame larger than burst), it adapts by
// raising burstBytes to the frame size so progress is always possible.
//
// Returns false if the limiter was stopped during the wait, true on success.
func (rl *RateLimiter) Acquire(frameBytes int) bool {
	bytesNeeded := float64(frameBytes)

	rl.mu.Lock()

	// Adapt burst so a single oversize frame never deadlocks the limiter.
	if rl.bytesPerSecond > 0 && bytesNeeded > rl.burstBytes {
		rl.burstBytes = bytesNeeded
	}

	for {
		if rl.stopped {
			rl.mu.Unlock()
			return false
		}

		rl.refill(time.Now())

		bytesOK := rl.bytesPerSecond == 0 || rl.availBytes >= bytesNeeded
		packetsOK := rl.packetsPerSecond == 0 || rl.availPackets >= 1

		if bytesOK && packetsOK {
			if rl.bytesPerSecond > 0 {
				rl.availBytes -= bytesNeeded
			}
			if rl.packetsPerSecond > 0 {
				rl.availPackets -= 1
			}
			rl.mu.Unlock()
			return true
		}

		// Compute the time until enough tokens accrue; cap by a safety floor so
		// we never busy-wait. 200µs is fine: at 10 Gbps it represents only
		// ~250 KB, well below sane burst sizes.
		waitSec := tokensWait(rl, bytesNeeded)
		if waitSec < 0.0002 {
			waitSec = 0.0002
		}

		// Wait without holding the lock so refill / Stop can race in. Selecting
		// on rl.done means Stop() wakes us immediately rather than us waiting
		// out the full timer (which is what time.Sleep would have done). Allocate
		// the timer just once per wait iteration; reuse is not worthwhile here
		// because timer overhead is negligible compared to the wait itself.
		rl.mu.Unlock()
		timer := time.NewTimer(time.Duration(waitSec * float64(time.Second)))
		select {
		case <-timer.C:
		case <-rl.done:
			if !timer.Stop() {
				// Drain the channel so the timer can be GC'd promptly.
				select {
				case <-timer.C:
				default:
				}
			}
		}
		rl.mu.Lock()
	}
}

// tokensWait returns the seconds until both buckets can satisfy the request.
// Caller holds rl.mu.
func tokensWait(rl *RateLimiter, bytesNeeded float64) float64 {
	var w float64
	if rl.bytesPerSecond > 0 && rl.availBytes < bytesNeeded {
		w = (bytesNeeded - rl.availBytes) / rl.bytesPerSecond
	}
	if rl.packetsPerSecond > 0 && rl.availPackets < 1 {
		wp := (1 - rl.availPackets) / rl.packetsPerSecond
		if wp > w {
			w = wp
		}
	}
	return w
}

// Stop releases all blocked Acquire callers so shutdown can drain. Safe to call
// multiple times; only the first call closes the done channel.
func (rl *RateLimiter) Stop() {
	rl.mu.Lock()
	if !rl.stopped {
		rl.stopped = true
		close(rl.done)
	}
	rl.mu.Unlock()
}

// SetupRateLimiter installs the global limiter from the loaded configuration.
// Registered as a measurement.SetupRateLimiter hook.
func SetupRateLimiter() {
	bandwidth := math.MaxInt
	if measurement.Config.Bandwidth != nil {
		bandwidth = int(*measurement.Config.Bandwidth)
	}

	pps := math.MaxInt
	if measurement.Config.PacketsPerSecond != nil {
		pps = int(*measurement.Config.PacketsPerSecond)
	}

	Limiter = newRateLimiter(bandwidth, pps, 100*time.Millisecond)
}
