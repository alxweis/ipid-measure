package sender

import (
	"sync"
	"time"

	"github.com/alxweis/ipid-measure/ipid/measurement"
)

type RateLimiter struct {
	mu sync.Mutex

	bytesPerSecond float64

	packetsPerSecond float64

	burstBytes   float64
	burstPackets float64

	availBytes   float64
	availPackets float64

	done    chan struct{}
	stopped bool
	last    time.Time
}

var Limiter *RateLimiter

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

		// Compute the time until enough tokens accrue. Cap by a safety floor, so we never busy-wait.
		waitSec := tokensWait(rl, bytesNeeded)
		if waitSec < 0.0002 {
			waitSec = 0.0002
		}

		// Wait without holding the lock so refill / Stop can race in.
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

func (rl *RateLimiter) Stop() {
	rl.mu.Lock()
	if !rl.stopped {
		rl.stopped = true
		close(rl.done)
	}
	rl.mu.Unlock()
}

func SetupRateLimiter() {
	bandwidth := 0
	if measurement.Config.Bandwidth != nil {
		bandwidth = int(*measurement.Config.Bandwidth)
	}

	pps := 0
	if measurement.Config.PacketsPerSecond != nil {
		pps = int(*measurement.Config.PacketsPerSecond)
	}

	Limiter = newRateLimiter(bandwidth, pps, 100*time.Millisecond)
}
