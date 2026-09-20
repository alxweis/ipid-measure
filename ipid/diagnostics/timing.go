package diagnostics

import (
	"fmt"
	"sync/atomic"
	"time"
)

const SampleEvery = 256

type Timing struct {
	calls   atomic.Int64
	samples atomic.Int64
	total   atomic.Int64
	maximum atomic.Int64
	slow    atomic.Int64
}

func (t *Timing) Start() time.Time {
	if (t.calls.Add(1)-1)%SampleEvery != 0 {
		return time.Time{}
	}
	return time.Now()
}

func (t *Timing) End(start time.Time) {
	if !start.IsZero() {
		t.Observe(time.Since(start))
	}
}

func (t *Timing) Observe(elapsed time.Duration) {
	if elapsed < 0 {
		return
	}
	ns := int64(elapsed)
	t.samples.Add(1)
	t.total.Add(ns)
	if elapsed >= time.Millisecond {
		t.slow.Add(1)
	}
	for previous := t.maximum.Load(); ns > previous; previous = t.maximum.Load() {
		if t.maximum.CompareAndSwap(previous, ns) {
			break
		}
	}
}

func (t *Timing) String() string {
	samples := t.samples.Load()
	average := float64(0)
	if samples > 0 {
		average = float64(t.total.Load()) / float64(samples) / 1e3
	}
	return fmt.Sprintf("samples=%d avg_us=%.1f max_us=%.1f ge_1ms=%d", samples, average, float64(t.maximum.Load())/1e3, t.slow.Load())
}

var (
	Headers       Timing
	Transport     Timing
	Lookup        Timing
	ReplyLock     Timing
	FailLock      Timing
	SendLock      Timing
	Sendmsg       Timing
	SendProbeHold Timing
)

var epoch = time.Now()

type Capture struct {
	ReadyNS         atomic.Int64
	FirstSendNS     atomic.Int64
	ReceiveBuffer   atomic.Int64
	Snaplen         atomic.Int64
	KernelTimestamp atomic.Int64
	SocketErrors    atomic.Int64
	Packets         atomic.Int64
	Drops           atomic.Int64
	FirstDropNS     atomic.Int64
	LastDropNS      atomic.Int64
	Read            Timing
	Age             Timing
	Process         Timing
}

var Captures [2]Capture

func NowNS() int64 { return time.Since(epoch).Nanoseconds() }

func (c *Capture) MarkSend() {
	if c.FirstSendNS.Load() == 0 {
		c.FirstSendNS.CompareAndSwap(0, NowNS())
	}
}

func (c *Capture) Record(packets, drops uint32) {
	c.Packets.Add(int64(packets))
	c.Drops.Add(int64(drops))
	if drops > 0 {
		now := NowNS()
		c.FirstDropNS.CompareAndSwap(0, now)
		c.LastDropNS.Store(now)
	}
}
