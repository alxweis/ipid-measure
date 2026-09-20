package diagnostics

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSamplingIncludesFirstCall(t *testing.T) {
	var timing Timing
	for i := 0; i < 2*SampleEvery+1; i++ {
		start := timing.Start()
		if start.IsZero() != (i%SampleEvery != 0) {
			t.Fatalf("unexpected sample at call %d", i)
		}
		timing.End(start)
	}
	if timing.samples.Load() != 3 {
		t.Fatal("wrong sample count")
	}
}

func TestTimingConcurrentObservations(t *testing.T) {
	var timing Timing
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			timing.Observe(time.Duration(i) * time.Millisecond)
			_ = timing.String()
		}(i)
	}
	wg.Wait()
	timing.Observe(-time.Second)
	if timing.samples.Load() != 32 || timing.maximum.Load() != int64(32*time.Millisecond) || timing.slow.Load() != 32 || timing.total.Load() != int64(528*time.Millisecond) {
		t.Fatal("lost timing observations")
	}
	if !strings.Contains(timing.String(), "avg_us=16500.0") {
		t.Fatal(timing.String())
	}
}

func TestCaptureAccumulatesAndKeepsFirstEvents(t *testing.T) {
	var c Capture
	c.MarkSend()
	first := c.FirstSendNS.Load()
	c.MarkSend()
	c.Record(100, 0)
	if c.FirstDropNS.Load() != 0 || c.FirstSendNS.Load() != first {
		t.Fatal("incorrect first event")
	}
	c.Record(50, 3)
	firstDrop := c.FirstDropNS.Load()
	c.Record(20, 2)
	if c.Packets.Load() != 170 || c.Drops.Load() != 5 || firstDrop <= 0 || c.FirstDropNS.Load() != firstDrop || c.LastDropNS.Load() < firstDrop {
		t.Fatal("incorrect capture accumulation")
	}
}

func BenchmarkSampledTiming(b *testing.B) {
	var timing Timing
	b.ReportAllocs()
	for b.Loop() {
		start := timing.Start()
		timing.End(start)
	}
}
