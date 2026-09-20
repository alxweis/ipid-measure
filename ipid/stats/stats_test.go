package stats

import (
	"bytes"
	"log"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alxweis/ipid-measure/ipid/measurement"
)

func TestStartStatsInitializesSequenceCountersSynchronously(t *testing.T) {
	measurement.RequestCount = 7
	measurement.StopLogs = make(chan struct{})
	measurement.LogsWg.Add(1)

	measurement.StartStats()
	if len(ProbesReachedSeq) != int(measurement.RequestCount) {
		t.Fatalf("len(ProbesReachedSeq) = %d, want %d", len(ProbesReachedSeq), measurement.RequestCount)
	}

	close(measurement.StopLogs)
	measurement.LogsWg.Wait()
}

func TestFinalCountersWithoutPeriodicTick(t *testing.T) {
	var output bytes.Buffer
	previousWriter, previousStop := log.Writer(), measurement.StopLogs
	previous := atomic.LoadInt64(&DropRateLow)
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		measurement.StopLogs = previousStop
		atomic.StoreInt64(&DropRateLow, previous)
	})
	log.SetOutput(&output)
	atomic.StoreInt64(&DropRateLow, 290)
	measurement.StopLogs = make(chan struct{})
	close(measurement.StopLogs)
	measurement.LogsWg.Add(1)
	Log()
	for _, want := range []string{"replies_final[", "probes_final[", "rate_low=290", "capture_final[packets=", "dropped=", "errors=", "receive_timing_final[", "receiver_diag_final[receiver=0", "receiver_diag_final[receiver=1"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %s in %s", want, output.String())
		}
	}
}
