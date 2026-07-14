package stats

import (
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
