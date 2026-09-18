package stats

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
)

func clearTCPBadFlags() {
	for phase := range tcpBadFlags {
		for mask := range tcpBadFlags[phase] {
			tcpBadFlags[phase][mask].Store(0)
		}
	}
}

func TestTCPBadFlagsConcurrentSummary(t *testing.T) {
	clearTCPBadFlags()
	t.Cleanup(clearTCPBadFlags)
	if got := TCPBadFlagsSummary(); got != "" {
		t.Fatalf("empty summary = %q", got)
	}
	RecordTCPBadFlags(TCPNoConnection, sets.New[string]())
	RecordTCPBadFlags(TCPHandshake, sets.New(types.TCPFlagACK, types.TCPFlagECE, types.TCPFlagNS))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				RecordTCPBadFlags(TCPData, sets.New(types.TCPFlagACK, types.TCPFlagPSH))
			}
		}()
	}
	_ = TCPBadFlagsSummary()
	wg.Wait()
	want := "no_connection:NONE=1 handshake:AEN=1 data:PA=800"
	if got := TCPBadFlagsSummary(); got != want {
		t.Fatalf("summary = %q, want %q", got, want)
	}
}

func TestTCPBadFlagsFinalLog(t *testing.T) {
	clearTCPBadFlags()
	oldStop, oldOutput := measurement.StopLogs, log.Writer()
	t.Cleanup(func() {
		measurement.StopLogs = oldStop
		log.SetOutput(oldOutput)
		clearTCPBadFlags()
	})
	var output bytes.Buffer
	log.SetOutput(&output)
	measurement.StopLogs = make(chan struct{})
	measurement.LogsWg.Add(1)
	go Log()
	RecordTCPBadFlags(TCPData, sets.New(types.TCPFlagFIN, types.TCPFlagACK))
	close(measurement.StopLogs)
	measurement.LogsWg.Wait()
	if !strings.Contains(output.String(), "tcp_bad_flags_final[data:FA=1]") {
		t.Fatalf("missing final counters: %s", output.String())
	}
}
