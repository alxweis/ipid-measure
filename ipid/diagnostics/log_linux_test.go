package diagnostics

import (
	"bytes"
	"log"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestFinalDiagnosticsBeforeFirstTick(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	t.Cleanup(func() {
		log.SetOutput(previous)
		Captures[0].ReadyNS.Store(0)
		Captures[0].FirstSendNS.Store(0)
	})
	log.SetOutput(&output)
	Begin()
	Captures[0].FirstSendNS.Store(1)
	Captures[0].ReadyNS.Store(2)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	Log(ms, true)
	for _, want := range []string{"receive_timing_final[sample_every=256", "receiver_diag_final[receiver=0", "receiver_diag_final[receiver=1", "send_before_ready=true", "receive_runtime_final[interval_s=", "cpu_pct=", "alloc_mib=", "gc_pause_ms="} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, output.String())
		}
	}
}

func TestCPUSecondsIncludesUserAndSystem(t *testing.T) {
	usage := syscall.Rusage{Utime: syscall.Timeval{Sec: 1, Usec: 250000}, Stime: syscall.Timeval{Sec: 2, Usec: 500000}}
	if cpuSeconds(usage) != 3.75 {
		t.Fatal(cpuSeconds(usage))
	}
}
