package worker

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/parquet-go/parquet-go"
)

func setupTargetStream(t *testing.T, path string, interprotocol bool) {
	t.Helper()
	oldPaths, oldProtocols, oldSample := measurement.Paths, measurement.InterProtocols, measurement.InterProtocolSample
	oldTargets := targets
	oldCount := atomic.LoadInt64(&stats.NumberOfTargetIPAddresses)
	t.Cleanup(func() {
		measurement.Paths, measurement.InterProtocols, measurement.InterProtocolSample = oldPaths, oldProtocols, oldSample
		targets = oldTargets
		atomic.StoreInt64(&stats.NumberOfTargetIPAddresses, oldCount)
	})
	measurement.Paths = &paths.IPIDMeasurement{ZMapLinkedMeasurement: paths.ZMapLinkedMeasurement{ZMapLinkPath: path}}
	measurement.InterProtocols = nil
	measurement.InterProtocolSample = "base"
	if interprotocol {
		// IsInterProtocol only needs a nonempty protocol list for dispatch.
		measurement.InterProtocols = append(measurement.InterProtocols, "icmp")
	}
	targets = make(chan target, 4)
	atomic.StoreInt64(&stats.NumberOfTargetIPAddresses, 99)
}

// Fixtures are written by PyArrow 26.0.0 using two explicit string columns
// and zero rows (pq.write_table(pa.table(...), path)). Unlike an empty Go
// writer, they contain an empty row group whose page offset cannot be read.
func TestEmptyPyArrowTargets(t *testing.T) {
	for _, test := range []struct {
		name          string
		interprotocol bool
	}{
		{"zmap", false},
		{"interprotocol", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setupTargetStream(t, filepath.Join("testdata", "empty-"+test.name+".pq"), test.interprotocol)
			if err := StreamZMapToWorkers(); err != nil {
				t.Fatalf("valid empty target file must succeed: %v", err)
			}
			if got := atomic.LoadInt64(&stats.NumberOfTargetIPAddresses); got != 0 {
				t.Fatalf("target count = %d, want 0", got)
			}
			if len(targets) != 0 {
				t.Fatal("empty cohort must not schedule probes")
			}
		})
	}
}

func writeTargets[T any](t *testing.T, rows []T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.pq")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := parquet.NewGenericWriter[T](f)
	if _, err := w.Write(rows); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNonemptyZMapTargets(t *testing.T) {
	path := writeTargets(t, []records.ZMap{{IPAddress: "192.0.2.1"}, {IPAddress: "192.0.2.2"}})
	setupTargetStream(t, path, false)
	if err := StreamZMapToWorkers(); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || atomic.LoadInt64(&stats.NumberOfTargetIPAddresses) != 2 {
		t.Fatal("nonempty target population changed")
	}
	for _, want := range []string{"192.0.2.1", "192.0.2.2"} {
		if got := (<-targets).ip.String(); got != want {
			t.Fatalf("target = %s, want %s", got, want)
		}
	}
}

func TestNonemptyInterprotocolTargets(t *testing.T) {
	path := writeTargets(t, []records.InterProtocolTarget{
		{IPAddress: "192.0.2.1", Strategy: "SINGLE"},
		{IPAddress: "192.0.2.2", Strategy: "RANDOM"},
	})
	setupTargetStream(t, path, true)
	if err := StreamZMapToWorkers(); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || atomic.LoadInt64(&stats.NumberOfTargetIPAddresses) != 1 {
		t.Fatal("BASE/MASS filtering changed")
	}
	if got := <-targets; got.ip.String() != "192.0.2.1" || got.strategy != "SINGLE" {
		t.Fatalf("unexpected target: %+v", got)
	}
}
