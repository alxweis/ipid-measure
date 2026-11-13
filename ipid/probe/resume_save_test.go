package probe

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/rtresume"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/internal/upload"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/parquet-go/parquet-go"
)

func TestResumeSaverPreservesOldRowsBeforeAcceptingTail(t *testing.T) {
	oldConfig, oldPaths, oldPlan, oldRequests, oldProtocols, oldStop := measurement.Config, measurement.Paths, measurement.ResumePlan, measurement.RequestCount, measurement.InterProtocols, measurement.StopSignal
	oldSave, oldReady := SaveProbesChannel, saveReady
	fields := []*int64{&stats.ValidProbes, &stats.ProbeCount, &stats.AbortProto, &stats.DropLimiterStop, &stats.DropSendErr, &stats.DropTimeout, &stats.DropInterrupt, &stats.DropNotRecv, &stats.AbortBadDst, &stats.AbortBadPort, &stats.AbortSeqOOR, &stats.AbortUnsent, &stats.AbortDup, &stats.AbortLate}
	values := make([]int64, len(fields))
	for i, p := range fields {
		values[i] = atomic.LoadInt64(p)
	}
	t.Cleanup(func() {
		measurement.Config, measurement.Paths, measurement.ResumePlan, measurement.RequestCount, measurement.InterProtocols, measurement.StopSignal = oldConfig, oldPaths, oldPlan, oldRequests, oldProtocols, oldStop
		SaveProbesChannel, saveReady = oldSave, oldReady
		for i, p := range fields {
			atomic.StoreInt64(p, values[i])
		}
	})
	directory := t.TempDir()
	source, target, out := filepath.Join(directory, "old.pq"), filepath.Join(directory, "zmap.pq"), filepath.Join(directory, "new.pq")
	old := records.IPIDRecord{IPAddress: "192.0.2.1", IPIDSequence: strings.TrimSuffix(strings.Repeat("42,", 16), ","), SendTimestampSequence: strings.TrimSuffix(strings.Repeat("100,", 16), ","), ReceiveTimestampSequence: strings.TrimSuffix(strings.Repeat("101,", 16), ","), DFSequence: strings.TrimSuffix(strings.Repeat("1,", 16), ",")}
	f, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	w := parquet.NewGenericWriter[records.IPIDRecord](f)
	if _, err := w.Write([]records.IPIDRecord{old}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.WriteFile(target, []byte("target evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	si, _ := os.Stat(source)
	ti, _ := os.Stat(target)
	before, _ := upload.Evidence(source)
	measurement.Config = &config.IPIDConfig{MeasurementMode: types.MeasurementModeRTBased}
	measurement.Paths = &paths.IPIDMeasurement{ZMapLinkedMeasurement: paths.ZMapLinkedMeasurement{Measurement: paths.Measurement{MeasurementFilePath: out}}}
	measurement.RequestCount = 16
	measurement.InterProtocols = nil
	measurement.StopSignal = make(chan struct{})
	measurement.ResumePlan = &rtresume.Plan{Source: source, Target: target, SourceInfo: si, TargetInfo: ti, Saved: 1, Started: 2, Total: 3, Failures: map[string]int64{"interrupt": 1}}
	SetupSaveChannel()
	measurement.SaveWg.Add(1)
	go Save()
	if err := <-saveReady; err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&stats.ValidProbes) != 1 || atomic.LoadInt64(&stats.ProbeCount) != 2 {
		t.Fatal("old successes/failures not restored before tail")
	}
	p := &Probe{Target: net.ParseIP("192.0.2.3"), Samples: make([]Sample, 16)}
	for i := range p.Samples {
		p.Samples[i].MarkSent(200)
		p.Samples[i].TryFill(77, 201, false)
	}
	atomic.AddInt64(&stats.ProbeCount, 1)
	atomic.AddInt64(&stats.ValidProbes, 1)
	SaveProbesChannel <- p
	CloseSaveChannel()
	measurement.SaveWg.Wait()
	rows, err := parquet.ReadFile[records.IPIDRecord](out)
	if err != nil || len(rows) != 2 || rows[0] != old || rows[1].IPAddress != "192.0.2.3" || rows[1].DFSequence != strings.TrimSuffix(strings.Repeat("0,", 16), ",") {
		t.Fatalf("lost old/new samples: %+v, %v", rows, err)
	}
	after, _ := upload.Evidence(source)
	if after != before {
		t.Fatal("old source changed")
	}
	if atomic.LoadInt64(&stats.DropInterrupt) != 1 || atomic.LoadInt64(&stats.ProbeCount) != 3 || atomic.LoadInt64(&stats.ValidProbes) != 2 {
		t.Fatal("cumulative coverage counters changed")
	}
}
