package os

import (
	"context"
	osstd "os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/parquet-go/parquet-go"
)

func TestObservationSidecarIncludesResponseWithoutEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.pq")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer, err := newObservationWriter(path, cancel)
	if err != nil {
		t.Fatal(err)
	}
	m := newMerger(make(chan records.OSRecord, 2), newCoverageStats(2))
	m.observe = writer.observe
	m.emit(evidenceRecord{IPAddress: "192.0.2.1", HTTPSResponded: true})
	m.emit(evidenceRecord{IPAddress: "192.0.2.2", SSHResponded: true, SSHServerID: "SSH-2.0-OpenSSH_9.0 Ubuntu"})
	if err = writer.close(2); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal(ctx.Err())
	}
	rows, err := parquet.ReadFile[observation](path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Response != 8 || rows[0].Evidence != 0 || rows[0].Status != "no-evidence" {
		t.Fatalf("lost response-only evidence: %+v", rows)
	}
	if rows[1].Response != 1 || rows[1].Evidence != 1 || rows[1].Tagged != 1 || rows[1].Status != "resolved" {
		t.Fatalf("bad masks/classification: %+v", rows[1])
	}
	if m.totalEmitted.Load() != 1 || m.totalDropped.Load() != 1 {
		t.Fatal("legacy os.pq inclusion changed")
	}
}

func TestObservationConcurrencyAndIncompleteOrFailedWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.pq")
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer, err := newObservationWriter(path, cancel)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 5000; j++ {
				writer.observe(evidenceRecord{IPAddress: "192.0.2.1"}, serviceTags{}, decision{status: "no-evidence"})
			}
		}()
	}
	workers.Wait()
	if err = writer.close(20001); err == nil {
		t.Fatal("incomplete target observations accepted")
	}
	ctx, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	broken, err := newObservationWriter(filepath.Join(t.TempDir(), "broken.pq"), cancel2)
	if err != nil {
		t.Fatal(err)
	}
	_ = broken.file.Close()
	broken.observe(evidenceRecord{IPAddress: "192.0.2.1"}, serviceTags{}, decision{status: "no-evidence"})
	if err = broken.close(1); err == nil {
		t.Fatal("writer error swallowed")
	}
	if ctx.Err() == nil {
		t.Fatal("writer failure did not cancel pipeline")
	}
	_ = osstd.Remove(path)
}
