package os

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/records"
)

func TestMergerRetainsFallbackEvidenceAndDropsEmptyRecords(t *testing.T) {
	out := make(chan records.OSRecord, 1)
	m := &merger{out: out}

	m.emit(records.OSRecord{IPAddress: "192.0.2.1", HTTPServer: "nginx/1.28.0"})
	select {
	case got := <-out:
		if got.OSName != "" || got.DetectedName != "nginx" ||
			got.DetectedType != detectionServerSoftware {
			t.Fatalf("unexpected emitted record: %+v", got)
		}
	default:
		t.Fatal("software fallback record was not emitted")
	}

	m.emit(records.OSRecord{IPAddress: "192.0.2.2"})
	if got := m.totalDropped.Load(); got != 1 {
		t.Fatalf("totalDropped = %d, want 1", got)
	}
}
