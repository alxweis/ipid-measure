package os

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/records"
)

func TestMergerWritesEvidenceAndDropsNoEvidence(t *testing.T) {
	out := make(chan records.OSRecord, 1)
	coverage := newCoverageStats(2)
	m := newMerger(out, coverage)

	m.emit(evidenceRecord{
		IPAddress: "192.0.2.1", HTTPServer: "nginx/1.24.0 (Ubuntu)", HTTPResponded: true,
	})
	got := <-out
	if got.OSStatus != statusResolved || got.OSTag == nil || *got.OSTag != "ubuntu" ||
		got.HTTPOS == nil || *got.HTTPOS != "ubuntu" {
		t.Fatalf("record = %+v", got)
	}

	m.emit(evidenceRecord{IPAddress: "192.0.2.2"})
	if got := m.totalDropped.Load(); got != 1 {
		t.Fatalf("totalDropped = %d, want 1", got)
	}
}

func TestMergerWaitsForAllThreeScannerResults(t *testing.T) {
	out := make(chan records.OSRecord, 1)
	m := newMerger(out, newCoverageStats(1))
	ip := "192.0.2.1"
	m.integrate(ip, scannerZGrab2, applyZGrab2(ZGrab2Result{IP: ip, SSHServerID: "Ubuntu"}))
	m.integrate(ip, scannerDNSChaos, applyDNSChaos(DNSChaosResult{IP: ip}))
	select {
	case record := <-out:
		t.Fatalf("record emitted early: %+v", record)
	default:
	}
	m.integrate(ip, scannerSNMP, applySNMP(SNMPResult{IP: ip}))
	if record := <-out; record.OSTag == nil || *record.OSTag != "ubuntu" {
		t.Fatalf("record = %+v", record)
	}
}
