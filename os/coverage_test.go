package os

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverageRecordsServiceAndClassificationCounts(t *testing.T) {
	coverage := newCoverageStats(2)
	coverage.record(evidenceRecord{
		HTTPServer: "Ubuntu", HTTPResponded: true, DNSResponded: true,
	}, serviceTags{HTTP: "ubuntu"}, decision{status: statusResolved, tag: "ubuntu"})
	coverage.recordWithoutEvidence(evidenceRecord{SSHResponded: true})
	path := filepath.Join(t.TempDir(), "os-coverage.json")
	if err := coverage.write(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document coverageDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != "3" || document.ClassifierVersion != "3" {
		t.Fatalf("versions = schema %q, classifier %q", document.SchemaVersion, document.ClassifierVersion)
	}
	if document.Detail.Targets.WithResponse != 2 || document.Detail.Targets.WithoutResponse != 0 ||
		document.Detail.Targets.WithEvidence != 1 || document.Detail.Targets.WithoutEvidence != 1 ||
		document.Detail.Targets.WithTag != 1 || document.Detail.Targets.WithoutTag != 1 ||
		document.Detail.Classification.Resolved != 1 {
		t.Fatalf("coverage = %+v", document)
	}
	if document.Detail.Services["http"].Tagged != 1 ||
		document.Detail.Services["ssh"].Responded != 1 ||
		document.Detail.Services["dns"].Responded != 1 {
		t.Fatalf("services = %+v", document.Detail.Services)
	}
	if document.Overview.RespondedTargets != 2 || document.Overview.RespondedCoverage != 1 ||
		document.Overview.EvidenceTargets != 1 || document.Overview.EvidenceCoverage != 0.5 ||
		document.Overview.TaggedTargets != 1 || document.Overview.TaggedCoverage != 0.5 ||
		document.Overview.ResolvedTargets != 1 || document.Overview.ResolvedCoverage != 0.5 ||
		document.Overview.ResolvedRateAmongEvidence != 1 {
		t.Fatalf("overview = %+v", document.Overview)
	}
	http := document.Overview.Services["http"]
	if http.RespondedCoverage != 0.5 || http.EvidenceCoverage != 0.5 ||
		http.TaggedCoverage != 0.5 || http.EvidenceRateAmongResponse != 1 ||
		http.TaggedRateAmongEvidence != 1 {
		t.Fatalf("HTTP overview = %+v", http)
	}
}

func TestCoverageRatiosAreZeroForEmptyInput(t *testing.T) {
	coverage := newCoverageStats(0)
	path := filepath.Join(t.TempDir(), "os-coverage.json")
	if err := coverage.write(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document coverageDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.Overview.ResolvedCoverage != 0 ||
		document.Overview.Services["ssh"].RespondedCoverage != 0 {
		t.Fatalf("overview = %+v", document.Overview)
	}
}
