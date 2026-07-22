package postprocessworkflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type recordingRunner struct {
	calls [][]string
}

func (r *recordingRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	return nil, nil
}

func writeConfig(t *testing.T, path, destination, workflowPrefix string) {
	t.Helper()
	content := "upload:\n  s3_destination: " + destination + "\n"
	if workflowPrefix != "" {
		content += "analysis_workflow:\n  s3_prefix: " + workflowPrefix + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestPublishWritesPersistentJobAndUploadsRequestLast(t *testing.T) {
	root := t.TempDir()
	zmapConfig := filepath.Join(root, "zmap.yaml")
	osConfig := filepath.Join(root, "os.yaml")
	ipidConfig := filepath.Join(root, "ipid.yaml")
	writeConfig(t, zmapConfig, "s3://bucket/raw/zmap/", "")
	writeConfig(t, osConfig, "s3://bucket/raw/os/", "")
	writeConfig(t, ipidConfig, "s3://bucket/raw/ipid/", "s3://bucket/workflow/")

	measurements := Measurements{
		ZMap:             "tcp-80_2026-07-22_10-00-00",
		OS:               "tcp-80_2026-07-22_10-00-01",
		RTBase:           "tcp-80_2026-07-22_10-00-02",
		FixedMass:        "tcp-80_2026-07-22_10-00-03",
		FixedBase:        "tcp-80_2026-07-22_10-00-04",
		ConnectionRTBase: "tcp-80_2026-07-22_10-00-05",
		ConnectionFIBase: "tcp-80_2026-07-22_10-00-06",
	}
	runner := &recordingRunner{}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))

	requestURI, err := publish(
		context.Background(), runner, measurements,
		ConfigPaths{ZMap: zmapConfig, OS: osConfig, IPID: ipidConfig},
		filepath.Join(root, "jobs"), now,
	)
	if err != nil {
		t.Fatal(err)
	}

	jobPrefix := "s3://bucket/workflow/analysis-jobs/" + measurements.ZMap
	if requestURI != jobPrefix+"/request.json" {
		t.Fatalf("unexpected request URI: %s", requestURI)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected two uploads, got %d", len(runner.calls))
	}
	if got := runner.calls[0][len(runner.calls[0])-1]; got != jobPrefix+"/manifest.json" {
		t.Fatalf("manifest must be uploaded first, got %s", got)
	}
	if got := runner.calls[1][len(runner.calls[1])-1]; got != requestURI {
		t.Fatalf("request must be uploaded last, got %s", got)
	}

	jobDirectory := filepath.Join(root, "jobs", measurements.ZMap)
	var request Request
	data, err := os.ReadFile(filepath.Join(jobDirectory, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if request.JobID != measurements.ZMap || request.Protocol != "tcp" {
		t.Fatalf("unexpected request: %+v", request)
	}
	if request.CreatedAt.Location() != time.UTC || !request.CreatedAt.Equal(now) {
		t.Fatalf("unexpected creation time: %s", request.CreatedAt)
	}

	var gotManifest map[string]ProtocolMeasurements
	data, err = os.ReadFile(filepath.Join(jobDirectory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &gotManifest); err != nil {
		t.Fatal(err)
	}
	wantManifest := manifest("tcp", measurements)
	if !reflect.DeepEqual(gotManifest, wantManifest) {
		t.Fatalf("manifest mismatch:\n got: %#v\nwant: %#v", gotManifest, wantManifest)
	}
}

func TestValidateMeasurementsRejectsMixedProtocols(t *testing.T) {
	_, err := validateMeasurements(Measurements{
		ZMap:      "icmp_2026-07-22_10-00-00",
		OS:        "icmp_2026-07-22_10-00-01",
		RTBase:    "icmp_2026-07-22_10-00-02",
		FixedMass: "icmp_2026-07-22_10-00-03",
		FixedBase: "tcp-80_2026-07-22_10-00-04",
	})
	if err == nil {
		t.Fatal("expected protocol mismatch to fail")
	}
}
