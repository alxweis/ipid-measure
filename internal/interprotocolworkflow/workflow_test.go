package interprotocolworkflow

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type recordingRunner struct{ calls [][]string }

func (r *recordingRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	return nil, nil
}

type completedRunner struct {
	doneURI  string
	doneJSON []byte
}

func (r *completedRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	if args[0] == "ls" && args[1] == r.doneURI {
		return []byte("2026-01-01 00:00 1 " + r.doneURI + "\n"), nil
	}
	if args[0] == "get" && args[3] == r.doneURI {
		return nil, os.WriteFile(args[4], r.doneJSON, 0644)
	}
	return nil, nil
}

func TestPublishUploadsRequestLast(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "ipid.yaml")
	if err := os.WriteFile(config, []byte("upload:\n  s3_destination: s3://bucket/raw/ipid/\nanalysis_workflow:\n  s3_prefix: s3://bucket/workflow/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	manifest := &Manifest{
		Version: Version, CampaignID: "campaign", RunID: "campaign_2026-01-01",
		Groups: map[string]*GroupRun{
			"icmp-udp": {Protocols: []string{"icmp", "udp"}, Status: "complete", MeasurementID: "interprotocol-icmp-udp_2026-01-01_00-00-00"},
		},
	}
	if err := Save(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	uri, err := publish(context.Background(), runner, config, manifestPath, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 || runner.calls[1][len(runner.calls[1])-1] != uri {
		t.Fatalf("request was not uploaded last: %#v", runner.calls)
	}
	var request Request
	data, err := os.ReadFile(filepath.Join(root, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &request); err != nil {
		t.Fatal(err)
	}
	if request.IPIDPrefix != "s3://bucket/raw/ipid" || request.ResultPrefix != "s3://bucket/workflow/interprotocol-jobs/campaign_2026-01-01/results" {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestWaitReturnsValidatedCompletion(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "ipid.yaml")
	if err := os.WriteFile(config, []byte("upload:\n  s3_destination: s3://bucket/raw/ipid/\nanalysis_workflow:\n  s3_prefix: s3://bucket/workflow/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	request := Request{
		Version: Version, JobID: "run", CampaignID: "campaign",
		DoneURI:      "s3://bucket/workflow/interprotocol-jobs/run/done.json",
		FailedURI:    "s3://bucket/workflow/interprotocol-jobs/run/failed.json",
		ResultPrefix: "s3://bucket/workflow/interprotocol-jobs/run/results",
	}
	requestData, _ := json.Marshal(request)
	if err := os.WriteFile(filepath.Join(root, "request.json"), requestData, 0644); err != nil {
		t.Fatal(err)
	}
	want := Done{Version: Version, JobID: "run", CampaignID: "campaign", ResultPrefix: request.ResultPrefix, Rows: 12}
	doneData, _ := json.Marshal(want)
	got, err := wait(context.Background(), &completedRunner{doneURI: request.DoneURI, doneJSON: doneData}, config, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rows != want.Rows || got.ResultPrefix != want.ResultPrefix {
		t.Fatalf("unexpected completion: %+v", got)
	}
}

func TestPublishRequiresCompleteGroups(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "ipid.yaml")
	if err := os.WriteFile(config, []byte("upload:\n  s3_destination: s3://bucket/raw/ipid/\nanalysis_workflow:\n  s3_prefix: s3://bucket/workflow/\n"), 0644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	manifest := &Manifest{Version: Version, CampaignID: "campaign", RunID: "run", Groups: map[string]*GroupRun{"icmp-udp": {Protocols: []string{"icmp", "udp"}, Status: "pending"}}}
	if err := Save(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := publish(context.Background(), &recordingRunner{}, config, manifestPath, time.Now()); err == nil {
		t.Fatal("expected incomplete campaign to fail")
	}
}
