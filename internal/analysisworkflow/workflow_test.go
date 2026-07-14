package analysisworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
)

type fakeRunner struct {
	objects map[string][]byte
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	switch args[0] {
	case "put":
		data, err := os.ReadFile(args[len(args)-2])
		if err != nil {
			return nil, err
		}
		f.objects[args[len(args)-1]] = data
		return nil, nil
	case "ls":
		uri := args[1]
		data, ok := f.objects[uri]
		if !ok {
			return nil, nil
		}
		return []byte(fmt.Sprintf("2026-01-01 00:00 %d %s\n", len(data), uri)), nil
	case "get":
		uri, path := args[len(args)-2], args[len(args)-1]
		data, ok := f.objects[uri]
		if !ok {
			return nil, fmt.Errorf("missing object %s", uri)
		}
		return nil, os.WriteFile(path, data, 0644)
	default:
		return nil, fmt.Errorf("unexpected command %s", strings.Join(args, " "))
	}
}

func TestRequestAndWaitPublishesRequestAndVerifiesResult(t *testing.T) {
	dir := t.TempDir()
	m := paths.Measurement{ID: "tcp-80_2026-01-01_00-00-00", Path: dir}
	w := config.AnalysisWorkflowConfig{
		S3Prefix:     "s3://bucket/workflow/",
		PollInterval: time.Hour,
		Timeout:      time.Second,
	}
	u := config.UploadConfig{S3Destination: "s3://bucket/raw/ipid/"}
	request := newRequest(w, u, m, time.Now())
	result := []byte("parquet-result")
	sum := sha256.Sum256(result)
	done := Done{
		Version: ProtocolVersion, JobID: m.ID, ResultURI: request.ResultURI,
		Rows: 7, SizeBytes: int64(len(result)), SHA256: hex.EncodeToString(sum[:]),
	}
	doneData, err := json.Marshal(done)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{objects: map[string][]byte{
		request.ResultURI: result,
		request.DoneURI:   doneData,
	}}

	resultPath, err := requestAndWait(context.Background(), runner, w, u, m)
	if err != nil {
		t.Fatalf("requestAndWait() error = %v", err)
	}
	if resultPath != filepath.Join(dir, UnclassifiedTarget) {
		t.Fatalf("result path = %s", resultPath)
	}
	if got, err := os.ReadFile(resultPath); err != nil || string(got) != string(result) {
		t.Fatalf("downloaded result = %q, err = %v", got, err)
	}
	requestURI := "s3://bucket/workflow/jobs/" + m.ID + "/request.json"
	if _, ok := runner.objects[requestURI]; !ok {
		t.Fatalf("request was not published to %s", requestURI)
	}
}

func TestPollReturnsRemoteFailure(t *testing.T) {
	dir := t.TempDir()
	request := Request{
		JobID: "job-1", FailedURI: "s3://bucket/jobs/job-1/failed.json",
	}
	marker, _ := json.Marshal(Failed{Version: ProtocolVersion, JobID: request.JobID, Error: "classifier failed"})
	runner := &fakeRunner{objects: map[string][]byte{request.FailedURI: marker}}

	_, _, err := poll(context.Background(), runner, request, dir)
	if err == nil || !strings.Contains(err.Error(), "classifier failed") {
		t.Fatalf("poll() error = %v", err)
	}
}
