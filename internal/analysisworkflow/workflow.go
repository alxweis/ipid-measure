package analysisworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/upload"
)

const (
	ProtocolVersion    = 1
	UnclassifiedTarget = "zmap_unclassified.pq"
)

type Request struct {
	Version       int       `json:"version"`
	JobID         string    `json:"job_id"`
	Protocol      string    `json:"protocol"`
	MeasurementID string    `json:"measurement_id"`
	IPIDURI       string    `json:"ipid_uri"`
	SnapshotURI   string    `json:"snapshot_uri"`
	ResultURI     string    `json:"result_uri"`
	DoneURI       string    `json:"done_uri"`
	FailedURI     string    `json:"failed_uri"`
	CreatedAt     time.Time `json:"created_at"`
}

type Done struct {
	Version   int    `json:"version"`
	JobID     string `json:"job_id"`
	ResultURI string `json:"result_uri"`
	Rows      int64  `json:"rows"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type Failed struct {
	Version int    `json:"version"`
	JobID   string `json:"job_id"`
	Error   string `json:"error"`
}

type runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "s3cmd", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("s3cmd %s: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func joinS3(prefix string, parts ...string) string {
	result := strings.TrimRight(prefix, "/")
	for _, part := range parts {
		result += "/" + strings.Trim(part, "/")
	}
	return result
}

func newRequest(
	w config.AnalysisWorkflowConfig,
	u config.UploadConfig,
	m paths.Measurement,
	now time.Time,
) (Request, error) {
	payload, _, _, err := paths.ParseMeasurementID(m.ID)
	if err != nil {
		return Request{}, fmt.Errorf("derive analysis protocol from measurement id: %w", err)
	}
	jobPrefix := joinS3(w.S3Prefix, "jobs", m.ID)
	inputPrefix := upload.RemoteMeasurementURI(u, m)
	return Request{
		Version:       ProtocolVersion,
		JobID:         m.ID,
		Protocol:      string(payload),
		MeasurementID: m.ID,
		IPIDURI:       joinS3(inputPrefix, files.IPIDMeasurementFile),
		SnapshotURI:   joinS3(inputPrefix, files.IPIDConfigSnapshotFile),
		ResultURI:     joinS3(jobPrefix, UnclassifiedTarget),
		DoneURI:       joinS3(jobPrefix, "done.json"),
		FailedURI:     joinS3(jobPrefix, "failed.json"),
		CreatedAt:     now.UTC(),
	}, nil
}

func RequestAndWait(
	ctx context.Context,
	w config.AnalysisWorkflowConfig,
	u config.UploadConfig,
	m paths.Measurement,
) (string, error) {
	return requestAndWait(ctx, commandRunner{}, w, u, m)
}

func requestAndWait(
	ctx context.Context,
	r runner,
	w config.AnalysisWorkflowConfig,
	u config.UploadConfig,
	m paths.Measurement,
) (string, error) {
	request, err := newRequest(w, u, m, time.Now())
	if err != nil {
		return "", err
	}
	requestPath := filepath.Join(m.Path, "analysis-request.json")
	if err := writeJSON(requestPath, request); err != nil {
		return "", err
	}
	requestURI := joinS3(w.S3Prefix, "jobs", request.JobID, "request.json")
	if _, err := r.Run(ctx, "put", "--no-progress", requestPath, requestURI); err != nil {
		return "", fmt.Errorf("publish analysis request: %w", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, w.Timeout)
	defer cancel()
	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()

	for {
		result, ready, err := poll(waitCtx, r, request, m.Path)
		if err != nil {
			return "", err
		}
		if ready {
			return result, nil
		}

		select {
		case <-waitCtx.Done():
			return "", fmt.Errorf("wait for analysis result: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func poll(ctx context.Context, r runner, request Request, outputDir string) (string, bool, error) {
	failed, err := exists(ctx, r, request.FailedURI)
	if err != nil {
		return "", false, err
	}
	if failed {
		var marker Failed
		if err := getJSON(ctx, r, request.FailedURI, filepath.Join(outputDir, "analysis-failed.json"), &marker); err != nil {
			return "", false, err
		}
		if marker.Version != ProtocolVersion || marker.JobID != request.JobID {
			return "", false, fmt.Errorf("invalid failure marker for job %s", request.JobID)
		}
		return "", false, fmt.Errorf("analysis job %s failed: %s", request.JobID, marker.Error)
	}

	doneExists, err := exists(ctx, r, request.DoneURI)
	if err != nil || !doneExists {
		return "", false, err
	}
	var done Done
	if err := getJSON(ctx, r, request.DoneURI, filepath.Join(outputDir, "analysis-done.json"), &done); err != nil {
		return "", false, err
	}
	if done.Version != ProtocolVersion || done.JobID != request.JobID || done.ResultURI != request.ResultURI {
		return "", false, fmt.Errorf("invalid completion marker for job %s", request.JobID)
	}

	resultPath := filepath.Join(outputDir, UnclassifiedTarget)
	temporaryPath := resultPath + ".part"
	if _, err := r.Run(ctx, "get", "--force", "--no-progress", request.ResultURI, temporaryPath); err != nil {
		return "", false, fmt.Errorf("download analysis result: %w", err)
	}
	if err := verifyFile(temporaryPath, done); err != nil {
		return "", false, err
	}
	if err := os.Rename(temporaryPath, resultPath); err != nil {
		return "", false, fmt.Errorf("publish local analysis result: %w", err)
	}
	return resultPath, true, nil
}

func exists(ctx context.Context, r runner, uri string) (bool, error) {
	output, err := r.Run(ctx, "ls", uri)
	if err != nil {
		return false, fmt.Errorf("check S3 object %s: %w", uri, err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] == uri {
			return true, nil
		}
	}
	return false, nil
}

func getJSON(ctx context.Context, r runner, uri, path string, value any) error {
	if _, err := r.Run(ctx, "get", "--force", "--no-progress", uri, path); err != nil {
		return fmt.Errorf("download %s: %w", uri, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func verifyFile(path string, done Done) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat analysis result: %w", err)
	}
	if info.Size() != done.SizeBytes {
		return fmt.Errorf("analysis result size is %d, want %d", info.Size(), done.SizeBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open analysis result: %w", err)
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return fmt.Errorf("hash analysis result: %w", err)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if !strings.EqualFold(actual, done.SHA256) {
		return fmt.Errorf("analysis result sha256 is %s, want %s", actual, done.SHA256)
	}
	if done.Rows < 0 {
		return fmt.Errorf("analysis result row count is negative: %d", done.Rows)
	}
	return nil
}
