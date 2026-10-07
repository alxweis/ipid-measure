package interprotocolworkflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = 1

var (
	SafeID         = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	OrderedGroups  = []string{"icmp-tcp", "icmp-udp", "tcp-udp", "icmp-tcp-udp"}
	GroupProtocols = map[string][]string{
		"icmp-tcp":     {"icmp", "tcp"},
		"icmp-udp":     {"icmp", "udp"},
		"tcp-udp":      {"tcp", "udp"},
		"icmp-tcp-udp": {"icmp", "tcp", "udp"},
	}
)

type GroupRun struct {
	Protocols     []string `json:"protocols"`
	TargetFile    string   `json:"target_file"`
	Status        string   `json:"status"`
	MeasurementID string   `json:"measurement_id,omitempty"`
	StartedAt     string   `json:"started_at,omitempty"`
	CompletedAt   string   `json:"completed_at,omitempty"`
	Error         string   `json:"error,omitempty"`
}

type Manifest struct {
	Version    int                  `json:"version"`
	CampaignID string               `json:"campaign_id"`
	RunID      string               `json:"run_id"`
	CreatedAt  string               `json:"created_at"`
	UpdatedAt  string               `json:"updated_at"`
	Config     string               `json:"config"`
	TargetsDir string               `json:"targets_dir"`
	TCPPort    uint16               `json:"tcp_port"`
	UDPPort    uint16               `json:"udp_port"`
	Groups     map[string]*GroupRun `json:"groups"`
}

type Request struct {
	Version      int       `json:"version"`
	JobID        string    `json:"job_id"`
	CampaignID   string    `json:"campaign_id"`
	ManifestURI  string    `json:"manifest_uri"`
	IPIDPrefix   string    `json:"ipid_prefix"`
	ResultPrefix string    `json:"result_prefix"`
	DoneURI      string    `json:"done_uri"`
	FailedURI    string    `json:"failed_uri"`
	CreatedAt    time.Time `json:"created_at"`
}

type Done struct {
	Version      int    `json:"version"`
	JobID        string `json:"job_id"`
	CampaignID   string `json:"campaign_id"`
	ResultPrefix string `json:"result_prefix"`
	Rows         int64  `json:"rows"`
	CompletedAt  string `json:"completed_at"`
}

type Failed struct {
	Version int    `json:"version"`
	JobID   string `json:"job_id"`
	Error   string `json:"error"`
}

type configFile struct {
	Upload struct {
		S3Destination string `yaml:"s3_destination"`
	} `yaml:"upload"`
	AnalysisWorkflow struct {
		S3Prefix     string `yaml:"s3_prefix"`
		PollInterval string `yaml:"poll_interval"`
		Timeout      string `yaml:"timeout"`
	} `yaml:"analysis_workflow"`
}

type runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, "s3cmd", args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("s3cmd %s: %w: %s", args[0], err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func joinS3(prefix string, parts ...string) string {
	value := strings.TrimRight(prefix, "/")
	for _, part := range parts {
		value += "/" + strings.Trim(part, "/")
	}
	return value
}

func validateS3(value, field string) error {
	if !strings.HasPrefix(value, "s3://") || strings.TrimSpace(strings.TrimPrefix(value, "s3://")) == "" {
		return fmt.Errorf("%s must be a non-empty s3:// URI", field)
	}
	return nil
}

func Validate(manifest *Manifest, requireComplete bool) error {
	if manifest.Version != Version {
		return fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	if !SafeID.MatchString(manifest.CampaignID) || !SafeID.MatchString(manifest.RunID) {
		return fmt.Errorf("campaign-id and run-id may only contain letters, digits, '.', '_' and '-'")
	}
	if len(manifest.Groups) == 0 {
		return fmt.Errorf("at least one protocol group is required")
	}
	for group, state := range manifest.Groups {
		protocols, ok := GroupProtocols[group]
		if !ok {
			return fmt.Errorf("unsupported protocol group %q", group)
		}
		if state == nil || strings.Join(state.Protocols, ",") != strings.Join(protocols, ",") {
			return fmt.Errorf("invalid protocol order for %q", group)
		}
		if requireComplete && (state.Status != "complete" || !strings.HasPrefix(state.MeasurementID, "interprotocol-"+group+"_")) {
			return fmt.Errorf("protocol group %q is not complete", group)
		}
	}
	return nil
}

func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := Validate(&manifest, false); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func Save(path string, manifest *Manifest) error {
	if err := Validate(manifest, false); err != nil {
		return err
	}
	manifest.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create manifest directory: %w", err)
	}
	temporary := path + ".part"
	if err := os.WriteFile(temporary, data, 0644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish manifest: %w", err)
	}
	return nil
}

func Publish(ctx context.Context, configPath, manifestPath string) (string, error) {
	return publish(ctx, commandRunner{}, configPath, manifestPath, time.Now())
}

func Wait(ctx context.Context, configPath, manifestPath string) (Done, error) {
	return wait(ctx, commandRunner{}, configPath, manifestPath)
}

func publish(ctx context.Context, r runner, configPath, manifestPath string, now time.Time) (string, error) {
	manifest, err := Load(manifestPath)
	if err != nil {
		return "", err
	}
	if err := Validate(manifest, true); err != nil {
		return "", err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", configPath, err)
	}
	var config configFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return "", fmt.Errorf("decode %s: %w", configPath, err)
	}
	if err := validateS3(config.Upload.S3Destination, "upload.s3_destination"); err != nil {
		return "", err
	}
	if err := validateS3(config.AnalysisWorkflow.S3Prefix, "analysis_workflow.s3_prefix"); err != nil {
		return "", err
	}
	jobPrefix := joinS3(config.AnalysisWorkflow.S3Prefix, "interprotocol-jobs", manifest.RunID)
	request := Request{
		Version: Version, JobID: manifest.RunID, CampaignID: manifest.CampaignID,
		ManifestURI:  joinS3(jobPrefix, "manifest.json"),
		IPIDPrefix:   strings.TrimRight(config.Upload.S3Destination, "/"),
		ResultPrefix: joinS3(jobPrefix, "results"), DoneURI: joinS3(jobPrefix, "done.json"),
		FailedURI: joinS3(jobPrefix, "failed.json"), CreatedAt: now.UTC(),
	}
	requestPath := filepath.Join(filepath.Dir(manifestPath), "request.json")
	requestData, err := json.MarshalIndent(request, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode request: %w", err)
	}
	if err := os.WriteFile(requestPath, append(requestData, '\n'), 0644); err != nil {
		return "", fmt.Errorf("write request: %w", err)
	}
	if _, err := r.Run(ctx, "put", "--no-progress", manifestPath, request.ManifestURI); err != nil {
		return "", err
	}
	requestURI := joinS3(jobPrefix, "request.json")
	if _, err := r.Run(ctx, "put", "--no-progress", requestPath, requestURI); err != nil {
		return "", err
	}
	return requestURI, nil
}

func duration(value string, fallback time.Duration, field string) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", field)
	}
	return parsed, nil
}

func objectExists(ctx context.Context, r runner, uri string) (bool, error) {
	output, err := r.Run(ctx, "ls", uri)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] == uri {
			return true, nil
		}
	}
	return false, nil
}

func downloadJSON(ctx context.Context, r runner, uri, path string, value any) error {
	if _, err := r.Run(ctx, "get", "--force", "--no-progress", uri, path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func wait(ctx context.Context, r runner, configPath, manifestPath string) (Done, error) {
	var done Done
	requestData, err := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), "request.json"))
	if err != nil {
		return done, fmt.Errorf("read inter-protocol request: %w", err)
	}
	var request Request
	if err := json.Unmarshal(requestData, &request); err != nil {
		return done, fmt.Errorf("decode inter-protocol request: %w", err)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return done, fmt.Errorf("read %s: %w", configPath, err)
	}
	var config configFile
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return done, fmt.Errorf("decode %s: %w", configPath, err)
	}
	pollInterval, err := duration(config.AnalysisWorkflow.PollInterval, 30*time.Second, "analysis_workflow.poll_interval")
	if err != nil {
		return done, err
	}
	timeout, err := duration(config.AnalysisWorkflow.Timeout, 24*time.Hour, "analysis_workflow.timeout")
	if err != nil {
		return done, err
	}
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		failedExists, pollErr := objectExists(waitContext, r, request.FailedURI)
		if pollErr != nil {
			return done, fmt.Errorf("check inter-protocol failure marker: %w", pollErr)
		}
		if failedExists {
			var failed Failed
			path := filepath.Join(filepath.Dir(manifestPath), "analysis-failed.json")
			if err := downloadJSON(waitContext, r, request.FailedURI, path, &failed); err != nil {
				return done, fmt.Errorf("download inter-protocol failure marker: %w", err)
			}
			return done, fmt.Errorf("inter-protocol analysis failed: %s", failed.Error)
		}
		doneExists, pollErr := objectExists(waitContext, r, request.DoneURI)
		if pollErr != nil {
			return done, fmt.Errorf("check inter-protocol completion marker: %w", pollErr)
		}
		if doneExists {
			path := filepath.Join(filepath.Dir(manifestPath), "analysis-done.json")
			if err := downloadJSON(waitContext, r, request.DoneURI, path, &done); err != nil {
				return done, fmt.Errorf("download inter-protocol completion marker: %w", err)
			}
			if done.Version != Version || done.JobID != request.JobID || done.CampaignID != request.CampaignID || done.ResultPrefix != request.ResultPrefix {
				return Done{}, fmt.Errorf("invalid inter-protocol completion marker")
			}
			return done, nil
		}
		select {
		case <-waitContext.Done():
			return done, fmt.Errorf("wait for inter-protocol analysis: %w", waitContext.Err())
		case <-ticker.C:
		}
	}
}
