package postprocessworkflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/paths"
	"gopkg.in/yaml.v3"
)

const ProtocolVersion = 1

type Measurements struct {
	ZMap             string
	OS               string
	RTBase           string
	FixedMass        string
	FixedBase        string
	ConnectionRTBase string
	ConnectionFIBase string
}

type ScaleMeasurements struct {
	Base string `json:"base,omitempty"`
	Mass string `json:"mass,omitempty"`
}

type IntervalMeasurements struct {
	RTBased       ScaleMeasurements `json:"rt-based"`
	FixedInterval ScaleMeasurements `json:"fixed-interval"`
}

type IPIDMeasurements struct {
	NoConnection IntervalMeasurements  `json:"no-connection"`
	Connection   *IntervalMeasurements `json:"connection,omitempty"`
}

type ProtocolMeasurements struct {
	ZMap string           `json:"zmap"`
	OS   string           `json:"os"`
	IPID IPIDMeasurements `json:"ipid"`
}

type Request struct {
	Version     int       `json:"version"`
	JobID       string    `json:"job_id"`
	Protocol    string    `json:"protocol"`
	ManifestURI string    `json:"manifest_uri"`
	ZMapPrefix  string    `json:"zmap_prefix"`
	OSPrefix    string    `json:"os_prefix"`
	IPIDPrefix  string    `json:"ipid_prefix"`
	DoneURI     string    `json:"done_uri"`
	FailedURI   string    `json:"failed_uri"`
	CreatedAt   time.Time `json:"created_at"`
}

type ConfigPaths struct {
	ZMap string
	OS   string
	IPID string
}

type uploadConfigFile struct {
	Upload struct {
		S3Destination string `yaml:"s3_destination"`
	} `yaml:"upload"`
	AnalysisWorkflow struct {
		S3Prefix string `yaml:"s3_prefix"`
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

func loadConfig(path string) (uploadConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return uploadConfigFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	var config uploadConfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return uploadConfigFile{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return config, nil
}

func requireS3(value, field string) error {
	if !strings.HasPrefix(value, "s3://") || strings.TrimSpace(strings.TrimPrefix(value, "s3://")) == "" {
		return fmt.Errorf("%s must be a non-empty s3:// URI", field)
	}
	return nil
}

func validateMeasurements(m Measurements) (string, error) {
	required := map[string]string{
		"zmap":       m.ZMap,
		"os":         m.OS,
		"rt-base":    m.RTBase,
		"fixed-mass": m.FixedMass,
		"fixed-base": m.FixedBase,
	}
	for field, value := range required {
		if value == "" {
			return "", fmt.Errorf("%s measurement id is required", field)
		}
	}

	payload, port, _, err := paths.ParseMeasurementID(m.ZMap)
	if err != nil {
		return "", fmt.Errorf("invalid zmap measurement id: %w", err)
	}
	all := []string{m.OS, m.RTBase, m.FixedMass, m.FixedBase}
	if (m.ConnectionRTBase == "") != (m.ConnectionFIBase == "") {
		return "", fmt.Errorf("both TCP connection measurement ids must be provided together")
	}
	if m.ConnectionRTBase != "" {
		if payload != "tcp" {
			return "", fmt.Errorf("connection measurements are only valid for TCP")
		}
		all = append(all, m.ConnectionRTBase, m.ConnectionFIBase)
	}
	for _, id := range all {
		candidatePayload, candidatePort, _, parseErr := paths.ParseMeasurementID(id)
		if parseErr != nil {
			return "", fmt.Errorf("invalid measurement id %q: %w", id, parseErr)
		}
		portsMatch := (port == nil && candidatePort == nil) ||
			(port != nil && candidatePort != nil && *port == *candidatePort)
		if candidatePayload != payload || !portsMatch {
			return "", fmt.Errorf("measurement id %q does not match zmap protocol", id)
		}
	}
	return string(payload), nil
}

func manifest(protocol string, m Measurements) map[string]ProtocolMeasurements {
	ipid := IPIDMeasurements{
		NoConnection: IntervalMeasurements{
			RTBased:       ScaleMeasurements{Base: m.RTBase},
			FixedInterval: ScaleMeasurements{Base: m.FixedBase, Mass: m.FixedMass},
		},
	}
	if m.ConnectionRTBase != "" {
		ipid.Connection = &IntervalMeasurements{
			RTBased:       ScaleMeasurements{Base: m.ConnectionRTBase},
			FixedInterval: ScaleMeasurements{Base: m.ConnectionFIBase},
		}
	}
	return map[string]ProtocolMeasurements{
		protocol: {ZMap: m.ZMap, OS: m.OS, IPID: ipid},
	}
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	temporary := path + ".part"
	if err := os.WriteFile(temporary, data, 0644); err != nil {
		return fmt.Errorf("write %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("publish %s: %w", path, err)
	}
	return nil
}

func Publish(
	ctx context.Context,
	measurements Measurements,
	configs ConfigPaths,
	outputRoot string,
) (string, error) {
	return publish(ctx, commandRunner{}, measurements, configs, outputRoot, time.Now())
}

func publish(
	ctx context.Context,
	r runner,
	measurements Measurements,
	configs ConfigPaths,
	outputRoot string,
	now time.Time,
) (string, error) {
	protocol, err := validateMeasurements(measurements)
	if err != nil {
		return "", err
	}
	zmapConfig, err := loadConfig(configs.ZMap)
	if err != nil {
		return "", err
	}
	osConfig, err := loadConfig(configs.OS)
	if err != nil {
		return "", err
	}
	ipidConfig, err := loadConfig(configs.IPID)
	if err != nil {
		return "", err
	}
	values := map[string]string{
		"zmap upload.s3_destination":  zmapConfig.Upload.S3Destination,
		"os upload.s3_destination":    osConfig.Upload.S3Destination,
		"ipid upload.s3_destination":  ipidConfig.Upload.S3Destination,
		"analysis_workflow.s3_prefix": ipidConfig.AnalysisWorkflow.S3Prefix,
	}
	for field, value := range values {
		if err := requireS3(value, field); err != nil {
			return "", err
		}
	}

	jobID := measurements.ZMap
	jobDirectory := filepath.Join(outputRoot, jobID)
	if err := os.MkdirAll(jobDirectory, 0755); err != nil {
		return "", fmt.Errorf("create analysis job directory: %w", err)
	}
	manifestPath := filepath.Join(jobDirectory, "manifest.json")
	requestPath := filepath.Join(jobDirectory, "request.json")
	jobPrefix := joinS3(ipidConfig.AnalysisWorkflow.S3Prefix, "analysis-jobs", jobID)
	request := Request{
		Version:     ProtocolVersion,
		JobID:       jobID,
		Protocol:    protocol,
		ManifestURI: joinS3(jobPrefix, "manifest.json"),
		ZMapPrefix:  zmapConfig.Upload.S3Destination,
		OSPrefix:    osConfig.Upload.S3Destination,
		IPIDPrefix:  ipidConfig.Upload.S3Destination,
		DoneURI:     joinS3(jobPrefix, "done.json"),
		FailedURI:   joinS3(jobPrefix, "failed.json"),
		CreatedAt:   now.UTC(),
	}
	if err := writeJSON(manifestPath, manifest(protocol, measurements)); err != nil {
		return "", err
	}
	if err := writeJSON(requestPath, request); err != nil {
		return "", err
	}
	if _, err := r.Run(ctx, "put", "--no-progress", manifestPath, request.ManifestURI); err != nil {
		return "", fmt.Errorf("upload campaign manifest: %w", err)
	}
	requestURI := joinS3(jobPrefix, "request.json")
	if _, err := r.Run(ctx, "put", "--no-progress", requestPath, requestURI); err != nil {
		return "", fmt.Errorf("publish campaign request: %w", err)
	}
	return requestURI, nil
}
