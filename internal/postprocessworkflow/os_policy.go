package postprocessworkflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alxweis/ipid-measure/internal/paths"
)

// OS policy is immutable for an analysis job, including retries started from
// an existing discovery. The policy is committed before OS/IPID measurements.
type osPolicy struct {
	Version int    `json:"version"`
	JobID   string `json:"job_id"`
	Status  string `json:"os_status"`
}

func RecordOSPolicy(ctx context.Context, zmap string, skip bool, configPath, outputRoot string) (string, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return "", err
	}
	return recordOSPolicy(ctx, commandRunner{}, zmap, skip, config.AnalysisWorkflow.S3Prefix, outputRoot)
}

func readRemoteObject(ctx context.Context, r runner, uri, directory string) ([]byte, bool, error) {
	output, err := r.Run(ctx, "ls", uri)
	if err != nil {
		return nil, false, err
	}
	exists := false
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] == uri {
			exists = true
		}
	}
	if !exists {
		return nil, false, nil
	}
	f, err := os.CreateTemp(directory, "policy-check-*.json")
	if err != nil {
		return nil, false, err
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)
	if _, err = r.Run(ctx, "get", "--force", "--no-progress", uri, path); err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	return data, true, err
}

func checkManifestPolicy(data []byte, protocol string, skip bool) error {
	var manifest map[string]ProtocolMeasurements
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	section, exists := manifest[protocol]
	if !exists {
		return fmt.Errorf("existing manifest has wrong protocol")
	}
	if section.OSStatus != "" && section.OSStatus != "not_requested" {
		return fmt.Errorf("existing manifest has invalid OS policy")
	}
	disabled := section.OSStatus == "not_requested"
	if disabled != (section.OS == "") {
		return fmt.Errorf("existing manifest has inconsistent OS policy")
	}
	if disabled != skip {
		return fmt.Errorf("OS policy differs from existing manifest; use the original mode or a new ZMap ID")
	}
	return nil
}

func recordOSPolicy(ctx context.Context, r runner, zmap string, skip bool, prefix, outputRoot string) (string, error) {
	payload, _, _, err := paths.ParseMeasurementID(zmap)
	if err != nil {
		return "", err
	}
	if err = requireS3(prefix, "analysis_workflow.s3_prefix"); err != nil {
		return "", err
	}
	expected := osPolicy{1, zmap, "requested"}
	if skip {
		expected.Status = "not_requested"
	}
	directory := filepath.Join(outputRoot, zmap)
	if err = os.MkdirAll(directory, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(directory, "os-policy.json")
	check := func(data []byte) error {
		var previous osPolicy
		if err := json.Unmarshal(data, &previous); err != nil {
			return err
		}
		if previous != expected {
			return fmt.Errorf("OS policy differs from persisted intent; restart with the original OS mode or a new ZMap ID")
		}
		return nil
	}
	if data, err := os.ReadFile(path); err == nil {
		if err = check(data); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	if data, err := os.ReadFile(manifestPath); err == nil {
		if err = checkManifestPolicy(data, string(payload), skip); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	job := joinS3(prefix, "analysis-jobs", zmap)
	uri := joinS3(job, "os-policy.json")
	old, exists, err := readRemoteObject(ctx, r, uri, directory)
	if err != nil {
		return "", err
	}
	if exists {
		if err = check(old); err != nil {
			return "", err
		}
	}
	if data, found, err := readRemoteObject(ctx, r, joinS3(job, "manifest.json"), directory); err != nil {
		return "", err
	} else if found {
		if err = checkManifestPolicy(data, string(payload), skip); err != nil {
			return "", err
		}
	}
	if err = writeJSON(path, expected); err != nil {
		return "", err
	}
	if !exists {
		if _, err = r.Run(ctx, "put", "--no-progress", path, uri); err != nil {
			return "", fmt.Errorf("publish OS policy: %w", err)
		}
	}
	return uri, nil
}
