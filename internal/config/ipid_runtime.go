package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alxweis/ipid-measure/internal/types"
	"gopkg.in/yaml.v3"
)

const IPIDRuntimeFile = "ipid-runtime.yaml"

// IPIDRuntimeEvidence records a resource-only override in the effective snapshot.
// The normal Geo configuration binding and committed step identities stay intact.
type IPIDRuntimeEvidence struct {
	PolicySHA256 string       `yaml:"policy_sha256"`
	Binding      string       `yaml:"workspace_binding"`
	Profile      string       `yaml:"profile"`
	Previous     ScaledNumber `yaml:"previous_number_of_inflight_probes"`
}

type ipidRuntimePolicy struct {
	Version  int                           `yaml:"version"`
	Binding  string                        `yaml:"workspace_binding"`
	Profiles map[string]ipidRuntimeProfile `yaml:"profiles"`
}

type ipidRuntimeProfile struct {
	Inflight *ScaledNumber `yaml:"number_of_inflight_probes"`
}

func SingleProtocolResourceProfile(c *IPIDConfig) string {
	profile := "single-rt"
	if c.MeasurementMode == types.MeasurementModeFixedInterval {
		profile = "single-fi"
	}
	if c.ZMapPayload == types.PayloadTCP && c.TCPConfig.EstablishConnection {
		if c.MeasurementMode == types.MeasurementModeFixedInterval {
			return "connection-fi"
		}
		return "connection-rt"
	}
	return profile
}

func validRuntimeProfile(profile string) bool {
	switch profile {
	case "single-rt", "single-fi", "connection-rt", "connection-fi",
		"interprotocol-base", "interprotocol-mass", "local-reference-base", "local-reference-mass":
		return true
	}
	return false
}

// ApplyIPIDRuntimeResources runs once, after CLI overrides/config validation and
// before any output directory or probe is created. An already-running scanner
// never rereads this file. Only Geo workspace configs opt into auto-discovery.
func ApplyIPIDRuntimeResources(configPath string, c *IPIDConfig, profile string) error {
	workspace := os.Getenv("IPID_MEASURE_WORKSPACE")
	if workspace == "" {
		return nil
	}
	workspace, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	policyPath := filepath.Join(workspace, "config", IPIDRuntimeFile)
	f, err := os.Open(policyPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open IPID runtime resources: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 32769))
	if err != nil {
		return err
	}
	if len(data) > 32768 {
		return fmt.Errorf("IPID runtime resources exceed 32 KiB")
	}
	configPath, err = filepath.Abs(configPath)
	if err != nil {
		return err
	}
	if configPath != filepath.Join(workspace, "config", "ipid.yaml") &&
		configPath != filepath.Join(workspace, "config", "interprotocol.yaml") {
		return fmt.Errorf("IPID runtime resources require this workspace's effective config")
	}
	var policy ipidRuntimePolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return fmt.Errorf("decode IPID runtime resources: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("IPID runtime resources must contain exactly one YAML document")
	}
	decodedBinding, err := hex.DecodeString(policy.Binding)
	if policy.Version != 1 || err != nil || len(decodedBinding) != sha256.Size || len(policy.Profiles) == 0 {
		return fmt.Errorf("invalid IPID runtime resources version, workspace binding or empty profiles")
	}
	for name, resource := range policy.Profiles {
		if !validRuntimeProfile(name) || resource.Inflight == nil || *resource.Inflight < 1 || *resource.Inflight > 1_000_000 {
			return fmt.Errorf("invalid IPID runtime resource profile %q; inflight must be in [1, 1M]", name)
		}
	}
	stateData, err := os.ReadFile(filepath.Join(workspace, "state.json"))
	if err != nil {
		return fmt.Errorf("read runtime resources workspace state: %w", err)
	}
	var state struct {
		Version int    `json:"version"`
		Binding string `json:"binding"`
	}
	if err := json.Unmarshal(stateData, &state); err != nil {
		return fmt.Errorf("decode runtime resources workspace state: %w", err)
	}
	if state.Version != 1 || state.Binding != policy.Binding {
		return fmt.Errorf("IPID runtime resources belong to a different workspace binding")
	}
	if !validRuntimeProfile(profile) {
		return fmt.Errorf("unknown requested IPID runtime profile %q", profile)
	}
	resource, exists := policy.Profiles[profile]
	if !exists {
		return nil
	}
	sum := sha256.Sum256(data)
	c.RuntimeResources = &IPIDRuntimeEvidence{
		PolicySHA256: hex.EncodeToString(sum[:]), Binding: policy.Binding,
		Profile: profile, Previous: c.NumberOfInflightProbes,
	}
	c.NumberOfInflightProbes = *resource.Inflight
	return nil
}
