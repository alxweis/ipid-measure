package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/types"
	"gopkg.in/yaml.v3"
)

func runtimeFixture(t *testing.T) (string, string, string) {
	t.Helper()
	workspace := t.TempDir()
	t.Setenv("IPID_MEASURE_WORKSPACE", workspace)
	if err := os.Mkdir(filepath.Join(workspace, "config"), 0700); err != nil {
		t.Fatal(err)
	}
	binding := strings.Repeat("a", 64)
	if err := os.WriteFile(filepath.Join(workspace, "state.json"), []byte(`{"version":1,"binding":"`+binding+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(workspace, "config", "ipid.yaml"), filepath.Join(workspace, "config", IPIDRuntimeFile), binding
}

func writeRuntimePolicy(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeResourcesOnlyChangeFutureSelectedConcurrency(t *testing.T) {
	path, policy, binding := runtimeFixture(t)
	bandwidth := ScaledNumber(30_000_000)
	heap := ScaledNumber(700 << 20)
	before := IPIDConfig{
		ConnectionCount: 4, RequestsPerConnection: 25, NumberOfInflightProbes: 2000,
		MeasurementMode: types.MeasurementModeFixedInterval, MaximumToleratedRTT: 2 * time.Second,
		FixedIntervalConfig: FixedIntervalConfig{RequestInterval: 20 * time.Millisecond, MinimumReplyRate: .8},
		Bandwidth:           &bandwidth, GoMemoryLimit: &heap,
	}
	running := before
	body := "version: 1\nworkspace_binding: " + binding + "\nprofiles:\n  single-fi:\n    number_of_inflight_probes: 5K\n"
	writeRuntimePolicy(t, policy, body)
	future := before
	if err := ApplyIPIDRuntimeResources(path, &future, "single-fi"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	if future.NumberOfInflightProbes != 5000 || future.RuntimeResources == nil ||
		future.RuntimeResources.Previous != 2000 || future.RuntimeResources.PolicySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("missing effective override/provenance: %+v", future)
	}
	snapshot, err := yaml.Marshal(future)
	if err != nil || !strings.Contains(string(snapshot), "number_of_inflight_probes: 5000") ||
		!strings.Contains(string(snapshot), "policy_sha256:") {
		t.Fatalf("snapshot lacks effective policy: %s, %v", snapshot, err)
	}
	future.NumberOfInflightProbes, future.RuntimeResources = before.NumberOfInflightProbes, nil
	if !reflect.DeepEqual(future, before) || !reflect.DeepEqual(running, before) {
		t.Fatal("changed probe semantics, bandwidth, memory or already-running configuration")
	}
	if err := ApplyIPIDRuntimeResources(path, &running, "single-rt"); err != nil || !reflect.DeepEqual(running, before) {
		t.Fatalf("unselected workload changed: %v", err)
	}
	// An updated/removed policy applies only when another process loads it.
	writeRuntimePolicy(t, policy, strings.Replace(body, "5K", "3K", 1))
	if err := ApplyIPIDRuntimeResources(path, &future, "single-fi"); err != nil || future.NumberOfInflightProbes != 3000 {
		t.Fatalf("next phase did not reread policy: %v", err)
	}
}

func TestRuntimeResourcesRejectInvalidPolicyBeforeMutation(t *testing.T) {
	path, policy, binding := runtimeFixture(t)
	valid := "version: 1\nworkspace_binding: " + binding + "\nprofiles:\n  single-rt:\n    number_of_inflight_probes: 5K\n"
	for name, body := range map[string]string{
		"wrong binding":     strings.Replace(valid, binding, strings.Repeat("b", 64), 1),
		"version":           strings.Replace(valid, "version: 1", "version: 2", 1),
		"missing binding":   strings.Replace(valid, "workspace_binding: "+binding+"\n", "", 1),
		"missing value":     strings.Replace(valid, "number_of_inflight_probes: 5K", "number_of_inflight_probes:", 1),
		"unknown phase":     strings.Replace(valid, "single-rt", "singel-rt", 1),
		"semantic override": valid + "    maximum_tolerated_rtt: 1s\n",
		"zero":              strings.Replace(valid, "5K", "0", 1),
		"too many":          strings.Replace(valid, "5K", "1000001", 1),
		"second doc":        valid + "---\nversion: 1\n",
		"empty":             "",
		"empty profiles":    "version: 1\nworkspace_binding: " + binding + "\nprofiles: {}\n",
		"oversize":          strings.Repeat("#", 32769),
	} {
		t.Run(name, func(t *testing.T) {
			writeRuntimePolicy(t, policy, body)
			c := IPIDConfig{NumberOfInflightProbes: 2000}
			if err := ApplyIPIDRuntimeResources(path, &c, "single-rt"); err == nil {
				t.Fatal("invalid override accepted")
			}
			if c.NumberOfInflightProbes != 2000 || c.RuntimeResources != nil {
				t.Fatal("invalid override mutated configuration")
			}
		})
	}
}

func TestRuntimeResourcesDefaultAndWorkspaceScoping(t *testing.T) {
	path, policy, binding := runtimeFixture(t)
	c := IPIDConfig{NumberOfInflightProbes: 2000}
	if err := ApplyIPIDRuntimeResources(path, &c, "single-rt"); err != nil || c.NumberOfInflightProbes != 2000 {
		t.Fatal("absent policy changed defaults", err)
	}
	writeRuntimePolicy(t, policy, "version: 1\nworkspace_binding: "+binding+"\nprofiles:\n  single-rt:\n    number_of_inflight_probes: 5K\n")
	if err := ApplyIPIDRuntimeResources(filepath.Join(t.TempDir(), "ipid.yaml"), &c, "single-rt"); err == nil {
		t.Fatal("policy applied to unrelated config")
	}
	t.Setenv("IPID_MEASURE_WORKSPACE", "")
	if err := ApplyIPIDRuntimeResources(path, &c, "single-rt"); err != nil || c.NumberOfInflightProbes != 2000 {
		t.Fatal("non-Geo invocation auto-loaded Geo policy", err)
	}
}

func TestSingleProtocolRuntimeProfileSelection(t *testing.T) {
	for _, test := range []struct {
		mode       types.MeasurementMode
		payload    types.Payload
		connection bool
		want       string
	}{
		{types.MeasurementModeRTBased, types.PayloadICMP, false, "single-rt"},
		{types.MeasurementModeFixedInterval, types.PayloadUDPDNS, false, "single-fi"},
		{types.MeasurementModeRTBased, types.PayloadTCP, false, "single-rt"},
		{types.MeasurementModeRTBased, types.PayloadTCP, true, "connection-rt"},
		{types.MeasurementModeFixedInterval, types.PayloadTCP, true, "connection-fi"},
	} {
		c := IPIDConfig{MeasurementMode: test.mode, TCPConfig: TCPConfig{EstablishConnection: test.connection}}
		c.ZMapPayload = test.payload
		if got := SingleProtocolResourceProfile(&c); got != test.want {
			t.Fatalf("got %q want %q", got, test.want)
		}
	}
	for _, name := range []string{"interprotocol-base", "interprotocol-mass", "local-reference-base", "local-reference-mass"} {
		t.Run(name, func(t *testing.T) {
			path, policy, binding := runtimeFixture(t)
			writeRuntimePolicy(t, policy, "version: 1\nworkspace_binding: "+binding+"\nprofiles:\n  "+name+":\n    number_of_inflight_probes: 5K\n")
			c := IPIDConfig{NumberOfInflightProbes: 2000}
			path = filepath.Join(filepath.Dir(path), "interprotocol.yaml")
			if err := ApplyIPIDRuntimeResources(path, &c, name); err != nil || c.NumberOfInflightProbes != 5000 {
				t.Fatal("interprotocol/reference profile not applied", err)
			}
		})
	}
}
