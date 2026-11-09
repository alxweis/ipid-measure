package continental

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
)

func TestRuntimePolicyPreservesGeoBindingAndCommittedSteps(t *testing.T) {
	r, store, calls := parallelFixture(t, "icmp")
	captureRawUploads(t, r, store)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(r.statePath())
	if err != nil {
		t.Fatal(err)
	}
	policy := filepath.Join(r.Workspace, "config", config.IPIDRuntimeFile)
	mustWrite(t, policy, []byte("version: 1\nworkspace_binding: "+r.state.Binding+"\nprofiles:\n  single-fi:\n    number_of_inflight_probes: 5K\n"))
	count := len(*calls)
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); err != nil || len(*calls) != count {
		t.Fatalf("runtime policy caused completed steps to repeat: %v", err)
	}
	after, err := os.ReadFile(r.statePath())
	if err != nil || string(before) != string(after) {
		t.Fatal("runtime policy changed Geo state", err)
	}
	assertPresent(t, policy)
	t.Setenv("IPID_MEASURE_WORKSPACE", r.Workspace)
	c := config.IPIDConfig{NumberOfInflightProbes: 2000}
	if err := config.ApplyIPIDRuntimeResources(r.configs["ipid"], &c, "single-fi"); err != nil || c.NumberOfInflightProbes != 5000 {
		t.Fatalf("controller preparation lost future-phase policy: %v", err)
	}
}
