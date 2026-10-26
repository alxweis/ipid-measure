package postprocessworkflow

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type policyRunner struct {
	objects              map[string][]byte
	writes               []string
	failURI, failCommand string
}

func (r *policyRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	uri := args[len(args)-1]
	if args[0] == "get" {
		uri = args[len(args)-2]
	}
	if uri == r.failURI && args[0] == r.failCommand {
		return nil, errors.New("403 AccessDenied")
	}
	switch args[0] {
	case "ls":
		if _, ok := r.objects[uri]; ok {
			return []byte("2026-10-26 00:00 1 " + uri + "\n"), nil
		}
	case "get":
		return nil, os.WriteFile(args[len(args)-1], r.objects[uri], 0600)
	case "put":
		data, err := os.ReadFile(args[len(args)-2])
		if err != nil {
			return nil, err
		}
		r.objects[uri] = data
		r.writes = append(r.writes, uri)
	}
	return nil, nil
}

func TestNoOSPublishIsExplicitAndDoesNotNeedOSConfig(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	r := &policyRunner{objects: map[string][]byte{}}
	configs := ConfigPaths{ZMap: filepath.Join(root, "zmap.yaml"), IPID: filepath.Join(root, "ipid.yaml"), OS: filepath.Join(root, "absent-os.yaml")}
	writeConfig(t, configs.ZMap, "s3://bucket/raw/zmap/", "")
	writeConfig(t, configs.IPID, "s3://bucket/raw/ipid/", "s3://bucket/workflow/")
	m := Measurements{SkipOS: true, ZMap: "icmp_2026-10-26_01-00-00", RTBase: "icmp_2026-10-26_01-00-01", FixedMass: "icmp_2026-10-26_01-00-02", FixedBase: "icmp_2026-10-26_01-00-03"}
	output := filepath.Join(root, "jobs")
	requestURI, err := publish(ctx, r, m, configs, output, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var request Request
	if err = json.Unmarshal(r.objects[requestURI], &request); err != nil {
		t.Fatal(err)
	}
	if request.OSPrefix != "" || request.OSStatus != "not_requested" {
		t.Fatalf("ambiguous no-OS request: %+v", request)
	}
	var manifest map[string]map[string]any
	_ = json.Unmarshal(r.objects[request.ManifestURI], &manifest)
	if _, exists := manifest["icmp"]["os"]; exists {
		t.Fatal("fabricated OS measurement ID")
	}
	if manifest["icmp"]["os_status"] != "not_requested" || manifest["icmp"]["ipid"] == nil {
		t.Fatal("missing intent or non-OS measurements")
	}
	if r.writes[len(r.writes)-1] != requestURI {
		t.Fatal("request must still be last")
	}
	if _, err = publish(ctx, r, m, configs, output, time.Now()); err != nil {
		t.Fatalf("no-OS restart failed: %v", err)
	}
	before := len(r.writes)
	if _, err = recordOSPolicy(ctx, r, m.ZMap, false, "s3://bucket/workflow", t.TempDir()); err == nil {
		t.Fatal("remote no-OS policy silently changed")
	}
	if len(r.writes) != before {
		t.Fatal("conflicting mode changed remote data")
	}
	m.OS = "icmp_2026-10-26_01-00-04"
	if _, err = validateMeasurements(m); err == nil {
		t.Fatal("skip with OS ID accepted")
	}
}

func TestLegacyOSManifestCannotBeReusedWithNoOSPolicy(t *testing.T) {
	ctx := context.Background()
	id := "icmp_2026-10-26_01-00-00"
	prefix := "s3://bucket/workflow"
	job := joinS3(prefix, "analysis-jobs", id)
	r := &policyRunner{objects: map[string][]byte{joinS3(job, "manifest.json"): []byte(`{"icmp":{"os":"icmp_2026-10-26_01-00-01"}}`)}}
	if _, err := recordOSPolicy(ctx, r, id, true, prefix, t.TempDir()); err == nil {
		t.Fatal("enabled legacy manifest became disabled")
	}
	if len(r.writes) != 0 {
		t.Fatal("legacy completion namespace modified")
	}
	uri, err := recordOSPolicy(ctx, r, id, false, prefix, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var policy osPolicy
	_ = json.Unmarshal(r.objects[uri], &policy)
	if policy.Status != "requested" {
		t.Fatal("missing policy was interpreted as disabled")
	}
}

func TestOSPolicyFailureAndRestartNeverInferDisabled(t *testing.T) {
	ctx := context.Background()
	id := "icmp_2026-10-26_01-00-00"
	prefix := "s3://bucket/workflow"
	uri := joinS3(prefix, "analysis-jobs", id, "os-policy.json")
	r := &policyRunner{objects: map[string][]byte{}, failURI: uri, failCommand: "ls"}
	if _, err := recordOSPolicy(ctx, r, id, true, prefix, t.TempDir()); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatal("permission failure treated as absence")
	}
	if len(r.writes) != 0 {
		t.Fatal("failure published a policy")
	}
	root := t.TempDir()
	r.failCommand = "put"
	if _, err := recordOSPolicy(ctx, r, id, true, prefix, root); err == nil {
		t.Fatal("failed policy upload ignored")
	}
	r.failCommand = ""
	if _, err := recordOSPolicy(ctx, r, id, false, prefix, root); err == nil {
		t.Fatal("local persisted intent changed on restart")
	}
	if _, err := recordOSPolicy(ctx, r, id, true, prefix, root); err != nil {
		t.Fatal(err)
	}
}
