package continental

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
	"gopkg.in/yaml.v3"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/upload"
	osmod "github.com/alxweis/ipid-measure/os"
)

func TestOSWorkerResumesClosedPartialAndPreservesAnalysisContract(t *testing.T) {
	ctx := context.Background()
	repo := t.TempDir()
	workspace := filepath.Join(repo, "worker")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(workspace, "targets.pq")
	if err := parquet.WriteFile(target, []records.ZMap{{IPAddress: "192.0.2.1"}, {IPAddress: "192.0.2.2"}}); err != nil {
		t.Fatal(err)
	}
	e, _ := upload.Evidence(target)
	targetBytes, _ := os.ReadFile(target)
	job := "s3://bucket/workflow/continental/round/os"
	raw := "s3://bucket/raw/continental/round/os/shared-os"
	request := OSRequest{Version: 1, Campaign: "round", RawRoot: "s3://bucket/raw", ZMap: "tcp-80_2026-11-07_03-30-08", Target: Target{URI: job + "/targets.pq", Size: e.Size, SHA256: e.SHA256, Rows: 2}}
	data := Encode(request)
	store := &memoryStore{values: map[string][]byte{request.Target.URI: targetBytes}}
	step := Step{ID: "tcp-80_2026-11-08_12-00-00", Stamp: "2026-11-08T12:00:00Z"}
	if err := AtomicJSON(filepath.Join(workspace, "scan.json"), step); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(workspace, "os", "raw", step.ID)
	if err := os.MkdirAll(old, 0755); err != nil {
		t.Fatal(err)
	}
	n := config.ScaledNumber(1)
	c := config.OSConfig{ZMapReference: config.ZMapReference{ZMapID: request.ZMap, TargetFile: target}, RecordTargetStatus: true,
		Modules:       config.OSModules{SSH: true, SMB: true, HTTP: true, HTTPS: true, SNMP: true, DNSChaos: true},
		SchemaVersion: osmod.SchemaVersion, ClassifierVersion: osmod.ClassifierVersion,
		ZGrab2Senders: &n, DNSChaosWorkers: &n, SNMPWorkers: &n, ConnectTimeout: time.Second, ReadTimeout: time.Second, DNSChaosTimeout: time.Second, SNMPTimeout: time.Second, SNMPCommunity: "public"}
	snapshot, _ := yaml.Marshal(c)
	mustWrite(t, filepath.Join(old, "os.snapshot.yaml"), snapshot)
	// Closed old source with no evidence is still a valid partial population.
	type observation struct {
		IP       string `parquet:"IP_ADDR"`
		Response int32  `parquet:"RESPONSE_MASK"`
		Evidence int32  `parquet:"EVIDENCE_MASK"`
		Tagged   int32  `parquet:"TAG_MASK"`
		Status   string `parquet:"OS_STATUS"`
		Conflict string `parquet:"CONFLICT"`
	}
	if err := parquet.WriteFile(filepath.Join(old, "os-observations.pq"), []observation{{IP: "192.0.2.1", Status: "no-evidence"}}); err != nil {
		t.Fatal(err)
	}
	if err := parquet.WriteFile[records.OSRecord](filepath.Join(old, "os.pq"), nil); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(repo, "config", "os.yaml"), snapshot)
	oldBytes, _ := os.ReadFile(filepath.Join(old, "os.pq"))
	calls := 0
	execute := func(_ context.Context, _ string, args, env []string) (string, error) {
		calls++
		if argument(args, "--resume-from") != old {
			t.Fatalf("missing retained source %v", args)
		}
		stamp, _ := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
		id := "tcp-80_" + stamp.Format("2006-01-02_15-04-05")
		if id == step.ID {
			t.Fatal("partial source overwritten")
		}
		out := filepath.Join(workspace, "os", "raw", id)
		for _, name := range []string{"os.pq", "os-observations.pq", "os-coverage.json", "os.snapshot.yaml", "os-resume.json"} {
			mustWrite(t, filepath.Join(out, name), []byte(name))
		}
		_, err := upload.WriteCompletion(paths.Measurement{ID: id, Path: out})
		return "", err
	}
	// Resume provenance upload must finish before canonical done publication.
	store.fail = raw + "/os-resume.json"
	if _, err := runOSScan(ctx, store, execute, repo, workspace, job, raw, "round", data, request, false, "shared-os-vm", false, true); err == nil {
		t.Fatal("partial upload accepted")
	}
	if _, ok := store.values[job+"/done.json"]; ok {
		t.Fatal("premature done")
	}
	store.fail = ""
	done, err := runOSScan(ctx, store, execute, repo, workspace, job, raw, "round", data, request, false, "shared-os-vm", false, true)
	if err != nil || !done || calls != 1 {
		t.Fatalf("repeated completed scan: done=%v err=%v calls=%d", done, err, calls)
	}
	var value struct {
		Files  map[string]upload.FileEvidence `json:"files"`
		Resume map[string]any                 `json:"resume"`
	}
	if json.Unmarshal(store.values[job+"/done.json"], &value) != nil || len(value.Files) != 4 || value.Resume["uri"] != raw+"/os-resume.json" {
		t.Fatalf("analysis contract changed: %s", store.values[job+"/done.json"])
	}
	if _, ok := value.Files["os-resume.json"]; ok {
		t.Fatal("extra file breaks existing analysis verifier")
	}
	current, _ := os.ReadFile(filepath.Join(old, "os.pq"))
	if string(current) != string(oldBytes) {
		t.Fatal("retained source changed")
	}
	if _, err := os.Stat(filepath.Join(old, "measurement-complete.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial source marked complete")
	}
}
