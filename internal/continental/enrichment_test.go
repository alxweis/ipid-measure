package continental

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/upload"
)

func TestEnrichmentRequestImmutableAndNoOSRequired(t *testing.T) {
	ctx := context.Background()
	store := &memoryStore{values: map[string][]byte{}}
	core, err := EnrichmentCore("s3://bucket/workflow", "", "icmp_2026-10-25_01-00-00")
	if err != nil {
		t.Fatal(err)
	}
	if err = RequestOSEnrichment(ctx, store, core, "late-vm"); err == nil {
		t.Fatal("incomplete core accepted")
	}
	store.values[Join(core, "done.json")] = []byte(`{"version":1}`)
	if err = RequestOSEnrichment(ctx, store, core, "late-vm"); err == nil {
		t.Fatal("enabled core accepted")
	}
	store.values[Join(core, "done.json")] = []byte(`{"version":1,"os_status":"not_requested"}`)
	before := string(store.values[Join(core, "done.json")])
	if err = RequestOSEnrichment(ctx, store, core, ""); err == nil {
		t.Fatal("missing vantage accepted")
	}
	if err = RequestOSEnrichment(ctx, store, core, "late-vm"); err != nil {
		t.Fatal(err)
	}
	count := len(store.writes)
	if err = RequestOSEnrichment(ctx, store, core, "late-vm"); err != nil {
		t.Fatal(err)
	}
	if len(store.writes) != count {
		t.Fatal("duplicate request rewritten")
	}
	if err = RequestOSEnrichment(ctx, store, core, "other-vm"); err == nil {
		t.Fatal("changed vantage accepted")
	}
	if string(store.values[Join(core, "done.json")]) != before {
		t.Fatal("core changed")
	}
	store.fail = Join(core, "done.json")
	if err = RequestOSEnrichment(ctx, store, core, "late-vm"); err == nil {
		t.Fatal("AccessDenied ignored")
	}
	for _, args := range [][2]string{{"", ""}, {"round", "icmp"}, {"../round", ""}, {"", "a/b"}} {
		if _, err = EnrichmentCore("s3://bucket/workflow", args[0], args[1]); err == nil {
			t.Fatal("unsafe identity accepted")
		}
	}
}

func TestLateOSScanRecoveryIntegrityAndIsolation(t *testing.T) {
	for _, geographic := range []bool{false, true} {
		t.Run(map[bool]string{false: "protocol", true: "geographic"}[geographic], func(t *testing.T) {
			r, store, _ := fixture(t, true)
			ctx := context.Background()
			core := Join(r.Prefix, "analysis-jobs", "icmp_2026-10-25_01-00-00")
			identity := "icmp_2026-10-25_01-00-00"
			if geographic {
				core = Join(r.Prefix, "continental", r.Campaign)
				identity = r.Campaign
			}
			store.values[Join(core, "done.json")] = []byte(`{"version":1,"os_status":"not_requested"}`)
			if !geographic {
				store.values[Join(core, "request.json")] = Encode(map[string]any{"job_id": identity, "os_status": "not_requested", "zmap_prefix": Join(r.RawRoot, "zmap")})
			}
			before := map[string]string{}
			for k, v := range store.values {
				before[k] = string(v)
			}
			if err := RequestOSEnrichment(ctx, store, core, "actual-os-vm"); err != nil {
				t.Fatal(err)
			}
			root := Join(core, "enrichments", "os")
			job := Join(root, "scan")
			workspace := filepath.Join(r.Repo, "late-os")
			calls := 0
			execute := func(_ context.Context, tool string, args, env []string) (string, error) {
				calls++
				if filepath.Base(tool) != "measure-os" || argument(args, "--target-file") == "" {
					t.Fatal("unexpected measurement executed")
				}
				stamp, _ := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
				id := "tcp-80_" + stamp.Format("2006-01-02_15-04-05")
				for _, name := range []string{"os.pq", "os-observations.pq", "os-coverage.json", "os.snapshot.yaml"} {
					mustWrite(t, filepath.Join(workspace, "os", "raw", id, name), []byte(name))
				}
				_, err := upload.WriteCompletion(paths.Measurement{ID: id, Path: filepath.Join(workspace, "os", "raw", id)})
				return id, err
			}
			if done, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err != nil || done {
				t.Fatal("scan started without targets", err)
			}
			target := []byte("original-population")
			path := filepath.Join(t.TempDir(), "targets.pq")
			mustWrite(t, path, target)
			e, _ := upload.Evidence(path)
			request := OSRequest{Version: 1, Campaign: identity, RawRoot: Join(root, "raw"), Target: Target{Join(job, "targets.pq"), e.Size, e.SHA256, 1}, ZMap: identity}
			if geographic {
				for _, site := range Sites {
					for _, p := range Protocols {
						id := map[string]string{"icmp": "icmp", "tcp": "tcp-80", "udp-dns": "udp-dns-53"}[p] + "_2026-10-25_01-00-00"
						request.Members = append(request.Members, map[string]string{"site": site, "protocol": p, "measurement_id": id, "uri": Join(r.RawRoot, "continental", r.Campaign, site, "zmap", id, "zmap.pq"), "sha256": strings.Repeat("a", 64)})
						if site == "eu" && p == "tcp" {
							request.ZMap = id
						}
					}
				}
			} else {
				request.Members = []map[string]string{{"protocol": "icmp", "measurement_id": identity, "uri": Join(r.RawRoot, "zmap", identity, "zmap.pq"), "sha256": strings.Repeat("a", 64)}}
			}
			store.values[Join(job, "request.json")] = Encode(request)
			store.values[request.Target.URI] = target
			store.fail = Join(root, "raw", "os-coverage.json")
			if done, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err == nil || done {
				t.Fatal("partial upload became completion")
			}
			if err := PublishEnrichmentScanFailure(ctx, store, core, errors.New("upload failed")); err != nil {
				t.Fatal(err)
			}
			if _, ok := store.values[Join(core, "failed.json")]; ok {
				t.Fatal("core failed")
			}
			if _, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err == nil {
				t.Fatal("failure auto-retried")
			}
			// Equivalent to explicit archived-failure recovery; closed local scan is adopted.
			store.values[Join(job, "attempts", "1", "failed.json")] = store.values[Join(job, "failed.json")]
			delete(store.values, Join(job, "failed.json"))
			store.fail = ""
			if done, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err != nil || !done {
				t.Fatal(err)
			}
			if done, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err != nil || !done || calls != 1 {
				t.Fatal("completed scan repeated", err)
			}
			var done map[string]any
			_ = json.Unmarshal(store.values[Join(job, "done.json")], &done)
			if done["late_enrichment"] != true || done["vantage"] != "actual-os-vm" || done["started_at"] == nil || done["completed_at"] == nil {
				t.Fatal("late provenance missing")
			}
			for k, v := range before {
				if string(store.values[k]) != v {
					t.Fatalf("core changed: %s", k)
				}
			}
			delete(store.values, Join(job, "done.json"))
			request.Target.SHA256 = strings.Repeat("0", 64)
			store.values[Join(job, "request.json")] = Encode(request)
			if _, err := RunOSEnrichment(ctx, store, execute, r.Repo, filepath.Join(r.Repo, "bad"), core, false); err == nil {
				t.Fatal("corrupt target accepted")
			}
		})
	}
}

func TestLateOSIncompleteAttemptNeedsExplicitRetry(t *testing.T) {
	r, store, _ := fixture(t, true)
	ctx := context.Background()
	id := "icmp_2026-10-25_01-00-00"
	core := Join(r.Prefix, "analysis-jobs", id)
	store.values[Join(core, "done.json")] = []byte(`{"version":1,"os_status":"not_requested"}`)
	store.values[Join(core, "request.json")] = Encode(map[string]any{"job_id": id, "os_status": "not_requested", "zmap_prefix": Join(r.RawRoot, "zmap")})
	if err := RequestOSEnrichment(ctx, store, core, "late-vm"); err != nil {
		t.Fatal(err)
	}
	root := Join(core, "enrichments", "os")
	job := Join(root, "scan")
	workspace := filepath.Join(r.Repo, "late-partial")
	target := []byte("target")
	path := filepath.Join(t.TempDir(), "target")
	mustWrite(t, path, target)
	e, _ := upload.Evidence(path)
	request := OSRequest{Version: 1, Campaign: id, RawRoot: Join(root, "raw"), Target: Target{Join(job, "targets.pq"), e.Size, e.SHA256, 1}, ZMap: id, Members: []map[string]string{{"protocol": "icmp", "measurement_id": id, "uri": Join(r.RawRoot, "zmap", id, "zmap.pq"), "sha256": e.SHA256}}}
	store.values[Join(job, "request.json")] = Encode(request)
	store.values[request.Target.URI] = target
	calls := 0
	execute := func(_ context.Context, _ string, args, env []string) (string, error) {
		calls++
		stamp, _ := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
		scanID := "tcp-80_" + stamp.Format("2006-01-02_15-04-05")
		output := filepath.Join(workspace, "os", "raw", scanID)
		mustWrite(t, filepath.Join(output, "os.pq"), []byte("partial"))
		if calls == 1 {
			return "", errors.New("interrupted scan")
		}
		for _, name := range []string{"os.pq", "os-observations.pq", "os-coverage.json", "os.snapshot.yaml"} {
			mustWrite(t, filepath.Join(output, name), []byte(name))
		}
		_, err := upload.WriteCompletion(paths.Measurement{ID: scanID, Path: output})
		return scanID, err
	}
	if _, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err == nil {
		t.Fatal("interrupted scan completed")
	}
	if _, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, false); err == nil || !strings.Contains(err.Error(), "retry-incomplete") {
		t.Fatal("partial scan silently resumed", err)
	}
	if done, err := RunOSEnrichment(ctx, store, execute, r.Repo, workspace, core, true); err != nil || !done || calls != 2 {
		t.Fatal("explicit retry failed", err)
	}
	archived, err := filepath.Glob(filepath.Join(workspace, "os", "raw", "*-attempt-*"))
	if err != nil || len(archived) != 1 {
		t.Fatal("partial scan not retained")
	}
}
