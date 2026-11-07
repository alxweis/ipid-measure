package continental

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alxweis/ipid-measure/internal/upload"
)

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected removed file %s, got %v", path, err)
	}
}

func assertPresent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected retained file %s: %v", path, err)
	}
}

// Model sync of the original bytes before the child publishes completion.
// No tests invoke scanners, subprocesses or a real S3 endpoint.
func captureRawUploads(t *testing.T, r *Runner, store *memoryStore) {
	t.Helper()
	original := r.Execute
	r.Execute = func(ctx context.Context, tool string, args, env []string) (string, error) {
		// A later phase must have its actual local input even though prior
		// bulk outputs have already been released.
		if target := argument(args, "--target-file"); target != "" {
			assertPresent(t, target)
		}
		for name, step := range r.state.Steps {
			if strings.HasPrefix(name, "zmap-") {
				continue
			}
			if _, committed := store.values[Join(r.rawPrefix("ipid"), step.ID, "measurement-complete.json")]; committed {
				assertMissing(t, r.rawPath("ipid", step.ID, bulkFile(step.ID)))
			}
		}
		out, err := original(ctx, tool, args, env)
		if err != nil {
			return out, err
		}
		for _, step := range r.state.Steps {
			for _, kind := range []string{"ipid", "zmap"} {
				uri := Join(r.rawPrefix(kind), step.ID)
				data, exists := store.values[Join(uri, "measurement-complete.json")]
				if !exists {
					continue
				}
				var marker struct {
					Files map[string]upload.FileEvidence
				}
				if err := json.Unmarshal(data, &marker); err != nil {
					t.Fatal(err)
				}
				for name := range marker.Files {
					if _, exists := store.values[Join(uri, name)]; exists {
						continue
					}
					contents, err := os.ReadFile(r.rawPath(kind, step.ID, name))
					if err != nil {
						t.Fatal(err)
					}
					store.values[Join(uri, name)] = contents
				}
			}
		}
		return out, nil
	}
}

func runTestIPID(t *testing.T, r *Runner) (string, error) {
	t.Helper()
	return r.measure(context.Background(), "test-rt", "ipid", "icmp", "--zmap", "icmp_2026-01-01_00-00-00")
}

func TestGeoCleanupRetainsInputsAndRemoteRaw(t *testing.T) {
	for _, protocol := range []string{"icmp", "tcp", "udp-dns"} {
		t.Run(protocol, func(t *testing.T) {
			r, s, calls := parallelFixture(t, protocol)
			captureRawUploads(t, r, s)
			// UDP needs the other two completed protocol manifests.
			for _, p := range []string{"icmp", "tcp"} {
				if protocol != "udp-dns" {
					break
				}
				flow := Join(r.sitePrefix(), "protocols", p)
				job := p + "_2026-01-01_00-00-00"
				uri := Join(flow, "analysis-jobs", job, "manifest.json")
				s.values[uri] = []byte("{}")
				s.values[Join(flow, "done.json")] = Encode(map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": p, "manifest_uri": uri, "job_id": job})
			}
			if err := r.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			for name, step := range r.state.Steps {
				if strings.HasPrefix(name, "zmap-") {
					assertPresent(t, r.rawPath("zmap", step.ID, "zmap.pq"))
					continue
				}
				bulk := bulkFile(step.ID)
				assertMissing(t, r.rawPath("ipid", step.ID, bulk))
				assertPresent(t, r.rawPath("ipid", step.ID, strings.TrimSuffix(bulk, ".pq")+".snapshot.yaml"))
				if len(s.values[Join(r.rawPrefix("ipid"), step.ID, bulk)]) == 0 {
					t.Fatal("cleanup lost the uploaded raw data")
				}
				if ok, err := r.committed(context.Background(), "ipid", step); !ok || err != nil {
					t.Fatalf("cannot adopt cleaned measurement: %v", err)
				}
			}
			for _, phase := range []string{"rt", "mass"} {
				step := r.state.Steps[protocol+"-"+phase]
				target := "zmap_unclassified.pq"
				if phase == "mass" {
					target = "random-reproducibility-targets.pq"
				}
				assertPresent(t, r.rawPath("ipid", step.ID, target))
			}
			before := len(*calls)
			if err := r.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := r.Run(context.Background()); err != nil || len(*calls) != before {
				t.Fatalf("completed restart repeated measurements: %v", err)
			}
		})
	}
}

func TestCleanupDefaultKeepsLegacyAndRetainLocal(t *testing.T) {
	for _, mode := range []string{"legacy", "retain-local"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _ := fixture(t)
			if mode == "retain-local" {
				r.Protocol, r.RetainLocal = "icmp", true
			}
			id, err := runTestIPID(t, r)
			if err != nil {
				t.Fatal(err)
			}
			assertPresent(t, r.rawPath("ipid", id, "ipid.pq"))
			path, _ := r.cleanupReceiptPath(id)
			assertMissing(t, path)
		})
	}
}

func TestCleanupRestartDuringHandoffDoesNotReprobe(t *testing.T) {
	r, s, calls := parallelFixture(t, "icmp")
	captureRawUploads(t, r, s)
	original := r.handoffOverride
	r.handoffOverride = func(context.Context, string, bool) error { return errors.New("analysis temporarily unavailable") }
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("missing handoff ignored")
	}
	rt := r.state.Steps["icmp-rt"]
	assertMissing(t, r.rawPath("ipid", rt.ID, "ipid.pq"))
	if len(*calls) != 2 {
		t.Fatal("unexpected probes before blocked handoff")
	}
	r.handoffOverride = original
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); err != nil || len(*calls) != 9 {
		t.Fatalf("restart remeasured cleaned RT or lost targets: %v, %v", err, *calls)
	}
}

func TestCleanupRequiresUnchangedRemoteCompletionAndReceipt(t *testing.T) {
	for _, failure := range []string{"missing-marker", "access-denied", "changed-marker", "changed-receipt", "lost-receipt", "lost-snapshot", "recreated-corrupt-data"} {
		t.Run(failure, func(t *testing.T) {
			r, s, calls := parallelFixture(t, "icmp")
			id, err := runTestIPID(t, r)
			if err != nil {
				t.Fatal(err)
			}
			markerURI := Join(r.rawPrefix("ipid"), id, "measurement-complete.json")
			receiptPath, _ := r.cleanupReceiptPath(id)
			switch failure {
			case "missing-marker":
				delete(s.values, markerURI)
			case "access-denied":
				s.fail = markerURI
			case "changed-marker":
				s.values[markerURI] = append(s.values[markerURI], ' ')
			case "changed-receipt":
				data, _ := os.ReadFile(receiptPath)
				mustWrite(t, receiptPath, []byte(strings.Replace(string(data), r.state.Binding, "wrong-binding", 1)))
			case "lost-receipt":
				if err := os.Remove(receiptPath); err != nil {
					t.Fatal(err)
				}
			case "lost-snapshot":
				if err := os.Remove(r.rawPath("ipid", id, "ipid.snapshot.yaml")); err != nil {
					t.Fatal(err)
				}
			case "recreated-corrupt-data":
				mustWrite(t, r.rawPath("ipid", id, "ipid.pq"), []byte("tampered"))
			}
			r.RetryIncomplete = true
			if _, err := runTestIPID(t, r); err == nil || len(*calls) != 1 {
				t.Fatalf("missing/corrupt provenance remeasured or was accepted: %v", err)
			}
		})
	}
}

func TestCleanupNeverDeletesUncommittedOrMismatchingData(t *testing.T) {
	for _, failure := range []string{"upload", "local-mismatch", "receipt-write"} {
		t.Run(failure, func(t *testing.T) {
			r, s, _ := parallelFixture(t, "icmp")
			original := r.Execute
			r.Execute = func(ctx context.Context, tool string, args, env []string) (string, error) {
				out, err := original(ctx, tool, args, env)
				if err != nil {
					return out, err
				}
				id := r.state.Steps["test-rt"].ID
				switch failure {
				case "upload":
					delete(s.values, Join(r.rawPrefix("ipid"), id, "measurement-complete.json"))
					return out, errors.New("upload failed")
				case "local-mismatch":
					mustWrite(t, r.rawPath("ipid", id, "ipid.pq"), []byte("changed"))
				case "receipt-write":
					mustWrite(t, filepath.Join(r.Workspace, "cleanup"), []byte("not a directory"))
				}
				return out, nil
			}
			if _, err := runTestIPID(t, r); err == nil {
				t.Fatal("unsafe cleanup accepted")
			}
			id := r.state.Steps["test-rt"].ID
			assertPresent(t, r.rawPath("ipid", id, "ipid.pq"))
		})
	}
}

func TestCleanupRecoversWriteAheadReceiptBeforeUnlink(t *testing.T) {
	r, _, calls := parallelFixture(t, "icmp")
	r.RetainLocal = true
	id, err := runTestIPID(t, r)
	if err != nil {
		t.Fatal(err)
	}
	step := r.state.Steps["test-rt"]
	data, _, err := r.Store.Read(context.Background(), Join(r.rawPrefix("ipid"), id, "measurement-complete.json"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := upload.Evidence(r.rawPath("ipid", id, "ipid.pq"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := cleanupReceipt{Version: 1, Binding: r.state.Binding, ID: id, MarkerSHA256: digest(data), File: "ipid.pq", Evidence: evidence}
	path, _ := r.cleanupReceiptPath(id)
	if err := r.writeCleanupReceipt(path, receipt); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between durable receipt and unlink.
	r.RetainLocal = false
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := runTestIPID(t, r); err != nil || len(*calls) != 1 || r.state.Steps["test-rt"].ID != step.ID {
		t.Fatalf("pending cleanup repeated measurement: %v", err)
	}
	assertMissing(t, r.rawPath("ipid", id, "ipid.pq"))
}

func TestCleanupAdoptsLostSuccessfulChildExit(t *testing.T) {
	r, _, calls := parallelFixture(t, "icmp")
	original := r.Execute
	r.Execute = func(ctx context.Context, tool string, args, env []string) (string, error) {
		out, err := original(ctx, tool, args, env)
		if err != nil {
			return out, err
		}
		return out, errors.New("lost child exit after completed upload")
	}
	if _, err := runTestIPID(t, r); err == nil {
		t.Fatal("lost exit ignored")
	}
	id := r.state.Steps["test-rt"].ID
	assertPresent(t, r.rawPath("ipid", id, "ipid.pq"))
	r.Execute = original
	if _, err := runTestIPID(t, r); err != nil || len(*calls) != 1 {
		t.Fatalf("completed child was remeasured: %v", err)
	}
	assertMissing(t, r.rawPath("ipid", id, "ipid.pq"))
}

func TestCleanupDoesNotFollowSymlinksOutsideWorkspace(t *testing.T) {
	for _, mode := range []string{"file", "directory"} {
		t.Run(mode, func(t *testing.T) {
			r, _, _ := parallelFixture(t, "icmp")
			r.RetainLocal = true
			id, err := runTestIPID(t, r)
			if err != nil {
				t.Fatal(err)
			}
			path := r.rawPath("ipid", id, "ipid.pq")
			outside := filepath.Join(t.TempDir(), "outside")
			if mode == "file" {
				data, _ := os.ReadFile(path)
				mustWrite(t, outside, data)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(filepath.Dir(path), outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
				outside = filepath.Join(outside, "ipid.pq")
			}
			r.RetainLocal = false
			if _, err := runTestIPID(t, r); err == nil {
				t.Fatal("cleanup followed an external symlink")
			}
			assertPresent(t, outside)
		})
	}
}
