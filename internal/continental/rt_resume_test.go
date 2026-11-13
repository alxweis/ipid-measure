package continental

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alxweis/ipid-measure/internal/rtresume"
	"github.com/alxweis/ipid-measure/internal/upload"
)

func legacyRunner(t *testing.T) (*Runner, Step, []string, *int) {
	t.Helper()
	r, _, _ := fixture(t)
	r.Campaign = rtresume.Campaign
	r.Protocol = "icmp"
	r.Site = "sa"
	r.RetainLocal = true
	r.Workspace = filepath.Join(r.Repo, "parallel", r.Campaign, r.Site, r.Protocol)
	id, zmap := "icmp_2026-11-08_03-04-51", "icmp_2026-11-07_03-50-17"
	args := []string{"--zmap", zmap, "--measurement_mode", "rt-based"}
	signature := digest(Encode(append([]string{"ipid"}, args...)))
	original := Step{id, "2026-11-08T03:04:51Z", signature}
	r.state = State{Version: 1, Binding: "binding", Steps: map[string]Step{"icmp-rt": original, "zmap-icmp": {ID: zmap, Stamp: "2026-11-07T03:50:17Z"}}}
	root := "s3://netds3o:aweis/ipid-2/raw/recovery/" + r.Campaign + "/sa/icmp/" + id
	receipt := rtresume.Receipt{Version: 1, Purpose: "interrupted-rt-preservation-not-measurement-completion", Campaign: r.Campaign, Site: r.Site, ID: id, ZMap: zmap, Binding: "binding", Files: map[string]rtresume.File{}}
	for _, name := range []string{"ipid.pq", "ipid.snapshot.yaml", "zmap.pq", "zmap.snapshot.yaml", "state.json", "original-scanner.journal.jsonl"} {
		path := r.rawPath("ipid", id, name)
		if strings.HasPrefix(name, "zmap.") {
			path = r.rawPath("zmap", zmap, name)
		}
		if name == "state.json" {
			path = r.statePath()
		}
		if name == "original-scanner.journal.jsonl" {
			path = filepath.Join(r.Workspace, "recovery-backup", id, "scanner.jsonl")
		}
		sha := strings.Repeat("a", 64)
		if name == "ipid.pq" {
			sha = "2b38049e65adfa9d24e77969760d1c0008e86bc9e1052ebf7f08527c8e57fcb7"
		}
		receipt.Files[name] = rtresume.File{FileEvidence: upload.FileEvidence{Size: 10, SHA256: sha}, URI: root + "/sha256-" + sha + "/" + name, LocalPath: path}
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	r.ResumeRTReceipt = filepath.Join(r.Workspace, "recovery-backup", id, "backup-verified.json")
	mustWrite(t, r.ResumeRTReceipt, data)
	mustWrite(t, r.rawPath("ipid", id, "ipid.pq"), []byte("untouched original"))
	r.resumeFetchOverride = func(_ context.Context, uri string) ([]byte, error) {
		if !strings.Contains(uri, "/receipts/sha256-") {
			return nil, fmt.Errorf("unexpected fetch")
		}
		return data, nil
	}
	called := 0
	originalExecute := r.Execute
	r.Execute = func(ctx context.Context, tool string, got, env []string) (string, error) {
		called++
		if argument(got, "--resume-from") != filepath.Dir(r.rawPath("ipid", id, "ipid.pq")) || argument(got, "--resume-backup") != r.ResumeRTReceipt || argument(got, "--resume-site") != "sa" || argument(got, "--resume-binding") != "binding" || argument(got, "--measurement_mode") != "rt-based" {
			t.Fatalf("incorrect resume args: %v", got)
		}
		return originalExecute(ctx, tool, got, env)
	}
	return r, original, args, &called
}

func TestLegacyControllerAdoptsNewIDWithoutOverwritingOriginal(t *testing.T) {
	r, original, args, called := legacyRunner(t)
	id, err := r.measure(context.Background(), "icmp-rt", "ipid", "icmp", args...)
	if err != nil {
		t.Fatal(err)
	}
	if id == original.ID || *called != 1 {
		t.Fatalf("new id %s calls %d", id, *called)
	}
	if r.state.Recoveries["icmp-rt"].Original != original || r.state.Recoveries["icmp-rt"].ResumeID != id {
		t.Fatal("lost original recovery binding")
	}
	b, err := os.ReadFile(r.rawPath("ipid", original.ID, "ipid.pq"))
	if err != nil || string(b) != "untouched original" {
		t.Fatal("original modified")
	}
	if _, err := r.measure(context.Background(), "icmp-rt", "ipid", "icmp", args...); err != nil {
		t.Fatal(err)
	}
	if *called != 1 {
		t.Fatal("committed resumed attempt was repeated")
	}
}

func TestLegacyControllerFailureRetainsProgressAndRejectsFreshRetry(t *testing.T) {
	r, _, args, _ := legacyRunner(t)
	r.Execute = func(_ context.Context, _ string, _ []string, _ []string) (string, error) {
		step := r.state.Steps["icmp-rt"]
		mustWrite(t, r.rawPath("ipid", step.ID, "ipid.pq"), []byte("new retained progress"))
		return "", fmt.Errorf("interrupted again")
	}
	if _, err := r.measure(context.Background(), "icmp-rt", "ipid", "icmp", args...); err == nil {
		t.Fatal("accepted interrupted child")
	}
	for _, receipt := range []string{r.ResumeRTReceipt, ""} {
		r.ResumeRTReceipt = receipt
		if _, err := r.measure(context.Background(), "icmp-rt", "ipid", "icmp", args...); err == nil {
			t.Fatal("silently replaced retained resumed attempt")
		}
	}
}
