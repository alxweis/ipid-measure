package rtresume

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/internal/upload"
	"github.com/parquet-go/parquet-go"
	"gopkg.in/yaml.v3"
)

func parquetFixture[T any](t *testing.T, path string, rows []T) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := parquet.NewGenericWriter[T](f, parquet.MaxRowsPerRowGroup(1))
	if _, err = w.Write(rows); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
func completeRecord(ip string) records.IPIDRecord {
	return records.IPIDRecord{IPAddress: ip, IPIDSequence: strings.TrimSuffix(strings.Repeat("0,", 16), ","),
		SendTimestampSequence: strings.TrimSuffix(strings.Repeat("100,", 16), ","), ReceiveTimestampSequence: strings.TrimSuffix(strings.Repeat("101,", 16), ","), DFSequence: strings.TrimSuffix(strings.Repeat("1,", 16), ",")}
}

func TestPopulationPreservesFailuresAndRejectsWrongPrefixes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		targets   []string
		successes []string
		started   int64
		bad       string
	}{
		{"valid", []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}, []string{"192.0.2.3", "192.0.2.1"}, 3, ""},
		{"saved-outside-prefix", []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}, []string{"192.0.2.1", "192.0.2.4"}, 3, "outside"},
		{"duplicate-target", []string{"192.0.2.1", "192.0.2.1", "192.0.2.3"}, []string{"192.0.2.1"}, 2, "duplicate target"},
		{"duplicate-success", []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, []string{"192.0.2.1", "192.0.2.1"}, 2, "duplicate"},
		{"invalid-target", []string{"192.0.2.1", "bad"}, []string{"192.0.2.1"}, 1, "IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target, source := filepath.Join(dir, "zmap.pq"), filepath.Join(dir, "ipid.pq")
			var targets []records.ZMap
			for _, ip := range tc.targets {
				targets = append(targets, records.ZMap{IPAddress: ip})
			}
			var successes []records.IPIDRecord
			for _, ip := range tc.successes {
				successes = append(successes, completeRecord(ip))
			}
			parquetFixture(t, target, targets)
			parquetFixture(t, source, successes)
			n, err := ValidatePopulation(context.Background(), target, source, int64(len(successes)), tc.started)
			if tc.bad != "" {
				if err == nil || !strings.Contains(err.Error(), tc.bad) {
					t.Fatalf("want %s, got %v", tc.bad, err)
				}
				return
			}
			if err != nil || n != int64(len(targets)) {
				t.Fatalf("population %d: %v", n, err)
			}
		})
	}
}

func TestCountersUseProbeOutcomesNotReplyDrops(t *testing.T) {
	lines := []map[string]string{{"MESSAGE": "replies_final[matched=100 proto=90000] probes_final[timeout=7 interrupt=2 limiter_stop=1] capture_final[packets=2]"}, {"MESSAGE": "run measurement (wrote 10 records before error): interrupted"}}
	var raw []byte
	for _, line := range lines {
		b, _ := json.Marshal(line)
		raw = append(append(raw, b...), '\n')
	}
	rows, started, failures, err := Counters(raw)
	if err != nil || rows != 10 || started != 20 || failures["timeout"] != 7 {
		t.Fatalf("%d %d %v %v", rows, started, failures, err)
	}
	for _, bad := range []string{"rate_low=1", "timeout=-1", "timeout=1 timeout=2", "unknown=1"} {
		b, _ := json.Marshal(map[string]string{"MESSAGE": "probes_final[" + bad + "]"})
		w, _ := json.Marshal(map[string]string{"MESSAGE": "wrote 10 records before error"})
		_, _, _, err := Counters(append(append(b, '\n'), w...))
		if err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, _, _, err := Counters(append(raw, raw...)); err == nil {
		t.Fatal("accepted ambiguous repeated final logs")
	}
}

func TestCopyRefusesChangedSourceOrCancellation(t *testing.T) {
	for _, kind := range []string{"changed", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			f := admissionFixture(t)
			p, err := Admit(context.Background(), f.receipt, f.workspace, "sa", f.id, f.binding, f.current, f.fetch)
			if err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			if kind == "changed" {
				if err := os.WriteFile(p.Source, []byte("changed source"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				close(stop)
			}
			out, err := os.Create(filepath.Join(f.workspace, "not-a-completion.pq"))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			w := parquet.NewGenericWriter[records.IPIDRecord](out)
			defer w.Close()
			if err := Copy(p, w, stop); err == nil {
				t.Fatal("accepted changed/cancelled source replay")
			}
		})
	}
}

type fixture struct {
	workspace, receipt, id, binding string
	current                         *config.IPIDConfig
	remote                          map[string][]byte
}

func (f fixture) fetch(_ context.Context, uri string) ([]byte, error) {
	b, ok := f.remote[uri]
	if !ok {
		return nil, fmt.Errorf("missing metadata %s", uri)
	}
	return b, nil
}
func admissionFixture(t *testing.T) fixture {
	t.Helper()
	original := originals["sa"]
	t.Cleanup(func() { originals["sa"] = original })
	ws := t.TempDir()
	id, zmap := original.ID, original.ZMap
	source, target := filepath.Join(ws, "ipid/raw", id, "ipid.pq"), filepath.Join(ws, "zmap/raw", zmap, "zmap.pq")
	parquetFixture(t, source, []records.IPIDRecord{completeRecord("192.0.2.1"), completeRecord("192.0.2.3")})
	parquetFixture(t, target, []records.ZMap{{IPAddress: "192.0.2.1"}, {IPAddress: "192.0.2.2"}, {IPAddress: "192.0.2.3"}, {IPAddress: "192.0.2.4"}})
	c := &config.IPIDConfig{ZMapReference: config.ZMapReference{ZMapID: zmap, ZMapPayload: types.PayloadICMP, ZMapFilePath: target}, ConnectionCount: 4, RequestsPerConnection: 4, MeasurementMode: types.MeasurementModeRTBased}
	snapshot, _ := yaml.Marshal(c)
	journalDir := filepath.Join(ws, "recovery-backup", id)
	if err := os.MkdirAll(journalDir, 0755); err != nil {
		t.Fatal(err)
	}
	state := []byte(fmt.Sprintf(`{"version":1,"binding":"binding","steps":{"icmp-rt":{"id":%q},"zmap-icmp":{"id":%q}}}`, id, zmap))
	journal := []byte("{\"MESSAGE\":\"run measurement (wrote 2 records before error): interrupted\"}\n{\"MESSAGE\":\"probes_final[interrupt=1]\"}\n")
	paths := map[string]string{"ipid.pq": source, "zmap.pq": target, "ipid.snapshot.yaml": filepath.Join(filepath.Dir(source), "ipid.snapshot.yaml"), "zmap.snapshot.yaml": filepath.Join(filepath.Dir(target), "zmap.snapshot.yaml"), "state.json": filepath.Join(ws, "state.json"), "original-scanner.journal.jsonl": filepath.Join(journalDir, "scanner.jsonl")}
	for name, data := range map[string][]byte{"ipid.snapshot.yaml": snapshot, "zmap.snapshot.yaml": []byte("original: true\n"), "state.json": state, "original-scanner.journal.jsonl": journal} {
		if err := os.WriteFile(paths[name], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := Receipt{Version: 1, Purpose: "interrupted-rt-preservation-not-measurement-completion", Campaign: Campaign, Site: "sa", ID: id, ZMap: zmap, Binding: "binding", Files: map[string]File{}}
	remote := map[string][]byte{}
	for name, path := range paths {
		e, err := upload.Evidence(path)
		if err != nil {
			t.Fatal(err)
		}
		uri := recoveryRoot + "/sa/icmp/" + id + "/sha256-" + e.SHA256 + "/" + name
		r.Files[name] = File{e, uri, path}
		data, _ := os.ReadFile(path)
		remote[uri] = data
	}
	updated := original
	updated.Rows = 2
	updated.Started = 3
	updated.SHA256 = r.Files["ipid.pq"].SHA256
	originals["sa"] = updated
	b, _ := json.Marshal(r)
	path := filepath.Join(journalDir, "backup-verified.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	remote[recoveryRoot+"/sa/icmp/"+id+"/receipts/sha256-"+hash(b)+"/backup-verified.json"] = b
	return fixture{ws, path, id, "binding", c, remote}
}

func TestOriginalCommittedZMapReferenceAdmission(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-uri", "wrong-id", "wrong-hash", "wrong-evidence", "missing-marker", "missing-reference"} {
		t.Run(kind, func(t *testing.T) {
			f := admissionFixture(t)
			raw, err := os.ReadFile(f.receipt)
			if err != nil {
				t.Fatal(err)
			}
			var r Receipt
			if err = json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			root := originalRawRoot + "/sa/zmap/" + r.ZMap
			files := map[string]upload.FileEvidence{}
			for _, name := range []string{"zmap.pq", "zmap.snapshot.yaml"} {
				entry := r.Files[name]
				entry.URI = root + "/" + name
				r.Files[name] = entry
				files[name] = entry.FileEvidence
			}
			if kind == "wrong-evidence" {
				value := files["zmap.pq"]
				value.Size++
				files["zmap.pq"] = value
			}
			marker, _ := json.Marshal(map[string]any{"version": 1, "measurement_id": r.ZMap, "files": files})
			r.ZMapReference = &ZMapReference{Version: 1, ID: r.ZMap, CompletionURI: root + "/measurement-complete.json", CompletionSHA256: hash(marker)}
			f.remote[r.ZMapReference.CompletionURI] = marker
			switch kind {
			case "wrong-uri":
				r.ZMapReference.CompletionURI = "s3://wrong/measurement-complete.json"
			case "wrong-id":
				r.ZMapReference.ID = "wrong"
			case "wrong-hash":
				r.ZMapReference.CompletionSHA256 = strings.Repeat("0", 64)
			case "missing-marker":
				delete(f.remote, r.ZMapReference.CompletionURI)
			case "missing-reference":
				r.ZMapReference = nil
			}
			raw, _ = json.Marshal(r)
			if err = os.WriteFile(f.receipt, raw, 0600); err != nil {
				t.Fatal(err)
			}
			f.remote[recoveryRoot+"/sa/icmp/"+f.id+"/receipts/sha256-"+hash(raw)+"/backup-verified.json"] = raw
			_, err = Admit(context.Background(), f.receipt, f.workspace, "sa", f.id, f.binding, f.current, f.fetch)
			if kind == "valid" && err != nil {
				t.Fatal(err)
			}
			if kind != "valid" && err == nil {
				t.Fatal("accepted invalid committed ZMap reference")
			}
		})
	}
}

func TestAdmissionCopyAndAppendPreservesOriginalSamples(t *testing.T) {
	f := admissionFixture(t)
	p, err := Admit(context.Background(), f.receipt, f.workspace, "sa", f.id, f.binding, f.current, f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	if p.Saved != 2 || p.Started != 3 || p.Total != 4 {
		t.Fatalf("bad admitted plan: %+v", p)
	}
	before, err := upload.Evidence(p.Source)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.workspace, "resumed.pq")
	file, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	w := parquet.NewGenericWriter[records.IPIDRecord](file)
	if err := Copy(p, w, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]records.IPIDRecord{completeRecord("192.0.2.4")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	file.Close()
	var actual []records.IPIDRecord
	_, err = readRows[records.IPIDRecord](context.Background(), out, func(r records.IPIDRecord) error { actual = append(actual, r); return nil })
	if err != nil || len(actual) != 3 || actual[0] != completeRecord("192.0.2.1") || actual[1] != completeRecord("192.0.2.3") || actual[2].IPAddress != "192.0.2.4" {
		t.Fatalf("merged samples: %+v, %v", actual, err)
	}
	after, _ := upload.Evidence(p.Source)
	if after != before {
		t.Fatal("original changed")
	}
}

func TestAdmissionRefusesMissingRemoteReceiptAndChangedConfigOrSource(t *testing.T) {
	for _, kind := range []string{"missing-receipt", "changed-config", "changed-source"} {
		t.Run(kind, func(t *testing.T) {
			f := admissionFixture(t)
			switch kind {
			case "missing-receipt":
				f.remote = map[string][]byte{}
			case "changed-config":
				f.current.NumberOfInflightProbes = 3000
			case "changed-source":
				os.WriteFile(filepath.Join(f.workspace, "ipid/raw", f.id, "ipid.pq"), []byte("corrupt"), 0600)
			}
			if _, err := Admit(context.Background(), f.receipt, f.workspace, "sa", f.id, f.binding, f.current, f.fetch); err == nil {
				t.Fatal("unsafe admission accepted")
			}
		})
	}
}
