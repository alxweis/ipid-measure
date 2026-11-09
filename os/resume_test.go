package os

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/parquet-go/parquet-go"
	"gopkg.in/yaml.v3"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/records"
)

func resumeFixture(t testing.TB) (*config.OSConfig, string, []observation, []records.OSRecord) {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "targets.pq")
	if err := parquet.WriteFile(target, []records.ZMap{{IPAddress: "127.0.0.1"}, {IPAddress: "127.0.0.2"}, {IPAddress: "127.0.0.3"}}); err != nil {
		t.Fatal(err)
	}
	n := config.ScaledNumber(1)
	c := &config.OSConfig{ZMapReference: config.ZMapReference{ZMapID: "tcp-80_2026-11-07_03-30-08", TargetFile: target, ZMapFilePath: target},
		SchemaVersion: SchemaVersion, ClassifierVersion: ClassifierVersion, RecordTargetStatus: true,
		ZGrab2Senders: &n, DNSChaosWorkers: &n, SNMPWorkers: &n, ConnectTimeout: time.Second, ReadTimeout: time.Second,
		DNSChaosTimeout: time.Millisecond, SNMPTimeout: time.Millisecond, SNMPCommunity: "public"}
	old := filepath.Join(root, "old")
	if err := os.Mkdir(old, 0755); err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(old, "os.snapshot.yaml"), data, 0644); err != nil {
		t.Fatal(err)
	}
	observations := []observation{
		{IP: "127.0.0.1", Status: "no-evidence"},
		{IP: "127.0.0.2", Response: 5, Evidence: 5, Tagged: 5, Status: statusAmbiguous, Conflict: "linux|windows"},
	}
	linux, windows, ssh, http := "linux", "windows", "Ubuntu", "Microsoft-IIS"
	evidence := []records.OSRecord{{IPAddress: "127.0.0.2", OSStatus: statusAmbiguous, SSHOS: &linux, HTTPOS: &windows, SSHServerID: &ssh, HTTPServer: &http}}
	if err = parquet.WriteFile(filepath.Join(old, "os-observations.pq"), observations); err != nil {
		t.Fatal(err)
	}
	if err = parquet.WriteFile(filepath.Join(old, "os.pq"), evidence); err != nil {
		t.Fatal(err)
	}
	c.ResumeFrom = old
	return c, old, observations, evidence
}

func restoreFixture(t testing.TB, c *config.OSConfig) (*resumeState, *coverageStats, string, error) {
	t.Helper()
	dir := t.TempDir()
	w, err := NewWriter(filepath.Join(dir, "os.pq"))
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	o, err := newObservationWriter(filepath.Join(dir, "os-observations.pq"), cancel)
	if err != nil {
		t.Fatal(err)
	}
	coverage := newCoverageStats(3)
	s, restoreErr := restoreOS(context.Background(), c, filepath.Join(dir, "os.pq"), w, o, coverage, 3)
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = o.close(o.count); err != nil {
		t.Fatal(err)
	}
	return s, coverage, dir, restoreErr
}

func TestOSResumePreservesEvidenceNoEvidenceAndCoverage(t *testing.T) {
	c, old, expectedObs, expectedRows := resumeFixture(t)
	before, _ := os.ReadFile(filepath.Join(old, "os.pq"))
	s, coverage, dir, err := restoreFixture(t, c)
	if err != nil {
		t.Fatal(err)
	}
	if s.completed.count != 2 || s.evidence != 1 {
		t.Fatalf("restored %+v", s)
	}
	rows, err := parquet.ReadFile[records.OSRecord](filepath.Join(dir, "os.pq"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := parquet.ReadFile[observation](filepath.Join(dir, "os-observations.pq"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rows, expectedRows) || !reflect.DeepEqual(obs, expectedObs) {
		t.Fatal("restored data changed")
	}
	d := coverage.document.Detail
	if d.Targets.WithoutEvidence != 1 || d.Targets.WithEvidence != 1 || d.Classification.Ambiguous != 1 || d.Services["http"].Evidence != 1 || d.Services["dns"].Attempted != 3 {
		t.Fatalf("coverage changed %+v", d)
	}
	after, _ := os.ReadFile(filepath.Join(old, "os.pq"))
	if string(before) != string(after) {
		t.Fatal("source was overwritten")
	}
	var proof ResumeEvidence
	data, _ := os.ReadFile(filepath.Join(dir, "os-resume.json"))
	if json.Unmarshal(data, &proof) != nil || proof.Completed != 2 || proof.Status != "imported" || len(proof.Files) != 3 {
		t.Fatal("resume provenance missing")
	}
}

func TestOSResumeRejectsMalformedOrIncompletePartialFiles(t *testing.T) {
	for _, mode := range []string{"duplicate-observation", "missing-evidence", "duplicate-evidence", "unclosed", "outside-input", "unknown-status", "changed-record-status", "changed-record-mask"} {
		t.Run(mode, func(t *testing.T) {
			c, old, obs, rows := resumeFixture(t)
			switch mode {
			case "duplicate-observation":
				obs = append(obs, obs[0])
			case "missing-evidence":
				rows = nil
			case "duplicate-evidence":
				rows = append(rows, rows[0])
			case "outside-input":
				obs[0].IP = "192.0.2.1"
			case "unknown-status":
				obs[0].Status = "unfinished"
			case "changed-record-status":
				rows[0].OSStatus = statusResolved
			case "changed-record-mask":
				rows[0].HTTPServer = nil
			}
			if err := parquet.WriteFile(filepath.Join(old, "os-observations.pq"), obs); err != nil {
				t.Fatal(err)
			}
			if err := parquet.WriteFile(filepath.Join(old, "os.pq"), rows); err != nil {
				t.Fatal(err)
			}
			if mode == "unclosed" {
				data, _ := os.ReadFile(filepath.Join(old, "os.pq"))
				os.WriteFile(filepath.Join(old, "os.pq"), data[:len(data)-8], 0644)
			}
			_, _, dir, err := restoreFixture(t, c)
			if err == nil {
				t.Fatal("unsafe partial source accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "os-resume.json")); !os.IsNotExist(err) {
				t.Fatal("failed import committed")
			}
		})
	}
}

func TestOSResumeAllowsResourceChangesButRejectsScientificChanges(t *testing.T) {
	c, old, _, _ := resumeFixture(t)
	n := config.ScaledNumber(10000)
	c.DNSChaosWorkers = &n
	c.SNMPWorkers = &n
	c.ZGrab2Senders = &n
	if err := ValidateResumeSource(c, old); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config.OSConfig){
		func(c *config.OSConfig) { c.DNSChaosTimeout += time.Second },
		func(c *config.OSConfig) { c.Modules.HTTP = !c.Modules.HTTP },
		func(c *config.OSConfig) { c.RecordTargetStatus = false },
		func(c *config.OSConfig) { c.TargetFile += "different" },
	} {
		changed := *c
		mutate(&changed)
		if err := ValidateResumeSource(&changed, old); err == nil {
			t.Fatal("scientific setting changed")
		}
	}
}

func TestOSResumeRefusesUncommittedEarlierImport(t *testing.T) {
	c, old, _, _ := resumeFixture(t)
	data, _ := os.ReadFile(filepath.Join(old, "os.snapshot.yaml"))
	var previous config.OSConfig
	yaml.Unmarshal(data, &previous)
	previous.ResumeFrom = "earlier"
	data, _ = yaml.Marshal(previous)
	os.WriteFile(filepath.Join(old, "os.snapshot.yaml"), data, 0644)
	if err := ValidateResumeSource(c, old); err == nil {
		t.Fatal("unfinished predecessor accepted")
	}
}

func TestIPv4ResumeSetBoundaries(t *testing.T) {
	var set ipv4Set
	for _, n := range []uint32{0, 1, 63, 64, 65535, 65536, 1 << 31, 1<<32 - 1} {
		if !set.add(n) || set.add(n) || !set.has(n) {
			t.Fatalf("membership %d", n)
		}
		if !set.remove(n) || set.remove(n) || set.has(n) {
			t.Fatalf("removal %d", n)
		}
	}
	if set.count != 0 {
		t.Fatal(set.count)
	}
}

func TestResumedPipelineProbesOnlyRemainingTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake zgrab executable")
	}
	c, _, expectedObs, expectedRows := resumeFixture(t)
	root := t.TempDir()
	inputLog := filepath.Join(root, "probed.txt")
	fake := filepath.Join(root, "zgrab2")
	script := "#!/bin/sh\nwhile IFS= read -r ip; do\n printf '%s\\n' \"$ip\" >> '" + inputLog + "'\n printf '{\"ip\":\"%s\",\"data\":{}}\\n' \"$ip\"\ndone\n"
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := filepath.Join(root, "os.pq")
	// The fake local scanners test resume dispatch independently of the host's
	// /proc resource interface (not implemented by WSL1). Admission is tested
	// separately; the production entry always uses validateProbeResources.
	written, err := runPipelineWithResources(context.Background(), c, c.TargetFile, out, filepath.Join(root, "coverage.json"), func(*config.OSConfig) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	probed, _ := os.ReadFile(inputLog)
	if strings.TrimSpace(string(probed)) != "127.0.0.3" {
		t.Fatalf("reprobed completed IPs: %s", probed)
	}
	rows, err := parquet.ReadFile[records.OSRecord](out)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := parquet.ReadFile[observation](filepath.Join(root, "os-observations.pq"))
	if err != nil {
		t.Fatal(err)
	}
	if written != 1 || !reflect.DeepEqual(rows, expectedRows) || len(obs) != 3 || !reflect.DeepEqual(obs[:2], expectedObs) {
		t.Fatalf("bad resumed output rows=%v observations=%v", rows, obs)
	}
}

func TestGracefulPartialScanCanResumeWithMoreWorkers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX fake zgrab executable")
	}
	c, old, _, _ := resumeFixture(t)
	c.ResumeFrom = ""
	const targets = 1000
	rows := make([]records.ZMap, targets)
	for i := range rows {
		rows[i].IPAddress = fmt.Sprintf("127.1.%d.%d", i>>8, i&255)
	}
	if err := parquet.WriteFile(c.TargetFile, rows); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := yaml.Marshal(c)
	if err := os.WriteFile(filepath.Join(old, "os.snapshot.yaml"), snapshot, 0644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	inputLog := filepath.Join(root, "probed.txt")
	script := "#!/bin/sh\nwhile IFS= read -r ip; do\n printf '%s\\n' \"$ip\" >> '" + inputLog + "'\n printf '{\"ip\":\"%s\",\"data\":{}}\\n' \"$ip\"\ndone\n"
	if err := os.WriteFile(filepath.Join(root, "zgrab2"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	firstQuery := dnsQueryIDCounter.Load()
	go func() {
		_, err := runPipelineWithResources(ctx, c, c.TargetFile, filepath.Join(old, "os.pq"), filepath.Join(old, "coverage.json"), func(*config.OSConfig) error { return nil })
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(inputLog)
		if dnsQueryIDCounter.Load() >= firstQuery+8 && strings.Count(string(data), "\n") >= 8 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("interrupted attempt became complete")
	}
	completed, err := parquet.ReadFile[observation](filepath.Join(old, "os-observations.pq"))
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) == 0 || len(completed) >= targets {
		t.Fatalf("expected closed partial population, got %d", len(completed))
	}
	if err := os.WriteFile(inputLog, nil, 0644); err != nil {
		t.Fatal(err)
	}
	c.ResumeFrom = old
	n := config.ScaledNumber(100)
	c.DNSChaosWorkers = &n
	c.SNMPWorkers = &n
	out := filepath.Join(root, "os.pq")
	if _, err := runPipelineWithResources(context.Background(), c, c.TargetFile, out, filepath.Join(root, "coverage.json"), func(*config.OSConfig) error { return nil }); err != nil {
		t.Fatal(err)
	}
	probed, _ := os.ReadFile(inputLog)
	seen := map[string]bool{}
	for _, ip := range strings.Fields(string(probed)) {
		if seen[ip] {
			t.Fatal("duplicate new probe", ip)
		}
		seen[ip] = true
	}
	for _, row := range completed {
		if seen[row.IP] {
			t.Fatal("completed target probed again", row.IP)
		}
	}
	if len(seen)+len(completed) != targets {
		t.Fatalf("population changed: restored=%d new=%d", len(completed), len(seen))
	}
	all, err := parquet.ReadFile[observation](filepath.Join(root, "os-observations.pq"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != targets {
		t.Fatal("missing final observations", len(all))
	}
}

func TestAllResumedTargetsNeedNoScannerProcess(t *testing.T) {
	c, _, _, _ := resumeFixture(t)
	if err := parquet.WriteFile(c.TargetFile, []records.ZMap{{IPAddress: "127.0.0.1"}, {IPAddress: "127.0.0.2"}}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("PATH", root)
	written, err := runPipelineWithResources(context.Background(), c, c.TargetFile, filepath.Join(root, "os.pq"), filepath.Join(root, "coverage.json"), func(*config.OSConfig) error { return nil })
	if err != nil || written != 1 {
		t.Fatalf("completed population rescanned: %d %v", written, err)
	}
}
