package continental

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/interprotocolworkflow"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/upload"
)

type memoryStore struct {
	values map[string][]byte
	writes []string
	fail   string
	reads  []string
}

func (s *memoryStore) Read(_ context.Context, uri string) ([]byte, bool, error) {
	s.reads = append(s.reads, uri)
	if uri == s.fail {
		return nil, false, errors.New("AccessDenied")
	}
	data, ok := s.values[uri]
	return data, ok, nil
}
func (s *memoryStore) Put(_ context.Context, uri string, data []byte) error {
	if uri == s.fail {
		return errors.New("upload failed")
	}
	s.values[uri] = append([]byte(nil), data...)
	s.writes = append(s.writes, uri)
	return nil
}
func (s *memoryStore) PutFile(ctx context.Context, uri, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return s.Put(ctx, uri, data)
}
func (s *memoryStore) GetFile(_ context.Context, uri, path string) error {
	data, ok := s.values[uri]
	if !ok {
		return os.ErrNotExist
	}
	return os.WriteFile(path, data, 0600)
}
func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func argument(args []string, key string) string {
	for i, arg := range args {
		if arg == key && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
func environment(env []string, key string) string {
	for _, value := range env {
		if strings.HasPrefix(value, key+"=") {
			return strings.TrimPrefix(value, key+"=")
		}
	}
	return ""
}

func fixture(t *testing.T, noOS ...bool) (*Runner, *memoryStore, *[]string) {
	t.Helper()
	repo := t.TempDir()
	store := &memoryStore{values: map[string][]byte{}}
	for _, kind := range []string{"zmap", "ipid", "os"} {
		data := "upload:\n  enable: true\n  s3_destination: s3://bucket/raw/" + kind + "/\n  delete_local: false\nanalysis_workflow:\n  s3_prefix: s3://bucket/workflow/\n  poll_interval: 1s\n  timeout: 1m\n"
		mustWrite(t, filepath.Join(repo, "config", kind+".yaml"), []byte(data))
	}
	r := &Runner{Repo: repo, Workspace: filepath.Join(repo, "continental", "campaign", "eu"), Campaign: "campaign", Site: "eu", Store: store}
	r.SkipOS = len(noOS) > 0 && noOS[0]
	calls := []string{}
	r.Execute = func(ctx context.Context, tool string, args, env []string) (string, error) {
		kind := strings.TrimPrefix(filepath.Base(tool), "measure-")
		if kind == "sample-zmap" {
			name := "zmap-fixed-base-sample"
			if argument(args, "--reply-type") == "synack" {
				name = "zmap-connection-sample"
			}
			for _, ext := range []string{".pq", ".json"} {
				mustWrite(t, r.rawPath("zmap", argument(args, "--zmap"), name+ext), []byte("sample"))
			}
			return "", nil
		}
		stamp, err := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
		if err != nil {
			t.Fatal(err)
		}
		payload := argument(args, "--payload")
		if kind == "zmap" && payload != "icmp" {
			payload += "-" + argument(args, "--port")
		}
		if kind == "ipid" {
			payload = strings.Split(argument(args, "--zmap"), "_")[0]
		}
		storage := kind
		if kind == "interprotocol" {
			storage = "ipid"
			payload = "interprotocol-" + strings.ReplaceAll(argument(args, "--protocols"), ",", "-")
		}
		id := payload + "_" + stamp.Format("2006-01-02_15-04-05")
		if kind == "interprotocol" {
			id += "_" + argument(args, "--sample")
		}
		calls = append(calls, kind+":"+payload+":"+argument(args, "--measurement_mode")+":"+argument(args, "--requests_per_connection")+":"+argument(args, "--tcp.establish_connection"))
		files := map[string]upload.FileEvidence{}
		for _, name := range []string{kind + ".pq", kind + ".snapshot.yaml"} {
			path := r.rawPath(storage, id, name)
			mustWrite(t, path, []byte(kind+id))
			e, err := upload.Evidence(path)
			if err != nil {
				t.Fatal(err)
			}
			files[name] = e
		}
		if err = store.Put(ctx, Join(r.rawPrefix(storage), id, "measurement-complete.json"), Encode(map[string]any{"version": 1, "measurement_id": id, "files": files})); err != nil {
			return "", err
		}
		return id, nil
	}
	r.handoffOverride = func(_ context.Context, id string, mass bool) error {
		file := "zmap_unclassified.pq"
		if mass {
			file = "random-reproducibility-targets.pq"
		}
		mustWrite(t, r.rawPath("ipid", id, file), []byte("targets"))
		return nil
	}
	r.targetsOverride = func(_ context.Context, _ string, _ string, manifests map[string]string, directory string) (string, error) {
		for _, uri := range manifests {
			if _, ok := store.values[uri]; !ok {
				t.Fatal("targets before all protocol manifests")
			}
		}
		for _, group := range interprotocolworkflow.OrderedGroups {
			mustWrite(t, filepath.Join(directory, group+"-targets.pq"), []byte("targets"))
		}
		return directory, nil
	}
	r.publishOverride = func(_ context.Context, _, path string) (string, error) {
		m, err := interprotocolworkflow.Load(path)
		if err != nil {
			return "", err
		}
		if err = interprotocolworkflow.Validate(m, true); err != nil {
			return "", err
		}
		return "published", nil
	}
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r, store, &calls
}

func TestCompleteSequentialSiteAndRestart(t *testing.T) {
	r, store, calls := fixture(t)
	ctx := context.Background()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 37 {
		t.Fatalf("got %d measurement executions, want 3+26+8", len(*calls))
	}
	for i, payload := range []string{"icmp", "tcp-80", "udp-dns-53"} {
		if !strings.HasPrefix((*calls)[i], "zmap:"+payload+":") {
			t.Fatalf("discovery not first: %v", *calls)
		}
	}
	offset := 3
	for i, count := range []int{8, 10, 8} {
		payload := []string{"icmp", "tcp-80", "udp-dns-53"}[i]
		for j := 0; j < count; j++ {
			if !strings.HasPrefix((*calls)[offset+j], "ipid:"+payload+":") {
				t.Fatal("protocols not sequential")
			}
		}
		offset += count
	}
	mass := 0
	connection := 0
	for _, call := range (*calls)[3:29] {
		if strings.Contains(call, ":fixed-interval:25:") {
			mass++
		}
		if strings.HasSuffix(call, ":true") {
			connection++
		}
	}
	if mass != 18 || connection != 2 {
		t.Fatalf("changed legacy parameter sets: mass=%d connection=%d", mass, connection)
	}
	if !strings.HasSuffix(store.writes[len(store.writes)-1], "/final/request.json") {
		t.Fatal("site event must be last")
	}
	discoveries := 0
	strategyEvents := 0
	for uri := range store.values {
		if strings.HasSuffix(uri, "/discovery.json") {
			discoveries++
		}
		if strings.Contains(uri, "/strategy-jobs/") {
			strategyEvents++
		}
		if strings.Contains(uri, "/analysis-jobs/") && strings.HasSuffix(uri, "/request.json") {
			t.Fatal("site published final analysis before OS dependency")
		}
	}
	if discoveries != 1 || strategyEvents != 3 {
		t.Fatal("missing discovery/protocol events")
	}
	before := len(*calls)
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != before {
		t.Fatal("completed site remeasured on restart")
	}
}

func TestLostExitAdoptsCommittedMeasurement(t *testing.T) {
	r, _, calls := fixture(t)
	original := r.Execute
	r.Execute = func(ctx context.Context, tool string, args, env []string) (string, error) {
		out, err := original(ctx, tool, args, env)
		if err != nil {
			return out, err
		}
		return out, errors.New("lost subprocess response")
	}
	_, err := r.measure(context.Background(), "probe", "zmap", "icmp", "--payload", "icmp")
	if err == nil {
		t.Fatal("expected lost exit")
	}
	r.Execute = original
	id, err := r.measure(context.Background(), "probe", "zmap", "icmp", "--payload", "icmp")
	if err != nil || id == "" {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatal("committed source remeasured")
	}
	mustWrite(t, r.rawPath("zmap", id, "zmap.pq"), []byte("tampered"))
	if _, err = r.measure(context.Background(), "probe", "zmap", "icmp", "--payload", "icmp"); err == nil {
		t.Fatal("tampered committed source adopted")
	}
}

func TestIncompleteAttemptRequiresExplicitRetry(t *testing.T) {
	r, _, _ := fixture(t)
	original := r.Execute
	r.Execute = func(_ context.Context, _ string, _ []string, env []string) (string, error) {
		stamp, _ := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
		id := "icmp_" + stamp.Format("2006-01-02_15-04-05")
		mustWrite(t, r.rawPath("zmap", id, "zmap.pq"), []byte("partial"))
		return "", errors.New("failure")
	}
	_, _ = r.measure(context.Background(), "probe", "zmap", "icmp", "--payload", "icmp")
	old := r.state.Steps["probe"].ID
	r.Execute = original
	if _, err := r.measure(context.Background(), "probe", "zmap", "icmp", "--payload", "icmp"); err == nil {
		t.Fatal("silently overwrote incomplete measurement")
	}
	r.RetryIncomplete = true
	id, err := r.measure(context.Background(), "probe", "zmap", "icmp", "--payload", "icmp")
	if err != nil {
		t.Fatal(err)
	}
	if id == old {
		t.Fatal("retry reused uncertain raw identity")
	}
	if _, err = os.Stat(filepath.Join(r.Workspace, "attempts", "probe-"+old, "zmap.pq")); err != nil {
		t.Fatal("failed source not retained")
	}
}

func TestClosedZMapWithoutUploadCompletionRequiresExplicitRetry(t *testing.T) {
	r, store, _ := fixture(t, true)
	ctx := context.Background()
	original := r.Execute
	calls := 0
	r.Execute = func(_ context.Context, _ string, _ []string, env []string) (string, error) {
		calls++
		stamp, _ := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
		id := "icmp_" + stamp.Format("2006-01-02_15-04-05")
		// Both closed outputs exist, but sync failed before completeScoped.
		for _, name := range []string{"zmap.pq", "zmap.snapshot.yaml"} {
			mustWrite(t, r.rawPath("zmap", id, name), []byte("closed-"+name))
		}
		return "", errors.New("sync to s3: exit status 64")
	}
	if _, err := r.measure(ctx, "zmap-icmp", "zmap", "icmp", "--payload", "icmp"); err == nil {
		t.Fatal("upload failure ignored")
	}
	old := r.state.Steps["zmap-icmp"].ID
	if _, exists := store.values[Join(r.rawPrefix("zmap"), old, "measurement-complete.json")]; exists {
		t.Fatal("failed upload committed raw completion")
	}
	if err := r.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.measure(ctx, "zmap-icmp", "zmap", "icmp", "--payload", "icmp"); err == nil || !strings.Contains(err.Error(), "--retry-incomplete") {
		t.Fatalf("closed files without publication were silently adopted: %v", err)
	}
	if calls != 1 {
		t.Fatal("restart silently rescanned")
	}
	r.Execute = original
	r.RetryIncomplete = true
	id, err := r.measure(ctx, "zmap-icmp", "zmap", "icmp", "--payload", "icmp")
	if err != nil || id == old {
		t.Fatalf("explicit retry did not use a new identity: %s: %v", id, err)
	}
	for _, name := range []string{"zmap.pq", "zmap.snapshot.yaml"} {
		path := filepath.Join(r.Workspace, "attempts", "zmap-icmp-"+old, name)
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "closed-"+name {
			t.Fatalf("original closed output was not retained: %s: %v", path, err)
		}
	}
}

func TestImmutableAndConfigurationBinding(t *testing.T) {
	r, store, _ := fixture(t)
	ctx := context.Background()
	uri := Join(r.Prefix, "continental", r.Campaign, "campaign.json")
	if err := Immutable(ctx, store, uri, map[string]int{"wrong": 1}); err == nil {
		t.Fatal("descriptor overwritten")
	}
	store.fail = uri
	if err := r.Prepare(ctx); err == nil {
		t.Fatal("AccessDenied treated as cache miss")
	}
	store.fail = ""
	path := filepath.Join(r.Repo, "config", "ipid.yaml")
	data, _ := os.ReadFile(path)
	mustWrite(t, path, append(data, []byte("changed: true\n")...))
	if err := r.Prepare(ctx); err == nil {
		t.Fatal("configuration changed while resuming")
	}
	for _, id := range []string{"", "..", "../round", "round/2", "round space"} {
		if Validate(id, "eu") == nil {
			t.Fatal("unsafe campaign accepted")
		}
	}
	if Validate("round", "EU") == nil {
		t.Fatal("unknown site accepted")
	}
}

func TestKernelLeaseReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	release, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Lock(path); err == nil {
		other()
		t.Fatal("concurrent site runner acquired lease")
	}
	release()
	again, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	again()
}

func TestNoOSCampaignKeepsEveryMeasurementAndPinsPolicy(t *testing.T) {
	r, store, calls := fixture(t, true)
	ctx := context.Background()
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 37 {
		t.Fatalf("no-OS changed measurement workflow: %d", len(*calls))
	}
	marker := Join(r.Prefix, "continental", r.Campaign, "os", "not-requested.json")
	if _, exists := store.values[marker]; !exists {
		t.Fatal("no persistent no-OS status")
	}
	for uri, data := range store.values {
		if strings.HasSuffix(uri, "/os/request.json") || strings.HasSuffix(uri, "/os/done.json") {
			t.Fatal("fabricated OS job")
		}
		if strings.Contains(uri, "/analysis-jobs/") && strings.HasSuffix(uri, "/manifest.json") {
			var m map[string]map[string]any
			_ = json.Unmarshal(data, &m)
			for _, section := range m {
				if section["os_status"] != "not_requested" {
					t.Fatal("manifest lost policy")
				}
				if _, exists := section["os"]; exists {
					t.Fatal("fake OS ID")
				}
			}
		}
		if strings.Contains(uri, "/strategy-jobs/") && strings.HasSuffix(uri, "/request.json") {
			var req map[string]any
			_ = json.Unmarshal(data, &req)
			if req["os_status"] != "not_requested" || req["os_prefix"] != "" {
				t.Fatal("request lost no-OS intent")
			}
		}
	}
	before := len(*calls)
	if err := r.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != before {
		t.Fatal("completed no-OS campaign remeasured")
	}
	r.SkipOS = false
	if err := r.Prepare(ctx); err == nil {
		t.Fatal("same site changed persisted mode")
	}
	r.Workspace = filepath.Join(r.Repo, "different-site")
	r.Site = "as"
	if err := r.Prepare(ctx); err == nil {
		t.Fatal("sites disagreed on campaign OS policy")
	}
}

func TestOSWorkerDoesNotReadOSRequestOrDoneWhenDisabled(t *testing.T) {
	r, store, _ := fixture(t, true)
	store.reads = nil
	store.fail = Join(r.Prefix, "continental", r.Campaign, "os", "request.json")
	execute := func(context.Context, string, []string, []string) (string, error) {
		t.Fatal("disabled OS scan executed")
		return "", nil
	}
	done, err := RunOS(context.Background(), store, execute, r.Repo, filepath.Join(r.Repo, "os-worker"), r.Prefix, r.Campaign)
	if err != nil || !done {
		t.Fatal(err)
	}
	if err = PublishOSFailure(context.Background(), store, r.Prefix, r.Campaign, errors.New("metadata outage")); err != nil {
		t.Fatal(err)
	}
	if _, exists := store.values[Join(r.Prefix, "continental", r.Campaign, "os", "failed.json")]; exists {
		t.Fatal("disabled OS became a failed scan")
	}
	for _, uri := range store.reads {
		if strings.HasSuffix(uri, "/os/request.json") || strings.HasSuffix(uri, "/os/done.json") {
			t.Fatalf("disabled worker waited on %s", uri)
		}
	}
}

func TestSharedOSCommitAndIntegrity(t *testing.T) {
	r, store, _ := fixture(t)
	ctx := context.Background()
	job := Join(r.Prefix, "continental", r.Campaign, "os")
	target := []byte("union")
	temp := filepath.Join(t.TempDir(), "targets.pq")
	mustWrite(t, temp, target)
	e, _ := upload.Evidence(temp)
	request := OSRequest{Version: 1, Campaign: r.Campaign, RawRoot: r.RawRoot, Target: Target{Join(job, "targets.pq"), e.Size, e.SHA256, 3}, ZMap: "tcp-80_2026-10-25_01-00-00"}
	for _, site := range Sites {
		for _, p := range Protocols {
			request.Members = append(request.Members, map[string]string{"site": site, "protocol": p, "measurement_id": map[string]string{"icmp": "icmp", "tcp": "tcp-80", "udp-dns": "udp-dns-53"}[p] + "_2026-10-25_01-00-00", "uri": Join(r.RawRoot, "continental", r.Campaign, site, "zmap", map[string]string{"icmp": "icmp", "tcp": "tcp-80", "udp-dns": "udp-dns-53"}[p]+"_2026-10-25_01-00-00", "zmap.pq"), "sha256": strings.Repeat("a", 64)})
		}
	}
	store.values[Join(job, "request.json")] = Encode(request)
	store.values[Join(job, "targets.pq")] = target
	workspace := filepath.Join(r.Repo, "os-worker")
	mustWrite(t, filepath.Join(workspace, "targets.pq"), []byte("truncated cache from an earlier transfer"))
	executed := 0
	execute := func(_ context.Context, _ string, args, env []string) (string, error) {
		executed++
		if argument(args, "--target-file") == "" {
			t.Fatal("OS union not selected")
		}
		stamp, _ := time.Parse(time.RFC3339, environment(env, "IPID_MEASUREMENT_TIME"))
		id := "tcp-80_" + stamp.Format("2006-01-02_15-04-05")
		for _, name := range []string{"os.pq", "os-observations.pq", "os-coverage.json", "os.snapshot.yaml"} {
			mustWrite(t, filepath.Join(workspace, "os", "raw", id, name), []byte(name))
		}
		_, err := upload.WriteCompletion(paths.Measurement{ID: id, Path: filepath.Join(workspace, "os", "raw", id)})
		return id, err
	}
	store.fail = Join(r.RawRoot, "continental", r.Campaign, "os", "shared-os", "os-coverage.json")
	if done, err := RunOS(ctx, store, execute, r.Repo, workspace, r.Prefix, r.Campaign); err == nil || done {
		t.Fatal("partial OS upload published completion")
	}
	if _, exists := store.values[Join(job, "done.json")]; exists {
		t.Fatal("OS Done before all uploads")
	}
	store.fail = ""
	if done, err := RunOS(ctx, store, execute, r.Repo, workspace, r.Prefix, r.Campaign); err != nil || !done {
		t.Fatal(err)
	}
	if executed != 1 || store.writes[len(store.writes)-1] != Join(job, "done.json") {
		t.Fatal("OS marker order")
	}
	if done, err := RunOS(ctx, store, execute, r.Repo, workspace, r.Prefix, r.Campaign); err != nil || !done || executed != 1 {
		t.Fatal("completed OS repeated")
	}
	delete(store.values, Join(job, "done.json"))
	request.Target.SHA256 = strings.Repeat("0", 64)
	store.values[Join(job, "request.json")] = Encode(request)
	if _, err := RunOS(ctx, store, execute, r.Repo, filepath.Join(r.Repo, "other-os"), r.Prefix, r.Campaign); err == nil {
		t.Fatal("corrupt union accepted")
	}
	var marker map[string]any
	_ = json.Unmarshal(store.values[Join(job, "request.json")], &marker)
}
