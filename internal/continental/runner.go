package continental

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/analysisworkflow"
	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/postprocessworkflow"
	"github.com/alxweis/ipid-measure/internal/upload"
	"gopkg.in/yaml.v3"
)

type Step struct {
	ID        string `json:"id"`
	Stamp     string `json:"stamp"`
	Signature string `json:"signature"`
}
type State struct {
	Version int             `json:"version"`
	Binding string          `json:"binding"`
	Steps   map[string]Step `json:"steps"`
}
type Execute func(context.Context, string, []string, []string) (string, error)

func Command(ctx context.Context, tool string, args, env []string) (string, error) {
	command := exec.CommandContext(ctx, tool, args...)
	command.Env = env
	command.Stderr = os.Stderr
	var out strings.Builder
	command.Stdout = io.MultiWriter(os.Stdout, &out)
	err := command.Run()
	return out.String(), err
}

type Runner struct {
	Repo, Workspace, Campaign, Site, Prefix, RawRoot string
	Store                                            Store
	Execute                                          Execute
	RetryIncomplete                                  bool
	state                                            State
	configs                                          map[string]string
	workflow                                         config.AnalysisWorkflowConfig
	handoffOverride                                  func(context.Context, string, bool) error
	targetsOverride                                  func(context.Context, string, string, map[string]string, string) (string, error)
	publishOverride                                  func(context.Context, string, string) (string, error)
	uploads                                          map[string]config.UploadConfig
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func (r *Runner) sitePrefix() string {
	return Join(r.Prefix, "continental", r.Campaign, "sites", r.Site)
}
func (r *Runner) rawPrefix(kind string) string {
	return Join(r.RawRoot, "continental", r.Campaign, r.Site, kind)
}
func (r *Runner) rawPath(kind, id, name string) string {
	return filepath.Join(r.Workspace, kind, "raw", id, name)
}
func (r *Runner) statePath() string { return filepath.Join(r.Workspace, "state.json") }

// Prepare pins the configuration and namespace before any packets are sent.
func (r *Runner) Prepare(ctx context.Context) error {
	if err := Validate(r.Campaign, r.Site); err != nil {
		return err
	}
	if r.Execute == nil {
		r.Execute = Command
	}
	r.configs = map[string]string{}
	r.uploads = map[string]config.UploadConfig{}
	source := map[string]map[string]any{}
	binding := map[string]any{"campaign": r.Campaign, "site": r.Site, "version": 1}
	for _, kind := range []string{"zmap", "ipid"} {
		data, err := os.ReadFile(filepath.Join(r.Repo, "config", kind+".yaml"))
		if err != nil {
			return err
		}
		var value map[string]any
		if err = yaml.Unmarshal(data, &value); err != nil {
			return err
		}
		source[kind] = value
		binding[kind] = value
	}
	get := func(kind, key, field string) (string, error) {
		section, ok := source[kind][key].(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s.%s is required", kind, key)
		}
		value, ok := section[field].(string)
		if !ok || !strings.HasPrefix(value, "s3://") {
			return "", fmt.Errorf("%s.%s.%s needs an S3 URI", kind, key, field)
		}
		return strings.TrimRight(value, "/"), nil
	}
	zmap, err := get("zmap", "upload", "s3_destination")
	if err != nil {
		return err
	}
	ipid, err := get("ipid", "upload", "s3_destination")
	if err != nil {
		return err
	}
	prefix, err := get("ipid", "analysis_workflow", "s3_prefix")
	if err != nil {
		return err
	}
	if !strings.HasSuffix(zmap, "/zmap") || !strings.HasSuffix(ipid, "/ipid") || strings.TrimSuffix(zmap, "/zmap") != strings.TrimSuffix(ipid, "/ipid") {
		return fmt.Errorf("ZMap and IPID destinations must share one raw root")
	}
	r.RawRoot = strings.TrimSuffix(zmap, "/zmap")
	r.Prefix = prefix
	bindingHash := digest(Encode(binding))
	r.state = State{Version: 1, Binding: bindingHash, Steps: map[string]Step{}}
	data, err := os.ReadFile(r.statePath())
	if err == nil {
		if err = json.Unmarshal(data, &r.state); err != nil {
			return err
		}
		if r.state.Version != 1 || r.state.Binding != bindingHash || r.state.Steps == nil {
			return fmt.Errorf("existing workspace has different campaign/site/configuration")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = AtomicJSON(r.statePath(), r.state); err != nil {
		return err
	}
	descriptor := Descriptor{1, r.Campaign, Sites, Protocols, r.RawRoot}
	if err = Immutable(ctx, r.Store, Join(prefix, "continental", r.Campaign, "campaign.json"), descriptor); err != nil {
		return err
	}
	for _, kind := range []string{"zmap", "ipid"} {
		value := source[kind]
		destination := r.rawPrefix(kind)
		value["upload"] = map[string]any{"enable": true, "delete_local": false, "s3_destination": destination}
		if kind == "ipid" {
			workflow := value["analysis_workflow"].(map[string]any)
			workflow["s3_prefix"] = r.sitePrefix()
			workflow["enable"] = false
		}
		encoded, err := yaml.Marshal(value)
		if err != nil {
			return err
		}
		path := filepath.Join(r.Workspace, "config", kind+".yaml")
		if err = os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		if err = os.WriteFile(path, encoded, 0600); err != nil {
			return err
		}
		r.configs[kind] = path
		r.uploads[kind] = config.UploadConfig{Enable: true, S3Destination: destination}
		if kind == "ipid" {
			var parsed struct {
				Workflow config.AnalysisWorkflowConfig `yaml:"analysis_workflow"`
			}
			if err = yaml.Unmarshal(encoded, &parsed); err != nil {
				return err
			}
			r.workflow = parsed.Workflow
			r.workflow.Enable = true
			if r.workflow.PollInterval < time.Second || r.workflow.Timeout < r.workflow.PollInterval {
				return fmt.Errorf("invalid workflow poll interval/timeout")
			}
		}
	}
	return nil
}

func (r *Runner) env(stamp string) []string {
	env := []string{}
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "IPID_MEASURE_WORKSPACE=") && !strings.HasPrefix(value, "IPID_MEASUREMENT_TIME=") {
			env = append(env, value)
		}
	}
	return append(env, "IPID_MEASURE_WORKSPACE="+r.Workspace, "IPID_MEASUREMENT_TIME="+stamp)
}

func (r *Runner) committed(ctx context.Context, kind string, step Step) (bool, error) {
	data, exists, err := r.Store.Read(ctx, Join(r.rawPrefix(kind), step.ID, "measurement-complete.json"))
	if err != nil || !exists {
		return false, err
	}
	var marker struct {
		Version int                            `json:"version"`
		ID      string                         `json:"measurement_id"`
		Files   map[string]upload.FileEvidence `json:"files"`
	}
	if err = json.Unmarshal(data, &marker); err != nil {
		return false, err
	}
	if marker.Version != 1 || marker.ID != step.ID || len(marker.Files) < 2 {
		return false, fmt.Errorf("invalid measurement completion marker")
	}
	expectedKind := kind
	if strings.HasPrefix(step.ID, "interprotocol-") {
		expectedKind = "interprotocol"
	}
	for _, required := range []string{expectedKind + ".pq", expectedKind + ".snapshot.yaml"} {
		if _, ok := marker.Files[required]; !ok {
			return false, fmt.Errorf("measurement completion omits %s", required)
		}
	}
	for name, expected := range marker.Files {
		if filepath.Base(name) != name {
			return false, fmt.Errorf("unsafe completion file")
		}
		actual, err := upload.Evidence(r.rawPath(kind, step.ID, name))
		if err != nil {
			return false, err
		}
		if actual != expected {
			return false, fmt.Errorf("local source differs from committed measurement %s/%s", step.ID, name)
		}
	}
	return true, nil
}

func (r *Runner) measure(ctx context.Context, name, kind, payload string, args ...string) (string, error) {
	tool := kind
	if kind == "interprotocol" {
		kind = "ipid"
	}
	signature := digest(Encode(append([]string{tool}, args...)))
	step, exists := r.state.Steps[name]
	if exists && step.Signature != signature {
		return "", fmt.Errorf("step parameters changed: %s", name)
	}
	if exists {
		complete, err := r.committed(ctx, kind, step)
		if err != nil {
			return "", err
		}
		if complete {
			return step.ID, nil
		}
		directory := filepath.Dir(r.rawPath(kind, step.ID, "unused"))
		if _, err = os.Stat(directory); err == nil {
			if !r.RetryIncomplete {
				return "", fmt.Errorf("uncommitted %s: inspect retained data, then use --retry-incomplete to start a new attempt", name)
			}
			archive := filepath.Join(r.Workspace, "attempts", name+"-"+step.ID)
			if err = os.MkdirAll(filepath.Dir(archive), 0755); err != nil {
				return "", err
			}
			if err = os.Rename(directory, archive); err != nil {
				return "", err
			}
			exists = false
		} else if !os.IsNotExist(err) {
			return "", err
		} else {
			exists = false
		}
	}
	if !exists {
		stamp := time.Now().UTC().Truncate(time.Second)
		for _, prior := range r.state.Steps {
			t, err := time.Parse(time.RFC3339, prior.Stamp)
			if err != nil {
				return "", err
			}
			if !stamp.After(t) {
				stamp = t.Add(time.Second)
			}
		}
		id := payload + "_" + stamp.Format("2006-01-02_15-04-05")
		if tool == "interprotocol" {
			for i, arg := range args {
				if arg == "--sample" && i+1 < len(args) {
					id += "_" + args[i+1]
				}
			}
		}
		step = Step{id, stamp.Format(time.RFC3339), signature}
		r.state.Steps[name] = step
		if err := AtomicJSON(r.statePath(), r.state); err != nil {
			return "", err
		}
	}
	commandArgs := append([]string{"--config", r.configs[kind]}, args...)
	commandArgs = append(commandArgs, "--print-id")
	if _, err := r.Execute(ctx, filepath.Join(r.Repo, "bin", "measure-"+tool), commandArgs, r.env(step.Stamp)); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	complete, err := r.committed(ctx, kind, step)
	if err != nil {
		return "", err
	}
	if !complete {
		return "", fmt.Errorf("%s exited without durable raw completion", name)
	}
	return step.ID, nil
}

func (r *Runner) handoff(ctx context.Context, id string, mass bool) error {
	if r.handoffOverride != nil {
		return r.handoffOverride(ctx, id, mass)
	}
	measurement := paths.Measurement{ID: id, Path: filepath.Dir(r.rawPath("ipid", id, "ipid.pq"))}
	var err error
	if mass {
		_, err = analysisworkflow.RequestRandomReproducibilityAndWait(ctx, r.workflow, r.uploads["ipid"], measurement, 10000, 42)
	} else {
		_, err = analysisworkflow.RequestAndWait(ctx, r.workflow, r.uploads["ipid"], measurement)
	}
	return err
}

func (r *Runner) sample(ctx context.Context, zmap string, connection bool) (string, error) {
	args := []string{"--zmap", zmap, "--percent", "10", "--minimum", "1000000"}
	name := "zmap-fixed-base-sample.pq"
	if connection {
		args = append(args, "--reply-type", "synack")
		name = "zmap-connection-sample.pq"
	}
	if _, err := r.Execute(ctx, filepath.Join(r.Repo, "bin", "sample-zmap"), args, r.env("")); err != nil {
		return "", err
	}
	path := r.rawPath("zmap", zmap, name)
	// Sampling happens after the ZMap commit; publish both immutable auxiliaries.
	for _, local := range []string{path, strings.TrimSuffix(path, ".pq") + ".json"} {
		if err := r.Store.PutFile(ctx, Join(r.rawPrefix("zmap"), zmap, filepath.Base(local)), local); err != nil {
			return "", err
		}
	}
	return path, nil
}

func (r *Runner) ipid(ctx context.Context, name, payload, zmap, target string, mass, connection bool) (string, error) {
	mode, requests, rate := "fixed-interval", "4", "1.0"
	if strings.HasSuffix(name, "rt") {
		mode = "rt-based"
	}
	if mass {
		requests = "25"
		rate = "0.8"
	}
	args := []string{"--zmap", zmap, "--connection_count", "4", "--requests_per_connection", requests, "--measurement_mode", mode, "--tcp.establish_connection", fmt.Sprint(connection), "--analysis_workflow.enable", "false"}
	if mode == "fixed-interval" {
		args = append(args, "--fixed_interval.request_interval", "20ms", "--fixed_interval.minimum_reply_rate", rate)
	}
	if target != "" {
		args = append(args, "--target-file", target)
	}
	return r.measure(ctx, name, "ipid", payload, args...)
}

func (r *Runner) Run(ctx context.Context) error {
	if _, exists, err := r.Store.Read(ctx, Join(r.sitePrefix(), "final", "request.json")); err != nil {
		return err
	} else if exists {
		return nil
	}
	discovery := map[string]string{}
	for i, protocol := range Protocols {
		payload := []string{"icmp", "tcp-80", "udp-dns-53"}[i]
		args := []string{"--payload", protocol}
		if i > 0 {
			args = append(args, "--port", []string{"", "80", "53"}[i])
		}
		if i == 2 {
			args = append(args, "--probe-args", "A,www.example.com")
		}
		id, err := r.measure(ctx, "zmap-"+protocol, "zmap", payload, args...)
		if err != nil {
			return err
		}
		discovery[protocol] = id
	}
	if err := Immutable(ctx, r.Store, Join(r.sitePrefix(), "discovery.json"), map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "zmap": discovery, "raw_prefix": r.rawPrefix("zmap")}); err != nil {
		return err
	}
	manifests := map[string]string{}
	for i, protocol := range Protocols {
		payload := []string{"icmp", "tcp-80", "udp-dns-53"}[i]
		zmap := discovery[protocol]
		rt, err := r.ipid(ctx, protocol+"-rt", payload, zmap, "", false, false)
		if err != nil {
			return err
		}
		if err = r.handoff(ctx, rt, false); err != nil {
			return err
		}
		mass, err := r.ipid(ctx, protocol+"-mass", payload, zmap, r.rawPath("ipid", rt, "zmap_unclassified.pq"), true, false)
		if err != nil {
			return err
		}
		if err = r.handoff(ctx, mass, true); err != nil {
			return err
		}
		repeats := []string{}
		for repeat := 1; repeat <= 5; repeat++ {
			id, err := r.ipid(ctx, fmt.Sprintf("%s-repeat-%d", protocol, repeat), payload, zmap, r.rawPath("ipid", mass, "random-reproducibility-targets.pq"), true, false)
			if err != nil {
				return err
			}
			repeats = append(repeats, id)
		}
		target, err := r.sample(ctx, zmap, false)
		if err != nil {
			return err
		}
		base, err := r.ipid(ctx, protocol+"-base", payload, zmap, target, false, false)
		if err != nil {
			return err
		}
		measurements := postprocessworkflow.Measurements{ZMap: zmap, OS: "shared-os", RTBase: rt, FixedMass: mass, FixedBase: base, FixedBaseTarget: target, RandomReproducibilityRepeats: repeats, RandomReproducibilityMaximumTargets: 10000, RandomReproducibilitySelectionSeed: 42}
		if protocol == "tcp" {
			measurements.ConnectionTarget, err = r.sample(ctx, zmap, true)
			if err != nil {
				return err
			}
			measurements.ConnectionRTBase, err = r.ipid(ctx, "tcp-connection-rt", payload, zmap, measurements.ConnectionTarget, false, true)
			if err != nil {
				return err
			}
			measurements.ConnectionFIBase, err = r.ipid(ctx, "tcp-connection-fi", payload, zmap, measurements.ConnectionTarget, false, true)
			if err != nil {
				return err
			}
		}
		job := Join(r.sitePrefix(), "analysis-jobs", zmap)
		manifestURI := Join(job, "manifest.json")
		manifest := postprocessworkflow.BuildManifest(protocol, measurements)
		if err = Immutable(ctx, r.Store, manifestURI, manifest); err != nil {
			return err
		}
		created, _ := time.Parse(time.RFC3339, r.state.Steps["zmap-"+protocol].Stamp)
		request := postprocessworkflow.Request{CreatedAt: created, Version: 1, JobID: zmap, Protocol: protocol, ManifestURI: manifestURI, ZMapPrefix: r.rawPrefix("zmap"), OSPrefix: Join(r.RawRoot, "continental", r.Campaign, "os"), IPIDPrefix: r.rawPrefix("ipid"), DoneURI: Join(job, "done.json"), FailedURI: Join(job, "failed.json"), FixedBaseTargetURI: Join(r.rawPrefix("zmap"), zmap, filepath.Base(target))}
		if protocol == "tcp" {
			request.ConnectionTargetURI = Join(r.rawPrefix("zmap"), zmap, filepath.Base(measurements.ConnectionTarget))
		}
		// Publication is an immutable protocol-completion event, not yet a final job.
		if err = Immutable(ctx, r.Store, Join(r.sitePrefix(), "strategy-jobs", zmap, "request.json"), request); err != nil {
			return err
		}
		key := protocol
		if key == "udp-dns" {
			key = "udp"
		}
		manifests[key] = manifestURI
	}
	return r.interprotocol(ctx, manifests)
}
