package continental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/alxweis/ipid-measure/internal/paths"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/upload"
	"gopkg.in/yaml.v3"
)

type Target struct {
	URI    string `json:"uri"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
	Rows   int64  `json:"rows"`
}
type OSRequest struct {
	Version  int                 `json:"version"`
	Campaign string              `json:"campaign_id"`
	Target   Target              `json:"target"`
	RawRoot  string              `json:"raw_root"`
	ZMap     string              `json:"reference_zmap"`
	Members  []map[string]string `json:"members"`
}

// RunOS returns false while discovery is incomplete. It never scans on a site
// VM and never changes a terminal success/failure or a committed raw dataset.
func RunOS(ctx context.Context, store Store, execute Execute, repo, workspace, prefix, campaign string, retryIncomplete ...bool) (bool, error) {
	if err := Validate(campaign, "eu"); err != nil {
		return false, err
	}
	job := Join(prefix, "continental", campaign, "os")
	if _, exists, err := store.Read(ctx, Join(job, "done.json")); err != nil {
		return false, err
	} else if exists {
		return true, nil
	}
	if _, exists, err := store.Read(ctx, Join(job, "failed.json")); err != nil {
		return false, err
	} else if exists {
		return false, fmt.Errorf("OS job has a terminal failure; inspect and explicitly retry it")
	}
	data, exists, err := store.Read(ctx, Join(job, "request.json"))
	if err != nil || !exists {
		return false, err
	}
	var request OSRequest
	if err = json.Unmarshal(data, &request); err != nil {
		return false, err
	}
	descriptor, exists, err := store.Read(ctx, Join(prefix, "continental", campaign, "campaign.json"))
	if err != nil {
		return false, err
	}
	if !exists {
		return false, fmt.Errorf("missing campaign descriptor")
	}
	var binding Descriptor
	if err = json.Unmarshal(descriptor, &binding); err != nil {
		return false, err
	}
	if request.Version != 1 || binding.Version != 1 || request.Campaign != campaign || binding.Campaign != campaign || request.RawRoot != binding.RawRoot || request.Target.URI != Join(job, "targets.pq") || len(request.Members) != 18 || request.Target.Rows < 1 || request.Target.Size < 1 || len(request.Target.SHA256) != 64 {
		return false, fmt.Errorf("invalid OS request/campaign binding")
	}
	if strings.Join(binding.Sites, ",") != strings.Join(Sites, ",") || strings.Join(binding.Protocols, ",") != strings.Join(Protocols, ",") {
		return false, fmt.Errorf("campaign participant mismatch")
	}
	if _, err = hex.DecodeString(request.Target.SHA256); err != nil {
		return false, fmt.Errorf("invalid union digest")
	}
	for i, member := range request.Members {
		site, protocol := Sites[i/3], Protocols[i%3]
		payload, port, _, parseErr := paths.ParseMeasurementID(member["measurement_id"])
		expectedPayload := protocol
		expectedPort := uint16(0)
		if protocol == "tcp" {
			expectedPort = 80
		}
		if protocol == "udp-dns" {
			expectedPort = 53
		}
		if parseErr != nil || string(payload) != expectedPayload || !(port == nil && expectedPort == 0 || port != nil && *port == expectedPort) || member["site"] != site || member["protocol"] != protocol || member["uri"] != Join(binding.RawRoot, "continental", campaign, site, "zmap", member["measurement_id"], "zmap.pq") || len(member["sha256"]) != 64 {
			return false, fmt.Errorf("invalid OS source membership")
		}
		if site == "eu" && protocol == "tcp" && request.ZMap != member["measurement_id"] {
			return false, fmt.Errorf("invalid OS reference")
		}
	}
	if err = os.MkdirAll(workspace, 0755); err != nil {
		return false, err
	}
	// Pin the immutable input before starting; a changed request is never adopted.
	pinned := filepath.Join(workspace, "request.json")
	if old, err := os.ReadFile(pinned); err == nil {
		if !JSONEqual(old, data) {
			return false, fmt.Errorf("OS request changed on restart")
		}
	} else if !os.IsNotExist(err) {
		return false, err
	} else if err = AtomicJSON(pinned, request); err != nil {
		return false, err
	}
	target := filepath.Join(workspace, "targets.pq")
	if _, err = os.Stat(target); os.IsNotExist(err) {
		if err = store.GetFile(ctx, request.Target.URI, target); err != nil {
			return false, err
		}
	}
	actual, err := upload.Evidence(target)
	if err != nil {
		return false, err
	}
	if actual.Size != request.Target.Size || actual.SHA256 != request.Target.SHA256 {
		// Only the disposable local target cache is replaced. A truncated
		// previous transfer must not make an explicit retry permanently fail.
		if err = store.GetFile(ctx, request.Target.URI, target); err != nil {
			return false, err
		}
		actual, err = upload.Evidence(target)
		if err != nil {
			return false, err
		}
		if actual.Size != request.Target.Size || actual.SHA256 != request.Target.SHA256 {
			return false, fmt.Errorf("OS union integrity mismatch")
		}
	}
	statePath := filepath.Join(workspace, "scan.json")
	step := Step{}
	if value, err := os.ReadFile(statePath); err == nil {
		if err = json.Unmarshal(value, &step); err != nil {
			return false, err
		}
	} else if !os.IsNotExist(err) {
		return false, err
	} else {
		stamp := time.Now().UTC().Truncate(time.Second)
		step = Step{ID: "tcp-80_" + stamp.Format("2006-01-02_15-04-05"), Stamp: stamp.Format(time.RFC3339)}
		if err = AtomicJSON(statePath, step); err != nil {
			return false, err
		}
	}
	output := filepath.Join(workspace, "os", "raw", step.ID)
	complete := filepath.Join(output, "measurement-complete.json")
	if _, err = os.Stat(complete); os.IsNotExist(err) {
		if _, err = os.Stat(output); err == nil {
			if len(retryIncomplete) == 0 || !retryIncomplete[0] {
				return false, fmt.Errorf("incomplete OS attempt retained at %s; inspect and use --retry-incomplete for a new attempt", output)
			}
			archive := output + "-attempt-" + fmt.Sprint(time.Now().UnixNano())
			if err = os.Rename(output, archive); err != nil {
				return false, err
			}
			stamp := time.Now().UTC().Truncate(time.Second)
			previous, _ := time.Parse(time.RFC3339, step.Stamp)
			if !stamp.After(previous) {
				stamp = previous.Add(time.Second)
			}
			step = Step{ID: "tcp-80_" + stamp.Format("2006-01-02_15-04-05"), Stamp: stamp.Format(time.RFC3339)}
			if err = AtomicJSON(statePath, step); err != nil {
				return false, err
			}
			output = filepath.Join(workspace, "os", "raw", step.ID)
		} else if !os.IsNotExist(err) {
			return false, err
		}
		configData, err := os.ReadFile(filepath.Join(repo, "config", "os.yaml"))
		if err != nil {
			return false, err
		}
		var config map[string]any
		if err = yaml.Unmarshal(configData, &config); err != nil {
			return false, err
		}
		config["upload"] = map[string]any{"enable": false, "delete_local": false}
		config["record_target_status"] = true
		configData, err = yaml.Marshal(config)
		if err != nil {
			return false, err
		}
		configPath := filepath.Join(workspace, "os.yaml")
		if err = os.WriteFile(configPath, configData, 0600); err != nil {
			return false, err
		}
		// Explicit target-file overrides the legacy reference's data path. The
		// request and done marker retain all 18 sources, never just this reference.
		args := []string{"--config", configPath, "--zmap", request.ZMap, "--target-file", target, "--record-target-status", "--zgrab2-senders", "5K", "--dns-chaos-workers", "1K", "--snmp-workers", "3K", "--connect-timeout", "1s", "--read-timeout", "1s", "--snmp-timeout", "1s", "--print-id"}
		runner := Runner{Workspace: workspace}
		if _, err = execute(ctx, filepath.Join(repo, "bin", "measure-os"), args, runner.env(step.Stamp)); err != nil {
			return false, err
		}
		complete = filepath.Join(output, "measurement-complete.json")
	} else if err != nil {
		return false, err
	}
	value, err := os.ReadFile(complete)
	if err != nil {
		return false, fmt.Errorf("OS scan exited without closed-file completion: %w", err)
	}
	var marker struct {
		Version int                            `json:"version"`
		ID      string                         `json:"measurement_id"`
		Files   map[string]upload.FileEvidence `json:"files"`
	}
	if err = json.Unmarshal(value, &marker); err != nil {
		return false, err
	}
	if marker.Version != 1 || marker.ID != step.ID {
		return false, fmt.Errorf("OS local completion mismatch")
	}
	files := map[string]upload.FileEvidence{}
	for _, name := range []string{"os.pq", "os-coverage.json", "os-observations.pq", "os.snapshot.yaml"} {
		path := filepath.Join(output, name)
		evidence, err := upload.Evidence(path)
		if err != nil {
			return false, err
		}
		if marker.Files[name] != evidence {
			return false, fmt.Errorf("OS source changed since completion: %s", name)
		}
		if err = store.PutFile(ctx, Join(request.RawRoot, "continental", campaign, "os", "shared-os", name), path); err != nil {
			return false, err
		}
		files[name] = evidence
	}
	done := map[string]any{"version": 1, "campaign_id": campaign, "measurement_id": step.ID, "target": request.Target, "members": request.Members, "vantage": "shared-os-vm", "files": files}
	if err = Immutable(ctx, store, Join(job, "done.json"), done); err != nil {
		return false, err
	}
	return true, nil
}
