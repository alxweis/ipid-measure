package continental

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/alxweis/ipid-measure/internal/paths"
	"strings"
	"time"
)

// EnrichmentCore only accepts canonical core namespaces, never arbitrary jobs.
func EnrichmentCore(prefix, campaign, zmap string) (string, error) {
	if (campaign == "") == (zmap == "") {
		return "", fmt.Errorf("specify exactly one of --campaign or --zmap")
	}
	id := campaign
	if zmap != "" {
		id = zmap
	}
	if !safeID.MatchString(id) {
		return "", fmt.Errorf("invalid enrichment identity")
	}
	if campaign != "" {
		return Join(prefix, "continental", campaign), nil
	}
	return Join(prefix, "analysis-jobs", zmap), nil
}

func readNoOSCore(ctx context.Context, store Store, core string) ([]byte, error) {
	data, exists, err := store.Read(ctx, Join(core, "done.json"))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("core is not completed")
	}
	var done map[string]any
	if err = json.Unmarshal(data, &done); err != nil {
		return nil, err
	}
	if done["version"] != float64(1) || done["os_status"] != "not_requested" {
		return nil, fmt.Errorf("late enrichment requires a completed no-OS core")
	}
	return data, nil
}

// RequestOSEnrichment never changes core policy or completion. Repeated requests
// adopt the first timestamp/vantage, so a completed scan cannot be duplicated.
func RequestOSEnrichment(ctx context.Context, store Store, core, vantage string) error {
	if strings.TrimSpace(vantage) == "" {
		return fmt.Errorf("explicit --vantage required")
	}
	data, err := readNoOSCore(ctx, store, core)
	if err != nil {
		return err
	}
	uri := Join(core, "enrichments", "os", "request.json")
	old, exists, err := store.Read(ctx, uri)
	if err != nil {
		return err
	}
	if exists {
		var value map[string]any
		if err = json.Unmarshal(old, &value); err != nil {
			return err
		}
		if value["version"] != float64(1) || value["core_prefix"] != core || value["core_done_sha256"] != digest(data) || value["vantage"] != vantage {
			return fmt.Errorf("enrichment request differs from committed request")
		}
		return nil
	}
	return Immutable(ctx, store, uri, map[string]any{"version": 1, "core_prefix": core, "core_done_sha256": digest(data), "vantage": vantage, "requested_at": time.Now().UTC().Format(time.RFC3339), "status": "requested"})
}

// RunOSEnrichment consumes only the centrally validated enrichment scan request.
// Core OS policy stays disabled; scan state and outputs live in a new namespace.
func RunOSEnrichment(ctx context.Context, store Store, execute Execute, repo, workspace, core string, retryIncomplete bool) (bool, error) {
	coreData, err := readNoOSCore(ctx, store, core)
	if err != nil {
		return false, err
	}
	root := Join(core, "enrichments", "os")
	job := Join(root, "scan")
	data, exists, err := store.Read(ctx, Join(root, "request.json"))
	if err != nil || !exists {
		return false, err
	}
	var intent struct {
		Version int    `json:"version"`
		Core    string `json:"core_prefix"`
		SHA     string `json:"core_done_sha256"`
		Vantage string `json:"vantage"`
	}
	if err = json.Unmarshal(data, &intent); err != nil {
		return false, err
	}
	if intent.Version != 1 || intent.Core != core || intent.SHA != digest(coreData) || strings.TrimSpace(intent.Vantage) == "" {
		return false, fmt.Errorf("invalid enrichment/core binding")
	}
	if _, exists, err = store.Read(ctx, Join(job, "done.json")); err != nil || exists {
		return exists, err
	}
	for _, stage := range []string{root, job} {
		if _, exists, err = store.Read(ctx, Join(stage, "failed.json")); err != nil {
			return false, err
		} else if exists {
			return false, fmt.Errorf("enrichment failed; inspect and explicitly retry")
		}
	}
	data, exists, err = store.Read(ctx, Join(job, "request.json"))
	if err != nil || !exists {
		return false, err
	}
	var request OSRequest
	if err = json.Unmarshal(data, &request); err != nil {
		return false, err
	}
	raw := Join(root, "raw")
	if request.Version != 1 || request.RawRoot != raw || request.Target.URI != Join(job, "targets.pq") || request.Target.Rows < 1 || request.Target.Size < 1 || len(request.Target.SHA256) != 64 || len(request.Members) == 0 {
		return false, fmt.Errorf("invalid enrichment scan request")
	}
	if _, err = hex.DecodeString(request.Target.SHA256); err != nil {
		return false, err
	}
	// The analysis worker pins all member evidence before committing this request.
	// Bind the scan to that exact request rather than weakening the core policy.
	expected := 1
	if enrichmentCampaign(core) {
		expected = 18
	}
	if len(request.Members) != expected {
		return false, fmt.Errorf("enrichment discovery membership mismatch")
	}
	if err = validateEnrichmentMembers(ctx, store, core, request); err != nil {
		return false, err
	}
	if err = Immutable(ctx, store, Join(root, "running.json"), map[string]any{"version": 1, "status": "running", "core_prefix": core, "scan_request_sha256": digest(data)}); err != nil {
		return false, err
	}
	return runOSScan(ctx, store, execute, repo, workspace, job, raw, request.Campaign, data, request, true, intent.Vantage, retryIncomplete)
}

func PublishEnrichmentScanFailure(ctx context.Context, store Store, core string, cause error) error {
	job := Join(core, "enrichments", "os", "scan")
	if _, exists, err := store.Read(ctx, Join(job, "request.json")); err != nil || !exists {
		return err
	}
	for _, name := range []string{"done.json", "failed.json"} {
		if _, exists, err := store.Read(ctx, Join(job, name)); err != nil || exists {
			return err
		}
	}
	return Immutable(ctx, store, Join(job, "failed.json"), map[string]any{"version": 1, "status": "failed", "error": cause.Error()})
}

func validateEnrichmentMembers(ctx context.Context, store Store, core string, request OSRequest) error {
	identity := core[strings.LastIndex(core, "/")+1:]
	if request.Campaign != identity {
		return fmt.Errorf("enrichment scan identity mismatch")
	}
	rawPrefix := ""
	if enrichmentCampaign(core) {
		data, exists, err := store.Read(ctx, Join(core, "campaign.json"))
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("missing campaign policy")
		}
		var binding Descriptor
		if err = json.Unmarshal(data, &binding); err != nil {
			return err
		}
		disabled, err := binding.OSDisabled()
		if err != nil {
			return err
		}
		if !disabled || binding.Version != 1 || binding.Campaign != identity || strings.Join(binding.Sites, ",") != strings.Join(Sites, ",") || strings.Join(binding.Protocols, ",") != strings.Join(Protocols, ",") {
			return fmt.Errorf("invalid no-OS campaign binding")
		}
		rawPrefix = Join(binding.RawRoot, "continental", identity)
	} else {
		data, exists, err := store.Read(ctx, Join(core, "request.json"))
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("missing protocol core request")
		}
		var binding struct {
			Job        string `json:"job_id"`
			OSStatus   string `json:"os_status"`
			ZMapPrefix string `json:"zmap_prefix"`
		}
		if err = json.Unmarshal(data, &binding); err != nil {
			return err
		}
		if binding.Job != identity || binding.OSStatus != "not_requested" || !strings.HasPrefix(binding.ZMapPrefix, "s3://") {
			return fmt.Errorf("invalid no-OS protocol binding")
		}
		rawPrefix = binding.ZMapPrefix
	}
	reference := ""
	for i, member := range request.Members {
		source := member["measurement_id"]
		protocol, port, _, err := paths.ParseMeasurementID(source)
		if err != nil {
			return err
		}
		expectedPort := uint16(0)
		if string(protocol) == "tcp" {
			expectedPort = 80
		}
		if string(protocol) == "udp-dns" {
			expectedPort = 53
		}
		if !(port == nil && expectedPort == 0 || port != nil && *port == expectedPort) {
			return fmt.Errorf("invalid discovery port")
		}
		uri := Join(rawPrefix, source, "zmap.pq")
		if len(request.Members) == 18 {
			site, p := Sites[i/3], Protocols[i%3]
			uri = Join(rawPrefix, site, "zmap", source, "zmap.pq")
			if member["site"] != site || member["protocol"] != p || string(protocol) != p {
				return fmt.Errorf("invalid geographic enrichment member")
			}
			if site == "eu" && p == "tcp" {
				reference = source
			}
		} else {
			if source != identity || member["protocol"] != string(protocol) {
				return fmt.Errorf("invalid protocol enrichment member")
			}
			reference = source
		}
		if member["uri"] != uri || len(member["sha256"]) != 64 {
			return fmt.Errorf("invalid enrichment source provenance")
		}
		if _, err = hex.DecodeString(member["sha256"]); err != nil {
			return err
		}
	}
	if request.ZMap != reference {
		return fmt.Errorf("invalid enrichment OS reference")
	}
	return nil
}

func enrichmentCampaign(core string) bool {
	parts := strings.Split(strings.TrimRight(core, "/"), "/")
	return len(parts) > 1 && parts[len(parts)-2] == "continental"
}
