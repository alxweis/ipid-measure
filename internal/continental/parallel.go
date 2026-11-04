package continental

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/alxweis/ipid-measure/internal/postprocessworkflow"
	"github.com/alxweis/ipid-measure/internal/upload"
	"gopkg.in/yaml.v3"
	"os"
)

func validProtocol(p string) bool { return p == "icmp" || p == "tcp" || p == "udp-dns" }

func (r *Runner) PublishProtocolFailure(ctx context.Context, cause error) error {
	return Immutable(ctx, r.Store, Join(r.flowPrefix(), "controller", "failed.json"), map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": r.Protocol, "error": cause.Error()})
}

func (s S3) RetryProtocolFailure(ctx context.Context, r Runner) error {
	return s.retryScanFailure(ctx, Join(r.flowPrefix(), "controller"))
}

func (r *Runner) streamMeasurement(ctx context.Context, id, zmap, target, variant string) error {
	if target == "" {
		target = r.rawPath("zmap", zmap, "zmap.pq")
	}
	evidence, err := upload.Evidence(target)
	if err != nil {
		return err
	}
	name := filepath.Base(target)
	var targetURI string
	switch name {
	case "zmap.pq", "zmap-fixed-base-sample.pq", "zmap-connection-sample.pq":
		targetURI = Join(r.rawPrefix("zmap"), zmap, name)
	case "zmap_unclassified.pq", "random-reproducibility-targets.pq":
		targetURI = Join(r.rawPrefix("ipid"), filepath.Base(filepath.Dir(target)), name)
	default:
		return fmt.Errorf("unsupported stream target %s", target)
	}
	return Immutable(ctx, r.Store, Join(r.flowPrefix(), "measurement-jobs", id, "request.json"), map[string]any{
		"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": r.Protocol,
		"measurement_id": id, "zmap_id": zmap, "variant": variant,
		"raw_prefix": r.rawPrefix("ipid"), "zmap_prefix": r.rawPrefix("zmap"),
		"target": map[string]any{"uri": targetURI, "size_bytes": evidence.Size, "sha256": evidence.SHA256},
	})
}

func (r *Runner) runProtocol(ctx context.Context) error {
	if _, exists, err := r.Store.Read(ctx, Join(r.flowPrefix(), "controller", "failed.json")); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("protocol controller failed; inspect and use --retry-failed")
	}
	if _, exists, err := r.Store.Read(ctx, Join(r.flowPrefix(), "controller", "done.json")); err != nil {
		return err
	} else if exists {
		return nil
	}
	p := r.Protocol
	payload := map[string]string{"icmp": "icmp", "tcp": "tcp-80", "udp-dns": "udp-dns-53"}[p]
	args := []string{"--payload", p}
	if p == "tcp" {
		args = append(args, "--port", "80")
	}
	if p == "udp-dns" {
		args = append(args, "--port", "53", "--probe-args", "A,www.example.com")
	}
	zmap, err := r.measure(ctx, "zmap-"+p, "zmap", payload, args...)
	if err != nil {
		return err
	}
	if err = Immutable(ctx, r.Store, Join(r.flowPrefix(), "discovery.json"), map[string]any{
		"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": p,
		"measurement_id": zmap, "raw_prefix": r.rawPrefix("zmap"),
	}); err != nil {
		return err
	}
	rt, err := r.ipid(ctx, p+"-rt", payload, zmap, "", false, false)
	if err != nil {
		return err
	}
	if err = r.handoff(ctx, rt, false); err != nil {
		return err
	}
	if err = r.streamMeasurement(ctx, rt, zmap, "", "rt-base"); err != nil {
		return err
	}
	unclassified := r.rawPath("ipid", rt, "zmap_unclassified.pq")
	mass, err := r.ipid(ctx, p+"-mass", payload, zmap, unclassified, true, false)
	if err != nil {
		return err
	}
	if err = r.handoff(ctx, mass, true); err != nil {
		return err
	}
	if err = r.streamMeasurement(ctx, mass, zmap, unclassified, "fi-mass"); err != nil {
		return err
	}
	cohort := r.rawPath("ipid", mass, "random-reproducibility-targets.pq")
	repeats := []string{}
	for n := 1; n <= 5; n++ {
		id, err := r.ipid(ctx, fmt.Sprintf("%s-repeat-%d", p, n), payload, zmap, cohort, true, false)
		if err != nil {
			return err
		}
		if err = r.streamMeasurement(ctx, id, zmap, cohort, "repeat"); err != nil {
			return err
		}
		repeats = append(repeats, id)
	}
	target, err := r.sample(ctx, zmap, false)
	if err != nil {
		return err
	}
	base, err := r.ipid(ctx, p+"-base", payload, zmap, target, false, false)
	if err != nil {
		return err
	}
	if err = r.streamMeasurement(ctx, base, zmap, target, "fi-base"); err != nil {
		return err
	}
	m := postprocessworkflow.Measurements{ZMap: zmap, OS: "shared-os", SkipOS: r.SkipOS, RTBase: rt, FixedMass: mass, FixedBase: base, FixedBaseTarget: target, RandomReproducibilityRepeats: repeats, RandomReproducibilityMaximumTargets: 10000, RandomReproducibilitySelectionSeed: 42}
	if p == "tcp" {
		m.ConnectionTarget, err = r.sample(ctx, zmap, true)
		if err != nil {
			return err
		}
		m.ConnectionRTBase, err = r.ipid(ctx, "tcp-connection-rt", payload, zmap, m.ConnectionTarget, false, true)
		if err != nil {
			return err
		}
		if err = r.streamMeasurement(ctx, m.ConnectionRTBase, zmap, m.ConnectionTarget, "connection-rt-base"); err != nil {
			return err
		}
		m.ConnectionFIBase, err = r.ipid(ctx, "tcp-connection-fi", payload, zmap, m.ConnectionTarget, false, true)
		if err != nil {
			return err
		}
		if err = r.streamMeasurement(ctx, m.ConnectionFIBase, zmap, m.ConnectionTarget, "connection-fi-base"); err != nil {
			return err
		}
	}
	if r.SkipOS {
		m.OS = ""
	}
	job := Join(r.flowPrefix(), "analysis-jobs", zmap)
	manifestURI := Join(job, "manifest.json")
	if err = Immutable(ctx, r.Store, manifestURI, postprocessworkflow.BuildManifest(p, m)); err != nil {
		return err
	}
	created, _ := time.Parse(time.RFC3339, r.state.Steps["zmap-"+p].Stamp)
	request := postprocessworkflow.Request{Version: 1, JobID: zmap, Protocol: p, ManifestURI: manifestURI, ZMapPrefix: r.rawPrefix("zmap"), OSPrefix: Join(r.RawRoot, "continental", r.Campaign, "os"), IPIDPrefix: r.rawPrefix("ipid"), DoneURI: Join(job, "done.json"), FailedURI: Join(job, "failed.json"), CreatedAt: created, FixedBaseTargetURI: Join(r.rawPrefix("zmap"), zmap, filepath.Base(target))}
	if r.SkipOS {
		request.OSStatus = "not_requested"
		request.OSPrefix = ""
	}
	if p == "tcp" {
		request.ConnectionTargetURI = Join(r.rawPrefix("zmap"), zmap, filepath.Base(m.ConnectionTarget))
	}
	if err = Immutable(ctx, r.Store, Join(r.flowPrefix(), "strategy-jobs", zmap, "request.json"), request); err != nil {
		return err
	}
	if err = Immutable(ctx, r.Store, Join(r.flowPrefix(), "done.json"), map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": p, "manifest_uri": manifestURI, "job_id": zmap}); err != nil {
		return err
	}
	if p == "udp-dns" {
		manifests, err := r.waitProtocols(ctx)
		if err != nil {
			return err
		}
		// Interprotocol control remains continent-local, outside the UDP queue.
		data, err := os.ReadFile(r.configs["ipid"])
		if err != nil {
			return err
		}
		var config map[string]any
		if err = yaml.Unmarshal(data, &config); err != nil {
			return err
		}
		config["analysis_workflow"].(map[string]any)["s3_prefix"] = r.sitePrefix()
		data, err = yaml.Marshal(config)
		if err != nil {
			return err
		}
		path := filepath.Join(r.Workspace, "config", "interprotocol.yaml")
		if err = os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		r.configs["ipid"] = path
		if err = r.interprotocol(ctx, manifests); err != nil {
			return err
		}
	}
	return Immutable(ctx, r.Store, Join(r.flowPrefix(), "controller", "done.json"), map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": p})
}

func (r *Runner) waitProtocols(ctx context.Context) (map[string]string, error) {
	wait, cancel := context.WithTimeout(ctx, r.workflow.Timeout)
	defer cancel()
	ticker := time.NewTicker(r.workflow.PollInterval)
	defer ticker.Stop()
	for {
		manifests := map[string]string{}
		for _, p := range Protocols {
			flow := Join(r.sitePrefix(), "protocols", p)
			data, ok, err := r.Store.Read(wait, Join(flow, "done.json"))
			if err != nil {
				return nil, err
			}
			if !ok {
				if _, failed, err := r.Store.Read(wait, Join(flow, "controller", "failed.json")); err != nil {
					return nil, err
				} else if failed {
					return nil, fmt.Errorf("%s protocol controller failed", p)
				}
				continue
			}
			var value struct {
				Version  int    `json:"version"`
				Campaign string `json:"campaign_id"`
				Site     string `json:"site"`
				Protocol string `json:"protocol"`
				Manifest string `json:"manifest_uri"`
				Job      string `json:"job_id"`
			}
			if err = json.Unmarshal(data, &value); err != nil {
				return nil, err
			}
			if value.Version != 1 || value.Campaign != r.Campaign || value.Site != r.Site || value.Protocol != p || value.Manifest != Join(flow, "analysis-jobs", value.Job, "manifest.json") {
				return nil, fmt.Errorf("invalid %s protocol completion", p)
			}
			key := p
			if p == "udp-dns" {
				key = "udp"
			}
			manifests[key] = value.Manifest
		}
		if len(manifests) == 3 {
			return manifests, nil
		}
		select {
		case <-wait.Done():
			return nil, fmt.Errorf("wait for continent protocols: %w", wait.Err())
		case <-ticker.C:
		}
	}
}
