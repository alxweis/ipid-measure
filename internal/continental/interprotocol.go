package continental

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/alxweis/ipid-measure/internal/interprotocolworkflow"
)

func (r *Runner) interprotocol(ctx context.Context, manifests map[string]string) error {
	runID := "interprotocol"
	directory := filepath.Join(r.Workspace, "interprotocol")
	prepare := r.targetsOverride
	if prepare == nil {
		prepare = interprotocolworkflow.PrepareTargetsReady
	}
	publish := r.publishOverride
	if publish == nil {
		publish = interprotocolworkflow.Publish
	}
	targets, err := prepare(ctx, r.configs["ipid"], runID, manifests, directory)
	if err != nil {
		return err
	}
	manifest := &interprotocolworkflow.Manifest{Version: 2, CampaignID: runID, RunID: runID, CreatedAt: r.state.Steps["icmp-rt"].Stamp, Config: r.configs["ipid"], TargetsDir: targets, TCPPort: 80, UDPPort: 53, BaseManifests: manifests, Groups: map[string]*interprotocolworkflow.GroupRun{}}
	for _, group := range interprotocolworkflow.OrderedGroups {
		manifest.Groups[group] = &interprotocolworkflow.GroupRun{Protocols: interprotocolworkflow.GroupProtocols[group], TargetFile: filepath.Join(targets, group+"-targets.pq"), Measurements: map[string]string{}, Status: "pending"}
	}
	for _, sample := range []string{"base", "mass"} {
		for _, group := range interprotocolworkflow.OrderedGroups {
			state := manifest.Groups[group]
			id, err := r.measure(ctx, "interprotocol-"+group+"-"+sample, "interprotocol", "interprotocol-"+group,
				"--sample", sample, "--target-file", state.TargetFile, "--protocols", strings.Join(state.Protocols, ","), "--tcp-port", "80", "--udp-port", "53")
			if err != nil {
				return err
			}
			state.Measurements[sample] = id
			state.Status = "complete"
		}
	}
	path := filepath.Join(directory, "manifest.json")
	if err = interprotocolworkflow.Save(path, manifest); err != nil {
		return err
	}
	if _, err = publish(ctx, r.configs["ipid"], path); err != nil {
		return err
	}
	return Immutable(ctx, r.Store, Join(r.sitePrefix(), "final", "request.json"), map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "interprotocol_job": runID})
}
