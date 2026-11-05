package continental

import (
	"context"
	"path/filepath"

	"github.com/alxweis/ipid-measure/internal/upload"
)

// Controls precede interleaving, run on the UDP VM with the identical config,
// and have their own measurement IDs and analysis artifacts. They never modify
// the baseline cohorts or the eight existing interprotocol measurements.
func (r *Runner) localReferences(ctx context.Context, targets string) error {
	for _, sample := range []string{"base", "mass"} {
		for _, protocol := range []string{"icmp", "tcp", "udp"} {
			name := "reference-" + protocol + "-" + sample
			target := filepath.Join(targets, name+"-targets.pq")
			evidence, err := upload.Evidence(target)
			if err != nil {
				return err
			}
			id, err := r.measure(ctx, name, "interprotocol", "interprotocol-"+protocol,
				"--local-reference", "--sample", sample, "--target-file", target,
				"--protocols", protocol, "--tcp-port", "80", "--udp-port", "53")
			if err != nil {
				return err
			}
			targetURI := Join(r.sitePrefix(), "interprotocol-target-jobs", "interprotocol", "targets", filepath.Base(target))
			if err = Immutable(ctx, r.Store, Join(r.sitePrefix(), "reference-jobs", name, "request.json"), map[string]any{
				"version": 1, "campaign_id": r.Campaign, "site": r.Site,
				"protocol": protocol, "sample": sample, "measurement_id": id,
				"raw_prefix": r.rawPrefix("ipid"),
				"target":     map[string]any{"uri": targetURI, "size_bytes": evidence.Size, "sha256": evidence.SHA256},
			}); err != nil {
				return err
			}
		}
	}
	return Immutable(ctx, r.Store, Join(r.sitePrefix(), "reference-comparison", "request.json"), map[string]any{
		"version": 1, "campaign_id": r.Campaign, "site": r.Site,
	})
}
