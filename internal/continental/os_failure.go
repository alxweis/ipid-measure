package continental

import (
	"context"
	"encoding/json"
	"fmt"
)

// A control-plane outage is not a failed OS scan unless this campaign actually
// requested an OS job. In particular, disabled campaigns never get OS failures.
func PublishOSFailure(ctx context.Context, store Store, prefix, campaign string, cause error) error {
	data, exists, err := store.Read(ctx, Join(prefix, "continental", campaign, "campaign.json"))
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	var binding Descriptor
	if err = json.Unmarshal(data, &binding); err != nil {
		return err
	}
	if binding.Version != 1 || binding.Campaign != campaign {
		return fmt.Errorf("invalid campaign binding")
	}
	disabled, err := binding.OSDisabled()
	if err != nil {
		return err
	}
	if disabled {
		return nil
	}
	job := Join(prefix, "continental", campaign, "os")
	if _, exists, err = store.Read(ctx, Join(job, "request.json")); err != nil {
		return err
	} else if !exists {
		return nil
	}
	for _, marker := range []string{"done.json", "failed.json"} {
		if _, exists, err = store.Read(ctx, Join(job, marker)); err != nil {
			return err
		} else if exists {
			return nil
		}
	}
	return Immutable(ctx, store, Join(job, "failed.json"), map[string]any{"version": 1, "campaign_id": campaign, "error": cause.Error()})
}
