package continental

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/alxweis/ipid-measure/internal/rtresume"
)

type RTRecovery struct {
	Original Step   `json:"original"`
	ResumeID string `json:"resume_id"`
	Receipt  string `json:"receipt"`
}

func (r *Runner) resumeLegacyRT(ctx context.Context, name string, current Step, signature, payload string, args []string) (string, error) {
	if r.Protocol != "icmp" || r.Campaign != rtresume.Campaign || name != "icmp-rt" || r.RetryIncomplete || r.ResumeRTReceipt == "" {
		return "", fmt.Errorf("retained RT recovery requires the explicit --resume-legacy-rt receipt; --retry-incomplete cannot replace it")
	}
	receipt, err := filepath.Abs(r.ResumeRTReceipt)
	if err != nil {
		return "", err
	}
	recovery, restarting := r.state.Recoveries[name]
	if restarting {
		if recovery.ResumeID != current.ID || recovery.Receipt != receipt {
			return "", fmt.Errorf("resume state or receipt changed")
		}
	} else {
		recovery = RTRecovery{Original: current, Receipt: receipt}
	}
	if recovery.Original.Signature != signature || len(r.state.Steps) != 2 {
		return "", fmt.Errorf("unexpected state around original RT prefix")
	}
	fetch := rtresume.FetchS3
	if r.resumeFetchOverride != nil {
		fetch = r.resumeFetchOverride
	}
	if _, _, _, err = rtresume.ReadReceipt(ctx, receipt, r.Workspace, r.Site, recovery.Original.ID, r.state.Binding, fetch); err != nil {
		return "", err
	}
	if !restarting {
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
		current = Step{payload + "_" + stamp.Format("2006-01-02_15-04-05"), stamp.Format(time.RFC3339), signature}
		recovery.ResumeID = current.ID
		if r.state.Recoveries == nil {
			r.state.Recoveries = map[string]RTRecovery{}
		}
		r.state.Recoveries[name] = recovery
		r.state.Steps[name] = current
		if err := AtomicJSON(r.statePath(), r.state); err != nil {
			return "", err
		}
		// Persist the old/new ID mapping before the child can send probes.
		file, err := os.Open(r.statePath())
		if err != nil {
			return "", err
		}
		err = file.Sync()
		closeErr := file.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		directory, err := os.Open(filepath.Dir(r.statePath()))
		if err != nil {
			return "", err
		}
		err = directory.Sync()
		closeErr = directory.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	directory := filepath.Dir(r.rawPath("ipid", current.ID, "unused"))
	if _, err := os.Stat(directory); err == nil {
		return "", fmt.Errorf("resumed attempt is already retained at %s; refusing to overwrite/retry it; inspect and preserve its additional progress", directory)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	source := filepath.Dir(r.rawPath("ipid", recovery.Original.ID, "ipid.pq"))
	commandArgs := append([]string{"--config", r.configs["ipid"]}, args...)
	commandArgs = append(commandArgs, "--resume-from", source, "--resume-backup", receipt, "--resume-site", r.Site, "--resume-binding", r.state.Binding, "--print-id")
	if _, err := r.Execute(ctx, filepath.Join(r.Repo, "bin", "measure-ipid"), commandArgs, r.env(current.Stamp)); err != nil {
		return "", fmt.Errorf("resume %s: %w", name, err)
	}
	complete, err := r.committed(ctx, "ipid", current)
	if err != nil {
		return "", err
	}
	if !complete {
		return "", fmt.Errorf("resumed RT has no durable raw completion")
	}
	return current.ID, nil
}
