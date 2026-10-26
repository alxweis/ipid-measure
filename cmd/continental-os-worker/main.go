package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/alxweis/ipid-measure/internal/continental"
	"gopkg.in/yaml.v3"
)

func main() {
	campaign := flag.String("campaign", os.Getenv("IPID_CAMPAIGN_ID"), "shared explicit campaign ID")
	prefix := flag.String("s3-prefix", os.Getenv("IPID_ANALYSIS_S3_PREFIX"), "same workflow root as six measurement VMs")
	retry := flag.Bool("retry-failed", false, "archive and explicitly retry this campaign OS failure")
	retryIncomplete := flag.Bool("retry-incomplete", false, "retain a partial OS attempt and scan with a new measurement ID")
	once := flag.Bool("once", false, "check once and exit; otherwise wait for discovery")
	poll := flag.Duration("poll-interval", 30*time.Second, "poll interval")
	flag.Parse()
	if err := continental.Validate(*campaign, "eu"); err != nil {
		log.Fatal(err)
	}
	if *prefix == "" {
		data, err := os.ReadFile("config/ipid.yaml")
		if err != nil {
			log.Fatal(err)
		}
		var c struct {
			Workflow struct {
				Prefix string `yaml:"s3_prefix"`
			} `yaml:"analysis_workflow"`
		}
		if err = yaml.Unmarshal(data, &c); err != nil {
			log.Fatal(err)
		}
		*prefix = c.Workflow.Prefix
	}
	if len(*prefix) < 6 || (*prefix)[:5] != "s3://" || *poll < time.Second {
		log.Fatal("valid S3 workflow prefix and poll interval required")
	}
	repo, err := filepath.Abs(".")
	if err != nil {
		log.Fatal(err)
	}
	workspace := filepath.Join(repo, "continental", *campaign, "os")
	if err = os.MkdirAll(workspace, 0755); err != nil {
		log.Fatal(err)
	}
	unlock, err := continental.Lock(filepath.Join(workspace, ".runner.lock"))
	if err != nil {
		log.Fatal(err)
	}
	defer unlock()
	store := continental.S3{Directory: filepath.Join(workspace, "publication")}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if *retry {
		if err = store.RetryOSFailure(ctx, continental.Join(*prefix, "continental", *campaign, "os")); err != nil {
			log.Fatal(err)
		}
	}
	for {
		done, err := continental.RunOS(ctx, store, continental.Command, repo, workspace, *prefix, *campaign, *retryIncomplete)
		if err != nil {
			// Explicit terminal failure: no automatic destructive retry of real scans.
			if ctx.Err() != nil {
				return
			}
			job := continental.Join(*prefix, "continental", *campaign, "os")
			if _, done, checkErr := store.Read(ctx, continental.Join(job, "done.json")); checkErr == nil && !done {
				if _, failed, checkErr := store.Read(ctx, continental.Join(job, "failed.json")); checkErr == nil && !failed {
					if publishErr := continental.Immutable(ctx, store, continental.Join(job, "failed.json"), map[string]any{"version": 1, "campaign_id": *campaign, "error": err.Error()}); publishErr != nil {
						log.Printf("could not publish OS failure: %v", publishErr)
					}
				}
			}
			log.Fatal(err)
		}
		if done || *once {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(*poll):
		}
	}
}
