package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/alxweis/ipid-measure/internal/continental"
)

func main() {
	campaign := flag.String("campaign", os.Getenv("IPID_CAMPAIGN_ID"), "explicit shared campaign ID; same on all six sites and OS VM")
	site := flag.String("site", "", "eu,as,af,na,sa,au")
	protocol := flag.String("protocol", "", "one protocol (icmp,tcp,udp); empty runs the existing three-protocol workflow")
	retryFailed := flag.Bool("retry-failed", false, "archive this protocol controller's failure before resuming")
	skipOS := flag.Bool("skip-os", false, "disable OS for the entire immutable campaign (must match all sites)")
	retry := flag.Bool("retry-incomplete", false, "retain an incomplete local attempt and start it with a new ID")
	resumeRT := flag.String("resume-legacy-rt", "", "verified preservation receipt for one of the four original interrupted Geo ICMP RT prefixes")
	retainLocal := flag.Bool("retain-local", false, "retain uploaded IPID/interprotocol bulk files in protocol-specific Geo runs")
	flag.Parse()
	if *resumeRT != "" && (*retry || *protocol != "icmp") {
		log.Fatal("--resume-legacy-rt requires --protocol icmp and cannot be combined with --retry-incomplete")
	}
	if err := continental.Validate(*campaign, *site); err != nil {
		log.Fatal(err)
	}
	repo, err := filepath.Abs(".")
	if err != nil {
		log.Fatal(err)
	}
	workspace := filepath.Join(repo, "continental", *campaign, *site)
	if *protocol == "udp" {
		*protocol = "udp-dns"
	}
	if *protocol != "" {
		workspace = filepath.Join(repo, "parallel", *campaign, *site, *protocol)
	}
	if err = os.MkdirAll(workspace, 0755); err != nil {
		log.Fatal(err)
	}
	unlock, err := continental.Lock(filepath.Join(workspace, ".runner.lock"))
	if err != nil {
		log.Fatalf("site already running or unavailable: %v", err)
	}
	defer unlock()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	store := continental.S3{Directory: filepath.Join(workspace, "publication")}
	runner := continental.Runner{Repo: repo, Workspace: workspace, Campaign: *campaign, Site: *site, Protocol: *protocol, Store: store, RetryIncomplete: *retry, ResumeRTReceipt: *resumeRT, SkipOS: *skipOS, RetainLocal: *retainLocal}
	if err = runner.Prepare(ctx); err != nil {
		log.Fatal(err)
	}
	if *retryFailed {
		if *protocol == "" {
			log.Fatal("--retry-failed requires --protocol")
		}
		if err = store.RetryProtocolFailure(ctx, runner); err != nil {
			log.Fatal(err)
		}
	}
	if err = runner.Run(ctx); err != nil {
		if *protocol != "" && ctx.Err() == nil {
			_ = runner.PublishProtocolFailure(ctx, err)
		}
		log.Fatal(err)
	}
	log.Printf("campaign %s site %s: all measurements published; final analyses are asynchronous", *campaign, *site)
}
