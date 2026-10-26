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
	retry := flag.Bool("retry-incomplete", false, "retain an incomplete local attempt and start it with a new ID")
	flag.Parse()
	if err := continental.Validate(*campaign, *site); err != nil {
		log.Fatal(err)
	}
	repo, err := filepath.Abs(".")
	if err != nil {
		log.Fatal(err)
	}
	workspace := filepath.Join(repo, "continental", *campaign, *site)
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
	runner := continental.Runner{Repo: repo, Workspace: workspace, Campaign: *campaign, Site: *site, Store: continental.S3{Directory: filepath.Join(workspace, "publication")}, RetryIncomplete: *retry}
	if err = runner.Prepare(ctx); err != nil {
		log.Fatal(err)
	}
	if err = runner.Run(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("campaign %s site %s: all measurements published; final analyses are asynchronous", *campaign, *site)
}
