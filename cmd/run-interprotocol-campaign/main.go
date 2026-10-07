package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/interprotocolworkflow"
)

func measurementID(output, group string) (string, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		candidate := strings.TrimSpace(lines[index])
		if strings.HasPrefix(candidate, "interprotocol-"+group+"_") && !strings.ContainsAny(candidate, " \t") {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("measurement command did not print an id for %s", group)
}

func main() {
	icmpManifest := flag.String("manifest-icmp", "", "S3 URI printed by make run-all-icmp")
	tcpManifest := flag.String("manifest-tcp", "", "S3 URI printed by make run-all-tcp")
	udpManifest := flag.String("manifest-udp", "", "S3 URI printed by make run-all-udp")
	flag.Parse()
	if flag.NArg() != 0 || *icmpManifest == "" || *tcpManifest == "" || *udpManifest == "" {
		log.Fatal("exactly --manifest-icmp, --manifest-tcp, and --manifest-udp are required")
	}

	runID := "interprotocol_" + time.Now().Format("2006-01-02_15-04-05")
	runDirectory := filepath.Join("ipid", "interprotocol-runs", runID)
	configPath := files.IPIDConfigFilePath
	baseManifests := map[string]string{
		"icmp": *icmpManifest,
		"tcp":  *tcpManifest,
		"udp":  *udpManifest,
	}
	log.Printf("inter-protocol run_id=%s", runID)
	log.Printf("waiting for base analyses and building target intersections")
	targetsDir, err := interprotocolworkflow.PrepareTargets(
		context.Background(), configPath, runID, baseManifests, runDirectory,
	)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	manifestPath := filepath.Join(runDirectory, "manifest.json")
	manifest := &interprotocolworkflow.Manifest{
		Version: interprotocolworkflow.Version, CampaignID: runID, RunID: runID,
		CreatedAt: now, Config: configPath, TargetsDir: targetsDir,
		TCPPort: 80, UDPPort: 53, BaseManifests: baseManifests,
		Groups: make(map[string]*interprotocolworkflow.GroupRun),
	}
	for _, group := range interprotocolworkflow.OrderedGroups {
		target, absoluteErr := filepath.Abs(filepath.Join(targetsDir, group+"-targets.pq"))
		if absoluteErr != nil {
			log.Fatal(absoluteErr)
		}
		if _, statErr := os.Stat(target); statErr != nil {
			log.Fatalf("target file for %s: %v", group, statErr)
		}
		manifest.Groups[group] = &interprotocolworkflow.GroupRun{
			Protocols:  append([]string(nil), interprotocolworkflow.GroupProtocols[group]...),
			TargetFile: target, Status: "pending",
		}
	}
	if err := interprotocolworkflow.Save(manifestPath, manifest); err != nil {
		log.Fatal(err)
	}

	for _, group := range interprotocolworkflow.OrderedGroups {
		state := manifest.Groups[group]
		state.Status = "running"
		state.StartedAt = time.Now().UTC().Format(time.RFC3339)
		if err := interprotocolworkflow.Save(manifestPath, manifest); err != nil {
			log.Fatal(err)
		}
		args := []string{
			"--config", configPath,
			"--target-file", state.TargetFile,
			"--protocols", strings.Join(state.Protocols, ","),
			"--tcp-port", "80", "--udp-port", "53", "--print-id",
		}
		log.Printf("starting inter-protocol group %s", group)
		command := exec.Command("bin/measure-interprotocol", args...)
		var stdout bytes.Buffer
		command.Stdout = io.MultiWriter(os.Stdout, &stdout)
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			state.Status, state.Error = "failed", err.Error()
			_ = interprotocolworkflow.Save(manifestPath, manifest)
			log.Fatalf("measurement %s failed: %v", group, err)
		}
		id, err := measurementID(stdout.String(), group)
		if err != nil {
			log.Fatal(err)
		}
		state.Status, state.MeasurementID = "complete", id
		state.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if err := interprotocolworkflow.Save(manifestPath, manifest); err != nil {
			log.Fatal(err)
		}
	}
	requestURI, err := interprotocolworkflow.Publish(context.Background(), configPath, manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("final analysis job published: %s", requestURI)
	done, err := interprotocolworkflow.Wait(context.Background(), configPath, manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("analysis completed: rows=%d\n", done.Rows)
	fmt.Printf("S3_RESULTS=%s\n", done.ResultPrefix)
	fmt.Printf("ANALYSIS_VM_RESULTS=data/processed/interprotocol/%s/runs/%s\n", runID, runID)
}
