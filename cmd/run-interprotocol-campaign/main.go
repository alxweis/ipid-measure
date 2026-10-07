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

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func parseGroups(value string) ([]string, error) {
	seen := make(map[string]bool)
	var groups []string
	for _, raw := range strings.Split(value, ",") {
		group := strings.TrimSpace(strings.ToLower(raw))
		if _, ok := interprotocolworkflow.GroupProtocols[group]; !ok {
			return nil, fmt.Errorf("unsupported protocol group %q", group)
		}
		if seen[group] {
			return nil, fmt.Errorf("duplicate protocol group %q", group)
		}
		seen[group] = true
		groups = append(groups, group)
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("at least one protocol group is required")
	}
	return groups, nil
}

func parseExisting(values []string) (map[string]string, error) {
	result := make(map[string]string)
	for _, value := range values {
		group, measurementID, ok := strings.Cut(value, "=")
		if !ok {
			return nil, fmt.Errorf("--existing must be GROUP=MEASUREMENT-ID")
		}
		if _, supported := interprotocolworkflow.GroupProtocols[group]; !supported {
			return nil, fmt.Errorf("unsupported existing protocol group %q", group)
		}
		if !strings.HasPrefix(measurementID, "interprotocol-"+group+"_") {
			return nil, fmt.Errorf("measurement id %q does not match group %q", measurementID, group)
		}
		result[group] = measurementID
	}
	return result, nil
}

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
	campaignID := flag.String("campaign-id", "", "target campaign id")
	targetsDir := flag.String("targets-dir", "", "directory containing <group>-targets.pq")
	configPath := flag.String("config", files.IPIDConfigFilePath, "IPID measurement config")
	groupsFlag := flag.String("groups", strings.Join(interprotocolworkflow.OrderedGroups, ","), "comma-separated protocol groups")
	tcpPort := flag.Uint("tcp-port", 80, "stateless TCP destination port")
	udpPort := flag.Uint("udp-port", 53, "UDP DNS destination port")
	runID := flag.String("run-id", "", "stable run id; generated when omitted")
	runRoot := flag.String("run-root", "ipid/interprotocol-runs", "local campaign state directory")
	manifestFlag := flag.String("manifest", "", "manifest path (required with --resume unless --run-id is set)")
	resume := flag.Bool("resume", false, "continue an existing run manifest")
	noPublish := flag.Bool("no-publish", false, "complete locally without publishing the analysis request")
	noWait := flag.Bool("no-wait", false, "publish the analysis request without waiting for completion")
	measureBinary := flag.String("measure-binary", "bin/measure-interprotocol", "measurement binary")
	var existing repeatedFlag
	flag.Var(&existing, "existing", "reuse a completed GROUP=MEASUREMENT-ID (repeatable)")
	flag.Parse()

	if *campaignID == "" || *targetsDir == "" {
		log.Fatal("--campaign-id and --targets-dir are required")
	}
	if !interprotocolworkflow.SafeID.MatchString(*campaignID) {
		log.Fatal("--campaign-id may only contain letters, digits, '.', '_' and '-'")
	}
	if *tcpPort > 65535 || *udpPort > 65535 {
		log.Fatal("ports must be in [0,65535]")
	}
	groups, err := parseGroups(*groupsFlag)
	if err != nil {
		log.Fatal(err)
	}
	existingIDs, err := parseExisting(existing)
	if err != nil {
		log.Fatal(err)
	}
	runIDProvided := *runID != ""
	if !runIDProvided && !(*resume && *manifestFlag != "") {
		*runID = *campaignID + "_" + time.Now().Format("2006-01-02_15-04-05")
	}
	if *runID != "" && !interprotocolworkflow.SafeID.MatchString(*runID) {
		log.Fatal("--run-id may only contain letters, digits, '.', '_' and '-'")
	}
	manifestPath := *manifestFlag
	if manifestPath == "" {
		manifestPath = filepath.Join(*runRoot, *runID, "manifest.json")
	}
	if *resume && *manifestFlag == "" && !runIDProvided {
		log.Fatal("--resume requires --manifest or --run-id")
	}

	var manifest *interprotocolworkflow.Manifest
	if *resume {
		manifest, err = interprotocolworkflow.Load(manifestPath)
		if err != nil {
			log.Fatal(err)
		}
		if !runIDProvided {
			*runID = manifest.RunID
		}
		if manifest.CampaignID != *campaignID || manifest.RunID != *runID {
			log.Fatal("resume manifest does not match --campaign-id/--run-id")
		}
	} else {
		now := time.Now().UTC().Format(time.RFC3339)
		manifest = &interprotocolworkflow.Manifest{
			Version: interprotocolworkflow.Version, CampaignID: *campaignID, RunID: *runID,
			CreatedAt: now, Config: *configPath, TargetsDir: *targetsDir,
			TCPPort: uint16(*tcpPort), UDPPort: uint16(*udpPort),
			Groups: make(map[string]*interprotocolworkflow.GroupRun),
		}
		for _, group := range groups {
			target, absoluteErr := filepath.Abs(filepath.Join(*targetsDir, group+"-targets.pq"))
			if absoluteErr != nil {
				log.Fatal(absoluteErr)
			}
			if _, statErr := os.Stat(target); statErr != nil {
				log.Fatalf("target file for %s: %v", group, statErr)
			}
			state := &interprotocolworkflow.GroupRun{
				Protocols:  append([]string(nil), interprotocolworkflow.GroupProtocols[group]...),
				TargetFile: target, Status: "pending",
			}
			if id := existingIDs[group]; id != "" {
				state.Status, state.MeasurementID, state.CompletedAt = "complete", id, now
			}
			manifest.Groups[group] = state
		}
		if err := interprotocolworkflow.Save(manifestPath, manifest); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("inter-protocol campaign run_id=%s manifest=%s", manifest.RunID, manifestPath)

	for _, group := range interprotocolworkflow.OrderedGroups {
		state, selected := manifest.Groups[group]
		if !selected || state.Status == "complete" {
			continue
		}
		state.Status = "running"
		state.Error = ""
		state.StartedAt = time.Now().UTC().Format(time.RFC3339)
		if err := interprotocolworkflow.Save(manifestPath, manifest); err != nil {
			log.Fatal(err)
		}
		args := []string{
			"--config", manifest.Config,
			"--target-file", state.TargetFile,
			"--protocols", strings.Join(state.Protocols, ","),
			"--tcp-port", fmt.Sprint(manifest.TCPPort),
			"--udp-port", fmt.Sprint(manifest.UDPPort),
			"--print-id",
		}
		log.Printf("starting inter-protocol group %s", group)
		command := exec.Command(*measureBinary, args...)
		var stdout bytes.Buffer
		command.Stdout = io.MultiWriter(os.Stdout, &stdout)
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			state.Status, state.Error = "failed", err.Error()
			_ = interprotocolworkflow.Save(manifestPath, manifest)
			log.Fatalf("measurement %s failed: %v; resume with this manifest", group, err)
		}
		id, err := measurementID(stdout.String(), group)
		if err != nil {
			state.Status, state.Error = "failed", err.Error()
			_ = interprotocolworkflow.Save(manifestPath, manifest)
			log.Fatal(err)
		}
		state.Status, state.MeasurementID = "complete", id
		state.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if err := interprotocolworkflow.Save(manifestPath, manifest); err != nil {
			log.Fatal(err)
		}
	}
	if *noPublish {
		fmt.Printf("campaign completed locally: %s\n", manifestPath)
		return
	}
	requestURI, err := interprotocolworkflow.Publish(context.Background(), manifest.Config, manifestPath)
	if err != nil {
		log.Fatalf("publish analysis request: %v; measurements are complete and can be published by resuming", err)
	}
	fmt.Printf("campaign manifest: %s\nanalysis request: %s\n", manifestPath, requestURI)
	if *noWait {
		return
	}
	done, err := interprotocolworkflow.Wait(context.Background(), manifest.Config, manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("analysis completed: rows=%d results=%s\n", done.Rows, done.ResultPrefix)
}
