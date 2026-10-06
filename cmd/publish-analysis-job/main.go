package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/postprocessworkflow"
	"github.com/alxweis/ipid-measure/internal/root"
)

func main() {
	zmapID := flag.String("zmap", "", "zmap measurement id (also used as job id)")
	osID := flag.String("os", "", "OS measurement id")
	rtBase := flag.String("rt-base", "", "stateless RT-based base IPID measurement id")
	fixedMass := flag.String("fixed-mass", "", "stateless fixed-interval mass IPID id")
	fixedBase := flag.String("fixed-base", "", "stateless fixed-interval base IPID id")
	fixedBaseTarget := flag.String("fixed-base-target", "", "sampled ZMap-compatible target used by no-connection fixed-interval base measurements")
	connectionTarget := flag.String("connection-target", "", "shared SYN-ACK target sample for TCP connection measurements")
	connectionRT := flag.String("connection-rt-base", "", "TCP connection RT-based base IPID id")
	connectionFI := flag.String("connection-fixed-base", "", "TCP connection fixed-interval base IPID id")
	randomReproducibilityRepeats := flag.String("random-reproducibility-repeats", "", "comma-separated five RANDOM reproducibility measurement ids")
	randomReproducibilityMaximumTargets := flag.Int("random-reproducibility-maximum-targets", 10000, "maximum reproducibility targets")
	randomReproducibilitySelectionSeed := flag.Int("random-reproducibility-selection-seed", 42, "deterministic reproducibility selection seed")
	zmapConfig := flag.String("zmap-config", files.ZMapConfigFilePath, "zmap config path")
	osConfig := flag.String("os-config", files.OSConfigFilePath, "OS config path")
	ipidConfig := flag.String("ipid-config", files.IPIDConfigFilePath, "IPID config path")
	flag.Parse()
	var repeatIDs []string
	if *randomReproducibilityRepeats != "" {
		repeatIDs = strings.Split(*randomReproducibilityRepeats, ",")
	}

	requestURI, err := postprocessworkflow.Publish(
		context.Background(),
		postprocessworkflow.Measurements{
			ZMap:                                *zmapID,
			OS:                                  *osID,
			RTBase:                              *rtBase,
			FixedMass:                           *fixedMass,
			FixedBase:                           *fixedBase,
			FixedBaseTarget:                     *fixedBaseTarget,
			ConnectionTarget:                    *connectionTarget,
			ConnectionRTBase:                    *connectionRT,
			ConnectionFIBase:                    *connectionFI,
			RandomReproducibilityRepeats:        repeatIDs,
			RandomReproducibilityMaximumTargets: *randomReproducibilityMaximumTargets,
			RandomReproducibilitySelectionSeed:  *randomReproducibilitySelectionSeed,
		},
		postprocessworkflow.ConfigPaths{
			ZMap: *zmapConfig,
			OS:   *osConfig,
			IPID: *ipidConfig,
		},
		filepath.Join(root.Root, "analysis-jobs"),
	)
	if err != nil {
		log.Fatalf("publish analysis job: %v", err)
	}
	fmt.Println(requestURI)
}
