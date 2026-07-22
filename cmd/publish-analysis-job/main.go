package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"

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
	connectionRT := flag.String("connection-rt-base", "", "TCP connection RT-based base IPID id")
	connectionFI := flag.String("connection-fixed-base", "", "TCP connection fixed-interval base IPID id")
	zmapConfig := flag.String("zmap-config", files.ZMapConfigFilePath, "zmap config path")
	osConfig := flag.String("os-config", files.OSConfigFilePath, "OS config path")
	ipidConfig := flag.String("ipid-config", files.IPIDConfigFilePath, "IPID config path")
	flag.Parse()

	requestURI, err := postprocessworkflow.Publish(
		context.Background(),
		postprocessworkflow.Measurements{
			ZMap:             *zmapID,
			OS:               *osID,
			RTBase:           *rtBase,
			FixedMass:        *fixedMass,
			FixedBase:        *fixedBase,
			ConnectionRTBase: *connectionRT,
			ConnectionFIBase: *connectionFI,
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
