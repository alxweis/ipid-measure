package main

import (
	"log"
	"path/filepath"
	"time"

	"github.com/netd-tud/ipid-measure/internal/config"
	"github.com/netd-tud/ipid-measure/internal/files"
	"github.com/netd-tud/ipid-measure/internal/paths"
	"github.com/netd-tud/ipid-measure/ipid/measurement"

	// Blank imports register each sub-package's orchestration hooks into the
	// measurement package via their init() functions. measurement itself imports
	// no sub-package (so the import graph stays acyclic), which is why the wiring
	// is done here at the composition root. Importing the top-level stages pulls
	// in their transitive dependencies (packet, payload, port, sender, probe...),
	// so every hook is registered.
	_ "github.com/netd-tud/ipid-measure/ipid/receiver"
	_ "github.com/netd-tud/ipid-measure/ipid/stats"
	_ "github.com/netd-tud/ipid-measure/ipid/worker"
)

func main() {
	configFilePath, err := filepath.Abs(files.IPIDConfigFilePath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	c, err := config.LoadIPIDConfig(configFilePath)
	if err != nil {
		log.Fatalf("load ipid config: %v", err)
	}

	m := paths.NewIPIDMeasurement(
		c.ZMapPayload,
		c.ZMapPort,
		time.Now(),
	)

	if err := m.CreateDirectory(); err != nil {
		log.Fatalf("create measurement directory: %v", err)
	}

	if err := m.CreateZMapLink(c.ZMapFilePath); err != nil {
		log.Fatalf("create zmap symlink: %v", err)
	}

	if err := m.CreateConfigSnapshot(configFilePath); err != nil {
		log.Fatalf("create config snapshot: %v", err)
	}

	if err := measurement.Run(c, m); err != nil {
		log.Fatalf("run measurement: %v", err)
	}
}
