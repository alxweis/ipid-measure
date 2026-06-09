package main

import (
	"log"
	"path/filepath"
	"time"

	"github.com/netd-tud/ipid-measure/internal/config"
	"github.com/netd-tud/ipid-measure/internal/files"
	"github.com/netd-tud/ipid-measure/internal/paths"
	osmod "github.com/netd-tud/ipid-measure/os"
)

func main() {
	configFilePath, err := filepath.Abs(files.OSConfigFilePath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	c, err := config.LoadOSConfig(configFilePath)
	if err != nil {
		log.Fatalf("load os config: %v", err)
	}

	now := time.Now()
	m := paths.NewOSMeasurement(c.ZMapPayload, c.ZMapPort, now)

	if err := m.CreateDirectory(); err != nil {
		log.Fatalf("create measurement directory: %v", err)
	}
	if err := m.CreateZMapLink(c.ZMapFilePath); err != nil {
		log.Fatalf("create zmap symlink: %v", err)
	}
	if err := m.CreateConfigSnapshot(configFilePath); err != nil {
		log.Fatalf("create config snapshot: %v", err)
	}

	written, err := osmod.Run(c, m)
	if err != nil {
		log.Fatalf("run os measurement (wrote %d before error): %v", written, err)
	}
	log.Printf("os measurement completed: %s (records=%d)", m.Path, written)
}
