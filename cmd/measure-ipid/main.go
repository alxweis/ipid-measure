package main

import (
	"github.com/alxweis/ipid-measure/internal/upload"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/ipid/measurement"

	// Blank imports register each sub-package's orchestration hooks into the
	// measurement package via their init() functions. measurement itself imports
	// no sub-package (so the import graph stays acyclic), which is why the wiring
	// is done here at the composition root. Importing the top-level stages pulls
	// in their transitive dependencies (packet, payload, port, sender, probe...),
	// so every hook is registered.
	_ "github.com/alxweis/ipid-measure/ipid/receiver"
	_ "github.com/alxweis/ipid-measure/ipid/stats"
	_ "github.com/alxweis/ipid-measure/ipid/worker"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configFilePath, err := filepath.Abs(files.IPIDConfigFilePath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	c, err := config.LoadIPIDConfig(configFilePath)
	if err != nil {
		log.Fatalf("load ipid config: %v", err)
	}

	m := paths.NewIPIDMeasurement(c.ZMapPayload, c.ZMapPort, time.Now())

	if err := m.CreateDirectory(); err != nil {
		log.Fatalf("create measurement directory: %v", err)
	}
	if err := m.CreateZMapLink(c.ZMapFilePath); err != nil {
		log.Fatalf("create zmap symlink: %v", err)
	}
	if err := m.CreateConfigSnapshot(configFilePath); err != nil {
		log.Fatalf("create config snapshot: %v", err)
	}

	if c.LogToFile {
		closer, err := logger.SetupFile(m.LogFilePath)
		if err != nil {
			log.Fatalf("setup log file: %v", err)
		}
		defer closer()
	}

	records, err := measurement.Run(c, m)
	if err != nil {
		log.Fatalf("run measurement (wrote %d records before error): %v", records, err)
	}

	log.Printf("ipid measurement completed: %s (records=%d)", m.Path, records)

	if err = upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}
}
