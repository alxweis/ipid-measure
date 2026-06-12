package main

import (
	"log"
	"path/filepath"
	"runtime"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/zmap"
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configFilePath, err := filepath.Abs(files.ZMapConfigFilePath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	c, err := config.LoadZMapConfig(configFilePath)
	if err != nil {
		log.Fatalf("load zmap config: %v", err)
	}

	now := time.Now()
	m := paths.NewZMapMeasurement(c.Payload, c.Port, now)

	if err := m.CreateDirectory(); err != nil {
		log.Fatalf("create measurement directory: %v", err)
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

	written, err := zmap.Run(c, m)
	if err != nil {
		log.Fatalf("run zmap measurement (wrote %d records before error): %v", written, err)
	}

	log.Printf("zmap measurement completed: %s (records=%d)", m.Path, written)
}
