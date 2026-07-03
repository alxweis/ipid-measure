package main

import (
	"log"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/upload"
	osmod "github.com/alxweis/ipid-measure/os"
)

const GoMemLimitDefaultBytes = 384 << 20 // 384 MiB

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configFilePath, err := filepath.Abs(files.OSConfigFilePath)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	c, err := config.LoadOSConfig(configFilePath)
	if err != nil {
		log.Fatalf("load os config: %v", err)
	}

	debug.SetMemoryLimit(config.GoMemoryLimitOrDefault(c.GoMemoryLimit, GoMemLimitDefaultBytes))

	m := paths.NewOSMeasurement(c.ZMapPayload, c.ZMapPort, time.Now())

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

	written, err := osmod.Run(c, m)
	if err != nil {
		log.Fatalf("run os measurement (wrote %d records before error): %v", written, err)
	}

	log.Printf("os measurement completed: %s (records=%d)", m.Path, written)

	if err = upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}
}
