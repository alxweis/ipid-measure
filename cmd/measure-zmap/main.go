package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/internal/upload"
	"github.com/alxweis/ipid-measure/zmap"
)

const GoMemLimitDefaultBytes = 256 << 20 // 256 MiB

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configFlag := flag.String("config", files.ZMapConfigFilePath, "path to the zmap config file")
	payloadFlag := flag.String("payload", "", "override payload (icmp|tcp|udp-dns)")
	portFlag := flag.Int("port", -1, "override destination port (-1 keeps the configured value)")
	probeArgsFlag := flag.String("probe-args", "", `override dns probe_args, e.g. "A,www.example.com"`)
	printID := flag.Bool("print-id", false, "print the measurement id to stdout on success")
	flag.Parse()

	configFilePath, err := filepath.Abs(*configFlag)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	c, err := config.LoadZMapConfig(configFilePath, func(c *config.ZMapConfig) {
		applyZMapFlags(c, *payloadFlag, *portFlag, *probeArgsFlag)
	})
	if err != nil {
		log.Fatalf("load zmap config: %v", err)
	}

	debug.SetMemoryLimit(config.GoMemoryLimitOrDefault(c.GoMemoryLimit, GoMemLimitDefaultBytes))

	m := paths.NewZMapMeasurement(c.Payload, c.Port, time.Now())

	if err := m.CreateDirectory(); err != nil {
		log.Fatalf("create measurement directory: %v", err)
	}
	if err := m.CreateConfigSnapshot(c); err != nil {
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

	if err = upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}

	if *printID {
		fmt.Println(m.ID)
	}
}

func applyZMapFlags(c *config.ZMapConfig, payload string, port int, probeArgs string) {
	if payload != "" {
		c.Payload = types.Payload(payload)
	}
	if port >= 0 {
		p := uint16(port)
		c.Port = &p
	}
	if probeArgs != "" {
		c.ProbeArgs = &probeArgs
	}
	if c.Payload == types.PayloadICMP {
		c.Port = nil
		c.ProbeArgs = nil
	}
}
