package main

import (
	"flag"
	"log"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/alxweis/ipid-measure/internal/upload"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"

	_ "github.com/alxweis/ipid-measure/ipid/receiver"
	_ "github.com/alxweis/ipid-measure/ipid/stats"
	_ "github.com/alxweis/ipid-measure/ipid/worker"
)

const GoMemLimitDefaultBytes = 700 << 20 // 700 MiB

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	configFlag := flag.String("config", files.IPIDConfigFilePath, "path to the ipid config file")
	zmapFlag := flag.String("zmap", "", "override the zmap run id referenced in the config")
	measurementModeFlag := flag.String("measurement_mode", "", "override measurement_mode (fixed-interval|rt-based)")
	requestIntervalFlag := flag.Duration("fixed_interval.request_interval", -1, "override fixed_interval.request_interval (e.g. 20ms); negative keeps the configured value")
	minReplyRateFlag := flag.Float64("fixed_interval.minimum_reply_rate", -1, "override fixed_interval.minimum_reply_rate [0.0,1.0]; negative keeps the configured value")
	establishConnFlag := flag.String("tcp.establish_connection", "", "override tcp.establish_connection (true|false); empty keeps the configured value")
	flag.Parse()

	configFilePath, err := filepath.Abs(*configFlag)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	// Pre-parse the tri-state boolean here so the apply closure stays error-free.
	var establishConn *bool
	if *establishConnFlag != "" {
		b, err := strconv.ParseBool(*establishConnFlag)
		if err != nil {
			log.Fatalf("invalid --tcp.establish_connection %q: %v", *establishConnFlag, err)
		}
		establishConn = &b
	}

	c, err := config.LoadIPIDConfig(configFilePath, func(c *config.IPIDConfig) {
		applyIPIDFlags(c, *zmapFlag, *measurementModeFlag, *requestIntervalFlag, *minReplyRateFlag, establishConn)
	})
	if err != nil {
		log.Fatalf("load ipid config: %v", err)
	}

	debug.SetMemoryLimit(config.GoMemoryLimitOrDefault(c.GoMemoryLimit, GoMemLimitDefaultBytes))

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

	recordCount, err := measurement.Run(c, m)
	if err != nil {
		log.Fatalf("run measurement (wrote %d records before error): %v", recordCount, err)
	}

	log.Printf("ipid measurement completed: %s (records=%d)", m.Path, recordCount)

	if err = upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}
}

func applyIPIDFlags(
	c *config.IPIDConfig,
	zmapID string,
	measurementMode string,
	requestInterval time.Duration,
	minReplyRate float64,
	establishConn *bool,
) {
	if zmapID != "" {
		c.ZMapID = zmapID
	}
	if measurementMode != "" {
		c.MeasurementMode = types.MeasurementMode(measurementMode)
	}
	if requestInterval >= 0 {
		c.FixedIntervalConfig.RequestInterval = requestInterval
	}
	if minReplyRate >= 0 {
		c.FixedIntervalConfig.MinimumReplyRate = minReplyRate
	}
	if establishConn != nil {
		c.TCPConfig.EstablishConnection = *establishConn
	}
}
