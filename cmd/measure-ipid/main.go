package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/alxweis/ipid-measure/internal/analysisworkflow"
	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/logger"
	"github.com/alxweis/ipid-measure/internal/paths"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/internal/upload"
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
	connectionCountFlag := flag.Int("connection_count", 0, "override connection_count (even, [2,16]); 0 keeps the configured value")
	requestsPerConnFlag := flag.Int("requests_per_connection", 0, "override requests_per_connection ([1,100]); 0 keeps the configured value")
	measurementModeFlag := flag.String("measurement_mode", "", "override measurement_mode (fixed-interval|rt-based)")
	requestIntervalFlag := flag.Duration("fixed_interval.request_interval", -1, "override fixed_interval.request_interval (e.g. 20ms); negative keeps the configured value")
	minReplyRateFlag := flag.Float64("fixed_interval.minimum_reply_rate", -1, "override fixed_interval.minimum_reply_rate [0.0,1.0]; negative keeps the configured value")
	establishConnFlag := flag.String("tcp.establish_connection", "", "override tcp.establish_connection (true|false); empty keeps the configured value")
	targetFileFlag := flag.String("target-file", "", "override the zmap parquet used as the target set")
	analysisWorkflowFlag := flag.String("analysis_workflow.enable", "", "override analysis_workflow.enable (true|false); empty keeps the configured value")
	printID := flag.Bool("print-id", false, "print the measurement id to stdout on success")
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
	var analysisWorkflow *bool
	if *analysisWorkflowFlag != "" {
		b, err := strconv.ParseBool(*analysisWorkflowFlag)
		if err != nil {
			log.Fatalf("invalid --analysis_workflow.enable %q: %v", *analysisWorkflowFlag, err)
		}
		analysisWorkflow = &b
	}

	c, err := config.LoadIPIDConfig(configFilePath, func(c *config.IPIDConfig) {
		applyIPIDFlags(
			c,
			*zmapFlag,
			*targetFileFlag,
			*connectionCountFlag,
			*requestsPerConnFlag,
			*measurementModeFlag,
			*requestIntervalFlag,
			*minReplyRateFlag,
			establishConn,
			analysisWorkflow,
		)
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

	recordCount, err := measurement.Run(c, m)
	if err != nil {
		log.Fatalf("run measurement (wrote %d records before error): %v", recordCount, err)
	}

	log.Printf("ipid measurement completed: %s (records=%d)", m.Path, recordCount)

	if err = upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}
	if c.AnalysisWorkflowConfig.Enable {
		resultPath, err := analysisworkflow.RequestAndWait(
			context.Background(), c.AnalysisWorkflowConfig, c.UploadConfig, m.Measurement,
		)
		if err != nil {
			log.Fatalf("analysis workflow: %v", err)
		}
		log.Printf("analysis workflow completed: %s", resultPath)
	}

	if *printID {
		fmt.Println(m.ID)
	}
}

func applyIPIDFlags(
	c *config.IPIDConfig,
	zmapID string,
	targetFile string,
	connectionCount int,
	requestsPerConnection int,
	measurementMode string,
	requestInterval time.Duration,
	minReplyRate float64,
	establishConn *bool,
	analysisWorkflow *bool,
) {
	if zmapID != "" {
		c.ZMapID = zmapID
	}
	if targetFile != "" {
		c.TargetFile = targetFile
	}
	if connectionCount > 0 {
		c.ConnectionCount = uint16(connectionCount)
	}
	if requestsPerConnection > 0 {
		c.RequestsPerConnection = uint16(requestsPerConnection)
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
	if analysisWorkflow != nil {
		c.AnalysisWorkflowConfig.Enable = *analysisWorkflow
	}
}
