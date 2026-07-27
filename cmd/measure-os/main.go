package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
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

	configFlag := flag.String("config", files.OSConfigFilePath, "path to the os config file")
	zmapFlag := flag.String("zmap", "", "override the zmap run id referenced in the config")
	secondarySampleRateFlag := flag.String(
		"secondary-sample-rate",
		"",
		"override the deterministic secondary-module sample rate [0,1]",
	)
	zgrab2SendersFlag := flag.String("zgrab2-senders", "", "override zgrab2 sender concurrency")
	zdnsThreadsFlag := flag.String("zdns-threads", "", "override zdns thread concurrency")
	snmpWorkersFlag := flag.String("snmp-workers", "", "override SNMP worker concurrency")
	connectTimeoutFlag := flag.Duration("connect-timeout", 0, "override application connect timeout")
	readTimeoutFlag := flag.Duration("read-timeout", 0, "override application read timeout")
	snmpTimeoutFlag := flag.Duration("snmp-timeout", 0, "override SNMP timeout")
	printID := flag.Bool("print-id", false, "print the measurement id to stdout on success")
	flag.Parse()

	configFilePath, err := filepath.Abs(*configFlag)
	if err != nil {
		log.Fatalf("resolve config path: %v", err)
	}

	zgrab2Senders := parseOptionalScaledNumber("zgrab2-senders", *zgrab2SendersFlag)
	zdnsThreads := parseOptionalScaledNumber("zdns-threads", *zdnsThreadsFlag)
	snmpWorkers := parseOptionalScaledNumber("snmp-workers", *snmpWorkersFlag)
	secondarySampleRate := parseOptionalFloat64(
		"secondary-sample-rate",
		*secondarySampleRateFlag,
	)

	c, err := config.LoadOSConfig(configFilePath, func(c *config.OSConfig) {
		if *zmapFlag != "" {
			c.ZMapID = *zmapFlag
		}
		if secondarySampleRate != nil {
			c.SecondarySampleRate = *secondarySampleRate
		}
		if zgrab2Senders != nil {
			c.ZGrab2Senders = zgrab2Senders
		}
		if zdnsThreads != nil {
			c.ZDNSThreads = zdnsThreads
		}
		if snmpWorkers != nil {
			c.SNMPWorkers = snmpWorkers
		}
		if *connectTimeoutFlag != 0 {
			c.ConnectTimeout = *connectTimeoutFlag
		}
		if *readTimeoutFlag != 0 {
			c.ReadTimeout = *readTimeoutFlag
		}
		if *snmpTimeoutFlag != 0 {
			c.SNMPTimeout = *snmpTimeoutFlag
		}
	})
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

	written, err := osmod.Run(c, m)
	if err != nil {
		log.Fatalf("run os measurement (wrote %d records before error): %v", written, err)
	}

	log.Printf("os measurement completed: %s (records=%d)", m.Path, written)

	if err = upload.Upload(c.UploadConfig, m.Measurement); err != nil {
		log.Fatalf("upload measurement: %v", err)
	}

	if *printID {
		fmt.Println(m.ID)
	}
}

func parseOptionalScaledNumber(name, value string) *config.ScaledNumber {
	if value == "" {
		return nil
	}
	parsed, err := config.ParseScaledNumber(value)
	if err != nil {
		log.Fatalf("parse --%s: %v", name, err)
	}
	result := config.ScaledNumber(parsed)
	return &result
}

func parseOptionalFloat64(name, value string) *float64 {
	if value == "" {
		return nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		log.Fatalf("parse --%s: %v", name, err)
	}
	return &parsed
}
