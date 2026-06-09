// Package os drives an OS-fingerprinting scan that, given a ZMap result set
// of responder IPs, runs a battery of application-layer probes per IP
// (zgrab2 for TCP services, zdns for DNS CHAOS, and an in-process SNMP UDP
// probe), heuristically extracts an OS family from the replies, and writes
// the result to a parquet file.
//
// Only IPs for which at least one probe yielded an inferrable OS family are
// written. The intent is that os.pq is dense in actionable rows.
package os

import (
	"context"
	"log"
	osstd "os"
	"os/signal"
	"syscall"

	"github.com/netd-tud/ipid-measure/internal/config"
	"github.com/netd-tud/ipid-measure/internal/paths"
)

// Run executes one OS-fingerprinting measurement end-to-end.
//
// The input ZMap parquet is read once; per-IP results from the three
// scanners are merged and written incrementally to outputPath.
//
// SIGINT/SIGTERM trigger a graceful shutdown: the IP feeder stops, the
// external subprocesses are sent SIGTERM (and SIGKILL after a grace
// period), the merger is flushed, and the parquet file is closed properly.
func Run(c *config.OSConfig, m *paths.OSMeasurement) (uint64, error) {
	rcfg := c.Resolve()

	log.Printf("=== OS measurement configuration ===")
	log.Printf("zmap_input             = %s", m.ZMapLinkPath)
	log.Printf("output_path            = %s", m.MeasurementFilePath)
	log.Printf("interface              = %s (%s)", rcfg.Interface.Name, rcfg.Interface.IP)
	log.Printf("zgrab2_senders         = %d", rcfg.ZGrab2Senders)
	log.Printf("zdns_threads           = %d", rcfg.ZDNSThreads)
	log.Printf("snmp_workers           = %d", rcfg.SNMPWorkers)
	log.Printf("connect_timeout        = %s", rcfg.ConnectTimeout)
	log.Printf("read_timeout           = %s", rcfg.ReadTimeout)
	log.Printf("snmp_timeout           = %s", rcfg.SNMPTimeout)
	log.Printf("snmp_community         = %s", rcfg.SNMPCommunity)
	log.Printf("modules:")
	for k, v := range rcfg.Modules {
		log.Printf("  %-10s = %v", k, v)
	}
	log.Printf("====================================")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on Ctrl+C / SIGTERM.
	sigCh := make(chan osstd.Signal, 1)
	signal.Notify(sigCh, osstd.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			log.Printf("os: interrupt received, shutting down scanners and flushing parquet...")
			cancel()
		case <-ctx.Done():
		}
	}()

	return runPipeline(ctx, rcfg, m.ZMapLinkPath, m.MeasurementFilePath)
}
