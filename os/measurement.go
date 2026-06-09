package os

import (
	"context"
	"fmt"
	"log"
	osstd "os"
	"os/signal"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
)

// scaledNumberLog renders an optional ScaledNumber for the startup log:
// "(unset)" when nil, the underlying integer otherwise.
func scaledNumberLog(s *config.ScaledNumber) string {
	if s == nil {
		return "(unset)"
	}
	return fmt.Sprintf("%d", uint64(*s))
}

// Run executes one OS-fingerprinting measurement end-to-end.
func Run(c *config.OSConfig, m *paths.OSMeasurement) (uint64, error) {
	log.Printf("=== OS measurement configuration ===")
	log.Printf("zmap_input             = %s", m.ZMapLinkPath)
	log.Printf("output_path            = %s", m.MeasurementFilePath)
	log.Printf("interface              = %s (%s)", c.Interface.Name, c.Interface.IP)
	log.Printf("zgrab2_senders         = %s", scaledNumberLog(c.ZGrab2Senders))
	log.Printf("zdns_threads           = %s", scaledNumberLog(c.ZDNSThreads))
	log.Printf("snmp_workers           = %s", scaledNumberLog(c.SNMPWorkers))
	log.Printf("connect_timeout        = %s", c.ConnectTimeout)
	log.Printf("read_timeout           = %s", c.ReadTimeout)
	log.Printf("snmp_timeout           = %s", c.SNMPTimeout)
	log.Printf("snmp_community         = %s", c.SNMPCommunity)
	log.Printf("modules:")
	log.Printf("  ssh                  = %v", c.Modules.SSH)
	log.Printf("  smb                  = %v", c.Modules.SMB)
	log.Printf("  http                 = %v", c.Modules.HTTP)
	log.Printf("  https                = %v", c.Modules.HTTPS)
	log.Printf("  snmp                 = %v", c.Modules.SNMP)
	log.Printf("  smtp                 = %v", c.Modules.SMTP)
	log.Printf("  mssql                = %v", c.Modules.MSSQL)
	log.Printf("  pop3                 = %v", c.Modules.POP3)
	log.Printf("  imap                 = %v", c.Modules.IMAP)
	log.Printf("  ftp                  = %v", c.Modules.FTP)
	log.Printf("  telnet               = %v", c.Modules.TELNET)
	log.Printf("  dns_chaos            = %v", c.Modules.DNSChaos)
	log.Printf("====================================")

	// Top-level context with interrupt handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on Ctrl+C / SIGTERM.
	sigCh := make(chan osstd.Signal, 1)
	signal.Notify(sigCh, osstd.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			log.Printf("os: interrupt received, shutting down...")
			cancel()
		case <-ctx.Done():
		}
	}()

	return runPipeline(ctx, c, m.ZMapLinkPath, m.MeasurementFilePath)
}
