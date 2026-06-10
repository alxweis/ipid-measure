package os

import (
	"context"
	"log"
	osstd "os"
	"os/signal"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
)

// Run executes one OS-fingerprinting measurement end-to-end.
func Run(c *config.OSConfig, m *paths.OSMeasurement) (uint64, error) {
	log.Printf("=== OS measurement configuration ===")
	log.Printf("zmap_input             = %s", c.ZMapFilePath)
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

	log.Printf("zgrab2_senders         = %s", c.ZGrab2Senders.Str())
	log.Printf("zdns_threads           = %s", c.ZDNSThreads.Str())
	log.Printf("snmp_workers           = %s", c.SNMPWorkers.Str())

	log.Printf("interface              = %s (%s)", c.Interface.Name, c.Interface.IP)

	log.Printf("connect_timeout        = %s", c.ConnectTimeout)
	log.Printf("read_timeout           = %s", c.ReadTimeout)
	log.Printf("snmp_timeout           = %s", c.SNMPTimeout)
	log.Printf("snmp_community         = %s", c.SNMPCommunity)

	log.Printf("output_path            = %s", m.MeasurementFilePath)
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
