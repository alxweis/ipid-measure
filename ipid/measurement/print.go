package measurement

import (
	"github.com/alxweis/ipid-measure/internal/types"
	"log"
)

// printConfig logs the effective configuration once at startup so every run is
// self-documenting in its log output.
func printConfig() {
	c := Config

	log.Printf("=== IPID measurement configuration ===")
	log.Printf("zmap_input            = %s", c.ZMapFilePath)
	log.Printf("payload               = %s", c.ZMapPayload)
	if c.ZMapPort != nil {
		log.Printf("port                  = %d", *c.ZMapPort)
	}
	log.Printf("connection_count      = %d", c.ConnectionCount)
	log.Printf("requests_per_conn     = %d", c.RequestsPerConnection)
	log.Printf("request_count         = %d", RequestCount)
	log.Printf("measurement_mode      = %s", c.MeasurementMode)

	if c.MeasurementMode == "fixed-interval" {
		log.Printf("request_interval      = %s", c.FixedIntervalConfig.RequestInterval)
		log.Printf("minimum_reply_rate    = %.2f", c.FixedIntervalConfig.MinimumReplyRate)
	}
	if c.ZMapPayload == types.PayloadTCP {
		if c.TCPConfig.EstablishConnection {
			log.Printf("establish_connection = %t", c.TCPConfig.EstablishConnection)
		} else {
			log.Printf("request_flags    = %v", c.TCPConfig.RequestFlags)
			log.Printf("reply_flags      = %v", c.TCPConfig.ReplyFlags)
		}
	}
	log.Printf("request_ip_ids        = %v", c.RequestIPIDs)
	log.Printf("maximum_tolerated_rtt = %s", c.MaximumToleratedRTT)

	log.Printf("bandwidth (bit/s)     = %s", c.Bandwidth.Str())
	log.Printf("packets_per_second    = %s", c.PacketsPerSecond.Str())
	log.Printf("concurrency           = %d", c.Concurrency)

	log.Printf("interface_a           = %s (%s)", c.Interfaces.A.Name, c.Interfaces.A.IP)
	log.Printf("interface_b           = %s (%s)", c.Interfaces.B.Name, c.Interfaces.B.IP)

	log.Printf("output_path           = %s", Paths.Path)
	log.Printf("======================================")
}
