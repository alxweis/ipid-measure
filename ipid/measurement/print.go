package measurement

import (
	"github.com/alxweis/ipid-measure/internal/types"
	"log"
)

// printConfig logs the effective configuration.
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

	log.Printf("bandwidth (bit/s)     = %s", c.Bandwidth.String())
	log.Printf("packets_per_second    = %s", c.PacketsPerSecond.String())
	log.Printf("number_of_inflight_probes = %d", c.NumberOfInflightProbes)

	log.Printf("interface             = %s", c.Interfaces.Name)
	log.Printf("interface_ip_a        = %s", c.Interfaces.IPA)
	log.Printf("interface_ip_b        = %s", c.Interfaces.IPB)

	log.Printf("output_path           = %s", Paths.Path)
	log.Printf("======================================")
}
