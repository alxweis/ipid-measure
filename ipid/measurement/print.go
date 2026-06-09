package measurement

import "log"

// printConfig logs the effective configuration once at startup so every run is
// self-documenting in its log output.
func printConfig() {
	c := Config

	log.Printf("=== IPID measurement configuration ===")
	log.Printf("zmap_reference        = %s", c.ZMapID)
	log.Printf("payload               = %s", c.ZMapPayload)
	if c.ZMapPort != nil {
		log.Printf("port                  = %d", *c.ZMapPort)
	}
	log.Printf("measurement_mode      = %s", c.MeasurementMode)
	log.Printf("connection_count      = %d", c.ConnectionCount)
	log.Printf("requests_per_conn     = %d", c.RequestsPerConnection)
	log.Printf("request_count         = %d", RequestCount)
	log.Printf("maximum_tolerated_rtt = %s", c.MaximumToleratedRTT)
	if c.MeasurementMode == "fixed-interval" {
		log.Printf("request_interval      = %s", c.FixedIntervalConfig.RequestInterval)
		log.Printf("minimum_reply_rate    = %.2f", c.FixedIntervalConfig.MinimumReplyRate)
	}
	log.Printf("worker_count          = %d", c.WorkerCount)
	log.Printf("concurrency           = %d", c.Concurrency)
	log.Printf("bandwidth (bit/s)     = %d", uint64(c.Bandwidth))
	log.Printf("packets_per_second    = %d", uint64(c.PacketsPerSecond))
	log.Printf("worker_chan_size      = %d", c.WorkerTargetChannelSize)
	log.Printf("interface_a           = %s (%s)", c.Interfaces.A.Name, c.Interfaces.A.IP)
	log.Printf("interface_b           = %s (%s)", c.Interfaces.B.Name, c.Interfaces.B.IP)
	log.Printf("output_path           = %s", Paths.Path)
	log.Printf("======================================")
}
