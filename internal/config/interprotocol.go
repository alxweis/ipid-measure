package config

import (
	"fmt"

	"github.com/alxweis/ipid-measure/internal/types"
)

func InterprotocolSample(strategy string) (string, error) {
	switch strategy {
	case "REFLECTION", "CONSTANT", "SINGLE", "PER_DESTINATION", "PER_BUCKET":
		return "base", nil
	case "MULTI", "RANDOM":
		return "mass", nil
	default:
		return "", fmt.Errorf("unsupported interprotocol strategy %q", strategy)
	}
}

// Each protocol receives the same request pattern, indexed by logical position.
func ConfigureInterprotocolSampling(c *IPIDConfig, protocolCount int, sample string) error {
	if protocolCount != 2 && protocolCount != 3 {
		return fmt.Errorf("interprotocol sampling requires two or three protocols")
	}
	c.ConnectionCount = 4
	switch sample {
	case "base":
		c.RequestsPerConnection = 4
		c.MeasurementMode = types.MeasurementModeRTBased
	case "mass":
		c.RequestsPerConnection = 25
		c.MeasurementMode = types.MeasurementModeFixedInterval
		c.FixedIntervalConfig.MinimumReplyRate = 0.8
		if c.FixedIntervalConfig.RequestInterval <= 0 {
			return fmt.Errorf("interprotocol MASS requires a positive request_interval")
		}
	default:
		return fmt.Errorf("interprotocol sample must be base or mass")
	}
	if len(c.RequestIPIDs) == 0 {
		return fmt.Errorf("interprotocol sampling requires request_ip_ids")
	}
	for i := 1; i < int(c.ConnectionCount*c.RequestsPerConnection); i++ {
		if c.RequestIPIDs[i%len(c.RequestIPIDs)] != c.RequestIPIDs[0] {
			return nil
		}
	}
	return fmt.Errorf("request_ip_ids must vary within the per-protocol sequence")
}
