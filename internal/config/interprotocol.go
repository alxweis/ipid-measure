package config

import "fmt"

// ConfigureInterprotocolSampling supplies the 4x25 per-protocol layout required
// by the production MULTI/RANDOM classifier. The request pattern is indexed by
// the flattened interleaved sequence number, exactly as in packet.Setup.
func ConfigureInterprotocolSampling(c *IPIDConfig, protocolCount int) error {
	if protocolCount != 2 && protocolCount != 3 {
		return fmt.Errorf("inter-protocol sampling requires two or three protocols")
	}
	if len(c.RequestIPIDs) == 0 {
		return fmt.Errorf("inter-protocol sampling requires request_ip_ids")
	}
	for protocol := 0; protocol < protocolCount; protocol++ {
		first := c.RequestIPIDs[protocol%len(c.RequestIPIDs)]
		varied := false
		for position := 1; position < 100; position++ {
			index := (position*protocolCount + protocol) % len(c.RequestIPIDs)
			if c.RequestIPIDs[index] != first {
				varied = true
				break
			}
		}
		if !varied {
			return fmt.Errorf("request_ip_ids is constant for interleaved protocol %d: use a varying pattern (for example the five values in config/ipid.yaml.example) to distinguish REFLECTION from CONSTANT", protocol)
		}
	}
	c.ConnectionCount = 4
	c.RequestsPerConnection = 25
	return nil
}
