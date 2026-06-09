package seqnum

import (
	"github.com/netd-tud/ipid-measure/ipid/measurement"
)

func GetConnectionIndex(seqNum uint16) uint16 {
	return seqNum / measurement.Config.ConnectionCount
}
