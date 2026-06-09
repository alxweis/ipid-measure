package payload_icmp

import (
	"github.com/google/gopacket"
	"github.com/netd-tud/ipid-measure/ipid/icmp"
)

func Layer(seqNum uint16) []gopacket.SerializableLayer {
	return []gopacket.SerializableLayer{icmp.Layer(seqNum)}
}
