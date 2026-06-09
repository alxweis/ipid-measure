package payload_icmp

import (
	"github.com/alxweis/ipid-measure/ipid/icmp"
	"github.com/google/gopacket"
)

func Layer(seqNum uint16) []gopacket.SerializableLayer {
	return []gopacket.SerializableLayer{icmp.Layer(seqNum)}
}
