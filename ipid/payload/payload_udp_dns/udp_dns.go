package payload_udp_dns

import (
	"github.com/alxweis/ipid-measure/ipid/dns"
	"github.com/alxweis/ipid-measure/ipid/udp"
	"github.com/google/gopacket"
)

func Layer(seqNum uint16) []gopacket.SerializableLayer {
	return []gopacket.SerializableLayer{udp.Layer(), dns.Layer(seqNum)}
}
