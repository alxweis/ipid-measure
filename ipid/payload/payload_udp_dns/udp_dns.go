package payload_udp_dns

import (
	"github.com/google/gopacket"
	"github.com/netd-tud/ipid-measure/ipid/dns"
	"github.com/netd-tud/ipid-measure/ipid/udp"
)

func Layer(seqNum uint16) []gopacket.SerializableLayer {
	return []gopacket.SerializableLayer{udp.Layer(), dns.Layer(seqNum)}
}
