package ip

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

// Layer builds an IPv4 header layer. The protocol is passed in (rather than read
// from a global) so that this package stays a dependency leaf. The destination
// is left zero here; packet.BuildPackets patches it per target in place.
func Layer(ipID uint16, senderIP net.IP, protocol layers.IPProtocol) gopacket.SerializableLayer {
	return &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      64,
		Id:       ipID,
		Flags:    0,
		Protocol: protocol,
		SrcIP:    senderIP,
		DstIP:    net.IPv4(0, 0, 0, 0),
	}
}
