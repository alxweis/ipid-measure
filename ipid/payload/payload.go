package payload

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/icmp"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload/payload_icmp"
	"github.com/alxweis/ipid-measure/ipid/payload/payload_tcp"
	"github.com/alxweis/ipid-measure/ipid/payload/payload_udp_dns"
	"github.com/alxweis/ipid-measure/ipid/tcp"
	"github.com/alxweis/ipid-measure/ipid/udp"
)

type Payload struct {
	ID            types.Payload
	ReceiveFilter string
	ProtocolID    layers.IPProtocol
	Layer         func(seqNum uint16) []gopacket.SerializableLayer
	SetChecksum   func(packet []byte)
}

var Active *Payload

var (
	ICMP = &Payload{
		ID:            types.PayloadICMP,
		ReceiveFilter: "icmp[icmptype] == icmp-echoreply",
		ProtocolID:    layers.IPProtocolICMPv4,
		Layer:         payload_icmp.Layer,
		SetChecksum:   icmp.SetChecksum,
	}

	TCP = &Payload{
		ID:            types.PayloadTCP,
		ReceiveFilter: "",
		ProtocolID:    layers.IPProtocolTCP,
		Layer:         payload_tcp.Layer,
		SetChecksum:   tcp.SetChecksum,
	}

	UdpDns = &Payload{
		ID:            types.PayloadUDPDNS,
		ReceiveFilter: "",
		ProtocolID:    layers.IPProtocolUDP,
		Layer:         payload_udp_dns.Layer,
		SetChecksum:   udp.SetChecksum,
	}

	payloads = map[types.Payload]*Payload{
		types.PayloadICMP:   ICMP,
		types.PayloadTCP:    TCP,
		types.PayloadUDPDNS: UdpDns,
	}
)

func Get() *Payload {
	return payloads[measurement.Config.ZMapPayload]
}

func Setup() {
	Active = Get()
	measurement.TcpEstablishConnection =
		Active.ProtocolID == layers.IPProtocolTCP &&
			measurement.Config.TCPConfig.EstablishConnection

	measurement.HasPorts = Active.ProtocolID == layers.IPProtocolTCP || Active.ProtocolID == layers.IPProtocolUDP

}

func init() {
	measurement.SetupPayload = Setup
}
