package payload

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/netd-tud/ipid-measure/internal/types"
	"github.com/netd-tud/ipid-measure/ipid/icmp"
	"github.com/netd-tud/ipid-measure/ipid/measurement"
	"github.com/netd-tud/ipid-measure/ipid/payload/payload_icmp"
	"github.com/netd-tud/ipid-measure/ipid/payload/payload_tcp"
	"github.com/netd-tud/ipid-measure/ipid/payload/payload_udp_dns"
	"github.com/netd-tud/ipid-measure/ipid/tcp"
	"github.com/netd-tud/ipid-measure/ipid/udp"
)

type Payload struct {
	ID            types.Payload
	ReceiveFilter string
	ProtocolID    layers.IPProtocol
	Layer         func(seqNum uint16) []gopacket.SerializableLayer
	SetChecksum   func(packet []byte)
}

// Active is the payload selected for this run. Owned by this package and set by
// Setup before any goroutine starts; read-only thereafter.
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

// Get returns the configured payload definition.
func Get() *Payload {
	return payloads[measurement.Config.ZMapPayload]
}

// Setup selects the active payload and derives the cached TcpEstablishConnection
// flag. Registered into measurement.SetupPayload.
func Setup() {
	Active = Get()
	measurement.TcpEstablishConnection =
		Active.ProtocolID == layers.IPProtocolTCP &&
			measurement.Config.TCPConfig.EstablishConnection
}

func init() {
	measurement.SetupPayload = Setup
}
