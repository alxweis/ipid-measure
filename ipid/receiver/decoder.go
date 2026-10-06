package receiver

import (
	"slices"
	"sync/atomic"
	"time"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/diagnostics"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packetDecoder struct {
	eth        layers.Ethernet
	ipv4       layers.IPv4
	tcp        layers.TCP
	udp        layers.UDP
	dns        layers.DNS
	icmp       layers.ICMPv4
	headers    *gopacket.DecodingLayerParser
	transports map[layers.IPProtocol]*gopacket.DecodingLayerParser
	decoded    []gopacket.LayerType
}

func newPacketDecoder() *packetDecoder {
	d := &packetDecoder{decoded: make([]gopacket.LayerType, 0, 3)}
	d.headers = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ipv4)
	d.transports = map[layers.IPProtocol]*gopacket.DecodingLayerParser{
		layers.IPProtocolTCP:    gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &d.tcp),
		layers.IPProtocolUDP:    gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &d.udp, &d.dns),
		layers.IPProtocolICMPv4: gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv4, &d.icmp),
	}
	d.headers.IgnoreUnsupported = true
	for _, parser := range d.transports {
		parser.IgnoreUnsupported = true
	}
	return d
}

func (d *packetDecoder) process(data []byte, received time.Time) {
	headerStart := diagnostics.Headers.Start()
	headerErr := d.headers.DecodeLayers(data, &d.decoded)
	diagnostics.Headers.End(headerStart)
	if headerErr != nil ||
		!slices.Contains(d.decoded, layers.LayerTypeIPv4) || d.ipv4.Version != 4 {
		atomic.AddInt64(&stats.DropDecode, 1)
		return
	}
	var src, dst [4]byte
	copy(src[:], d.ipv4.SrcIP)
	copy(dst[:], d.ipv4.DstIP)
	entry := probe.Inflight.Lookup(src)
	if entry == nil {
		atomic.AddInt64(&stats.DropNoEntry, 1)
		return
	}
	if !entry.AcceptProtocol(d.ipv4.Protocol) {
		return
	}
	if d.ipv4.FragOffset != 0 || d.ipv4.Flags&layers.IPv4MoreFragments != 0 {
		atomic.AddInt64(&stats.DropProto, 1)
		return
	}
	transport := d.transports[d.ipv4.Protocol]
	if transport == nil {
		atomic.AddInt64(&stats.DropProto, 1)
		return
	}
	transportStart := diagnostics.Transport.Start()
	transportErr := transport.DecodeLayers(d.ipv4.Payload, &d.decoded)
	diagnostics.Transport.End(transportStart)
	if transportErr != nil {
		atomic.AddInt64(&stats.DropDecode, 1)
		return
	}
	var (
		port, length uint16
		seq, tcpSeq  uint32
		flags        sets.Set[string]
		ok           bool
	)
	switch d.ipv4.Protocol {
	case layers.IPProtocolTCP:
		seq, tcpSeq, port, flags, ok = extractTCP(&d.tcp, d.decoded)
		length = uint16(len(d.tcp.Payload))
	case layers.IPProtocolUDP:
		seq, port, flags, ok = extractUDPDNS(&d.udp, &d.dns, d.decoded)
	case layers.IPProtocolICMPv4:
		seq, port, flags, ok = extractICMP(&d.icmp, d.decoded)
	}
	if !ok {
		atomic.AddInt64(&stats.DropProto, 1)
		switch d.ipv4.Protocol {
		case layers.IPProtocolTCP:
			if slices.Contains(d.decoded, layers.LayerTypeTCP) {
				port := measurement.PortForPayload(types.PayloadTCP)
				if port != nil && uint16(d.tcp.SrcPort) != *port {
					probe.RejectBaseReply(src, &stats.AbortBadPort)
				} else if !measurement.TcpEstablishConnection && d.tcp.Ack <= measurement.TcpSequenceNumOffset {
					probe.RejectBaseReply(src, &stats.AbortSeqOOR)
				}
			}
		case layers.IPProtocolUDP:
			port := measurement.PortForPayload(types.PayloadUDPDNS)
			if slices.Contains(d.decoded, layers.LayerTypeUDP) && port != nil && uint16(d.udp.SrcPort) != *port {
				probe.RejectBaseReply(src, &stats.AbortBadPort)
			}
		case layers.IPProtocolICMPv4:
			if slices.Contains(d.decoded, layers.LayerTypeICMPv4) {
				probe.RejectBaseReply(src, &stats.AbortProto)
			}
		}
		return
	}
	entry.FulfillReply(dst, d.ipv4.Protocol, port, seq, tcpSeq, d.ipv4.Id, flags, received.UnixMicro(), length)
}
