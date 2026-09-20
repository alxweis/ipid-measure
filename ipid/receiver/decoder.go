package receiver

import (
	"slices"
	"sync/atomic"
	"time"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/ipid/diagnostics"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packetDecoder struct {
	eth                layers.Ethernet
	ipv4               layers.IPv4
	tcp                layers.TCP
	udp                layers.UDP
	dns                layers.DNS
	icmp               layers.ICMPv4
	headers, transport *gopacket.DecodingLayerParser
	decoded            []gopacket.LayerType
}

func newPacketDecoder() *packetDecoder {
	d := &packetDecoder{decoded: make([]gopacket.LayerType, 0, 3)}
	d.headers = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ipv4)
	d.transport = gopacket.NewDecodingLayerParser(payload.Active.ProtocolID.LayerType(), &d.tcp, &d.udp, &d.dns, &d.icmp)
	d.headers.IgnoreUnsupported = true
	d.transport.IgnoreUnsupported = true
	return d
}

func (d *packetDecoder) process(data []byte) {
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
	transportStart := diagnostics.Transport.Start()
	transportErr := d.transport.DecodeLayers(d.ipv4.Payload, &d.decoded)
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
	switch payload.Active.ProtocolID {
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
		switch payload.Active.ProtocolID {
		case layers.IPProtocolTCP:
			if slices.Contains(d.decoded, layers.LayerTypeTCP) {
				if measurement.Config.ZMapPort != nil && uint16(d.tcp.SrcPort) != *measurement.Config.ZMapPort {
					probe.RejectBaseReply(src, &stats.AbortBadPort)
				} else if !measurement.TcpEstablishConnection && d.tcp.Ack <= measurement.TcpSequenceNumOffset {
					probe.RejectBaseReply(src, &stats.AbortSeqOOR)
				}
			}
		case layers.IPProtocolUDP:
			if slices.Contains(d.decoded, layers.LayerTypeUDP) && measurement.Config.ZMapPort != nil && uint16(d.udp.SrcPort) != *measurement.Config.ZMapPort {
				probe.RejectBaseReply(src, &stats.AbortBadPort)
			}
		case layers.IPProtocolICMPv4:
			if slices.Contains(d.decoded, layers.LayerTypeICMPv4) {
				probe.RejectBaseReply(src, &stats.AbortProto)
			}
		}
		return
	}
	entry.FulfillReply(dst, port, seq, tcpSeq, d.ipv4.Id, flags, time.Now().UnixMicro(), length)
}
