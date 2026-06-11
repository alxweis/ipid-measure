package packet

import (
	"encoding/binary"
	"net"

	"github.com/alxweis/ipid-measure/ipid/checksum"
	"github.com/alxweis/ipid-measure/ipid/ip"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/port"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/google/gopacket"
)

var opts = gopacket.SerializeOptions{ComputeChecksums: false, FixLengths: true}

type Packet struct {
	Sender *sender.Sender
	//SenderIP net.IP
	//SrcPort  uint16
	Bytes []byte
}

var RawPackets [][]byte

// Setup builds the immutable raw packet templates.
func Setup() {
	if payload.Active == nil {
		panic("packet.Setup: payload.Active is nil; SetupPayload must run first")
	}
	if sender.SenderA == nil || sender.SenderB == nil {
		panic("packet.Setup: senders are not initialized; SetupSenders must run first")
	}

	n := int(measurement.RequestCount)
	RawPackets = make([][]byte, n)

	protocol := payload.Active.ProtocolID
	packetBuf := gopacket.NewSerializeBuffer()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		s := sender.GetSender(seqNum)

		ipID := measurement.Config.RequestIPIDs[int(seqNum)%len(measurement.Config.RequestIPIDs)]

		ipLayer := ip.Layer(ipID, s.IP, protocol)
		payloadLayers := payload.Active.Layer(seqNum)

		packetLayers := make([]gopacket.SerializableLayer, 0, 1+len(payloadLayers))
		packetLayers = append(packetLayers, ipLayer)
		packetLayers = append(packetLayers, payloadLayers...)

		if err := packetBuf.Clear(); err != nil {
			panic(err)
		}
		if err := gopacket.SerializeLayers(packetBuf, opts, packetLayers...); err != nil {
			panic(err)
		}

		// Copy out: the serialize buffer is reused on the next iteration.
		RawPackets[seqNum] = append([]byte(nil), packetBuf.Bytes()...)
	}
}

// BuildPacketsInto fills the scratch slice with dst IP, src port and checksum per-target
func BuildPacketsInto(scratch []Packet, dstIP net.IP, basePort uint16) {
	dst4 := dstIP.To4()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		raw := RawPackets[seqNum]

		p := &scratch[seqNum]

		// Reuse the per-slot byte buffer; grow only if needed.
		if cap(p.Bytes) < len(raw) {
			p.Bytes = make([]byte, len(raw))
		}
		p.Bytes = p.Bytes[:len(raw)]
		copy(p.Bytes, raw)
		b := p.Bytes

		s := sender.GetSender(seqNum)
		srcPort := port.GetSrcPort(seqNum, basePort)

		// Patch destination IP.
		copy(b[16:20], dst4)

		// Recompute IPv4 header checksum over the 20-byte header.
		binary.BigEndian.PutUint16(b[10:12], 0)
		binary.BigEndian.PutUint16(b[10:12], checksum.Compute(b[:20]))

		// Patch L4 source port if applicable.
		if measurement.HasPorts {
			binary.BigEndian.PutUint16(b[20:22], srcPort)
		}

		// Recompute the L4/ICMP checksum.
		payload.Active.SetChecksum(b)

		p.Sender = s
		p.SenderIP = s.IP
		p.SrcPort = srcPort
	}
}

func init() {
	measurement.SetupRawPackets = Setup
}
