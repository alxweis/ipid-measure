package packet

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/checksum"
	"github.com/alxweis/ipid-measure/ipid/ip"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/port"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/tcp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var opts = gopacket.SerializeOptions{ComputeChecksums: false, FixLengths: true}

const tcpFINPacketBytes = 40

var (
	RawPacketsTotalBytes int
	rawPackets           [][]byte
)

// Setup builds the immutable raw packet templates.
func Setup() {
	if payload.Active == nil {
		panic("packet.Setup: payload.Active is nil; SetupPayload must run first")
	}
	if sender.SenderA == nil || sender.SenderB == nil {
		panic("packet.Setup: senders are not initialized; SetupSenders must run first")
	}

	n := int(measurement.RequestCount)
	rawPackets = make([][]byte, n)
	RawPacketsTotalBytes = 0

	protocol := payload.Active.ProtocolID
	packetBuf := gopacket.NewSerializeBuffer()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		sndr := sender.GetSender(seqNum)
		ipID := measurement.Config.RequestIPIDs[int(seqNum)%len(measurement.Config.RequestIPIDs)]

		ipLayer := ip.Layer(ipID, sndr.IP, protocol)
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

		RawPacketsTotalBytes += len(sndr.EthHeader) + len(packetBuf.Bytes())
		rawPackets[seqNum] = append([]byte(nil), packetBuf.Bytes()...)
	}

	if measurement.TcpEstablishConnection {
		RawPacketsTotalBytes += int(measurement.Config.ConnectionCount) *
			(len(sender.SenderA.EthHeader) + tcpFINPacketBytes)
	}
}

// BuildPacketsInto fills the packet slice with dst IP, src port and checksum per-target
func BuildPacketsInto(packets [][]byte, dstIP net.IP, basePort uint16) {
	dst4 := dstIP.To4()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		raw := rawPackets[seqNum]
		pkt := packets[seqNum]

		// Reuse the per-slot byte buffer; grow only if needed.
		if cap(pkt) < len(raw) {
			pkt = make([]byte, len(raw))
		}
		pkt = pkt[:len(raw)]
		copy(pkt, raw)

		srcPort := port.GetSrcPort(seqNum, basePort)

		// Patch destination IP.
		copy(pkt[16:20], dst4)

		// Recompute IPv4 header checksum.
		binary.BigEndian.PutUint16(pkt[10:12], 0)
		binary.BigEndian.PutUint16(pkt[10:12], checksum.Compute(pkt[:20]))

		// Patch L4 source port if applicable.
		if measurement.HasPorts {
			binary.BigEndian.PutUint16(pkt[20:22], srcPort)
		}

		// Recompute the L4/ICMP checksum.
		payload.Active.SetChecksum(pkt)

		// Commit the buffer back into the caller slice.
		packets[seqNum] = pkt
	}
}

// SetTCPAcknowledgment patches the TCP ACK field in a packet prepared for an
// established connection and recomputes its transport checksum.
func SetTCPAcknowledgment(packet []byte, acknowledgment uint32) {
	binary.BigEndian.PutUint32(packet[28:32], acknowledgment)
	payload.Active.SetChecksum(packet)
}

// BuildTCPFINPacket builds a FIN+ACK packet with the next sequence number for
// one established connection. FIN replies are intentionally not measured.
func BuildTCPFINPacket(
	dstIP net.IP,
	srcIP net.IP,
	srcPort uint16,
	connectionIndex uint16,
	nextRequestIndex uint16,
	acknowledgment uint32,
) ([]byte, error) {
	seqNum := nextRequestIndex*measurement.Config.ConnectionCount + connectionIndex
	ipID := measurement.Config.RequestIPIDs[int(seqNum)%len(measurement.Config.RequestIPIDs)]

	ipLayer, ok := ip.Layer(ipID, srcIP, payload.Active.ProtocolID).(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("unexpected IP layer type")
	}
	ipLayer.DstIP = dstIP
	tcpLayer, ok := tcp.Layer(
		seqNum,
		sets.New(types.TCPFlagFIN, types.TCPFlagACK),
	).(*layers.TCP)
	if !ok {
		return nil, fmt.Errorf("unexpected TCP layer type %T", tcpLayer)
	}
	tcpLayer.SrcPort = layers.TCPPort(srcPort)
	tcpLayer.Ack = acknowledgment

	packetBuffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(packetBuffer, opts, ipLayer, tcpLayer); err != nil {
		return nil, fmt.Errorf("serialize FIN+ACK packet: %w", err)
	}

	packetBytes := append([]byte(nil), packetBuffer.Bytes()...)
	binary.BigEndian.PutUint16(packetBytes[10:12], checksum.Compute(packetBytes[:20]))
	tcp.SetChecksum(packetBytes)
	return packetBytes, nil
}

func init() {
	measurement.SetupRawPackets = Setup
}
