package packet

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/netd-tud/ipid-measure/ipid/checksum"
	"github.com/netd-tud/ipid-measure/ipid/ip"
	"github.com/netd-tud/ipid-measure/ipid/measurement"
	"github.com/netd-tud/ipid-measure/ipid/payload"
	"github.com/netd-tud/ipid-measure/ipid/port"
	"github.com/netd-tud/ipid-measure/ipid/sender"
)

var opts = gopacket.SerializeOptions{ComputeChecksums: false, FixLengths: true}

// Packet is a ready-to-send request. SenderIP is cached alongside the *Sender so
// the hot path can build the ExpDstIPIs validator without dereferencing.
type Packet struct {
	Sender   *sender.Sender
	SenderIP net.IP
	SrcPort  uint16
	Bytes    []byte
}

// RawPackets holds, per sequence number, the fully serialized template packet
// (Ethernet-less L3 frame) with a zero destination IP. These are built once and
// only patched (dst IP, src port, checksums) per target. Owned by this package.
var RawPackets [][]byte

// hasPorts is cached once: whether the active protocol carries L4 ports.
var hasPorts bool

// Setup builds the immutable raw packet templates. Registered into
// measurement.SetupRawPackets and run once before any worker starts.
//
// Pre-conditions (enforced explicitly so a future ordering mistake produces a
// clear error instead of a nil-deref panic):
//   - payload.Active must be populated   (set by payload.Setup)
//   - sender.SenderA / sender.SenderB must be populated (set by sender.Setup)
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
	hasPorts = protocol == layers.IPProtocolTCP || protocol == layers.IPProtocolUDP

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

// BuildPacketsInto fills the caller-provided scratch slice (length RequestCount)
// with per-target request packets, reusing the caller's byte buffers so the hot
// path performs ZERO heap allocations per probe. The previous BuildPackets
// allocated a fresh []*Packet plus a new byte slice for every request on every
// target — prohibitive at 500M targets.
func BuildPacketsInto(scratch []Packet, dstIP net.IP, basePort uint16) {
	dst4 := dstIP.To4()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		raw := RawPackets[seqNum]

		p := &scratch[seqNum]

		// Reuse the per-slot byte buffer; grow only if needed (never, in practice
		// after the first probe, since all templates share a length per seqNum).
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
		if hasPorts {
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
