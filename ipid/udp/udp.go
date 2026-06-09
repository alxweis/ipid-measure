package udp

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/netd-tud/ipid-measure/ipid/checksum"
	"github.com/netd-tud/ipid-measure/ipid/measurement"
)

func Layer() gopacket.SerializableLayer {
	return &layers.UDP{
		SrcPort: layers.UDPPort(0),
		DstPort: layers.UDPPort(*measurement.Config.ZMapPort),
	}
}

func SetChecksum(packet []byte) {
	// set checksum 0
	binary.BigEndian.PutUint16(packet[26:28], 0)

	// create pseudo-header
	ipSrc := packet[12:16]
	ipDst := packet[16:20]
	udpData := packet[20:]

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipSrc)
	copy(pseudoHeader[4:8], ipDst)
	pseudoHeader[8] = 0  // zero
	pseudoHeader[9] = 17 // udp protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpData)))

	// combine pseudo-header + udp replies
	checksumData := append(pseudoHeader, udpData...)
	cs := checksum.Compute(checksumData)
	binary.BigEndian.PutUint16(packet[26:28], cs)
}
