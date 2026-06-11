package udp

import (
	"encoding/binary"
	"github.com/alxweis/ipid-measure/ipid/checksum"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Layer() gopacket.SerializableLayer {
	return &layers.UDP{
		SrcPort: layers.UDPPort(0),
		DstPort: layers.UDPPort(*measurement.Config.ZMapPort),
	}
}

func SetChecksum(packet []byte) {
	// Set checksum 0
	binary.BigEndian.PutUint16(packet[26:28], 0)

	// Create pseudo-header
	ipSrc := packet[12:16]
	ipDst := packet[16:20]
	udpData := packet[20:]

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipSrc)
	copy(pseudoHeader[4:8], ipDst)
	pseudoHeader[8] = 0  // Zero
	pseudoHeader[9] = 17 // UDP protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpData)))

	// Combine pseudo-header + UDP replies
	checksumData := append(pseudoHeader, udpData...)
	cs := checksum.Compute(checksumData)
	binary.BigEndian.PutUint16(packet[26:28], cs)
}
