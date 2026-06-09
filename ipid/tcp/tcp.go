package tcp

import (
	"encoding/binary"
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/checksum"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var payload = []byte("GET / HTTP/1.1\r\n\r\n")

func Payload(seqNum uint16) byte {
	return payload[int(seqNum)%len(payload)]
}

func Layer(seqNum uint16, overwriteRequestFlags types.TCPFlagSet) gopacket.SerializableLayer {
	flags := measurement.Config.TCPConfig.RequestFlags

	if overwriteRequestFlags != nil {
		flags = overwriteRequestFlags
	}

	return &layers.TCP{
		SrcPort: layers.TCPPort(0),
		DstPort: layers.TCPPort(*measurement.Config.ZMapPort),

		Seq: measurement.TcpSequenceNumOffset + uint32(seqNum),

		FIN: flags.Contains(types.TCPFlagFIN),
		SYN: flags.Contains(types.TCPFlagSYN),
		RST: flags.Contains(types.TCPFlagRST),
		PSH: flags.Contains(types.TCPFlagPSH),
		ACK: flags.Contains(types.TCPFlagACK),
		URG: flags.Contains(types.TCPFlagURG),
		ECE: flags.Contains(types.TCPFlagECE),
		CWR: flags.Contains(types.TCPFlagCWR),
		NS:  flags.Contains(types.TCPFlagNS),

		Window: 512,
	}
}

func SetChecksum(packet []byte) {
	// set checksum 0
	binary.BigEndian.PutUint16(packet[36:38], 0)

	ipSrc := packet[12:16]
	ipDst := packet[16:20]
	tcpData := packet[20:] // tcp header + replies

	// create pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipSrc)
	copy(pseudoHeader[4:8], ipDst)
	pseudoHeader[8] = 0 // zero
	pseudoHeader[9] = 6 // tcp protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpData)))

	// combine pseudo-header + tcp replies
	checksumData := append(pseudoHeader, tcpData...)
	cs := checksum.Compute(checksumData)
	binary.BigEndian.PutUint16(packet[36:38], cs)
}

func GetFlags(tcp *layers.TCP) types.TCPFlagSet {
	flags := sets.New[types.TCPFlag]()

	add := func(enabled bool, flag types.TCPFlag) {
		if enabled {
			flags.Add(flag)
		}
	}

	add(tcp.FIN, types.TCPFlagFIN)
	add(tcp.SYN, types.TCPFlagSYN)
	add(tcp.RST, types.TCPFlagRST)
	add(tcp.PSH, types.TCPFlagPSH)
	add(tcp.ACK, types.TCPFlagACK)
	add(tcp.URG, types.TCPFlagURG)
	add(tcp.ECE, types.TCPFlagECE)
	add(tcp.CWR, types.TCPFlagCWR)
	add(tcp.NS, types.TCPFlagNS)

	return flags
}
