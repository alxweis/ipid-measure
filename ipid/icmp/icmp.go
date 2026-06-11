package icmp

import (
	"encoding/binary"
	"github.com/alxweis/ipid-measure/ipid/checksum"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Layer(seqNum uint16) gopacket.SerializableLayer {
	return &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Seq:      seqNum,
	}
}

func SetChecksum(packet []byte) {
	// Set checksum 0
	binary.BigEndian.PutUint16(packet[22:24], 0)

	icmpData := packet[20:]
	cs := checksum.Compute(icmpData)
	binary.BigEndian.PutUint16(packet[22:24], cs)
}
