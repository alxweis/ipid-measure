package packet

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
)

func TestSetTCPAcknowledgment(t *testing.T) {
	previousPayload := payload.Active
	payload.Active = &payload.Payload{SetChecksum: func([]byte) {}}
	t.Cleanup(func() { payload.Active = previousPayload })

	packetBytes := make([]byte, 40)
	const want = uint32(0x12345678)
	SetTCPAcknowledgment(packetBytes, want)

	if got := binary.BigEndian.Uint32(packetBytes[28:32]); got != want {
		t.Fatalf("TCP acknowledgment = %#x, want %#x", got, want)
	}
}

func TestBuildTCPFINPacket(t *testing.T) {
	previousConfig := measurement.Config
	previousOffset := measurement.TcpSequenceNumOffset
	previousEstablish := measurement.TcpEstablishConnection
	previousPayload := payload.Active
	t.Cleanup(func() {
		measurement.Config = previousConfig
		measurement.TcpSequenceNumOffset = previousOffset
		measurement.TcpEstablishConnection = previousEstablish
		payload.Active = previousPayload
	})

	port := uint16(80)
	measurement.Config = &config.IPIDConfig{
		ConnectionCount:       4,
		RequestsPerConnection: 4,
		ZMapReference:         config.ZMapReference{ZMapPort: &port},
		RequestIPIDs:          []uint16{12345},
	}
	measurement.TcpSequenceNumOffset = 1_000_000
	measurement.TcpEstablishConnection = true
	payload.Active = payload.TCP

	packetBytes, err := BuildTCPFINPacket(
		net.IPv4(192, 0, 2, 10),
		net.IPv4(192, 0, 2, 20),
		40_002,
		2,
		4,
		0x12345678,
	)
	if err != nil {
		t.Fatalf("BuildTCPFINPacket() error = %v", err)
	}

	if len(packetBytes) != tcpFINPacketBytes {
		t.Fatalf("packet length = %d, want %d", len(packetBytes), tcpFINPacketBytes)
	}
	if got := net.IP(packetBytes[12:16]); !got.Equal(net.IPv4(192, 0, 2, 20)) {
		t.Fatalf("source IP = %s", got)
	}
	if got := net.IP(packetBytes[16:20]); !got.Equal(net.IPv4(192, 0, 2, 10)) {
		t.Fatalf("destination IP = %s", got)
	}
	if got := binary.BigEndian.Uint16(packetBytes[20:22]); got != 40_002 {
		t.Fatalf("source port = %d, want 40002", got)
	}
	if got := binary.BigEndian.Uint16(packetBytes[22:24]); got != port {
		t.Fatalf("destination port = %d, want %d", got, port)
	}
	if got := binary.BigEndian.Uint32(packetBytes[24:28]); got != 1_000_006 {
		t.Fatalf("sequence number = %d, want 1000006", got)
	}
	if got := binary.BigEndian.Uint32(packetBytes[28:32]); got != 0x12345678 {
		t.Fatalf("acknowledgment = %#x, want %#x", got, uint32(0x12345678))
	}
	if flags := packetBytes[33]; flags != 0x11 {
		t.Fatalf("TCP flags = %#x, want FIN+ACK (0x11)", flags)
	}
	if checksum := binary.BigEndian.Uint16(packetBytes[10:12]); checksum == 0 {
		t.Fatal("IPv4 checksum was not populated")
	}
	if checksum := binary.BigEndian.Uint16(packetBytes[36:38]); checksum == 0 {
		t.Fatal("TCP checksum was not populated")
	}
}
