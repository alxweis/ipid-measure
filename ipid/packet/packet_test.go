package packet

import (
	"encoding/binary"
	"testing"

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
