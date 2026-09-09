package dns

import (
	"testing"

	"github.com/google/gopacket/layers"
)

func TestResponseFlags(t *testing.T) {
	// Exercise the full flag extraction -> acceptance path. Extra DNS flags
	// must never turn a response into a query, or allow a query without QR.
	for mask := 0; mask < 32; mask++ {
		packet := &layers.DNS{
			QR: mask&1 != 0,
			AA: mask&2 != 0,
			TC: mask&4 != 0,
			RD: mask&8 != 0,
			RA: mask&16 != 0,
		}
		if got := IsResponse(GetFlags(packet)); got != packet.QR {
			t.Errorf("flags %05b: response=%v, want %v", mask, got, packet.QR)
		}
	}
}
