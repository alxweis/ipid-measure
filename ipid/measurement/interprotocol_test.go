package measurement

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/types"
)

func TestInterProtocolSequenceLayout(t *testing.T) {
	previousProtocols, previousConfig := InterProtocols, Config
	t.Cleanup(func() { InterProtocols, Config = previousProtocols, previousConfig })
	InterProtocols = []types.Payload{types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS}
	Config = &config.IPIDConfig{ConnectionCount: 4, RequestsPerConnection: 4}

	wantProtocols := []types.Payload{
		types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS,
		types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS,
	}
	for seq, want := range wantProtocols {
		if got := ProtocolForSequence(uint16(seq)); got != want {
			t.Fatalf("ProtocolForSequence(%d) = %s, want %s", seq, got, want)
		}
	}
	if BaseSequenceIndex(0) != 0 || BaseSequenceIndex(2) != 0 || BaseSequenceIndex(3) != 1 {
		t.Fatal("protocol expansion changed the logical source/connection position")
	}
}
