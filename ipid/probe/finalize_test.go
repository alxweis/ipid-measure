package probe

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/ipid/measurement"
)

func TestNextTCPRequestIndexUsesSentSamples(t *testing.T) {
	previousConfig := measurement.Config
	t.Cleanup(func() { measurement.Config = previousConfig })

	measurement.Config = &config.IPIDConfig{
		ConnectionCount:       4,
		RequestsPerConnection: 4,
	}
	probe := &Probe{Samples: make([]Sample, 16)}

	// Connection 2 sent its SYN and two data bytes; the next TCP sequence
	// number must therefore use request index 3.
	probe.Samples[2].MarkSent(1)
	probe.Samples[6].MarkSent(2)
	probe.Samples[10].MarkSent(3)

	if got := nextTCPRequestIndex(probe, 2); got != 3 {
		t.Fatalf("nextTCPRequestIndex() = %d, want 3", got)
	}
}
