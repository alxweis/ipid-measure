package main

import (
	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/types"
	"testing"
	"time"
)

func TestLocalReferenceRequiresExplicitSingleProtocol(t *testing.T) {
	for _, name := range []string{"icmp", "tcp", "udp"} {
		p, names, err := parseReferenceProtocol(name)
		if err != nil || len(p) != 1 || names[0] != name {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, err := parseProtocols(name); err == nil {
			t.Fatal("legacy group parser accepted singleton")
		}
	}
	for _, name := range []string{"icmp,tcp", "", "udp-dns", "tcp,udp,icmp"} {
		if _, _, err := parseReferenceProtocol(name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestReferenceSamplingMatchesInterleavedSampling(t *testing.T) {
	for _, sample := range []string{"base", "mass"} {
		control := config.IPIDConfig{RequestIPIDs: []uint16{1, 2}, FixedIntervalConfig: config.FixedIntervalConfig{RequestInterval: 20 * time.Millisecond}}
		interleaved := control
		if err := config.ConfigureLocalReferenceSampling(&control, sample); err != nil {
			t.Fatal(err)
		}
		if err := config.ConfigureInterprotocolSampling(&interleaved, 3, sample); err != nil {
			t.Fatal(err)
		}
		if control.ConnectionCount != interleaved.ConnectionCount || control.RequestsPerConnection != interleaved.RequestsPerConnection || control.MeasurementMode != interleaved.MeasurementMode || control.FixedIntervalConfig != interleaved.FixedIntervalConfig {
			t.Fatal("reference sampling differs")
		}
		if sample == "base" && control.MeasurementMode != types.MeasurementModeRTBased {
			t.Fatal("BASE must be RT-based")
		}
	}
}
