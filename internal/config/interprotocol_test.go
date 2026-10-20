package config

import (
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/types"
)

func TestInterprotocolLayouts(t *testing.T) {
	for _, count := range []int{2, 3} {
		for _, sample := range []string{"base", "mass"} {
			c := &IPIDConfig{RequestIPIDs: []uint16{1, 2}}
			c.FixedIntervalConfig.RequestInterval = 20 * time.Millisecond
			if err := ConfigureInterprotocolSampling(c, count, sample); err != nil {
				t.Fatal(err)
			}
			req, mode := uint16(4), types.MeasurementModeRTBased
			if sample == "mass" {
				req, mode = 25, types.MeasurementModeFixedInterval
			}
			if c.ConnectionCount != 4 || c.RequestsPerConnection != req || c.MeasurementMode != mode {
				t.Fatal(c)
			}
			if c.FixedIntervalConfig.RequestInterval != 20*time.Millisecond {
				t.Fatal("interval was divided by protocol count")
			}
		}
	}
}
func TestInterprotocolRejectsInvalidInputs(t *testing.T) {
	for _, pattern := range [][]uint16{nil, {1}, {1, 1}} {
		if ConfigureInterprotocolSampling(&IPIDConfig{RequestIPIDs: pattern}, 2, "base") == nil {
			t.Fatal(pattern)
		}
	}
	for _, sample := range []string{"unknown", "mass"} {
		if ConfigureInterprotocolSampling(&IPIDConfig{RequestIPIDs: []uint16{1, 2}}, 2, sample) == nil {
			t.Fatal(sample)
		}
	}
}
func TestInterprotocolPopulation(t *testing.T) {
	for _, s := range []string{"REFLECTION", "CONSTANT", "SINGLE", "PER_DESTINATION", "PER_BUCKET", "MULTI", "RANDOM"} {
		sample, err := InterprotocolSample(s)
		if err != nil {
			t.Fatal(err)
		}
		if (sample == "mass") != (s == "MULTI" || s == "RANDOM") {
			t.Fatal(s, sample)
		}
	}
	if _, err := InterprotocolSample("UNCLASSIFIED"); err == nil {
		t.Fatal("accepted unsupported target")
	}
}
