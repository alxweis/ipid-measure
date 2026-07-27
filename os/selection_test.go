package os

import (
	"fmt"
	"math"
	"testing"
)

func TestSelectSecondaryBoundaries(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "198.51.100.8", "203.0.113.255"} {
		if selectSecondary(ip, 0) {
			t.Fatalf("selectSecondary(%q, 0) = true", ip)
		}
		if !selectSecondary(ip, 1) {
			t.Fatalf("selectSecondary(%q, 1) = false", ip)
		}
	}
}

func TestSelectSecondaryIsStableAndCloseToRate(t *testing.T) {
	const (
		total = 100_000
		rate  = 0.01
	)
	selected := 0
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("198.51.%d.%d", (i/256)%256, i%256)
		first := selectSecondary(ip, rate)
		if first != selectSecondary(ip, rate) {
			t.Fatalf("selection changed for %s", ip)
		}
		if first {
			selected++
		}
	}

	want := float64(total) * rate
	// A generous deterministic-distribution guard: catches a broken hash or
	// threshold calculation without making the test statistically flaky.
	if math.Abs(float64(selected)-want) > want*0.2 {
		t.Fatalf("selected %d/%d, want about %.0f", selected, total, want)
	}
}

func TestZGrab2InputLine(t *testing.T) {
	if got := zgrab2InputLine("192.0.2.1", false); got != "192.0.2.1" {
		t.Fatalf("ordinary input = %q", got)
	}
	if got := zgrab2InputLine("192.0.2.1", true); got != "192.0.2.1,,secondary" {
		t.Fatalf("sampled input = %q", got)
	}
}
