package main

import "testing"

func TestParseInflightOverride(t *testing.T) {
	for value, want := range map[string]uint64{"1": 1, "5000": 5000, "5K": 5000, "1M": 1_000_000} {
		t.Run(value, func(t *testing.T) {
			got, err := parseInflightOverride(value)
			if err != nil || got == nil || got.Uint64() != want {
				t.Fatalf("parse(%q) = %v, %v; want %d", value, got, err, want)
			}
		})
	}
	for _, value := range []string{"", "0", "-1", "1000001", "2M", "NaN", "Inf", "invalid"} {
		t.Run("reject_"+value, func(t *testing.T) {
			if _, err := parseInflightOverride(value); err == nil {
				t.Fatalf("accepted invalid worker count %q", value)
			}
		})
	}
}
