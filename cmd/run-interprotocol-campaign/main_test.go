package main

import "testing"

func TestMeasurementID(t *testing.T) {
	id, err := measurementID("progress\ninterprotocol-icmp-udp_2026-01-01_00-00-00\n", "icmp-udp")
	if err != nil || id != "interprotocol-icmp-udp_2026-01-01_00-00-00" {
		t.Fatalf("unexpected id: %q, %v", id, err)
	}
}
