package main

import "testing"

func TestParseGroupsAndExisting(t *testing.T) {
	groups, err := parseGroups("icmp-udp,icmp-tcp-udp")
	if err != nil || len(groups) != 2 || groups[0] != "icmp-udp" {
		t.Fatalf("unexpected groups: %v, %v", groups, err)
	}
	existing, err := parseExisting([]string{"icmp-tcp-udp=interprotocol-icmp-tcp-udp_2026-01-01_00-00-00"})
	if err != nil || existing["icmp-tcp-udp"] == "" {
		t.Fatalf("unexpected existing map: %v, %v", existing, err)
	}
}

func TestMeasurementID(t *testing.T) {
	id, err := measurementID("progress\ninterprotocol-icmp-udp_2026-01-01_00-00-00\n", "icmp-udp")
	if err != nil || id != "interprotocol-icmp-udp_2026-01-01_00-00-00" {
		t.Fatalf("unexpected id: %q, %v", id, err)
	}
}
