package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateOSConfigRequiresSixServices(t *testing.T) {
	c := validTestOSConfig()
	if err := validateOSConfig(c); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	c.Modules.HTTPS = false
	if err := validateOSConfig(c); err == nil || !strings.Contains(err.Error(), "must all be enabled") {
		t.Fatalf("missing HTTPS error = %v", err)
	}
}

func TestLoadOSConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os.yaml")
	if err := os.WriteFile(path, []byte("zmap: icmp_2026-07-27_09-16-34\nsecondary_sample_rate: 0.01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOSConfig(path, nil); err == nil || !strings.Contains(err.Error(), "field secondary_sample_rate not found") {
		t.Fatalf("LoadOSConfig() error = %v", err)
	}
}

func validTestOSConfig() *OSConfig {
	zgrab := ScaledNumber(5000)
	zdns := ScaledNumber(1000)
	snmp := ScaledNumber(3000)
	return &OSConfig{
		ZMapReference: ZMapReference{ZMapID: "icmp_2026-07-27_09-16-34"},
		Modules: OSModules{
			SSH: true, SMB: true, HTTP: true, HTTPS: true, SNMP: true, DNSChaos: true,
		},
		ZGrab2Senders:   &zgrab,
		DNSChaosWorkers: &zdns,
		SNMPWorkers:     &snmp,
		ConnectTimeout:  time.Second,
		ReadTimeout:     time.Second,
		SNMPTimeout:     time.Second,
		SNMPCommunity:   "public",
	}
}
