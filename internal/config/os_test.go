package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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

func TestDNSChaosTimeoutCompatibilityAndSnapshot(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "independent"}[explicit], func(t *testing.T) {
			c := validTestOSConfig()
			c.ReadTimeout = 5 * time.Second
			want := c.ReadTimeout
			if explicit {
				c.DNSChaosTimeout = time.Second
				want = time.Second
			}
			data, err := yaml.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if !explicit {
				data = []byte(strings.ReplaceAll(string(data), "dns_chaos_timeout: 0s\n", ""))
			}
			path := filepath.Join(t.TempDir(), "os.yaml")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadOSConfig(path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.ReadTimeout != 5*time.Second || loaded.DNSChaosTimeout != want {
				t.Fatalf("read=%s DNS=%s, want 5s/%s", loaded.ReadTimeout, loaded.DNSChaosTimeout, want)
			}
			snapshot, err := yaml.Marshal(loaded)
			if err != nil {
				t.Fatal(err)
			}
			var recorded OSConfig
			if err := yaml.Unmarshal(snapshot, &recorded); err != nil || recorded.DNSChaosTimeout != want {
				t.Fatalf("effective DNS timeout missing from snapshot: %s, %v", snapshot, err)
			}
		})
	}
}

func TestDNSChaosTimeoutValidation(t *testing.T) {
	for _, timeout := range []time.Duration{-time.Second, time.Millisecond, 11 * time.Second} {
		c := validTestOSConfig()
		c.DNSChaosTimeout = timeout
		if err := validateOSConfig(c); err == nil || !strings.Contains(err.Error(), "dns_chaos_timeout") {
			t.Fatalf("timeout %s accepted or wrong error: %v", timeout, err)
		}
	}
}

func TestLoadOSConfigTCP20KProfile(t *testing.T) {
	c := validTestOSConfig()
	tcp, udp := ScaledNumber(20000), ScaledNumber(10000)
	c.ZGrab2Senders, c.DNSChaosWorkers, c.SNMPWorkers = &tcp, &udp, &udp
	c.ConnectTimeout, c.ReadTimeout = 3*time.Second, 5*time.Second
	c.DNSChaosTimeout, c.SNMPTimeout = 5*time.Second, 3*time.Second
	data, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "os.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOSConfig(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if *loaded.ZGrab2Senders != 20000 || *loaded.DNSChaosWorkers != 10000 || *loaded.SNMPWorkers != 10000 ||
		loaded.Modules != c.Modules || loaded.ConnectTimeout != c.ConnectTimeout || loaded.ReadTimeout != c.ReadTimeout ||
		loaded.DNSChaosTimeout != c.DNSChaosTimeout || loaded.SNMPTimeout != c.SNMPTimeout {
		t.Fatalf("effective OS profile changed: %+v", loaded)
	}
	for _, field := range []string{"tcp", "dns", "snmp"} {
		changed := *loaded
		over := ScaledNumber(10001)
		switch field {
		case "tcp":
			over = 20001
			changed.ZGrab2Senders = &over
		case "dns":
			changed.DNSChaosWorkers = &over
		case "snmp":
			changed.SNMPWorkers = &over
		}
		if err := validateOSConfig(&changed); err == nil {
			t.Fatalf("out-of-range %s accepted", field)
		}
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
