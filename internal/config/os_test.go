package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateOSConfigSecondarySampleRate(t *testing.T) {
	tests := []struct {
		name    string
		modules OSModules
		rate    float64
		wantErr string
	}{
		{
			name:    "core only at zero",
			modules: OSModules{SSH: true},
			rate:    0,
		},
		{
			name:    "secondary sampled",
			modules: OSModules{SMTP: true},
			rate:    0.01,
		},
		{
			name:    "secondary disabled leaves no effective module",
			modules: OSModules{SMTP: true},
			rate:    0,
			wantErr: "no effective os modules selected",
		},
		{
			name:    "negative rate",
			modules: OSModules{SSH: true},
			rate:    -0.01,
			wantErr: "secondary_sample_rate",
		},
		{
			name:    "rate above one",
			modules: OSModules{SSH: true},
			rate:    1.01,
			wantErr: "secondary_sample_rate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := validTestOSConfig()
			c.Modules = test.modules
			c.SecondarySampleRate = test.rate
			err := validateOSConfig(c)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("validateOSConfig() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateOSConfig() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func validTestOSConfig() *OSConfig {
	zgrab := ScaledNumber(5000)
	zdns := ScaledNumber(1000)
	snmp := ScaledNumber(3000)
	return &OSConfig{
		ZMapReference:  ZMapReference{ZMapID: "icmp_2026-07-27_09-16-34"},
		Modules:        OSModules{SSH: true},
		ZGrab2Senders:  &zgrab,
		ZDNSThreads:    &zdns,
		SNMPWorkers:    &snmp,
		ConnectTimeout: time.Second,
		ReadTimeout:    time.Second,
		SNMPTimeout:    time.Second,
		SNMPCommunity:  "public",
	}
}
