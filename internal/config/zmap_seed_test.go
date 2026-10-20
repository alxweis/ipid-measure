package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestZMapSeedYAML(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
	}{
		{"omitted", "payload: icmp", "seed: null"},
		{"null", "seed: null", "seed: null"},
		{"zero", "seed: 0", "seed: 0"},
		{"fixed", "seed: 42", "seed: 42"},
		{"maximum", "seed: 18446744073709551615", "seed: 18446744073709551615"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var cfg ZMapConfig
			if err := yaml.Unmarshal([]byte(test.input), &cfg); err != nil {
				t.Fatal(err)
			}
			data, err := yaml.Marshal(&cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), test.want+"\n") {
				t.Fatalf("snapshot missing %q: %s", test.want, data)
			}
			var restored ZMapConfig
			if err := yaml.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if cfg.Seed == nil {
				if restored.Seed != nil {
					t.Fatal("automatic seed became explicit")
				}
			} else if restored.Seed == nil || *restored.Seed != *cfg.Seed {
				t.Fatal("seed changed during snapshot round trip")
			}
		})
	}
}

func TestZMapSeedRejectsInvalidYAML(t *testing.T) {
	for _, value := range []string{"-1", "18446744073709551616", "1.5", "1.0", "1e3", "true", "'42'", "abc", "[]", "{}"} {
		t.Run(value, func(t *testing.T) {
			var cfg ZMapConfig
			if err := yaml.Unmarshal([]byte("seed: "+value), &cfg); err == nil {
				t.Fatalf("accepted invalid seed %s", value)
			}
		})
	}
}
