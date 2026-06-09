package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/netd-tud/ipid-measure/internal/consts"
)

// OSConfig describes one OS-fingerprinting measurement: which ZMap result set
// to consume, which probes to run, and how aggressively. The intent of the
// design is "many small UDP/TCP probes per IP, parallel across many IPs" --
// no global bandwidth steering, because application-layer probe sizes vary
// wildly (SSH banner ≈ 50 B, TLS handshake ≈ 5 KB). Steer via concurrency.
type OSConfig struct {
	ZMapReference `yaml:",inline"`

	// Egress interface. Required (used to set source IP for the subprocess
	// tools so they bind correctly on multi-homed hosts).
	Interface Interface `yaml:"interface"`

	// Concurrency / timeouts. All optional with sane defaults.
	ZGrab2Senders  *uint32 `yaml:"zgrab2_senders"`
	ZDNSThreads    *uint32 `yaml:"zdns_threads"`
	SNMPWorkers    *uint32 `yaml:"snmp_workers"`
	ConnectTimeout *string `yaml:"connect_timeout"`
	ReadTimeout    *string `yaml:"read_timeout"`
	SNMPTimeout    *string `yaml:"snmp_timeout"`
	SNMPCommunity  *string `yaml:"snmp_community"`

	// Tool binary paths. Optional override; defaults from consts.
	ZGrab2Binary *string `yaml:"zgrab2_binary"`
	ZDNSBinary   *string `yaml:"zdns_binary"`

	// Modules toggles per service. Unspecified entries default to the values
	// in consts.OSDefaultModules. Specifying any key here overrides ONLY
	// that key; the rest keep their defaults.
	Modules map[string]bool `yaml:"modules"`
}

// Resolved holds the post-validation view of OSConfig with all defaults
// applied. The runner uses this exclusively to avoid sprinkling nil-checks
// through the rest of the code.
type ResolvedOSConfig struct {
	Interface      Interface
	ZGrab2Senders  uint32
	ZDNSThreads    uint32
	SNMPWorkers    uint32
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	SNMPTimeout    time.Duration
	SNMPCommunity  string
	ZGrab2Binary   string
	ZDNSBinary     string
	Modules        map[string]bool
}

// Resolve applies defaults and returns the materialised configuration.
func (c *OSConfig) Resolve() ResolvedOSConfig {
	r := ResolvedOSConfig{
		Interface:      c.Interface,
		ZGrab2Senders:  consts.OSDefaultZGrab2Senders,
		ZDNSThreads:    consts.OSDefaultZDNSThreads,
		SNMPWorkers:    consts.OSDefaultSNMPWorkers,
		ConnectTimeout: time.Duration(consts.OSDefaultConnectTimeout) * time.Second,
		ReadTimeout:    time.Duration(consts.OSDefaultReadTimeout) * time.Second,
		SNMPTimeout:    time.Duration(consts.OSDefaultSNMPTimeout) * time.Second,
		SNMPCommunity:  consts.OSDefaultSNMPCommunity,
		ZGrab2Binary:   consts.OSZGrab2Binary,
		ZDNSBinary:     consts.OSZDNSBinary,
		Modules:        cloneModuleDefaults(),
	}

	if c.ZGrab2Senders != nil {
		r.ZGrab2Senders = *c.ZGrab2Senders
	}
	if c.ZDNSThreads != nil {
		r.ZDNSThreads = *c.ZDNSThreads
	}
	if c.SNMPWorkers != nil {
		r.SNMPWorkers = *c.SNMPWorkers
	}
	if c.ConnectTimeout != nil {
		if d, err := time.ParseDuration(*c.ConnectTimeout); err == nil {
			r.ConnectTimeout = d
		}
	}
	if c.ReadTimeout != nil {
		if d, err := time.ParseDuration(*c.ReadTimeout); err == nil {
			r.ReadTimeout = d
		}
	}
	if c.SNMPTimeout != nil {
		if d, err := time.ParseDuration(*c.SNMPTimeout); err == nil {
			r.SNMPTimeout = d
		}
	}
	if c.SNMPCommunity != nil {
		r.SNMPCommunity = *c.SNMPCommunity
	}
	if c.ZGrab2Binary != nil {
		r.ZGrab2Binary = *c.ZGrab2Binary
	}
	if c.ZDNSBinary != nil {
		r.ZDNSBinary = *c.ZDNSBinary
	}
	for k, v := range c.Modules {
		r.Modules[k] = v
	}
	return r
}

func cloneModuleDefaults() map[string]bool {
	out := make(map[string]bool, len(consts.OSDefaultModules))
	for k, v := range consts.OSDefaultModules {
		out[k] = v
	}
	return out
}

func LoadOSConfig(path string) (*OSConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c OSConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	if err := validateOSConfig(&c); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &c, nil
}

func validateOSConfig(c *OSConfig) error {
	if err := c.ValidateAndParseZMap(); err != nil {
		return fmt.Errorf("invalid zmap reference: %w", err)
	}

	if c.ZGrab2Senders != nil && *c.ZGrab2Senders == 0 {
		return fmt.Errorf("zgrab2_senders must be > 0 if set")
	}
	if c.ZDNSThreads != nil && *c.ZDNSThreads == 0 {
		return fmt.Errorf("zdns_threads must be > 0 if set")
	}
	if c.SNMPWorkers != nil && *c.SNMPWorkers == 0 {
		return fmt.Errorf("snmp_workers must be > 0 if set")
	}
	for _, ds := range []*string{c.ConnectTimeout, c.ReadTimeout, c.SNMPTimeout} {
		if ds == nil {
			continue
		}
		if _, err := time.ParseDuration(*ds); err != nil {
			return fmt.Errorf("invalid duration %q: %w", *ds, err)
		}
	}
	for k := range c.Modules {
		if _, ok := consts.OSDefaultModules[k]; !ok {
			return fmt.Errorf("unknown module %q in modules section", k)
		}
	}
	if err := validateInterface(c.Interface, "interface", true, true); err != nil {
		return err
	}
	return nil
}
