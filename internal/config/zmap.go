package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/netd-tud/ipid-measure/internal/types"
)

// ZMapConfig describes one ZMap scan. The mandatory knobs cover what every
// scan needs (payload, port, bandwidth, output volume, egress interface). The
// optional knobs map straight onto zmap CLI flags so users can fine-tune a
// scan without recompiling the binary.
//
// Pointer-typed optional fields use null/missing in YAML to mean "let zmap
// decide" (i.e. the flag is not emitted at all).
type ZMapConfig struct {
	// --- mandatory ---------------------------------------------------------

	Payload   types.Payload `yaml:"payload"`
	Port      *uint16       `yaml:"port"`
	Bandwidth ScaledNumber  `yaml:"bandwidth"`
	Interface Interface     `yaml:"interface"`

	// NumberOfTargetIPAddresses is the desired number of responding IPs; once
	// reached zmap exits. null/missing means "scan the whole IPv4 space".
	NumberOfTargetIPAddresses *ScaledNumber `yaml:"number_of_target_ip_addresses"`

	// --- optional zmap tuning ---------------------------------------------

	// PacketsPerSecond is an alternative rate cap; if non-nil, zmap is invoked
	// with -r instead of -B (mutually exclusive with Bandwidth at zmap's CLI;
	// here we forward whichever the user set, preferring rate when both are).
	PacketsPerSecond *ScaledNumber `yaml:"packets_per_second"`

	// CooldownSeconds: how long zmap keeps listening after sending; default
	// from consts.ZMapDefaultCooldownSeconds.
	CooldownSeconds *uint32 `yaml:"cooldown_seconds"`

	// SenderThreads: zmap -T. 0/nil means "let zmap decide".
	SenderThreads *uint32 `yaml:"sender_threads"`

	// ProbesPerTarget: zmap --probes; default 1.
	ProbesPerTarget *uint32 `yaml:"probes_per_target"`

	// Seed: zmap --seed for reproducible permutations. nil -> zmap picks one.
	Seed *uint64 `yaml:"seed"`

	// Verbosity: zmap -v level (0..5).
	Verbosity *uint8 `yaml:"verbosity"`

	// BlacklistFile: optional path passed to zmap -b. Useful for excluding
	// private/reserved ranges (zmap ships a default blocklist; explicit override
	// here).
	BlacklistFile *string `yaml:"blacklist_file"`

	// WhitelistFile: optional path passed to zmap -w (restrict targets).
	WhitelistFile *string `yaml:"whitelist_file"`

	// SourcePortMin/SourcePortMax: zmap --source-port=MIN-MAX. Both must be set
	// together or both null.
	SourcePortMin *uint16 `yaml:"source_port_min"`
	SourcePortMax *uint16 `yaml:"source_port_max"`

	// Dryrun: zmap --dryrun (do not actually transmit packets). For wiring up
	// the binary on a new host without flooding the network.
	Dryrun bool `yaml:"dryrun"`

	// ExtraArgs is an escape hatch for zmap CLI options not modelled above.
	// Passed verbatim after the structured flags. Use sparingly.
	ExtraArgs []string `yaml:"extra_args"`
}

func LoadZMapConfig(path string) (*ZMapConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var config ZMapConfig

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	if err := validateZMapConfig(&config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}

func validateZMapConfig(config *ZMapConfig) error {
	// ==================================================
	// Payload
	// ==================================================

	switch config.Payload {
	case types.PayloadICMP:
	case types.PayloadTCP:
	case types.PayloadUDPDNS:
	default:
		return fmt.Errorf("invalid payload: %s", config.Payload)
	}

	// ==================================================
	// Port
	// ==================================================

	if config.Payload == types.PayloadICMP {
		if config.Port != nil {
			return fmt.Errorf("port must be nil for ICMP")
		}

	} else {
		if config.Port == nil {
			return fmt.Errorf("port must not be nil")
		}

		if *config.Port == 0 {
			return fmt.Errorf("port must be between 1 and 65535")
		}
	}

	if config.Payload == types.PayloadUDPDNS && *config.Port != 53 {
		return fmt.Errorf("udp-dns payload requires port 53")
	}

	// ==================================================
	// NumberOfTargetIPAddresses
	// ==================================================

	if config.NumberOfTargetIPAddresses != nil {
		targets := uint64(*config.NumberOfTargetIPAddresses)

		if targets == 0 || targets > 5_000_000_000 {
			return fmt.Errorf(
				"number_of_target_ip_addresses must be between 1 and 5G or null",
			)
		}
	}

	// ==================================================
	// Bandwidth / pps
	// ==================================================

	bandwidth := uint64(config.Bandwidth)
	if bandwidth != 0 && (bandwidth < 1_000 || bandwidth > 5_000_000_000) {
		return fmt.Errorf("bandwidth must be between 1K and 5G")
	}

	if config.PacketsPerSecond != nil {
		pps := uint64(*config.PacketsPerSecond)
		if pps == 0 || pps > 100_000_000 {
			return fmt.Errorf("packets_per_second must be between 1 and 100M")
		}
	}

	if bandwidth == 0 && config.PacketsPerSecond == nil {
		return fmt.Errorf("either bandwidth or packets_per_second must be set")
	}

	// ==================================================
	// Source port range (paired)
	// ==================================================

	switch {
	case config.SourcePortMin == nil && config.SourcePortMax == nil:
		// both null -> zmap chooses
	case config.SourcePortMin != nil && config.SourcePortMax != nil:
		if *config.SourcePortMin == 0 || *config.SourcePortMax == 0 {
			return fmt.Errorf("source ports must be > 0")
		}
		if *config.SourcePortMin > *config.SourcePortMax {
			return fmt.Errorf("source_port_min must be <= source_port_max")
		}
	default:
		return fmt.Errorf("source_port_min and source_port_max must both be set or both null")
	}

	// ==================================================
	// Verbosity bounds
	// ==================================================

	if config.Verbosity != nil && *config.Verbosity > 5 {
		return fmt.Errorf("verbosity must be in [0,5]")
	}

	// ==================================================
	// Interface
	// ==================================================

	if err := validateInterface(
		config.Interface,
		"interface",
		true,
		true,
	); err != nil {
		return err
	}

	// ==================================================
	// Extra Args
	// ==================================================

	for _, a := range config.ExtraArgs {
		if a == "-o" || a == "--output-file" ||
			strings.HasPrefix(a, "-o=") ||
			strings.HasPrefix(a, "--output-file=") {
			return fmt.Errorf(
				"extra_args must not contain -o / --output-file; the output destination is managed by the runner (found %q)", a)
		}
	}

	return nil
}
