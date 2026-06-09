package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"

	"github.com/netd-tud/ipid-measure/internal/types"
)

type ZMapConfig struct {
	Payload                   types.Payload `yaml:"payload"`
	Port                      *uint16       `yaml:"port"`
	Interface                 Interface     `yaml:"interface"`
	NumberOfTargetIPAddresses *ScaledNumber `yaml:"number_of_target_ip_addresses"`

	Bandwidth        *ScaledNumber `yaml:"bandwidth"`
	PacketsPerSecond *ScaledNumber `yaml:"packets_per_second"`

	SenderThreads   ScaledNumber `yaml:"sender_threads"`
	ProbesPerTarget ScaledNumber `yaml:"probes_per_target"`
	Verbosity       uint8        `yaml:"verbosity"`

	Seed *uint64 `yaml:"seed"`

	BlacklistFile *string `yaml:"blacklist_file"`
	WhitelistFile *string `yaml:"whitelist_file"`

	SourcePortMin *uint16 `yaml:"source_port_min"`
	SourcePortMax *uint16 `yaml:"source_port_max"`

	Dryrun bool `yaml:"dryrun"`
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
	// Rate
	// ==================================================

	if config.Bandwidth != nil {
		bandwidth := uint64(*config.Bandwidth)
		if bandwidth != 0 && (bandwidth < 1_000 || bandwidth > 5_000_000_000) {
			return fmt.Errorf("bandwidth must be between 1K and 5G")
		}
	}

	if config.PacketsPerSecond != nil {
		pps := uint64(*config.PacketsPerSecond)
		if pps == 0 || pps > 100_000_000 {
			return fmt.Errorf("packets_per_second must be between 1 and 100M")
		}
	}

	if config.Bandwidth == nil && config.PacketsPerSecond == nil {
		return fmt.Errorf("either bandwidth or packets_per_second must be set")
	}

	// ==================================================
	// Optional
	// ==================================================

	if config.SenderThreads < 1 || config.SenderThreads > 1_000 {
		return fmt.Errorf("sender_threads must be between 1 and 1K")
	}

	if config.ProbesPerTarget < 1 || config.ProbesPerTarget > 100 {
		return fmt.Errorf("probes_per_target must be between 1 and 100")
	}

	if config.Verbosity > 5 {
		return fmt.Errorf("verbosity must be between 0 and 5")
	}

	// ==================================================
	// Source port range
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

	return nil
}
