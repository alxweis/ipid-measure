package config

import (
	"fmt"
	"github.com/alxweis/ipid-measure/internal/files"
	"gopkg.in/yaml.v3"
	"os"

	"github.com/alxweis/ipid-measure/internal/types"
)

type ZMapConfig struct {
	Payload                   types.Payload `yaml:"payload"`
	Port                      *uint16       `yaml:"port"`
	Interface                 Interface     `yaml:"interface"`
	NumberOfTargetIPAddresses *ScaledNumber `yaml:"number_of_target_ip_addresses"`

	Bandwidth        *ScaledNumber `yaml:"bandwidth"`
	PacketsPerSecond *ScaledNumber `yaml:"packets_per_second"`
	SenderThreads    ScaledNumber  `yaml:"sender_threads"`

	Dryrun        bool    `yaml:"dryrun"`
	BlacklistFile *string `yaml:"blacklist_file"`
	WhitelistFile *string `yaml:"whitelist_file"`
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
	// --- GENERAL -----------------------------------------------------------------

	switch config.Payload {
	case types.PayloadICMP:
	case types.PayloadTCP:
	case types.PayloadUDPDNS:
	default:
		return fmt.Errorf("invalid payload: %s", config.Payload)
	}

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

	if err := validateInterface(
		config.Interface,
		"interface",
		true,
		true,
	); err != nil {
		return err
	}

	if config.NumberOfTargetIPAddresses != nil {
		targets := uint64(*config.NumberOfTargetIPAddresses)
		if targets < 1 || targets > 5_000_000_000 {
			return fmt.Errorf("number_of_target_ip_addresses must be in [1, 5G] or null")
		}
	}

	// --- SPEED -------------------------------------------------------------------

	if config.Bandwidth != nil {
		bandwidth := uint64(*config.Bandwidth)
		if bandwidth < 1_000 || bandwidth > 5_000_000_000 {
			return fmt.Errorf("bandwidth must be in [1K, 5G]")
		}
	}

	if config.PacketsPerSecond != nil {
		pps := uint64(*config.PacketsPerSecond)
		if pps < 1 || pps > 100_000_000 {
			return fmt.Errorf("packets_per_second must be in [1, 100M]")
		}
	}

	if config.Bandwidth == nil && config.PacketsPerSecond == nil {
		return fmt.Errorf("either bandwidth or packets_per_second must be set")
	}

	if config.SenderThreads < 1 || config.SenderThreads > 1_000 {
		return fmt.Errorf("sender_threads must be between 1 and 1K")
	}

	// --- ADDITIONAL --------------------------------------------------------------

	if config.BlacklistFile != nil {
		if err := files.IsFile(*config.BlacklistFile, "blacklist_file", "*.*"); err != nil {
			return err
		}
	}
	if config.WhitelistFile != nil {
		if err := files.IsFile(*config.WhitelistFile, "whitelist_file", "*.*"); err != nil {
			return err
		}
	}

	return nil
}
