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
	// Speed
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

	if config.SenderThreads < 1 || config.SenderThreads > 1_000 {
		return fmt.Errorf("sender_threads must be between 1 and 1K")
	}

	// ==================================================
	// Additional
	// ==================================================

	if config.BlacklistFile != nil {
		if err := checkRegularFile(*config.BlacklistFile, "blacklist_file"); err != nil {
			return err
		}
	}
	if config.WhitelistFile != nil {
		if err := checkRegularFile(*config.WhitelistFile, "whitelist_file"); err != nil {
			return err
		}
	}

	return nil
}

func checkRegularFile(path, field string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s: file does not exist: %s", field, path)
		}
		return fmt.Errorf("%s: cannot stat %s: %w", field, path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file: %s", field, path)
	}
	return nil
}
