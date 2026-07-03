package config

import (
	"fmt"
	"os"

	"github.com/alxweis/ipid-measure/internal/files"
	"github.com/alxweis/ipid-measure/internal/types"
	"gopkg.in/yaml.v3"
)

type ZMapConfig struct {
	Payload                   types.Payload `yaml:"payload"`
	Port                      *uint16       `yaml:"port"`
	ProbeArgs                 *string       `yaml:"probe_args"`
	Interface                 Interface     `yaml:"interface"`
	NumberOfTargetIPAddresses *ScaledNumber `yaml:"number_of_target_ip_addresses"`

	Bandwidth        *ScaledNumber `yaml:"bandwidth"`
	PacketsPerSecond *ScaledNumber `yaml:"packets_per_second"`
	SenderThreads    *ScaledNumber `yaml:"sender_threads"`

	Dryrun        bool    `yaml:"dryrun"`
	BlacklistFile *string `yaml:"blacklist_file"`
	WhitelistFile *string `yaml:"whitelist_file"`

	LogToFile bool `yaml:"log_to_file"`

	GoMemoryLimit *ScaledNumber `yaml:"go_memory_limit"`

	UploadConfig UploadConfig `yaml:"upload"`
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
	case types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS:
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
			return fmt.Errorf("port must be in [1, 65535]")
		}
	}

	if config.Payload == types.PayloadUDPDNS && *config.Port != 53 {
		return fmt.Errorf("udp-dns payload requires port 53")
	}

	if config.Payload == types.PayloadUDPDNS {
		if config.ProbeArgs == nil {
			return fmt.Errorf("probe_args cannot be null for the udp-dns payload")
		} else if *config.ProbeArgs == "" {
			return fmt.Errorf("probe_args cannot be empty for the udp-dns payload")
		}
	} else if config.ProbeArgs != nil {
		return fmt.Errorf("probe_args must be null")
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

	if (config.Bandwidth == nil) == (config.PacketsPerSecond == nil) {
		return fmt.Errorf("set exactly one of bandwidth or packets_per_second")
	}

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

	if config.SenderThreads != nil {
		threads := uint64(*config.SenderThreads)
		if threads < 1 || threads > 1_000 {
			return fmt.Errorf("sender_threads must be in [1, 1K] or null")
		}
	}

	// --- MEMORY ------------------------------------------------------------------

	if err := validateGoMemoryLimit(config.GoMemoryLimit); err != nil {
		return err
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

	// --- UPLOAD ------------------------------------------------------------------

	if err := validateUpload(config.UploadConfig); err != nil {
		return err
	}

	return nil
}
