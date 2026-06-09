package config

import (
	"fmt"
	"github.com/alxweis/ipid-measure/internal/files"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type OSConfig struct {
	ZMapReference `yaml:",inline"`
	Interface     Interface `yaml:"interface"`
	Modules       OSModules `yaml:"modules"`

	ZGrab2Senders *ScaledNumber `yaml:"zgrab2_senders"`
	ZDNSThreads   *ScaledNumber `yaml:"zdns_threads"`
	SNMPWorkers   *ScaledNumber `yaml:"snmp_workers"`

	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	SNMPTimeout    time.Duration `yaml:"snmp_timeout"`

	SNMPCommunity string `yaml:"snmp_community"`

	ZGrab2Binary        *string `yaml:"zgrab2_binary"`
	ZDNSBinary          *string `yaml:"zdns_binary"`
	ZGrab2BlocklistFile *string `yaml:"zgrab2_blocklist_file"`
}

func LoadOSConfig(path string) (*OSConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var config OSConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}
	if err := validateOSConfig(&config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}
	return &config, nil
}

func validateOSConfig(config *OSConfig) error {
	// --- GENERAL -----------------------------------------------------------------

	if err := config.ValidateAndParseZMap(); err != nil {
		return fmt.Errorf("invalid zmap reference: %w", err)
	}

	// No raw-ICMP send/receive permission test required, as modules only open regular sockets
	if err := validateInterface(
		config.Interface,
		"interface",
		false,
		false,
	); err != nil {
		return err
	}

	if err := validateOSModules(config.Modules); err != nil {
		return err
	}

	// --- SPEED -------------------------------------------------------------------

	if config.ZGrab2Senders != nil {
		zgrab2Senders := uint64(*config.ZGrab2Senders)
		if zgrab2Senders < 1 || zgrab2Senders > 10_000 {
			return fmt.Errorf("zgrab2_senders must be in [1, 10K]")
		}
	} else if HasZGrab2Module(config.Modules) {
		return fmt.Errorf("zgrab2_senders must be set, if you use zgrab2 modules")
	}

	if config.ZDNSThreads != nil {
		zdnsThreads := uint64(*config.ZDNSThreads)
		if zdnsThreads < 1 || zdnsThreads > 10_000 {
			return fmt.Errorf("zdns_threads must be in [1, 10K]")
		}
	} else if HasZDNSModule(config.Modules) {
		return fmt.Errorf("zdns_threads must be set, if you use zdns modules")
	}

	if config.SNMPWorkers != nil {
		snmpWorkers := uint64(*config.SNMPWorkers)
		if snmpWorkers < 1 || snmpWorkers > 10_000 {
			return fmt.Errorf("snmp_workers must be in [1, 10K]")
		}
	} else if HasSNMPModule(config.Modules) {
		return fmt.Errorf("snmp_workers must be set, if you use snmp modules")
	}

	// --- ADDITIONAL --------------------------------------------------------------

	if config.ConnectTimeout < 500*time.Millisecond || config.ConnectTimeout > 10*time.Second {
		return fmt.Errorf("connect_timeout must be in [500ms, 10s]")
	}

	if config.ReadTimeout < 500*time.Millisecond || config.ReadTimeout > 10*time.Second {
		return fmt.Errorf("read_timeout must be in [500ms, 10s]")
	}

	if config.SNMPTimeout < 500*time.Millisecond || config.SNMPTimeout > 10*time.Second {
		return fmt.Errorf("snmp_timeout must be in [500ms, 10s]")
	}

	if config.SNMPCommunity != "public" && config.SNMPCommunity != "private" {
		return fmt.Errorf("snmp_community must be either public or private")
	}

	if config.ZGrab2Binary != nil {
		if err := files.IsFile(*config.ZGrab2Binary, "zgrab2_binary", "*"); err != nil {
			return err
		}
	}

	if config.ZDNSBinary != nil {
		if err := files.IsFile(*config.ZDNSBinary, "zdns_binary", "*"); err != nil {
			return err
		}
	}

	if config.ZGrab2BlocklistFile != nil {
		if err := files.IsFile(*config.ZGrab2BlocklistFile, "zgrab2_blocklist_file", "*"); err != nil {
			return err
		}
	}

	return nil
}
