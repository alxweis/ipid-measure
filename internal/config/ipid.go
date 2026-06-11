package config

import (
	"fmt"
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

type IPIDConfig struct {
	ZMapReference         `yaml:",inline"`
	ConnectionCount       uint16                `yaml:"connection_count"`
	RequestsPerConnection uint16                `yaml:"requests_per_connection"`
	MeasurementMode       types.MeasurementMode `yaml:"measurement_mode"`

	FixedIntervalConfig FixedIntervalConfig `yaml:"fixed_interval"`
	TCPConfig           TCPConfig           `yaml:"tcp"`
	RequestIPIDs        []uint16            `yaml:"request_ip_ids"`
	MaximumToleratedRTT time.Duration       `yaml:"maximum_tolerated_rtt"`

	Bandwidth              *ScaledNumber `yaml:"bandwidth"`
	PacketsPerSecond       *ScaledNumber `yaml:"packets_per_second"`
	NumberOfInflightProbes ScaledNumber  `yaml:"number_of_inflight_probes"`

	Interfaces InterfacePair `yaml:"interfaces"`
}

type FixedIntervalConfig struct {
	RequestInterval  time.Duration `yaml:"request_interval"`
	MinimumReplyRate float64       `yaml:"minimum_reply_rate"`
}

type TCPConfig struct {
	EstablishConnection bool               `yaml:"establish_connection"`
	RequestFlags        types.TCPFlagSet   `yaml:"request_flags"`
	ReplyFlags          []types.TCPFlagSet `yaml:"reply_flags"`
}

func (c *TCPConfig) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		EstablishConnection bool     `yaml:"establish_connection"`
		RequestFlags        string   `yaml:"request_flags"`
		ReplyFlags          []string `yaml:"reply_flags"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}

	c.EstablishConnection = raw.EstablishConnection

	if raw.RequestFlags != "" {
		c.RequestFlags = parseTCPFlagSet(raw.RequestFlags)
	}
	if len(raw.ReplyFlags) > 0 {
		c.ReplyFlags = make([]types.TCPFlagSet, len(raw.ReplyFlags))
		for i, s := range raw.ReplyFlags {
			c.ReplyFlags[i] = parseTCPFlagSet(s)
		}
	}
	return nil
}

// parseTCPFlagSet splits a flag string like "SA" into a set {S, A}.
func parseTCPFlagSet(s string) types.TCPFlagSet {
	set := sets.New[types.TCPFlag]()
	for i := 0; i < len(s); i++ {
		set.Add(string(s[i]))
	}
	return set
}

func LoadIPIDConfig(path string) (*IPIDConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var config IPIDConfig

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %w", err)
	}

	if err := validateIPIDConfig(&config); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &config, nil
}

func validateIPIDConfig(config *IPIDConfig) error {
	// --- GENERAL -----------------------------------------------------------------

	if err := config.ValidateAndParseZMap(); err != nil {
		return fmt.Errorf("invalid zmap reference: %w", err)
	}

	if config.ConnectionCount < 2 || config.ConnectionCount > 16 || config.ConnectionCount%2 == 1 {
		return fmt.Errorf("port_count must be even and in [2, 16]")
	}

	if config.RequestsPerConnection < 1 || config.RequestsPerConnection > 10 {
		return fmt.Errorf("requests_per_port must be in [1, 10]")
	}

	requestCount := config.ConnectionCount * config.RequestsPerConnection

	switch config.MeasurementMode {
	case types.MeasurementModeFixedInterval:
	case types.MeasurementModeRTBased:
	default:
		return fmt.Errorf("invalid measurement_mode: %s", config.MeasurementMode)
	}

	// --- DETAILS -----------------------------------------------------------------

	if config.FixedIntervalConfig.RequestInterval < 0 ||
		config.FixedIntervalConfig.RequestInterval > 10*time.Second {
		return fmt.Errorf("fixed_interval.request_interval must be in [0s, 10s]")
	}

	if config.FixedIntervalConfig.MinimumReplyRate < 0.0 ||
		config.FixedIntervalConfig.MinimumReplyRate > 1.0 {
		return fmt.Errorf("fixed_interval.minimum_reply_rate must be in [0.0, 1.0]")
	}

	if len(config.TCPConfig.RequestFlags) == 0 ||
		len(config.TCPConfig.RequestFlags) > 2 {
		return fmt.Errorf("tcp.request_flags length must be in [1, 2]")
	}

	if ok := validateTCPFlagSet(config.TCPConfig.RequestFlags); !ok {
		return fmt.Errorf("invalid tcp.request_flags")
	}

	if len(config.TCPConfig.ReplyFlags) == 0 ||
		len(config.TCPConfig.ReplyFlags) > 5 {
		return fmt.Errorf("tcp.reply_flags length must be in [1, 5]")
	}

	for _, flags := range config.TCPConfig.ReplyFlags {
		if len(flags) == 0 ||
			len(flags) > 2 {
			return fmt.Errorf("tcp.reply_flags item length must be in [1, 2]")
		}

		if ok := validateTCPFlagSet(flags); !ok {
			return fmt.Errorf("invalid tcp.reply_flags")
		}
	}

	if len(config.RequestIPIDs) == 0 {
		return fmt.Errorf("request_ip_ids must not be empty")
	}

	if len(config.RequestIPIDs) > int(requestCount) {
		return fmt.Errorf(
			"request_ip_ids length (%d) exceeds request_count (%d)",
			len(config.RequestIPIDs),
			requestCount,
		)
	}

	if config.MaximumToleratedRTT < time.Millisecond || config.MaximumToleratedRTT > 10*time.Second {
		return fmt.Errorf("maximum_tolerated_rtt must be in [1ms, 10s]")
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

	if config.NumberOfInflightProbes < 1 || config.NumberOfInflightProbes > 1_000_000 {
		return fmt.Errorf("number_of_inflight_probes must be in [1, 1M]")
	}

	// --- INTERFACES --------------------------------------------------------------

	if err := validateInterface(
		config.Interfaces.A,
		"interfaces.a",
		true,
		true,
	); err != nil {
		return err
	}

	if err := validateInterface(
		config.Interfaces.B,
		"interfaces.b",
		false,
		true,
	); err != nil {
		return err
	}

	return nil
}

func validateTCPFlagSet(flags types.TCPFlagSet) bool {
	allTCPFlags := sets.New(
		types.TCPFlagFIN,
		types.TCPFlagSYN,
		types.TCPFlagRST,
		types.TCPFlagPSH,
		types.TCPFlagACK,
		types.TCPFlagURG,
		types.TCPFlagECE,
		types.TCPFlagCWR,
		types.TCPFlagNS,
	)

	for flag := range flags {
		if !allTCPFlags.Contains(flag) {
			return false
		}
	}

	return true
}
