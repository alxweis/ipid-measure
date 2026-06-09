package config

import (
	"fmt"
	"github.com/netd-tud/ipid-measure/internal/sets"
	"github.com/netd-tud/ipid-measure/internal/types"
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

type IPIDConfig struct {
	ZMapReference `yaml:",inline"`

	ConnectionCount       uint16                `yaml:"connection_count"`
	RequestsPerConnection uint16                `yaml:"requests_per_connection"`
	MeasurementMode       types.MeasurementMode `yaml:"measurement_mode"`
	FixedIntervalConfig   FixedIntervalConfig   `yaml:"fixed_interval"`
	TCPConfig             TCPConfig             `yaml:"tcp"`
	RequestIPIDs          []uint16              `yaml:"request_ip_ids"`
	MaximumToleratedRTT   time.Duration         `yaml:"maximum_tolerated_rtt"`

	// Bandwidth caps the global send rate in bits per second (token bucket over
	// frame bytes). 0 disables the bandwidth cap. PacketsPerSecond optionally
	// caps the global send rate in packets per second; 0 disables it. At least
	// one of the two (or a finite Concurrency) must bound the run.
	Bandwidth        ScaledNumber `yaml:"bandwidth"`
	PacketsPerSecond ScaledNumber `yaml:"packets_per_second"`

	// Concurrency is the number of targets probed simultaneously (the size of the
	// prober goroutine pool). It decouples throughput from a per-worker model:
	// throughput is bounded by the rate limiter, while Concurrency only needs to
	// be large enough to cover bandwidth*RTT (Little's law). 0 -> derived default.
	Concurrency uint64 `yaml:"concurrency"`

	WorkerCount             uint64 `yaml:"worker_count"`
	WorkerTargetChannelSize uint64 `yaml:"worker_target_channel_size"`

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

// UnmarshalYAML lets users write TCP flag sets as compact strings ("SA", "R")
// instead of YAML sequences. Each character in the string maps to one TCP flag
// letter (S, A, R, P, F, U, E, C, N). request_flags is a single string;
// reply_flags is a list of strings — both are translated to sets.Set[string]
// so downstream code keeps using the existing set comparison logic.
func (c *TCPConfig) UnmarshalYAML(node *yaml.Node) error {
	// Mirror the struct but with the flag fields as strings so we can decode
	// the YAML in one pass and then convert to sets ourselves.
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

// parseTCPFlagSet splits a flag string like "SA" into a set {S, A}. Unknown
// or duplicate letters are simply added/deduped via the set; validation of
// the resulting set against the canonical flag alphabet is done separately
// by validateTCPFlagSet so the error message is unified with other config
// validation errors.
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
	if err := config.ValidateAndParseZMap(); err != nil {
		return fmt.Errorf("invalid zmap reference: %w", err)
	}

	// ==================================================
	// ConnectionCount
	// ==================================================

	if config.ConnectionCount < 2 || config.ConnectionCount > 16 || config.ConnectionCount%2 == 1 {
		return fmt.Errorf("port_count must be even between 2 and 16")
	}

	// ==================================================
	// RequestsPerConnection
	// ==================================================

	if config.RequestsPerConnection == 0 || config.RequestsPerConnection > 10 {
		return fmt.Errorf("requests_per_port must be between 1 and 10")
	}

	// ==================================================
	// RequestCount
	// ==================================================
	requestCount := config.ConnectionCount * config.RequestsPerConnection

	// ==================================================
	// MeasurementMode
	// ==================================================

	switch config.MeasurementMode {
	case types.MeasurementModeFixedInterval:
	case types.MeasurementModeRTBased:
	default:
		return fmt.Errorf("invalid measurement_mode: %s", config.MeasurementMode)
	}

	// ==================================================
	// FixedIntervalConfig
	// ==================================================

	if config.FixedIntervalConfig.RequestInterval < 0 ||
		config.FixedIntervalConfig.RequestInterval > 10*time.Second {
		return fmt.Errorf("fixed_interval.request_interval must be between 0s and 10s")
	}

	if config.FixedIntervalConfig.MinimumReplyRate < 0.0 ||
		config.FixedIntervalConfig.MinimumReplyRate > 1.0 {
		return fmt.Errorf("fixed_interval.minimum_reply_rate must be between 0.0 and 1.0")
	}

	// ==================================================
	// TCPConfig
	// ==================================================

	if len(config.TCPConfig.RequestFlags) == 0 ||
		len(config.TCPConfig.RequestFlags) > 2 {
		return fmt.Errorf("tcp.request_flags length must be between 1 and 2")
	}

	if ok := validateTCPFlagSet(config.TCPConfig.RequestFlags); !ok {
		return fmt.Errorf("invalid tcp.request_flags")
	}

	if len(config.TCPConfig.ReplyFlags) == 0 ||
		len(config.TCPConfig.ReplyFlags) > 5 {
		return fmt.Errorf("tcp.reply_flags length must be between 1 and 5")
	}

	for _, flags := range config.TCPConfig.ReplyFlags {
		if len(flags) == 0 ||
			len(flags) > 2 {
			return fmt.Errorf("tcp.reply_flags item length must be between 1 and 2")
		}

		if ok := validateTCPFlagSet(flags); !ok {
			return fmt.Errorf("invalid tcp.reply_flags")
		}
	}

	// ==================================================
	// RequestIPIDs
	// ==================================================

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

	// ==================================================
	// MaximumToleratedRTT
	// ==================================================

	if config.MaximumToleratedRTT < time.Millisecond ||
		config.MaximumToleratedRTT > 10*time.Second {
		return fmt.Errorf(
			"maximum_tolerated_rtt must be between 1ms and 10s",
		)
	}

	// ==================================================
	// Workers
	// ==================================================
	//
	// WorkerCount and Concurrency:
	//   - In the old architecture, replies were routed to a per-worker channel by
	//     a hash bitmask, which required WorkerCount to be a power of two.
	//   - The new decoupled architecture matches replies via a shared sharded
	//     inflight registry, so there is no per-worker reply channel and no
	//     bitmask requirement. WorkerCount is therefore validated only as a
	//     coarse sanity bound; the actual prober-pool size is Concurrency.
	//   - If Concurrency is 0 it falls back to WorkerCount for backward
	//     compatibility with existing config files.

	if config.WorkerCount == 0 || config.WorkerCount > 1_000_000 {
		return fmt.Errorf("worker_count must be between 1 and 1000000")
	}

	if config.Concurrency == 0 {
		config.Concurrency = config.WorkerCount
	}
	if config.Concurrency > 1_000_000 {
		return fmt.Errorf("concurrency must be <= 1000000")
	}

	// At least one effective rate bound must be configured to prevent runaway
	// sending. The bandwidth cap is the primary throttle (matching the ZMap
	// convention); pps is offered as an alternative or additional cap.
	if config.Bandwidth == 0 && config.PacketsPerSecond == 0 {
		return fmt.Errorf("at least one of bandwidth or packets_per_second must be > 0")
	}

	if config.WorkerTargetChannelSize == 0 ||
		config.WorkerTargetChannelSize > 1000 {
		return fmt.Errorf(
			"worker_target_queue_size must be between 1 and 1000",
		)
	}

	// ==================================================
	// Interfaces
	// ==================================================

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
