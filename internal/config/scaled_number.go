package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"math"
	"strconv"
	"strings"
)

type ScaledNumber uint64

func (s *ScaledNumber) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := ParseScaledNumber(node.Value)
	if err != nil {
		return err
	}

	*s = ScaledNumber(parsed)

	return nil
}

func (s ScaledNumber) Uint64() uint64 {
	return uint64(s)
}

func ParseScaledNumber(value string) (uint64, error) {
	value = strings.TrimSpace(strings.ToUpper(value))
	if value == "" {
		return 0, fmt.Errorf("empty number")
	}

	multiplier := float64(1)
	hasSuffix := true

	switch {
	case strings.HasSuffix(value, "K"):
		multiplier = 1_000
		value = strings.TrimSuffix(value, "K")

	case strings.HasSuffix(value, "M"):
		multiplier = 1_000_000
		value = strings.TrimSuffix(value, "M")

	case strings.HasSuffix(value, "G"):
		multiplier = 1_000_000_000
		value = strings.TrimSuffix(value, "G")

	case strings.HasSuffix(value, "T"):
		multiplier = 1_000_000_000_000
		value = strings.TrimSuffix(value, "T")

	default:
		hasSuffix = false
	}

	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	if number < 0 {
		return 0, fmt.Errorf("number must be >= 0")
	}

	// decimals without suffix are forbidden
	if !hasSuffix && math.Trunc(number) != number {
		return 0, fmt.Errorf(
			"decimal numbers require scale suffix (K, M, G, T)",
		)
	}

	result := number * multiplier

	// final result must be integer
	if math.Trunc(result) != result {
		return 0, fmt.Errorf(
			"scaled number does not resolve to integer",
		)
	}

	if result > math.MaxUint64 {
		return 0, fmt.Errorf("number overflow")
	}

	return uint64(result), nil
}

func (s *ScaledNumber) Str() string {
	if s == nil {
		return "(unset)"
	}
	return fmt.Sprintf("%d", uint64(*s))
}
