package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// ZMapSeed is an explicit unsigned 64-bit seed. A nil *ZMapSeed lets ZMap
// choose its own seed; zero is an explicit seed like any other integer.
type ZMapSeed uint64

func (s *ZMapSeed) UnmarshalYAML(node *yaml.Node) error {
	// yaml.v3 otherwise accepts floating-point values for integer fields.
	if node.Tag != "!!int" {
		return fmt.Errorf("seed must be an integer in [0, 18446744073709551615] or null")
	}
	var value uint64
	if err := node.Decode(&value); err != nil {
		return fmt.Errorf("invalid seed: %w", err)
	}
	*s = ZMapSeed(value)
	return nil
}
