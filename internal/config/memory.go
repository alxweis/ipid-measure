package config

import "fmt"

const MinGoMemoryLimitBytes = 64 << 20 // 64 MiB

func validateGoMemoryLimit(v *ScaledNumber) error {
	if v == nil {
		return nil
	}
	if uint64(*v) < MinGoMemoryLimitBytes {
		return fmt.Errorf("go_memory_limit must be at least 64M (or null for the built-in default)")
	}
	return nil
}

func GoMemoryLimitOrDefault(v *ScaledNumber, def int64) int64 {
	if v == nil {
		return def
	}
	return int64(*v)
}
