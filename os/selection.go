package os

import (
	"fmt"
	"math"
)

const secondaryZGrab2Trigger = "secondary"

// selectSecondary deterministically samples targets without retaining any
// per-IP state. The stable FNV-1a hash makes repeated campaigns select the
// same addresses for a given sample rate.
func selectSecondary(ip string, rate float64) bool {
	if rate <= 0 {
		return false
	}
	if rate >= 1 {
		return true
	}

	var hash uint64 = 14695981039346656037
	for i := 0; i < len(ip); i++ {
		hash ^= uint64(ip[i])
		hash *= 1099511628211
	}
	threshold := uint64(rate * float64(math.MaxUint64))
	return hash <= threshold
}

// zgrab2InputLine attaches a trigger tag only to sampled targets. Core modules
// have no trigger and therefore still run for every input line.
func zgrab2InputLine(ip string, secondary bool) string {
	if !secondary {
		return ip
	}
	return fmt.Sprintf("%s,,%s", ip, secondaryZGrab2Trigger)
}
