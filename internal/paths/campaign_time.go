package paths

import (
	"fmt"
	"os"
	"time"
)

// MeasurementTime permits a continental step to resume the same unpublished
// measurement after a crash. Normal commands retain their current timestamps.
func MeasurementTime() (time.Time, error) {
	if value := os.Getenv("IPID_MEASUREMENT_TIME"); value != "" {
		result, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("IPID_MEASUREMENT_TIME: %w", err)
		}
		return result.UTC(), nil
	}
	return time.Now(), nil
}
