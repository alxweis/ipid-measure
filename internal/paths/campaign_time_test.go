package paths

import (
	"testing"
	"time"
)

func TestCampaignTimeDefaultExplicitAndInvalid(t *testing.T) {
	t.Setenv("IPID_MEASUREMENT_TIME", "")
	now, err := MeasurementTime()
	if err != nil || time.Since(now) > time.Second {
		t.Fatal(now, err)
	}
	t.Setenv("IPID_MEASUREMENT_TIME", "2026-10-25T02:30:00+02:00")
	stamp, err := MeasurementTime()
	if err != nil || stamp.Format(time.RFC3339) != "2026-10-25T00:30:00Z" {
		t.Fatal(stamp, err)
	}
	t.Setenv("IPID_MEASUREMENT_TIME", "invalid")
	if _, err = MeasurementTime(); err == nil {
		t.Fatal("invalid planned time accepted")
	}
}
