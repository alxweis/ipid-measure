package paths

import (
	"fmt"
	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/internal/types"
	"strconv"
	"strings"
	"time"
)

// measurementID:
// icmp_YYYY-MM-DD_HH-MM-SS
// tcp-80_YYYY-MM-DD_HH-MM-SS
// udp-dns-53_YYYY-MM-DD_HH-MM-SS

func GetMeasurementID(payload types.Payload, port *uint16, timestamp time.Time) string {
	extendedPayload := string(payload)

	if port != nil {
		extendedPayload = fmt.Sprintf("%s-%d", extendedPayload, *port)
	}

	return fmt.Sprintf("%s_%s", extendedPayload, timestamp.Format(consts.TimestampFormat))
}

func ParseMeasurementID(measurementID string) (types.Payload, *uint16, time.Time, error) {
	parts := strings.SplitN(measurementID, "_", 2)
	if len(parts) != 2 {
		return "", nil, time.Time{}, fmt.Errorf("invalid measurement id format")
	}

	extendedPayload := parts[0]
	timestampStr := parts[1]

	timestamp, err := time.Parse(consts.TimestampFormat, timestampStr)
	if err != nil {
		return "", nil, time.Time{}, fmt.Errorf("invalid timestamp: %w", err)
	}

	lastDash := strings.LastIndex(extendedPayload, "-")

	// no port
	if lastDash == -1 {
		return types.Payload(extendedPayload), nil, timestamp, nil
	}

	payloadStr := extendedPayload[:lastDash]
	portStr := extendedPayload[lastDash+1:]

	portValue, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", nil, time.Time{}, fmt.Errorf("invalid port: %w", err)
	}

	port := uint16(portValue)

	return types.Payload(payloadStr), &port, timestamp, nil
}
