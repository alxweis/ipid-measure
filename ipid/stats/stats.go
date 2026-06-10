package stats

import (
	"fmt"
	"log"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/alxweis/ipid-measure/internal/consts"
	"github.com/alxweis/ipid-measure/ipid/measurement"
)

var (
	NumberOfTargetIPAddresses int64
	ValidProbes               int64
	ProbeCount                int64
	// InFlightProbes counts probes that have started but not yet finished
	// (success or timeout). Incremented at Measure() entry, decremented at
	// exit. Useful to distinguish "all probes started" from "all probes done".
	InFlightProbes int64
	SentBytes      int64
	SentPackets    int64

	// MatchedReplies: reply was matched to an in-flight probe and filled a
	// sample. UnmatchedReplies: validly decoded reply that did not match any
	// in-flight probe (typical for late replies and replies arriving after the
	// per-target window closed; these are not data loss). RejectedReplies:
	// reply could not be decoded (truncated/malformed); investigated via the
	// counter rate, not by dropping data silently.
	MatchedReplies   int64
	UnmatchedReplies int64
	RejectedReplies  int64
)

func Log() {
	defer measurement.LogsWg.Done()

	duration := consts.LogUpdateInterval
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	startTime := time.Now()

	var (
		lastValidProbes int64
		lastSentBytes   int64
		lastSentPackets int64
	)

	for {
		select {
		case <-measurement.StopLogs:
			return

		case <-ticker.C:
			// Atomic snapshot
			probeCount := atomic.LoadInt64(&ProbeCount)
			validProbes := atomic.LoadInt64(&ValidProbes)
			sentBytes := atomic.LoadInt64(&SentBytes)
			sentPackets := atomic.LoadInt64(&SentPackets)
			numberOfTargets := atomic.LoadInt64(&NumberOfTargetIPAddresses)

			// Deltas
			deltaValidProbeCount := validProbes - lastValidProbes
			deltaSentByteCount := sentBytes - lastSentBytes
			deltaSentPacketCount := sentPackets - lastSentPackets

			// Percentages
			probeCountPercentage := 0.0
			if numberOfTargets > 0 {
				probeCountPercentage = float64(probeCount) / float64(numberOfTargets) * 100
			}

			validProbeCountPercentage := 0.0
			if probeCount > 0 {
				validProbeCountPercentage = float64(validProbes) / float64(probeCount) * 100
			}

			// Sent bandwidth
			sentBit := deltaSentByteCount * 8
			sentMbps := float64(sentBit) / (1_000_000.0 * duration.Seconds())

			// Sent packet rate
			sentPps := float64(deltaSentPacketCount) / duration.Seconds()

			// Estimated remaining time
			timeLeft := "Warming up..."

			if probeCount > 0 {
				elapsedTime := time.Since(startTime)

				remainingTime := time.Duration(
					float64(elapsedTime) /
						float64(probeCount) *
						float64(numberOfTargets-probeCount),
				)

				days := int(remainingTime.Hours()) / 24
				hours := int(remainingTime.Hours()) % 24
				minutes := int(remainingTime.Minutes()) % 60
				seconds := int(remainingTime.Seconds()) % 60

				timeLeft = ""

				if days > 0 {
					timeLeft += fmt.Sprintf("%dd", days)
				}

				if hours > 0 {
					timeLeft += fmt.Sprintf("%02dh", hours)
				}

				if minutes > 0 {
					timeLeft += fmt.Sprintf("%02dm", minutes)
				}

				if seconds > 0 || timeLeft == "" {
					timeLeft += fmt.Sprintf("%02ds", seconds)
				}
			}

			matched := atomic.LoadInt64(&MatchedReplies)
			unmatched := atomic.LoadInt64(&UnmatchedReplies)
			rejected := atomic.LoadInt64(&RejectedReplies)

			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			inFlight := atomic.LoadInt64(&InFlightProbes)

			log.Printf(
				"estimated_time_left=[%s] "+
					"probed_ip_addresses=[%d, %.2f%%] "+
					"valid_probes=[%d, %.2f%%] "+
					"sent_mbps=[%.2f] "+
					"sent_pps=[%.0f] "+
					"replies[matched=%d unmatched=%d rejected=%d] "+
					"heap=[%dMB] "+
					"in_flight=[%d]",
				timeLeft,
				probeCount,
				probeCountPercentage,
				deltaValidProbeCount,
				validProbeCountPercentage,
				sentMbps,
				sentPps,
				matched, unmatched, rejected,
				ms.HeapAlloc>>20,
				inFlight,
			)

			lastValidProbes = validProbes
			lastSentBytes = sentBytes
			lastSentPackets = sentPackets
		}
	}
}

func init() {
	measurement.StartStats = func() { go Log() }
}
