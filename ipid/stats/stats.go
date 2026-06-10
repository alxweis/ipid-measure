package stats

import (
	"fmt"
	"log"
	"runtime"
	"strings"
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

	// ProbesReachedSeq[i] counts probes that successfully completed seqNum=i.
	// Size up to 256: practical RequestCount is small. A probe that finishes
	// seqNum=15 increments both ProbesReachedSeq[0..15]. Lets you spot whether
	// probes die mostly at the first seq (host unreachable) or mid-sequence
	// (ICMP rate-limiting). Sized at init() from RequestCount.
	ProbesReachedSeq []int64
)

func Log() {
	defer measurement.LogsWg.Done()

	if ProbesReachedSeq == nil {
		ProbesReachedSeq = make([]int64, measurement.RequestCount)
	}

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

			// Per-seq histogram. For small RequestCount (typical) show every
			// seq; otherwise show 5 quantile positions.
			n := len(ProbesReachedSeq)
			var seqHist string
			if n > 0 {
				if n <= 32 {
					var sb strings.Builder
					sb.WriteString("reached_seq=[")
					for i := 0; i < n; i++ {
						if i > 0 {
							sb.WriteByte(' ')
						}
						fmt.Fprintf(&sb, "%d", atomic.LoadInt64(&ProbesReachedSeq[i]))
					}
					sb.WriteByte(']')
					seqHist = sb.String()
				} else {
					seqHist = fmt.Sprintf("reached_seq[0=%d, q1=%d, q2=%d, q3=%d, last=%d]",
						atomic.LoadInt64(&ProbesReachedSeq[0]),
						atomic.LoadInt64(&ProbesReachedSeq[n/4]),
						atomic.LoadInt64(&ProbesReachedSeq[n/2]),
						atomic.LoadInt64(&ProbesReachedSeq[3*n/4]),
						atomic.LoadInt64(&ProbesReachedSeq[n-1]),
					)
				}
			}

			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			inFlight := atomic.LoadInt64(&InFlightProbes)

			log.Printf(
				"estimated_time_left=[%s] "+
					"probed_ip_addresses=[%d, %.2f%%] "+
					"in_flight=[%d] "+
					"valid_probes=[%d, %d/%d=%.2f%%] "+
					"sent_mbps=[%.2f] "+
					"sent_pps=[%.0f] "+
					"replies[matched=%d unmatched=%d rejected=%d] "+
					"%s "+
					"concurrency=[%d] "+
					"heap=%dMB goroutines=%d",
				timeLeft,
				probeCount,
				probeCountPercentage,
				inFlight,
				deltaValidProbeCount,
				validProbes,
				probeCount,
				validProbeCountPercentage,
				sentMbps,
				sentPps,
				matched, unmatched, rejected,
				seqHist,
				measurement.Config.Concurrency,
				ms.HeapAlloc>>20, runtime.NumGoroutine(),
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
