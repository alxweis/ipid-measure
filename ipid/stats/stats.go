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

	InFlightProbes int64
	SentBytes      int64
	SentPackets    int64

	MatchedReplies int64

	DropDecode   int64 // DecodeLayers failed: truncated or malformed
	DropProto    int64 // L4 extraction failed: layer missing, wrong type, ZMap-port mismatch
	DropNoEntry  int64 // No in-flight entry for srcIP (late reply / not our probe)
	DropBadDst   int64 // dstIP not one of our expected sender IPs
	DropBadPort  int64 // dstPort outside the probe's connection range
	DropBadFlags int64 // TCP/DNS flag set does not match expectation
	DropSeqOOR   int64 // recovered seqNum outside the probe's expected range
	DropLate     int64 // reply arrived after MaximumToleratedRTT
	DropDup      int64 // sample already filled (duplicate reply)

	DropBadTarget   int64 // target IP did not parse as v4
	DropLimiterStop int64 // rate limiter returned stopped (shutdown)
	DropSendErr     int64 // syscall.Sendmsg failed
	DropTimeout     int64 // probe abandoned at RTT timer
	DropInterrupt   int64 // StopSignal observed mid-probe
	DropNotRecv     int64 // RT-based: entry.done fired but IsReceived was false
	DropRateLow     int64 // FixedInterval: received/total < MinimumReplyRate

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
		lastProbeCount  int64
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
			deltaProbeCount := probeCount - lastProbeCount
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

			replyDrops := joinNonZero(
				kv{"decode", atomic.LoadInt64(&DropDecode)},
				kv{"proto", atomic.LoadInt64(&DropProto)},
				kv{"no_entry", atomic.LoadInt64(&DropNoEntry)},
				kv{"bad_dst", atomic.LoadInt64(&DropBadDst)},
				kv{"bad_port", atomic.LoadInt64(&DropBadPort)},
				kv{"bad_flags", atomic.LoadInt64(&DropBadFlags)},
				kv{"seq_oor", atomic.LoadInt64(&DropSeqOOR)},
				kv{"late", atomic.LoadInt64(&DropLate)},
				kv{"dup", atomic.LoadInt64(&DropDup)},
			)
			probeDrops := joinNonZero(
				kv{"bad_target", atomic.LoadInt64(&DropBadTarget)},
				kv{"limiter_stop", atomic.LoadInt64(&DropLimiterStop)},
				kv{"send_err", atomic.LoadInt64(&DropSendErr)},
				kv{"timeout", atomic.LoadInt64(&DropTimeout)},
				kv{"interrupt", atomic.LoadInt64(&DropInterrupt)},
				kv{"not_recv", atomic.LoadInt64(&DropNotRecv)},
				kv{"rate_low", atomic.LoadInt64(&DropRateLow)},
			)

			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			inFlight := atomic.LoadInt64(&InFlightProbes)

			log.Printf(
				"estimated_time_left=[%s] "+
					"probed_ip_addresses=[+%d, %.2f%%] "+
					"valid_probes=[+%d, %.2f%%] "+
					"sent_mbps=[%.0f] "+
					"sent_pps=[%.0f] "+
					"replies[matched=%d %s] "+
					"probes[%s] "+
					"heap=[%dMB] "+
					"in_flight=[%d]",
				timeLeft,
				deltaProbeCount,
				probeCountPercentage,
				deltaValidProbeCount,
				validProbeCountPercentage,
				sentMbps,
				sentPps,
				matched, replyDrops,
				probeDrops,
				ms.HeapAlloc>>20,
				inFlight,
			)

			lastProbeCount = probeCount
			lastValidProbes = validProbes
			lastSentBytes = sentBytes
			lastSentPackets = sentPackets
		}
	}
}

func init() {
	measurement.StartStats = func() { go Log() }
	measurement.GetRecordCount = func() int64 { return atomic.LoadInt64(&ValidProbes) }
}

type kv struct {
	name string
	val  int64
}

func joinNonZero(items ...kv) string {
	var sb strings.Builder
	for _, it := range items {
		if it.val == 0 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%s=%d", it.name, it.val)
	}
	if sb.Len() == 0 {
		return "none"
	}
	return sb.String()
}
