package probe

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/packet"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/port"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/seqnum"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

type SampleState int32

const (
	SampleEmpty    SampleState = 0
	SampleSent     SampleState = 1
	SampleReceived SampleState = 2
)

type Probe struct {
	Target  net.IP
	Samples []Sample
}

type Sample struct {
	state atomic.Int32 // SampleState

	SentTime    int64
	ReceiveTime int64
	IpID        uint16
}

func (s *Sample) MarkSent(now int64) {
	s.SentTime = now
	s.state.Store(int32(SampleSent))
}

func (s *Sample) TryFill(ipID uint16, receiveTime int64) bool {
	if SampleState(s.state.Load()) != SampleSent {
		return false
	}
	s.IpID = ipID
	s.ReceiveTime = receiveTime
	return s.state.CompareAndSwap(int32(SampleSent), int32(SampleReceived))
}

func (s *Sample) IsReceived() bool {
	return SampleState(s.state.Load()) == SampleReceived
}

var SaveProbesChannel chan *Probe

// sentinelAnySeq marks an InflightEntry as accepting any seq in [0, RequestCount).
const sentinelAnySeq uint32 = 0xFFFFFFFF

// Measure probes a single target end-to-end.
func Measure(target net.IP, scratch []packet.Packet) bool {
	target4 := target.To4()
	if target4 == nil {
		return false
	}

	atomic.AddInt64(&stats.ProbeCount, 1)
	atomic.AddInt64(&stats.InFlightProbes, 1)
	defer atomic.AddInt64(&stats.InFlightProbes, -1)

	basePort := port.Next()
	packet.BuildPacketsInto(scratch, target4, basePort)

	probe := &Probe{
		Target:  target4,
		Samples: make([]Sample, measurement.RequestCount),
	}

	var targetKey [4]byte
	copy(targetKey[:], target4)

	// Cache sender IP addresses for the receiver-side validation that runs out of the InflightEntry
	var sa, sb [4]byte
	copy(sa[:], sender.SenderA.IP.To4())
	copy(sb[:], sender.SenderB.IP.To4())

	switch measurement.Config.MeasurementMode {
	case types.MeasurementModeRTBased:
		return measureRTBased(probe, targetKey, scratch, basePort, sa, sb)
	case types.MeasurementModeFixedInterval:
		return measureFixedInterval(probe, targetKey, scratch, basePort, sa, sb)
	default:
		return false
	}
}

// measureRTBased: one outstanding request at a time.
// For each seqNum we register a one-shot inflight entry, mark+send, then wait for it or timeout.
// On timeout/duplicate/invalid the probe aborts.
func measureRTBased(
	probe *Probe,
	targetKey [4]byte,
	scratch []packet.Packet,
	basePort uint16,
	sa, sb [4]byte,
) bool {
	rtt := measurement.Config.MaximumToleratedRTT
	timer := time.NewTimer(rtt)
	defer timer.Stop()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		req := &scratch[seqNum]

		// Pick the flag expectation for this seqNum.
		flagMode := FlagsDefault
		if measurement.TcpEstablishConnection {
			if seqnum.GetConnectionIndex(seqNum) == 0 {
				flagMode = FlagsSynAck
			} else {
				flagMode = FlagsPshAck
			}
		}

		expectedPort := port.GetSrcPort(seqNum, basePort)

		entry := &InflightEntry{
			Probe:         probe,
			expectedCount: 1,
			expectedSeq:   uint32(seqNum),
			FlagMode:      flagMode,
			done:          make(chan struct{}),
			minPort:       expectedPort,
			maxPort:       expectedPort,
			senderA:       sa,
			senderB:       sb,
		}
		Inflight.Register(targetKey, entry)

		// MarkSent publishes SentTime before the sending.
		probe.Samples[seqNum].MarkSent(time.Now().UnixMicro())

		if err := req.Sender.Send(req.Bytes); err != nil {
			Inflight.Deregister(targetKey, entry)
			return false
		}
		// Update sent counters incrementally.
		atomic.AddInt64(&stats.SentBytes, int64(len(req.Bytes)))
		atomic.AddInt64(&stats.SentPackets, 1)

		// Reset and reuse the per-target timer to avoid per-seqNum allocation.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(rtt)

		select {
		case <-entry.done:
			// Sample filled by the receiver.
			Inflight.Deregister(targetKey, entry)
			if !probe.Samples[seqNum].IsReceived() {
				return false
			}
			atomic.AddInt64(&stats.ProbesReachedSeq[seqNum], 1)

		case <-timer.C:
			Inflight.Deregister(targetKey, entry)
			return false

		case <-measurement.StopSignal:
			Inflight.Deregister(targetKey, entry)
			return false
		}
	}

	SaveProbesChannel <- probe
	atomic.AddInt64(&stats.ValidProbes, 1)
	return true
}

// measureFixedInterval: send all requests spaced by request_interval
// Collect replies for up to MaximumToleratedRTT.
// The probe is kept iff the reply rate meets MinimumReplyRate.
func measureFixedInterval(
	probe *Probe,
	targetKey [4]byte,
	scratch []packet.Packet,
	basePort uint16,
	sa, sb [4]byte,
) bool {
	entry := &InflightEntry{
		Probe:         probe,
		expectedCount: uint32(measurement.RequestCount),
		expectedSeq:   sentinelAnySeq,
		done:          make(chan struct{}),
		minPort:       basePort,
		maxPort:       basePort + measurement.Config.ConnectionCount - 1,
		senderA:       sa,
		senderB:       sb,
	}
	Inflight.Register(targetKey, entry)
	defer Inflight.Deregister(targetKey, entry)

	interval := measurement.Config.FixedIntervalConfig.RequestInterval

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		req := &scratch[seqNum]
		probe.Samples[seqNum].MarkSent(time.Now().UnixMicro())
		if err := req.Sender.Send(req.Bytes); err != nil {
			return false
		}
		atomic.AddInt64(&stats.SentBytes, int64(len(req.Bytes)))
		atomic.AddInt64(&stats.SentPackets, 1)

		if interval > 0 && seqNum+1 < measurement.RequestCount {
			time.Sleep(interval)
		}
	}

	// Wait for all expected replies or for the MaximumToleratedRTT to elapse.
	timer := time.NewTimer(measurement.Config.MaximumToleratedRTT)
	defer timer.Stop()

	select {
	case <-entry.done:
	case <-timer.C:
	case <-measurement.StopSignal:
		return false
	}

	// Count finally received samples.
	received := 0
	for i := range probe.Samples {
		if probe.Samples[i].IsReceived() {
			received++
		}
	}

	rate := float64(received) / float64(measurement.RequestCount)
	if rate < measurement.Config.FixedIntervalConfig.MinimumReplyRate {
		return false
	}

	SaveProbesChannel <- probe
	atomic.AddInt64(&stats.ValidProbes, 1)
	return true
}

// FulfillReply is called by the receiver for every captured reply.
func FulfillReply(
	srcIP4 [4]byte,
	dstIP4 [4]byte,
	dstPort uint16,
	recoveredSeq uint16,
	ipID uint16,
	replyFlags sets.Set[string],
	receiveTime int64,
) bool {
	entry := Inflight.Lookup(srcIP4)
	if entry == nil {
		return false
	}

	// TODO: RateLimiter never interrupts a measurement of a target
	// TODO: Parameterize all constants

	// Destination IP must be one of our senders.
	if dstIP4 != entry.senderA && dstIP4 != entry.senderB {
		return false
	}

	// TODO: In RT-based mode, Destination IP has to match exactly.

	// Destination port must be within this probe's connection range.
	if measurement.HasPorts {
		if dstPort < entry.minPort || dstPort > entry.maxPort {
			return false
		}
	}

	// Flag-mode check
	if !flagsMatch(entry.FlagMode, replyFlags) {
		return false
	}

	// In RT-based mode, a specific seqNum is expected.
	if entry.expectedSeq != sentinelAnySeq && uint32(recoveredSeq) != entry.expectedSeq {
		return false
	}

	if int(recoveredSeq) >= len(entry.Probe.Samples) {
		return false
	}
	sample := &entry.Probe.Samples[recoveredSeq]

	// Late reply: reject if RTT exceeds tolerance.
	if receiveTime-sample.SentTime > measurement.Config.MaximumToleratedRTT.Microseconds() {
		return false
	}

	if !sample.TryFill(ipID, receiveTime) {
		// Duplicate reply or sample not in Sent state.
		return false
	}

	// Update the completion counter and signal if we have hit the target.
	if entry.validCount.Add(1) >= entry.expectedCount {
		entry.markDone()
	}
	return true
}

func flagsMatch(mode FlagExpectation, replyFlags sets.Set[string]) bool {
	switch mode {
	case FlagsSynAck:
		return replyFlags.Equal(sets.New(types.TCPFlagSYN, types.TCPFlagACK))
	case FlagsPshAck:
		return replyFlags.Equal(sets.New(types.TCPFlagPSH, types.TCPFlagACK))
	case FlagsDefault:
		// Defer to the configured payload-specific flag set selection.
		return defaultFlagsMatch(replyFlags)
	}
	return false
}

// defaultFlagsMatch implements the protocol-default flag check.
func defaultFlagsMatch(replyFlags sets.Set[string]) bool {
	switch payload.Active.ProtocolID {
	case layers.IPProtocolTCP:
		for _, expected := range measurement.Config.TCPConfig.ReplyFlags {
			if replyFlags.Equal(expected) {
				return true
			}
		}
		return false
	case layers.IPProtocolUDP:
		return replyFlags.Equal(sets.New(types.DNSFlagQR))
	case layers.IPProtocolICMPv4:
		return true // ICMP has no flag set.
	}
	return false
}
