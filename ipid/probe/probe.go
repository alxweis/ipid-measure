package probe

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/netd-tud/ipid-measure/internal/sets"
	"github.com/netd-tud/ipid-measure/internal/types"
	"github.com/netd-tud/ipid-measure/ipid/measurement"
	"github.com/netd-tud/ipid-measure/ipid/packet"
	"github.com/netd-tud/ipid-measure/ipid/payload"
	"github.com/netd-tud/ipid-measure/ipid/port"
	"github.com/netd-tud/ipid-measure/ipid/sender"
	"github.com/netd-tud/ipid-measure/ipid/seqnum"
	"github.com/netd-tud/ipid-measure/ipid/stats"
)

// SampleState is the state of one request slot, mutated by atomic ops so the
// prober (writes SentTime + advances state to Sent) and the receiver (reads
// state, writes ReceiveTime/IpID, CASes to Received) synchronise without locks.
//
// Order:
//
//	Empty -> Sent       (prober, after writing SentTime, before send())
//	Sent  -> Received   (receiver, via CompareAndSwap; one winner only)
//
// Any other transition is rejected.
type SampleState int32

const (
	SampleEmpty    SampleState = 0
	SampleSent     SampleState = 1
	SampleReceived SampleState = 2
)

// Probe is one target's full set of request/response samples. Samples is a fixed
// slice indexed by sequence number; the receiver fills slot[seqNum] atomically.
type Probe struct {
	Target  net.IP
	Samples []Sample
}

// Sample records one request and its (possible) matching reply.
//
// Concurrency: the prober writes SentTime, then publishes via atomic.Store on
// state (Empty->Sent). The receiver reads state (must be Sent), writes IpID and
// ReceiveTime, then CASes Sent->Received. The atomic state acts as a release/
// acquire barrier so the non-atomic field writes are safely visible.
type Sample struct {
	state atomic.Int32 // SampleState

	SentTime    int64
	ReceiveTime int64
	IpID        uint16
}

// MarkSent must be called by the prober immediately before transmitting the
// frame for sample seq. It records SentTime and advances Empty -> Sent.
func (s *Sample) MarkSent(now int64) {
	s.SentTime = now
	s.state.Store(int32(SampleSent))
}

// TryFill is called by the receiver upon a validated reply. It writes the
// reply's IpID and ReceiveTime and atomically advances Sent -> Received.
// Returns true exactly once per sample (the winner of the CAS). A failed CAS
// means either the sample was not yet sent or another receiver already filled
// it (duplicate reply).
func (s *Sample) TryFill(ipID uint16, receiveTime int64) bool {
	if SampleState(s.state.Load()) != SampleSent {
		return false
	}
	s.IpID = ipID
	s.ReceiveTime = receiveTime
	return s.state.CompareAndSwap(int32(SampleSent), int32(SampleReceived))
}

// IsReceived reports whether the sample has been filled with a valid reply.
func (s *Sample) IsReceived() bool {
	return SampleState(s.state.Load()) == SampleReceived
}

// SaveProbesChannel carries successful probes to the parquet writer. Owned here.
var SaveProbesChannel chan *Probe

// sentinelAnySeq marks an InflightEntry as accepting any seq in [0, RequestCount).
const sentinelAnySeq uint32 = 0xFFFFFFFF

// Measure probes a single target end-to-end. It is the only function the prober
// goroutines run. Reply matching and sample filling are done in the receiver
// path via the shared inflight registry; this function never touches a reply
// channel and therefore CANNOT lose replies due to channel backpressure.
//
// scratch is a per-goroutine, reused slice of built packets so the hot path
// allocates no per-target memory for packet construction.
func Measure(target net.IP, scratch []packet.Packet) bool {
	target4 := target.To4()
	if target4 == nil {
		return false
	}

	atomic.AddInt64(&stats.ProbeCount, 1)

	basePort := port.Next()
	packet.BuildPacketsInto(scratch, target4, basePort)

	probe := &Probe{
		Target:  target4,
		Samples: make([]Sample, measurement.RequestCount),
	}

	var targetKey [4]byte
	copy(targetKey[:], target4)

	// Cache sender IPs (4-byte form) for the receiver-side validation that runs
	// out of the InflightEntry, so the receiver does no global lookups.
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

// measureRTBased: one outstanding request at a time. For each seqNum we
// register a one-shot inflight entry, mark+send, then wait for it or timeout.
// On timeout/duplicate/invalid the probe aborts (the original semantics).
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

	var sentBytes, sentPackets int64

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		req := &scratch[seqNum]

		// Pick the flag expectation for this seqNum. TCP with EstablishConnection
		// expects the SYN-ACK on the first request of each connection (the start
		// of a connection's seqNum range), and PSH-ACK on the data requests
		// thereafter. Non-TCP and non-EstablishConnection use the protocol's
		// configured default reply flags.
		flagMode := FlagsDefault
		if measurement.TcpEstablishConnection {
			if seqnum.GetConnectionIndex(seqNum) == 0 {
				flagMode = FlagsSynAck
			} else {
				flagMode = FlagsPshAck
			}
		}

		entry := &InflightEntry{
			Probe:         probe,
			expectedCount: 1,
			expectedSeq:   uint32(seqNum),
			FlagMode:      flagMode,
			done:          make(chan struct{}),
			minPort:       basePort,
			maxPort:       basePort + measurement.Config.ConnectionCount - 1,
			senderA:       sa,
			senderB:       sb,
		}
		Inflight.Register(targetKey, entry)

		// MarkSent publishes SentTime BEFORE the send so any reply that arrives
		// immediately after send already sees a valid SentTime.
		probe.Samples[seqNum].MarkSent(time.Now().UnixMicro())

		if err := req.Sender.Send(req.Bytes); err != nil {
			Inflight.Deregister(targetKey, entry)
			return false
		}
		sentBytes += int64(len(req.Bytes))
		sentPackets++

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
			// Sample filled by the receiver. Validate that THIS seqNum is the
			// one that got filled (a duplicate-target safety net).
			Inflight.Deregister(targetKey, entry)
			if !probe.Samples[seqNum].IsReceived() {
				return false
			}
			// In RT-based mode the TCP handshake special case (EstablishConnection)
			// is implicit: we always wait for exactly one reply for each seq, and
			// the expected SYN-ACK flags are validated by the receiver via the
			// payload validator + expFlags.

		case <-timer.C:
			Inflight.Deregister(targetKey, entry)
			return false

		case <-measurement.StopSignal:
			Inflight.Deregister(targetKey, entry)
			return false
		}
	}

	atomic.AddInt64(&stats.SentBytes, sentBytes)
	atomic.AddInt64(&stats.SentPackets, sentPackets)

	SaveProbesChannel <- probe
	atomic.AddInt64(&stats.ValidProbes, 1)
	return true
}

// measureFixedInterval: send all requests spaced by request_interval, then
// collect replies for up to MaximumToleratedRTT. The probe is kept iff the
// reply rate meets MinimumReplyRate.
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
	// Ensure the registry is cleaned up no matter how we exit.
	defer Inflight.Deregister(targetKey, entry)

	interval := measurement.Config.FixedIntervalConfig.RequestInterval

	var sentBytes, sentPackets int64

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		req := &scratch[seqNum]
		probe.Samples[seqNum].MarkSent(time.Now().UnixMicro())
		if err := req.Sender.Send(req.Bytes); err != nil {
			return false
		}
		sentBytes += int64(len(req.Bytes))
		sentPackets++

		if interval > 0 && seqNum+1 < measurement.RequestCount {
			time.Sleep(interval)
		}
	}

	atomic.AddInt64(&stats.SentBytes, sentBytes)
	atomic.AddInt64(&stats.SentPackets, sentPackets)

	// Wait for all expected replies or for the MaximumToleratedRTT to elapse
	// after the LAST send (which is when the last reply could legitimately
	// arrive). A reusable timer is fine here since each prober has its own.
	timer := time.NewTimer(measurement.Config.MaximumToleratedRTT)
	defer timer.Stop()

	select {
	case <-entry.done:
	case <-timer.C:
	case <-measurement.StopSignal:
		return false
	}

	// Count finally received samples (the receiver may have filled some after
	// the timeout fired but before we returned; that is fine).
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

// FulfillReply is called by the receiver for every captured reply. It looks the
// reply up in the inflight registry, validates it against that entry's expected
// parameters, fills the matching sample, and signals the waiter if the entry's
// completion condition is reached. Returns true if the reply matched and was
// recorded; false otherwise (including for replies that arrive for targets we
// are not currently probing, which is normal and not an error).
//
// This function runs on the receiver goroutines, so it is the hot path's
// validation step. It performs no allocations and only one shard-map lookup.
//
// replyFlags is the set of protocol flags carried by the reply (TCP flags for
// TCP, DNS flags for UDP/DNS, zero for ICMP). FulfillReply compares it against
// the entry's FlagMode so the TCP handshake special case (expect SYN+ACK on
// the first reply when EstablishConnection is set) is preserved.
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

	// Destination IP must be one of our senders.
	if dstIP4 != entry.senderA && dstIP4 != entry.senderB {
		return false
	}

	// Destination port must be within this probe's connection range. ICMP has
	// no L4 ports, so the port check is skipped for ICMP.
	if payload.Active.ProtocolID != layers.IPProtocolICMPv4 {
		if dstPort < entry.minPort || dstPort > entry.maxPort {
			return false
		}
	}

	// Flag-mode check (preserves the TCP handshake / EstablishConnection
	// semantics that used to live in probe.go).
	if !flagsMatch(entry.FlagMode, replyFlags) {
		return false
	}

	// In RT-based mode a specific seqNum is expected.
	if entry.expectedSeq != sentinelAnySeq && uint32(recoveredSeq) != entry.expectedSeq {
		return false
	}

	if int(recoveredSeq) >= len(entry.Probe.Samples) {
		return false
	}
	sample := &entry.Probe.Samples[recoveredSeq]

	// Late reply: RTT exceeds tolerance, reject so RTT statistics stay clean.
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

// flagsMatch returns true iff replyFlags satisfy entry's FlagMode. For
// FlagsDefault the configured ReplyFlags (TCP) or DNS QR (UDP/DNS) apply; ICMP
// has no flags and always matches.
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

// defaultFlagsMatch implements the protocol-default flag check (formerly
// reply.ExpFlags). Centralised here so the receiver path doesn't depend on the
// reply package.
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
		return true // ICMP has no flag set; existence of valid echo reply is enough.
	}
	return false
}
