package probe

import (
	"net"
	"sync"
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
	SamplePending  SampleState = 3
)

type Probe struct {
	Target  net.IP
	Samples []Sample

	tcpAcknowledgments []atomic.Uint32
	tcpAckReady        []atomic.Bool
	tcpHandshakeCount  atomic.Uint32
	tcpHandshakeDone   chan struct{}
	tcpHandshakeOnce   sync.Once
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
	if !s.state.CompareAndSwap(int32(SampleSent), int32(SamplePending)) {
		return false
	}
	s.IpID = ipID
	s.ReceiveTime = receiveTime
	s.state.Store(int32(SampleReceived))
	return true
}

func (s *Sample) IsReceived() bool {
	return SampleState(s.state.Load()) == SampleReceived
}

func (s *Sample) WasSent() bool {
	return SampleState(s.state.Load()) != SampleEmpty
}

var SaveProbesChannel chan *Probe

// Measure probes a single target end-to-end.
func Measure(target net.IP, packets [][]byte) bool {
	target4 := target.To4()
	if target4 == nil {
		atomic.AddInt64(&stats.DropBadTarget, 1)
		return false
	}

	// Rate-limiting
	if sender.Limiter != nil {
		if !sender.Limiter.Acquire(packet.RawPacketsTotalBytes) {
			atomic.AddInt64(&stats.DropLimiterStop, 1)
			return false
		}
	}

	atomic.AddInt64(&stats.ProbeCount, 1)
	atomic.AddInt64(&stats.InFlightProbes, 1)
	defer atomic.AddInt64(&stats.InFlightProbes, -1)

	basePort := port.Next()
	packet.BuildPacketsInto(packets, target4, basePort)

	probe := &Probe{
		Target:  target4,
		Samples: make([]Sample, measurement.RequestCount),
	}
	if measurement.TcpEstablishConnection {
		probe.tcpAcknowledgments = make([]atomic.Uint32, measurement.Config.ConnectionCount)
		probe.tcpAckReady = make([]atomic.Bool, measurement.Config.ConnectionCount)
		probe.tcpHandshakeDone = make(chan struct{})
		defer finalizeTCPConnections(probe, target4, basePort)
	}

	var targetKey [4]byte
	copy(targetKey[:], target4)

	switch measurement.Config.MeasurementMode {
	case types.MeasurementModeRTBased:
		return measureRTBased(probe, targetKey, packets, basePort)
	case types.MeasurementModeFixedInterval:
		return measureFixedInterval(probe, targetKey, packets, basePort)
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
	packets [][]byte,
	basePort uint16,
) bool {
	rtt := measurement.Config.MaximumToleratedRTT
	timer := time.NewTimer(rtt)
	defer timer.Stop()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		pkt := packets[seqNum]

		// Pick the flag expectation for this seqNum.
		expectedFlags := FlagsDefault
		if measurement.TcpEstablishConnection {
			if seqnum.GetRequestIndex(seqNum) == 0 {
				expectedFlags = FlagsSynAck
			} else {
				expectedFlags = FlagsAck
			}
		}

		sndr := sender.GetSender(seqNum)
		expectedPort := port.GetSrcPort(seqNum, basePort)

		entry := &InflightEntry{
			Probe:           probe,
			expectedCount:   1,
			expectedDsts:    [2][4]byte{sndr.IPBytes, sndr.IPBytes},
			expectedMinPort: expectedPort,
			expectedMaxPort: expectedPort,
			basePort:        basePort,
			expectedFlags:   expectedFlags,
			expectedMinSeq:  seqNum,
			expectedMaxSeq:  seqNum,
			done:            make(chan struct{}),
		}
		Inflight.Register(targetKey, entry)

		if !prepareTCPPacket(probe, seqNum, pkt) {
			Inflight.Deregister(targetKey, entry)
			atomic.AddInt64(&stats.DropNotRecv, 1)
			return false
		}
		// MarkSent publishes SentTime before the sending.
		probe.Samples[seqNum].MarkSent(time.Now().UnixMicro())

		if err := sndr.Send(pkt); err != nil {
			Inflight.Deregister(targetKey, entry)
			atomic.AddInt64(&stats.DropSendErr, 1)
			return false
		}
		// Update sent counters incrementally.
		atomic.AddInt64(&stats.SentBytes, int64(len(sndr.EthHeader)+len(pkt)))
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
				atomic.AddInt64(&stats.DropNotRecv, 1)
				return false
			}
			atomic.AddInt64(&stats.ProbesReachedSeq[seqNum], 1)

		case <-timer.C:
			Inflight.Deregister(targetKey, entry)
			atomic.AddInt64(&stats.DropTimeout, 1)
			return false

		case <-measurement.StopSignal:
			Inflight.Deregister(targetKey, entry)
			atomic.AddInt64(&stats.DropInterrupt, 1)
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
	packets [][]byte,
	basePort uint16,
) bool {
	entry := &InflightEntry{
		Probe:           probe,
		expectedCount:   measurement.RequestCount,
		expectedDsts:    [2][4]byte{sender.SenderA.IPBytes, sender.SenderB.IPBytes},
		expectedMinPort: basePort,
		expectedMaxPort: basePort + measurement.Config.ConnectionCount - 1,
		basePort:        basePort,
		expectedMinSeq:  0,
		expectedMaxSeq:  measurement.RequestCount - 1,
		done:            make(chan struct{}),
	}
	Inflight.Register(targetKey, entry)
	defer Inflight.Deregister(targetKey, entry)

	interval := measurement.Config.FixedIntervalConfig.RequestInterval

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		sndr := sender.GetSender(seqNum)
		pkt := packets[seqNum]

		if !prepareTCPPacket(probe, seqNum, pkt) {
			atomic.AddInt64(&stats.DropNotRecv, 1)
			return false
		}
		probe.Samples[seqNum].MarkSent(time.Now().UnixMicro())
		if err := sndr.Send(pkt); err != nil {
			atomic.AddInt64(&stats.DropSendErr, 1)
			return false
		}
		atomic.AddInt64(&stats.SentBytes, int64(len(sndr.EthHeader)+len(pkt)))
		atomic.AddInt64(&stats.SentPackets, 1)

		if interval > 0 && seqNum+1 < measurement.RequestCount {
			time.Sleep(interval)
		}

		if measurement.TcpEstablishConnection &&
			seqNum+1 == measurement.Config.ConnectionCount &&
			!waitForTCPHandshakes(probe) {
			return false
		}
	}

	// Wait for all expected replies or for the MaximumToleratedRTT to elapse.
	timer := time.NewTimer(measurement.Config.MaximumToleratedRTT)
	defer timer.Stop()

	select {
	case <-entry.done:
	case <-timer.C:
	case <-measurement.StopSignal:
		atomic.AddInt64(&stats.DropInterrupt, 1)
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
		atomic.AddInt64(&stats.DropRateLow, 1)
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
	recoveredSeq uint32,
	replyTCPSeq uint32,
	ipID uint16,
	replyFlags sets.Set[string],
	receiveTime int64,
) bool {
	entry := Inflight.Lookup(srcIP4)
	if entry == nil {
		atomic.AddInt64(&stats.DropNoEntry, 1)
		return false
	}

	// Destination IP must be one of the expectedDsts.
	if dstIP4 != entry.expectedDsts[0] && dstIP4 != entry.expectedDsts[1] {
		atomic.AddInt64(&stats.DropBadDst, 1)
		return false
	}

	// Destination port must be within this probe's connection range.
	if measurement.HasPorts {
		if dstPort < entry.expectedMinPort || dstPort > entry.expectedMaxPort {
			atomic.AddInt64(&stats.DropBadPort, 1)
			return false
		}
	}

	logicalSeq, ok := recoverLogicalSequence(entry, dstPort, recoveredSeq)
	if !ok {
		atomic.AddInt64(&stats.DropSeqOOR, 1)
		return false
	}

	expectedFlags := entry.expectedFlags
	if measurement.TcpEstablishConnection {
		if seqnum.GetRequestIndex(logicalSeq) == 0 {
			expectedFlags = FlagsSynAck
		} else {
			expectedFlags = FlagsAck
		}
	}

	// Flag-mode check.
	if !flagsMatch(expectedFlags, replyFlags) {
		atomic.AddInt64(&stats.DropBadFlags, 1)
		return false
	}

	// seqNum must be within probe's seqNum range.
	if logicalSeq < entry.expectedMinSeq || logicalSeq > entry.expectedMaxSeq {
		atomic.AddInt64(&stats.DropSeqOOR, 1)
		return false
	}

	sample := &entry.Probe.Samples[logicalSeq]

	// Late reply: reject if RTT exceeds tolerance.
	if receiveTime-sample.SentTime > measurement.Config.MaximumToleratedRTT.Microseconds() {
		atomic.AddInt64(&stats.DropLate, 1)
		return false
	}

	if !sample.TryFill(ipID, receiveTime) {
		// Duplicate reply or sample not in Sent state.
		atomic.AddInt64(&stats.DropDup, 1)
		return false
	}

	if measurement.TcpEstablishConnection && expectedFlags == FlagsSynAck {
		connectionIndex := seqnum.GetConnectionIndex(logicalSeq)
		entry.Probe.tcpAcknowledgments[connectionIndex].Store(replyTCPSeq + 1)
		entry.Probe.tcpAckReady[connectionIndex].Store(true)
		if entry.Probe.tcpHandshakeCount.Add(1) == uint32(measurement.Config.ConnectionCount) {
			entry.Probe.tcpHandshakeOnce.Do(func() { close(entry.Probe.tcpHandshakeDone) })
		}
	}

	// Update the completion counter and signal if we have hit the target.
	if entry.validCount.Add(1) >= uint32(entry.expectedCount) {
		entry.markDone()
	}
	atomic.AddInt64(&stats.MatchedReplies, 1)
	return true
}

func prepareTCPPacket(probe *Probe, seqNum uint16, packetBytes []byte) bool {
	if !measurement.TcpEstablishConnection || seqnum.GetRequestIndex(seqNum) == 0 {
		return true
	}

	connectionIndex := seqnum.GetConnectionIndex(seqNum)
	if !probe.tcpAckReady[connectionIndex].Load() {
		return false
	}

	packet.SetTCPAcknowledgment(packetBytes, probe.tcpAcknowledgments[connectionIndex].Load())
	return true
}

func finalizeTCPConnections(probe *Probe, target net.IP, basePort uint16) {
	for connectionIndex := uint16(0); connectionIndex < measurement.Config.ConnectionCount; connectionIndex++ {
		if !probe.tcpAckReady[connectionIndex].Load() {
			continue
		}

		sndr := sender.GetSender(connectionIndex)
		finPacket, err := packet.BuildTCPFINPacket(
			target,
			sndr.IP,
			basePort+connectionIndex,
			connectionIndex,
			nextTCPRequestIndex(probe, connectionIndex),
			probe.tcpAcknowledgments[connectionIndex].Load(),
		)
		if err != nil {
			atomic.AddInt64(&stats.DropSendErr, 1)
			continue
		}

		if err := sndr.Send(finPacket); err != nil {
			atomic.AddInt64(&stats.DropSendErr, 1)
			continue
		}
		atomic.AddInt64(&stats.SentBytes, int64(len(sndr.EthHeader)+len(finPacket)))
		atomic.AddInt64(&stats.SentPackets, 1)
	}
}

func nextTCPRequestIndex(probe *Probe, connectionIndex uint16) uint16 {
	nextRequestIndex := uint16(1) // the acknowledged SYN consumed one sequence number
	for requestIndex := uint16(1); requestIndex < measurement.Config.RequestsPerConnection; requestIndex++ {
		seqNum := requestIndex*measurement.Config.ConnectionCount + connectionIndex
		if !probe.Samples[seqNum].WasSent() {
			break
		}
		nextRequestIndex = requestIndex + 1
	}
	return nextRequestIndex
}

func waitForTCPHandshakes(probe *Probe) bool {
	timer := time.NewTimer(measurement.Config.MaximumToleratedRTT)
	defer timer.Stop()

	select {
	case <-probe.tcpHandshakeDone:
		return true
	case <-timer.C:
		atomic.AddInt64(&stats.DropTimeout, 1)
		return false
	case <-measurement.StopSignal:
		atomic.AddInt64(&stats.DropInterrupt, 1)
		return false
	}
}

func recoverLogicalSequence(entry *InflightEntry, dstPort uint16, recoveredSeq uint32) (uint16, bool) {
	if measurement.TcpEstablishConnection {
		return seqnum.FromTCPAcknowledgment(
			recoveredSeq,
			measurement.TcpSequenceNumOffset,
			dstPort,
			entry.basePort,
			measurement.Config.ConnectionCount,
			measurement.Config.RequestsPerConnection,
		)
	}

	if recoveredSeq > uint32(^uint16(0)) {
		return 0, false
	}
	return uint16(recoveredSeq), true
}

func flagsMatch(mode FlagExpectation, replyFlags sets.Set[string]) bool {
	switch mode {
	case FlagsSynAck:
		return replyFlags.Equal(types.SynAckFlagSet)
	case FlagsAck:
		return replyFlags.Equal(types.AckFlagSet)
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
		return replyFlags.Equal(types.DnsQRFlagSet)
	case layers.IPProtocolICMPv4:
		return true // ICMP has no flag set.
	}
	return false
}
