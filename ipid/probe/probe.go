package probe

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/diagnostics"
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

	strict     bool
	mu         sync.Mutex
	status     int
	failed     chan struct{}
	replyReady chan struct{}

	tcpAcknowledgments []atomic.Uint32
	tcpAckReady        []atomic.Bool
	tcpHandshakeCount  atomic.Uint32
	tcpHandshakeDone   chan struct{}
	tcpHandshakeOnce   sync.Once
	tcpACKReplies      chan uint16
	tcpSendACK         func(uint16) bool
}

type Sample struct {
	state atomic.Int32 // SampleState

	SentTime    int64
	ReceiveTime int64
	IpID        uint16
	tcpSequence uint32
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

	atomic.AddInt64(&stats.ProbeCount, 1)
	atomic.AddInt64(&stats.InFlightProbes, 1)
	defer atomic.AddInt64(&stats.InFlightProbes, -1)

	basePort := port.Next()
	packet.BuildPacketsInto(packets, target4, basePort)

	probe := &Probe{
		Target:  target4,
		Samples: make([]Sample, measurement.RequestCount),
	}
	if measurement.Config.ConnectionCount == 4 && measurement.Config.RequestsPerConnection == 4 {
		probe.strict = true
		probe.failed = make(chan struct{})
		probe.replyReady = make(chan struct{}, 1)
		defer probe.fail(nil)
	}
	if measurement.TcpEstablishConnection {
		probe.tcpAcknowledgments = make([]atomic.Uint32, measurement.Config.ConnectionCount)
		probe.tcpAckReady = make([]atomic.Bool, measurement.Config.ConnectionCount)
		probe.tcpHandshakeDone = make(chan struct{})
		probe.tcpACKReplies = make(chan uint16, measurement.RequestCount)
		probe.tcpSendACK = func(connection uint16) bool {
			sequence := measurement.TcpSequenceNumOffset + uint32(connection) + uint32(nextTCPRequestIndex(probe, connection))
			ack := packet.BuildTCPACK(packets[connection], sequence, probe.tcpAcknowledgments[connection].Load())
			return sendPacket(sender.GetSender(connection), ack, nil, probe)
		}
		defer resetTCPConnections(probe, target4, basePort)
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
func measureRTBased(
	probe *Probe,
	targetKey [4]byte,
	packets [][]byte,
	basePort uint16,
) bool {
	if probe.strict {
		return measureBaseRT(probe, targetKey, packets, basePort)
	}
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
		if !sendPacket(sndr, pkt, &probe.Samples[seqNum], probe) {
			Inflight.Deregister(targetKey, entry)
			return false
		}

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
			if !probe.flushTCPACKs() {
				Inflight.Deregister(targetKey, entry)
				return false
			}
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

	select {
	case SaveProbesChannel <- probe:
	case <-measurement.StopSignal:
		atomic.AddInt64(&stats.DropInterrupt, 1)
		return false
	}
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
	timer := time.NewTimer(measurement.Config.MaximumToleratedRTT)
	defer timer.Stop()

	for seqNum := uint16(0); seqNum < measurement.RequestCount; seqNum++ {
		sndr := sender.GetSender(seqNum)
		pkt := packets[seqNum]
		if !probe.flushTCPACKs() {
			return false
		}

		if !prepareTCPPacket(probe, seqNum, pkt) {
			probe.fail(&stats.DropNotRecv)
			return false
		}
		if !sendPacket(sndr, pkt, &probe.Samples[seqNum], probe) {
			return false
		}

		if interval > 0 && seqNum+1 < measurement.RequestCount {
			if !probe.waitInterval(interval, timer) {
				return false
			}
		}

		if measurement.TcpEstablishConnection &&
			seqNum+1 == measurement.Config.ConnectionCount &&
			!waitForTCPHandshakes(probe) {
			return false
		}
	}

	timer.Reset(measurement.Config.MaximumToleratedRTT)
	if !waitForFixedReplies(probe, entry, timer) {
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
	minimumRate := measurement.Config.FixedIntervalConfig.MinimumReplyRate
	if probe.strict {
		minimumRate = 1
	}
	if rate < minimumRate {
		probe.fail(&stats.DropRateLow)
		return false
	}

	if !probe.complete() {
		return false
	}
	select {
	case SaveProbesChannel <- probe:
	case <-measurement.StopSignal:
		atomic.AddInt64(&stats.DropInterrupt, 1)
		return false
	}
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
	tcpPayloadLength uint16,
) bool {
	entry := Inflight.Lookup(srcIP4)
	if entry == nil {
		atomic.AddInt64(&stats.DropNoEntry, 1)
		return false
	}
	return entry.FulfillReply(dstIP4, dstPort, recoveredSeq, replyTCPSeq, ipID, replyFlags, receiveTime, tcpPayloadLength)
}

func (entry *InflightEntry) FulfillReply(
	dstIP4 [4]byte, dstPort uint16, recoveredSeq, replyTCPSeq uint32,
	ipID uint16, replyFlags sets.Set[string], receiveTime int64, tcpPayloadLength uint16,
) bool {
	if entry.Probe.strict {
		return fulfillBaseReply(entry, dstIP4, dstPort, recoveredSeq, replyTCPSeq, ipID, replyFlags, receiveTime, tcpPayloadLength)
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
		if entry.Probe.tcpACKReplies != nil {
			entry.Probe.tcpACKReplies <- connectionIndex
		}
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

func resetTCPConnections(probe *Probe, target net.IP, basePort uint16) {
	for connectionIndex := uint16(0); connectionIndex < measurement.Config.ConnectionCount; connectionIndex++ {
		if !probe.tcpAckReady[connectionIndex].Load() {
			continue
		}

		sndr := sender.GetSender(connectionIndex)
		resetPacket, err := packet.BuildTCPResetPacket(
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

		_ = sendPacket(sndr, resetPacket, nil, nil)
	}
}

func sendPacket(sndr *sender.Sender, packetBytes []byte, sample *Sample, probe *Probe) bool {
	frameBytes := len(sndr.EthHeader) + len(packetBytes)
	var cancelled <-chan struct{}
	if probe != nil {
		cancelled = probe.failed
	}
	if sender.Limiter != nil && !sender.Limiter.AcquireUntil(frameBytes, cancelled) {
		if probe != nil {
			probe.fail(&stats.DropLimiterStop)
		} else {
			atomic.AddInt64(&stats.DropLimiterStop, 1)
		}
		return false
	}
	locked := false
	var holdStart time.Time
	var ready func() bool
	if probe != nil && probe.strict {
		ready = func() bool {
			probe.mu.Lock()
			holdStart = diagnostics.SendProbeHold.Start()
			locked = true
			if probe.status != probeActive {
				return false
			}
			if sample != nil {
				sample.MarkSent(time.Now().UnixMicro())
			}
			return true
		}
	} else if sample != nil {
		sample.MarkSent(time.Now().UnixMicro())
	}
	sent, err := sndr.SendIf(packetBytes, ready)
	if locked {
		defer func() {
			probe.mu.Unlock()
			diagnostics.SendProbeHold.End(holdStart)
		}()
	}
	if !sent {
		return false
	}
	if err != nil {
		if probe != nil && probe.strict {
			probe.failLocked(&stats.DropSendErr)
		} else {
			atomic.AddInt64(&stats.DropSendErr, 1)
		}
		return false
	}
	atomic.AddInt64(&stats.SentBytes, int64(frameBytes))
	atomic.AddInt64(&stats.SentPackets, 1)
	return true
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

	for {
		select {
		case <-probe.failed:
			return false
		case <-probe.tcpHandshakeDone:
			return probe.flushTCPACKs()
		case connection := <-probe.tcpACKReplies:
			if !probe.tcpSendACK(connection) {
				return false
			}
		case <-timer.C:
			probe.fail(&stats.DropTimeout)
			return false
		case <-measurement.StopSignal:
			probe.fail(&stats.DropInterrupt)
			return false
		}
	}
}

func (p *Probe) flushTCPACKs() bool {
	for {
		select {
		case connection := <-p.tcpACKReplies:
			if !p.tcpSendACK(connection) {
				return false
			}
		default:
			return true
		}
	}
}

func waitForFixedReplies(probe *Probe, entry *InflightEntry, timer *time.Timer) bool {
	for {
		select {
		case <-entry.done:
			return probe.flushTCPACKs()
		case <-probe.failed:
			return false
		case <-timer.C:
			return probe.flushTCPACKs()
		case connection := <-probe.tcpACKReplies:
			if !probe.tcpSendACK(connection) {
				return false
			}
		case <-measurement.StopSignal:
			probe.fail(&stats.DropInterrupt)
			return false
		}
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
		return replyFlags.Contains(types.DNSFlagQR)
	case layers.IPProtocolICMPv4:
		return true // ICMP has no flag set.
	}
	return false
}
