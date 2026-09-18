package probe

import (
	"sync/atomic"
	"time"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/port"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/seqnum"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

const (
	probeActive = iota
	probeFailed
	probeComplete
)

func (p *Probe) failLocked(reason *int64) {
	if p.status != probeActive {
		return
	}
	p.status = probeFailed
	if reason != nil {
		atomic.AddInt64(reason, 1)
	}
	close(p.failed)
}

func (p *Probe) fail(reason *int64) {
	if !p.strict {
		if reason != nil {
			atomic.AddInt64(reason, 1)
		}
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failLocked(reason)
}

func (p *Probe) complete() bool {
	if !p.strict {
		return true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status != probeActive {
		return false
	}
	p.status = probeComplete
	return true
}

func (p *Probe) waitInterval(interval time.Duration, timer *time.Timer) bool {
	if !p.strict && p.tcpACKReplies == nil {
		time.Sleep(interval)
		return true
	}
	timer.Reset(interval)
	for {
		select {
		case <-timer.C:
			return true
		case <-p.failed:
			return false
		case connection := <-p.tcpACKReplies:
			if !p.tcpSendACK(connection) {
				return false
			}
		case <-measurement.StopSignal:
			p.fail(&stats.DropInterrupt)
			return false
		}
	}
}

func measureBaseRT(p *Probe, key [4]byte, packets [][]byte, basePort uint16) bool {
	entry := &InflightEntry{
		Probe: p, basePort: basePort,
		expectedCount:   measurement.RequestCount,
		expectedMinPort: basePort,
		expectedMaxPort: basePort + measurement.Config.ConnectionCount - 1,
		expectedDsts:    [2][4]byte{sender.SenderA.IPBytes, sender.SenderB.IPBytes},
		expectedMaxSeq:  measurement.RequestCount - 1,
		done:            make(chan struct{}),
	}
	Inflight.Register(key, entry)
	defer Inflight.Deregister(key, entry)
	timer := time.NewTimer(measurement.Config.MaximumToleratedRTT)
	defer timer.Stop()
	for seq := uint16(0); seq < measurement.RequestCount; seq++ {
		if !prepareTCPPacket(p, seq, packets[seq]) {
			p.fail(&stats.DropNotRecv)
			return false
		}
		if !sendPacket(sender.GetSender(seq), packets[seq], &p.Samples[seq], p) {
			return false
		}
		if !waitForBaseReply(p, timer) {
			return false
		}
		atomic.AddInt64(&stats.ProbesReachedSeq[seq], 1)
	}
	if !p.complete() {
		return false
	}
	select {
	case SaveProbesChannel <- p:
		atomic.AddInt64(&stats.ValidProbes, 1)
		return true
	case <-measurement.StopSignal:
		atomic.AddInt64(&stats.DropInterrupt, 1)
		return false
	}
}

func waitForBaseReply(p *Probe, timer *time.Timer) bool {
	timer.Reset(measurement.Config.MaximumToleratedRTT)
	select {
	case <-p.replyReady:
		return p.flushTCPACKs()
	case <-p.failed:
		return false
	case <-timer.C:
		p.fail(&stats.DropTimeout)
		return false
	case <-measurement.StopSignal:
		p.fail(&stats.DropInterrupt)
		return false
	}
}

func fulfillBaseReply(entry *InflightEntry, dst [4]byte, dstPort uint16, recoveredSeq, tcpSeq uint32, ipID uint16, flags sets.Set[string], received int64, tcpPayloadLength uint16) bool {
	p := entry.Probe
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status != probeActive {
		return false
	}
	reject := func(packetCounter, probeCounter *int64) bool {
		atomic.AddInt64(packetCounter, 1)
		p.failLocked(probeCounter)
		return false
	}
	if dst != entry.expectedDsts[0] && dst != entry.expectedDsts[1] {
		return reject(&stats.DropBadDst, &stats.AbortBadDst)
	}
	if measurement.HasPorts && (dstPort < entry.expectedMinPort || dstPort > entry.expectedMaxPort) {
		return reject(&stats.DropBadPort, &stats.AbortBadPort)
	}
	seq, ok := recoverLogicalSequence(entry, dstPort, recoveredSeq)
	if !ok || int(seq) >= len(p.Samples) {
		return reject(&stats.DropSeqOOR, &stats.AbortSeqOOR)
	}
	if dst != sender.GetSender(seq).IPBytes {
		return reject(&stats.DropBadDst, &stats.AbortBadDst)
	}
	if measurement.HasPorts && dstPort != port.GetSrcPort(seq, entry.basePort) {
		return reject(&stats.DropBadPort, &stats.AbortBadPort)
	}
	sample := &p.Samples[seq]
	if SampleState(sample.state.Load()) == SampleEmpty {
		return reject(&stats.DropUnsent, &stats.AbortUnsent)
	}
	if SampleState(sample.state.Load()) != SampleSent {
		return reject(&stats.DropDup, &stats.AbortDup)
	}
	if measurement.TcpEstablishConnection && flags.Contains(types.TCPFlagRST) {
		return reject(&stats.DropBadFlags, &stats.AbortReset)
	}
	expected := FlagsDefault
	if measurement.TcpEstablishConnection {
		expected = FlagsAck
		if seqnum.GetRequestIndex(seq) == 0 {
			expected = FlagsSynAck
		}
	}
	validFlags := flagsMatch(expected, flags)
	if expected == FlagsAck {
		validFlags = flags.Contains(types.TCPFlagACK) &&
			(len(flags) == 1 || (len(flags) == 2 && flags.Contains(types.TCPFlagPSH)))
	}
	if !validFlags {
		if payload.Active.ID == types.PayloadTCP {
			phase := stats.TCPNoConnection
			if expected == FlagsSynAck {
				phase = stats.TCPHandshake
			} else if expected == FlagsAck {
				phase = stats.TCPData
			}
			stats.RecordTCPBadFlags(phase, flags)
		}
		return reject(&stats.DropBadFlags, &stats.AbortBadFlags)
	}
	if received-sample.SentTime > measurement.Config.MaximumToleratedRTT.Microseconds() {
		return reject(&stats.DropLate, &stats.AbortLate)
	}
	connection := seqnum.GetConnectionIndex(seq)
	if measurement.TcpEstablishConnection && expected == FlagsAck {
		start := p.Samples[connection].tcpSequence + 1
		next := p.tcpAcknowledgments[connection].Load()
		if !p.tcpAckReady[connection].Load() ||
			(tcpPayloadLength > 0 && tcpSeq != next) ||
			(tcpPayloadLength == 0 && tcpSeq-start > next-start) {
			return reject(&stats.DropTCPSequence, &stats.AbortTCPSequence)
		}
	}
	sample.tcpSequence = tcpSeq
	if !sample.TryFill(ipID, received) {
		return reject(&stats.DropDup, &stats.AbortDup)
	}
	if measurement.TcpEstablishConnection && expected == FlagsSynAck {
		p.tcpAcknowledgments[connection].Store(tcpSeq + 1 + uint32(tcpPayloadLength))
		p.tcpAckReady[connection].Store(true)
		if p.tcpACKReplies != nil {
			p.tcpACKReplies <- connection
		}
		if p.tcpHandshakeCount.Add(1) == uint32(measurement.Config.ConnectionCount) {
			p.tcpHandshakeOnce.Do(func() { close(p.tcpHandshakeDone) })
		}
	} else if measurement.TcpEstablishConnection && tcpPayloadLength > 0 {
		p.tcpAcknowledgments[connection].Store(tcpSeq + uint32(tcpPayloadLength))
		if p.tcpACKReplies != nil {
			p.tcpACKReplies <- connection
		}
	}
	if entry.validCount.Add(1) >= uint32(entry.expectedCount) {
		entry.markDone()
	}
	if measurement.Config.MeasurementMode == types.MeasurementModeRTBased {
		select {
		case p.replyReady <- struct{}{}:
		default:
		}
	}
	atomic.AddInt64(&stats.MatchedReplies, 1)
	return true
}

func RejectBaseReply(src [4]byte, reason *int64) {
	entry := Inflight.Lookup(src)
	if entry == nil || !entry.Probe.strict {
		return
	}
	entry.Probe.fail(reason)
}
