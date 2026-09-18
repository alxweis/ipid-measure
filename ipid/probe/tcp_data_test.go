package probe

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

func TestBaseTCPDataAcknowledgments(t *testing.T) {
	for _, mode := range []types.MeasurementMode{types.MeasurementModeRTBased, types.MeasurementModeFixedInterval} {
		t.Run(string(mode), func(t *testing.T) {
			p, key, acks := handshakeFixture(t)
			measurement.Config.MeasurementMode = mode
			deliverSYNACK(t, p, key, 0)
			p.flushTCPACKs()
			expectHandshakeACK(t, acks, 0)
			for request := uint16(1); request <= 3; request++ {
				seq := request * 4
				p.Samples[seq].MarkSent(100)
				flags := types.AckFlagSet
				if request != 2 {
					flags = sets.New(types.TCPFlagACK, types.TCPFlagPSH)
				}
				serverSeq := uint32(2001 + (request-1)*3)
				if !FulfillReply(key, sender.SenderA.IPBytes, 40000, 1001+uint32(request), serverSeq, 42+seq, flags, 200, 3) {
					t.Fatal("contiguous data rejected")
				}
				if !p.flushTCPACKs() {
					t.Fatal("data ACK failed")
				}
				expectHandshakeACK(t, acks, 0)
				if p.tcpAcknowledgments[0].Load() != serverSeq+3 || nextTCPRequestIndex(p, 0) != request+1 {
					t.Fatal("wrong receive or send sequence after data")
				}
				if request < 3 {
					pkt := make([]byte, 41)
					if !prepareTCPPacket(p, seq+4, pkt) || binary.BigEndian.Uint32(pkt[28:32]) != serverSeq+3 {
						t.Fatal("next request does not acknowledge received data")
					}
				}
				if p.Samples[seq].IpID != 42+seq {
					t.Fatal("control ACK changed measurement sample")
				}
			}
		})
	}
}

func TestBaseTCPSequenceValidation(t *testing.T) {
	for _, test := range []struct {
		name     string
		sequence uint32
		length   uint16
	}{
		{"data gap", 2002, 3}, {"data overlap", 2000, 3},
		{"ACK ahead", 2002, 0}, {"ACK before SYN", 1999, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, key, _ := handshakeFixture(t)
			deliverSYNACK(t, p, key, 0)
			p.Samples[4].MarkSent(100)
			before := atomic.LoadInt64(&stats.AbortTCPSequence)
			if FulfillReply(key, sender.SenderA.IPBytes, 40000, 1002, test.sequence, 99, types.AckFlagSet, 200, test.length) || p.complete() {
				t.Fatal("invalid server sequence accepted")
			}
			if atomic.LoadInt64(&stats.AbortTCPSequence) != before+1 || p.Samples[4].IsReceived() {
				t.Fatal("sequence failure changed sample or was not counted")
			}
		})
	}
}

func TestBaseTCPExtraReplyStillAborts(t *testing.T) {
	for _, flags := range []types.TCPFlagSet{
		types.AckFlagSet, sets.New(types.TCPFlagACK, types.TCPFlagPSH), sets.New(types.TCPFlagACK, types.TCPFlagFIN),
	} {
		t.Run("extra reply", func(t *testing.T) {
			p, key, _ := handshakeFixture(t)
			deliverSYNACK(t, p, key, 0)
			before := atomic.LoadInt64(&stats.AbortDup)
			if FulfillReply(key, sender.SenderA.IPBytes, 40000, 1001, 2001, 42, flags, 201, 0) || p.complete() {
				t.Fatal("additional response accepted as handshake replacement")
			}
			if atomic.LoadInt64(&stats.AbortDup) != before+1 || p.Samples[0].IpID != 42 {
				t.Fatal("additional response was not counted or changed stored IPID")
			}
		})
	}
}

func TestBaseTCPFixedACKReordering(t *testing.T) {
	p, key, _ := handshakeFixture(t)
	for connection := uint16(0); connection < 4; connection++ {
		deliverSYNACK(t, p, key, connection)
	}
	for seq := 4; seq < 16; seq++ {
		p.Samples[seq].MarkSent(100)
	}
	for seq := uint16(15); seq >= 4; seq-- {
		if !FulfillReply(key, sender.GetSender(seq).IPBytes, 40000+seq%4, 1001+uint32(seq%4+seq/4), 2001, seq, types.AckFlagSet, 200, 0) {
			t.Fatal("reordered pure ACK rejected")
		}
	}
	if !p.complete() {
		t.Fatal("reordered measurement failed")
	}
}

func TestBaseTCPFinalDataACK(t *testing.T) {
	for _, sendOK := range []bool{true, false} {
		t.Run("final ACK", func(t *testing.T) {
			p, key, _ := handshakeFixture(t)
			deliverSYNACK(t, p, key, 0)
			p.flushTCPACKs()
			entry := Inflight.Lookup(key)
			entry.expectedCount = 2
			p.Samples[4].MarkSent(100)
			if !FulfillReply(key, sender.SenderA.IPBytes, 40000, 1002, 2001, 44, types.AckFlagSet, 200, 5) {
				t.Fatal("last data rejected")
			}
			calls := 0
			p.tcpSendACK = func(uint16) bool {
				calls++
				if !sendOK {
					p.fail(&stats.DropSendErr)
				}
				return sendOK
			}
			timer := time.NewTimer(time.Hour)
			defer timer.Stop()
			if waitForFixedReplies(p, entry, timer) != sendOK || calls != 1 || p.complete() != sendOK {
				t.Fatal("final data ACK was lost or send failure ignored")
			}
		})
	}
}

func TestBaseTCPFlagAllowlist(t *testing.T) {
	for _, extra := range []string{"", "P", "F", "S", "R", "U", "E", "C", "N"} {
		t.Run("ACK+"+extra, func(t *testing.T) {
			p, key, _ := handshakeFixture(t)
			deliverSYNACK(t, p, key, 0)
			p.Samples[4].MarkSent(100)
			flags := sets.New(types.TCPFlagACK)
			if extra != "" {
				flags.Add(extra)
			}
			accepted := FulfillReply(key, sender.SenderA.IPBytes, 40000, 1002, 2001, 44, flags, 200, 0)
			if accepted != (extra == "" || extra == "P") {
				t.Fatal("wrong flag acceptance")
			}
		})
	}
}

func TestBaseTCPDataSequenceWrapAndDelayedACK(t *testing.T) {
	p, key, _ := handshakeFixture(t)
	p.Samples[0].MarkSent(100)
	if !FulfillReply(key, sender.SenderA.IPBytes, 40000, 1001, ^uint32(0)-1, 42, types.SynAckFlagSet, 200, 0) {
		t.Fatal("SYN-ACK rejected")
	}
	p.Samples[4].MarkSent(100)
	p.Samples[8].MarkSent(100)
	if !FulfillReply(key, sender.SenderA.IPBytes, 40000, 1003, ^uint32(0), 48, types.AckFlagSet, 200, 3) || p.tcpAcknowledgments[0].Load() != 2 {
		t.Fatal("wrapped data sequence rejected")
	}
	if !FulfillReply(key, sender.SenderA.IPBytes, 40000, 1002, ^uint32(0), 44, types.AckFlagSet, 201, 0) || p.tcpAcknowledgments[0].Load() != 2 {
		t.Fatal("delayed pure ACK rejected or receive sequence regressed")
	}
}
