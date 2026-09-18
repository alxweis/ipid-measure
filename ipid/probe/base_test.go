package probe

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/google/gopacket/layers"
)

func baseFixture(t *testing.T) (*Probe, [4]byte) {
	t.Helper()
	oldConfig, oldPayload := measurement.Config, payload.Active
	oldA, oldB := sender.SenderA, sender.SenderB
	oldPorts, oldConnection := measurement.HasPorts, measurement.TcpEstablishConnection
	oldCount, oldOffset := measurement.RequestCount, measurement.TcpSequenceNumOffset
	t.Cleanup(func() {
		measurement.Config, payload.Active = oldConfig, oldPayload
		sender.SenderA, sender.SenderB = oldA, oldB
		measurement.HasPorts, measurement.TcpEstablishConnection = oldPorts, oldConnection
		measurement.RequestCount, measurement.TcpSequenceNumOffset = oldCount, oldOffset
	})
	measurement.Config = &config.IPIDConfig{
		ConnectionCount: 4, RequestsPerConnection: 4,
		MeasurementMode:     types.MeasurementModeFixedInterval,
		MaximumToleratedRTT: time.Second,
		TCPConfig:           config.TCPConfig{ReplyFlags: []types.TCPFlagSet{types.SynAckFlagSet}},
	}
	measurement.HasPorts, measurement.TcpEstablishConnection = true, false
	measurement.RequestCount, measurement.TcpSequenceNumOffset = 16, 1000
	payload.Active = payload.TCP
	sender.SenderA = &sender.Sender{IPBytes: [4]byte{192, 0, 2, 1}, Fd: -1}
	sender.SenderB = &sender.Sender{IPBytes: [4]byte{192, 0, 2, 2}, Fd: -1}
	p := &Probe{
		Samples: make([]Sample, 16), strict: true,
		failed: make(chan struct{}), replyReady: make(chan struct{}, 1),
		tcpAcknowledgments: make([]atomic.Uint32, 4), tcpAckReady: make([]atomic.Bool, 4),
		tcpHandshakeDone: make(chan struct{}),
	}
	key := [4]byte{198, 51, 100, 1}
	entry := &InflightEntry{
		Probe: p, expectedCount: 16, basePort: 40000,
		expectedDsts:    [2][4]byte{sender.SenderA.IPBytes, sender.SenderB.IPBytes},
		expectedMinPort: 40000, expectedMaxPort: 40003, expectedMaxSeq: 15,
		done: make(chan struct{}),
	}
	Inflight.Register(key, entry)
	t.Cleanup(func() { Inflight.Deregister(key, entry) })
	return p, key
}

func reply(t *testing.T, key [4]byte, seq uint16, flags sets.Set[string]) bool {
	t.Helper()
	return FulfillReply(key, sender.GetSender(seq).IPBytes, 40000+seq%4,
		uint32(seq), 2000, 42+seq, flags, 200, 0)
}

func TestBaseInvalidReplyAbortsOnce(t *testing.T) {
	for _, name := range []string{"dst", "port", "sequence", "unsent", "flags", "duplicate", "late", "reset"} {
		t.Run(name, func(t *testing.T) {
			p, key := baseFixture(t)
			p.Samples[0].MarkSent(100)
			dst, port, seq, flags, received := sender.SenderA.IPBytes, uint16(40000), uint32(0), types.SynAckFlagSet, int64(200)
			var counter *int64
			switch name {
			case "dst":
				dst, counter = sender.SenderB.IPBytes, &stats.AbortBadDst
			case "port":
				port, counter = 40001, &stats.AbortBadPort
			case "sequence":
				seq, counter = 16, &stats.AbortSeqOOR
			case "unsent":
				seq, counter = 4, &stats.AbortUnsent
			case "flags":
				flags, counter = types.AckFlagSet, &stats.AbortBadFlags
			case "duplicate":
				if !reply(t, key, 0, flags) {
					t.Fatal("first reply rejected")
				}
				counter = &stats.AbortDup
			case "late":
				received, counter = 100+time.Second.Microseconds()+1, &stats.AbortLate
			case "reset":
				measurement.TcpEstablishConnection = true
				seq, flags, counter = 1001, sets.New(types.TCPFlagRST), &stats.AbortReset
			}
			before := atomic.LoadInt64(counter)
			if FulfillReply(key, dst, port, seq, 2000, 99, flags, received, 0) {
				t.Fatal("invalid reply accepted")
			}
			if p.complete() {
				t.Fatal("failed target completed")
			}
			p.fail(counter)
			if atomic.LoadInt64(counter) != before+1 {
				t.Fatal("terminal reason not counted exactly once")
			}
			select {
			case <-p.failed:
			default:
				t.Fatal("worker was not notified")
			}
			if reply(t, key, 0, types.SynAckFlagSet) {
				t.Fatal("reply accepted after failure")
			}
			if p.Samples[0].IpID == 99 {
				t.Fatal("invalid reply changed sample")
			}
			if sendPacket(sender.SenderA, nil, &p.Samples[1], p) || p.Samples[1].WasSent() {
				t.Fatal("failed target attempted another request")
			}
		})
	}
}

func TestBaseRTDetectsReplyToEarlierRequest(t *testing.T) {
	p, key := baseFixture(t)
	measurement.Config.MeasurementMode = types.MeasurementModeRTBased
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for seq := uint16(0); seq < 2; seq++ {
		p.Samples[seq].MarkSent(100)
		if !reply(t, key, seq, types.SynAckFlagSet) || !waitForBaseReply(p, timer) {
			t.Fatal("valid RT reply rejected")
		}
	}
	before := atomic.LoadInt64(&stats.AbortDup)
	if reply(t, key, 0, types.SynAckFlagSet) || atomic.LoadInt64(&stats.AbortDup) != before+1 {
		t.Fatal("earlier reply was not attributed as a duplicate")
	}
}

func TestBaseFixedReorderingAndImmutableCompletion(t *testing.T) {
	for _, protocol := range []*payload.Payload{payload.ICMP, payload.UdpDns, payload.TCP} {
		t.Run(string(protocol.ID), func(t *testing.T) {
			p, key := baseFixture(t)
			payload.Active = protocol
			measurement.HasPorts = protocol != payload.ICMP
			flags := types.SynAckFlagSet
			if protocol == payload.UdpDns {
				flags = sets.New(types.DNSFlagQR, "AA")
			}
			for i := range p.Samples {
				p.Samples[i].MarkSent(100)
			}
			for seq := 15; seq >= 0; seq-- {
				if !reply(t, key, uint16(seq), flags) {
					t.Fatalf("reordered reply %d rejected", seq)
				}
			}
			if !p.complete() {
				t.Fatal("complete target failed")
			}
			before := atomic.LoadInt64(&stats.AbortDup)
			if reply(t, key, 0, flags) || atomic.LoadInt64(&stats.AbortDup) != before {
				t.Fatal("completed target changed")
			}
			if p.Samples[0].IpID != 42 {
				t.Fatal("stored IPID changed")
			}
		})
	}
}

func TestBaseConnectionHandshakeAndDataReplies(t *testing.T) {
	p, key := baseFixture(t)
	measurement.TcpEstablishConnection = true
	for seq := uint16(0); seq < 16; seq++ {
		p.Samples[seq].MarkSent(100)
		flags := types.AckFlagSet
		if seq < 4 {
			flags = types.SynAckFlagSet
		}
		ack := uint32(1001 + seq%4 + seq/4)
		serverSequence := uint32(2001)
		if seq < 4 {
			serverSequence = 2000
		}
		if !FulfillReply(key, sender.GetSender(seq).IPBytes, 40000+seq%4, ack, serverSequence, seq, flags, 200, 0) {
			t.Fatalf("connection reply %d rejected", seq)
		}
	}
	if !waitForTCPHandshakes(p) || !p.complete() {
		t.Fatal("handshake or completion failed")
	}
}

func TestBaseAbortWakesWaits(t *testing.T) {
	for _, name := range []string{"reply", "interval", "handshake"} {
		t.Run(name, func(t *testing.T) {
			p, _ := baseFixture(t)
			measurement.Config.MaximumToleratedRTT = time.Hour
			result := make(chan bool, 1)
			go func() {
				switch name {
				case "reply":
					timer := time.NewTimer(time.Hour)
					defer timer.Stop()
					result <- waitForBaseReply(p, timer)
				case "interval":
					timer := time.NewTimer(time.Hour)
					defer timer.Stop()
					result <- p.waitInterval(time.Hour, timer)
				case "handshake":
					result <- waitForTCPHandshakes(p)
				}
			}()
			p.fail(nil)
			select {
			case ok := <-result:
				if ok {
					t.Fatal("failed wait succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("failed target remained blocked")
			}
		})
	}
}

func TestBaseCompletionRacesWithDuplicate(t *testing.T) {
	p, key := baseFixture(t)
	p.Samples[0].MarkSent(100)
	if !reply(t, key, 0, types.SynAckFlagSet) {
		t.Fatal("first reply rejected")
	}
	var wg sync.WaitGroup
	wg.Add(2)
	completed := false
	go func() { defer wg.Done(); completed = p.complete() }()
	go func() { defer wg.Done(); reply(t, key, 0, types.SynAckFlagSet) }()
	wg.Wait()
	if completed != (p.status == probeComplete) {
		t.Fatal("inconsistent final state")
	}
	if p.Samples[0].IpID != 42 {
		t.Fatal("duplicate changed completed sample")
	}
}

func TestMassStillIgnoresDuplicate(t *testing.T) {
	p, key := baseFixture(t)
	p.strict = false
	measurement.Config.RequestsPerConnection, measurement.RequestCount = 25, 100
	p.Samples = make([]Sample, 100)
	entry := Inflight.Lookup(key)
	entry.expectedCount, entry.expectedMaxSeq = 100, 99
	p.Samples[0].MarkSent(100)
	p.Samples[1].MarkSent(100)
	before := atomic.LoadInt64(&stats.AbortDup)
	if !reply(t, key, 0, types.SynAckFlagSet) || reply(t, key, 0, types.SynAckFlagSet) || !reply(t, key, 1, types.SynAckFlagSet) {
		t.Fatal("Mass duplicate handling changed")
	}
	RejectBaseReply(key, &stats.AbortBadPort)
	if !p.complete() || atomic.LoadInt64(&stats.AbortDup) != before {
		t.Fatal("Mass target aborted")
	}
}

func TestBaseReceiverRejectionRequiresActiveTarget(t *testing.T) {
	p, key := baseFixture(t)
	before := atomic.LoadInt64(&stats.AbortBadPort)
	RejectBaseReply([4]byte{203, 0, 113, 1}, &stats.AbortBadPort)
	if p.status != probeActive || atomic.LoadInt64(&stats.AbortBadPort) != before {
		t.Fatal("unrelated reply aborted target")
	}
	RejectBaseReply(key, &stats.AbortBadPort)
	RejectBaseReply(key, &stats.AbortBadPort)
	if p.status != probeFailed || atomic.LoadInt64(&stats.AbortBadPort) != before+1 {
		t.Fatal("receiver rejection did not abort target exactly once")
	}
}

func TestUnexpectedProtocolPolicy(t *testing.T) {
	for _, mode := range []types.MeasurementMode{types.MeasurementModeRTBased, types.MeasurementModeFixedInterval} {
		for _, strict := range []bool{true, false} {
			t.Run(string(mode), func(t *testing.T) {
				p, key := baseFixture(t)
				p.strict = strict
				measurement.Config.MeasurementMode = mode
				entry := Inflight.Lookup(key)
				before := atomic.LoadInt64(&stats.AbortProto)
				if !entry.AcceptProtocol(layers.IPProtocolTCP) || entry.AcceptProtocol(layers.IPProtocolICMPv4) {
					t.Fatal("wrong protocol acceptance")
				}
				entry.AcceptProtocol(layers.IPProtocolICMPv4)
				want := before
				if strict {
					want++
				}
				if atomic.LoadInt64(&stats.AbortProto) != want || p.complete() == strict {
					t.Fatal("unexpected protocol did not preserve Base/Mass policy")
				}
				if strict {
					select {
					case <-p.failed:
					default:
						t.Fatal("worker not notified")
					}
				}
			})
		}
	}
}
