package probe

import (
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/sender"
)

func handshakeFixture(t *testing.T) (*Probe, [4]byte, <-chan uint16) {
	t.Helper()
	p, key := baseFixture(t)
	measurement.TcpEstablishConnection = true
	p.tcpHandshakeReplies = make(chan uint16, 4)
	acks := make(chan uint16, 4)
	p.tcpHandshakeACK = func(connection uint16) bool {
		acks <- connection
		return true
	}
	return p, key, acks
}

func deliverSYNACK(t *testing.T, p *Probe, key [4]byte, connection uint16) {
	t.Helper()
	p.Samples[connection].MarkSent(100)
	if !FulfillReply(key, sender.GetSender(connection).IPBytes, 40000+connection,
		1001+uint32(connection), 2000, 42, types.SynAckFlagSet, 200) {
		t.Fatal("valid SYN-ACK rejected")
	}
}

func expectHandshakeACK(t *testing.T, acks <-chan uint16, connection uint16) {
	t.Helper()
	select {
	case got := <-acks:
		if got != connection {
			t.Fatalf("ACK connection = %d, want %d", got, connection)
		}
	case <-time.After(time.Second):
		t.Fatal("ACK waited for unrelated handshakes")
	}
}

func TestRTConfirmsSYNACKBeforeNextRequest(t *testing.T) {
	p, key, acks := handshakeFixture(t)
	measurement.Config.MeasurementMode = types.MeasurementModeRTBased
	deliverSYNACK(t, p, key, 0)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	if !waitForBaseReply(p, timer) {
		t.Fatal("RT handshake failed")
	}
	expectHandshakeACK(t, acks, 0)
	if p.Samples[1].WasSent() || p.tcpHandshakeCount.Load() != 1 {
		t.Fatal("ACK required another request or handshake")
	}
	if p.Samples[0].SentTime != 100 || p.Samples[0].ReceiveTime != 200 || p.Samples[0].IpID != 42 {
		t.Fatal("handshake ACK changed the measurement sample")
	}
}

func TestFixedIntervalConfirmsSYNACKDuringInterval(t *testing.T) {
	p, key, acks := handshakeFixture(t)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	result := make(chan bool, 1)
	go func() { result <- p.waitInterval(time.Hour, timer) }()
	deliverSYNACK(t, p, key, 2)
	expectHandshakeACK(t, acks, 2)
	p.fail(nil)
	select {
	case ok := <-result:
		if ok {
			t.Fatal("aborted interval succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("interval did not stop")
	}
}

func TestHandshakeWaitConfirmsRepliesAsTheyArrive(t *testing.T) {
	p, key, acks := handshakeFixture(t)
	result := make(chan bool, 1)
	go func() { result <- waitForTCPHandshakes(p) }()
	for _, connection := range []uint16{2, 0, 3, 1} {
		deliverSYNACK(t, p, key, connection)
		expectHandshakeACK(t, acks, connection)
	}
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("complete handshakes failed")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake wait did not finish")
	}
	if !p.flushHandshakeACKs() {
		t.Fatal("empty queue failed")
	}
	select {
	case <-acks:
		t.Fatal("handshake acknowledged twice")
	default:
	}
}

func TestHandshakeACKFailureStopsQueue(t *testing.T) {
	p, key, _ := handshakeFixture(t)
	deliverSYNACK(t, p, key, 0)
	deliverSYNACK(t, p, key, 1)
	calls := 0
	p.tcpHandshakeACK = func(uint16) bool { calls++; p.fail(nil); return false }
	if p.flushHandshakeACKs() || calls != 1 || p.complete() {
		t.Fatal("ACK failure did not stop target")
	}
}

func TestDuplicateSYNACKStillAbortsWithoutAnotherACK(t *testing.T) {
	p, key, acks := handshakeFixture(t)
	deliverSYNACK(t, p, key, 0)
	if !p.flushHandshakeACKs() {
		t.Fatal("ACK failed")
	}
	expectHandshakeACK(t, acks, 0)
	if FulfillReply(key, sender.SenderA.IPBytes, 40000, 1001, 2000, 42, types.SynAckFlagSet, 201) || p.complete() {
		t.Fatal("duplicate policy changed")
	}
	if len(p.tcpHandshakeReplies) != 0 {
		t.Fatal("duplicate queued another ACK")
	}
}
