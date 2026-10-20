package probe

import (
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/google/gopacket/layers"
)

func TestInterprotocolFixedRetainsZeroReplyTarget(t *testing.T) {
	p, _ := baseFixture(t)
	p.strict = false
	oldProtocols, oldSave := measurement.InterProtocols, SaveProbesChannel
	t.Cleanup(func() { measurement.InterProtocols = oldProtocols; SaveProbesChannel = oldSave })
	measurement.InterProtocols = []types.Payload{types.PayloadICMP, types.PayloadTCP}
	measurement.Config.FixedIntervalConfig.MinimumReplyRate = .8
	SaveProbesChannel = make(chan *Probe, 1)
	if !finishFixedProbe(p) {
		t.Fatal("zero-reply target was discarded")
	}
	if got := <-SaveProbesChannel; got != p {
		t.Fatal("wrong target saved")
	}
	measurement.InterProtocols = nil
	p2 := &Probe{Samples: make([]Sample, 16)}
	if finishFixedProbe(p2) {
		t.Fatal("changed ordinary MASS filtering")
	}
}

func TestInterprotocolFixedReplyUsesLogicalSourceAndConnection(t *testing.T) {
	p, key := baseFixture(t)
	p.strict = false
	old := measurement.InterProtocols
	measurement.InterProtocols = []types.Payload{types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS}
	t.Cleanup(func() { measurement.InterProtocols = old })
	p.Samples[1].MarkSent(100)
	// TCP at global position 1 still belongs to logical connection 0/source A.
	if FulfillProtocolReply(key, sender.SenderB.IPBytes, layers.IPProtocolTCP, 40000, 1, 0, 42, types.SynAckFlagSet, 200, 0) {
		t.Fatal("accepted wrong source")
	}
	if FulfillProtocolReply(key, sender.SenderA.IPBytes, layers.IPProtocolTCP, 40001, 1, 0, 42, types.SynAckFlagSet, 200, 0) {
		t.Fatal("accepted wrong connection")
	}
	if !FulfillProtocolReply(key, sender.SenderA.IPBytes, layers.IPProtocolTCP, 40000, 1, 0, 42, types.SynAckFlagSet, 200, 0) {
		t.Fatal("valid reply rejected")
	}
	if FulfillProtocolReply(key, sender.SenderA.IPBytes, layers.IPProtocolTCP, 40000, 1, 0, 42, types.SynAckFlagSet, 200, 0) {
		t.Fatal("duplicate accepted")
	}
	p.Samples[4].MarkSent(100)
	if FulfillProtocolReply(key, sender.SenderB.IPBytes, layers.IPProtocolTCP, 40001, 4, 0, 42, types.SynAckFlagSet, 100+time.Second.Microseconds()+1, 0) {
		t.Fatal("late reply accepted")
	}
}
