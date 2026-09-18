package probe

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/sender"
	"github.com/alxweis/ipid-measure/ipid/stats"
)

func TestBaseTCPBadFlagsDiagnostics(t *testing.T) {
	for _, mode := range []types.MeasurementMode{types.MeasurementModeRTBased, types.MeasurementModeFixedInterval} {
		for _, phase := range []string{"no_connection", "handshake", "data"} {
			t.Run(string(mode)+"/"+phase, func(t *testing.T) {
				p, key := baseFixture(t)
				measurement.Config.MeasurementMode = mode
				measurement.TcpEstablishConnection = phase != "no_connection"
				seq, recovered := uint16(0), uint32(0)
				if phase == "handshake" {
					recovered = 1001
				} else if phase == "data" {
					seq, recovered = 4, 1002
				}
				p.Samples[seq].MarkSent(100)
				before := atomic.LoadInt64(&stats.AbortBadFlags)
				flags := sets.New(types.TCPFlagACK, types.TCPFlagURG)
				if FulfillReply(key, sender.GetSender(seq).IPBytes, 40000, recovered, 2000, 99, flags, 200, 0) {
					t.Fatal("diagnostic changed invalid reply acceptance")
				}
				if atomic.LoadInt64(&stats.AbortBadFlags) != before+1 || p.complete() {
					t.Fatal("invalid flags did not fail target once")
				}
				summary := stats.TCPBadFlagsSummary()
				if !strings.Contains(summary, phase+":AU=") {
					t.Fatalf("missing phase and flags: %s", summary)
				}
				FulfillReply(key, sender.GetSender(seq).IPBytes, 40000, recovered, 2000, 99, flags, 200, 0)
				if stats.TCPBadFlagsSummary() != summary || p.Samples[seq].IsReceived() {
					t.Fatal("failed target was counted again or sample was filled")
				}
			})
		}
	}
}

func TestTCPBadFlagsDiagnosticsExclusions(t *testing.T) {
	for _, name := range []string{"accepted", "reset", "dns", "mass"} {
		t.Run(name, func(t *testing.T) {
			p, key := baseFixture(t)
			p.Samples[0].MarkSent(100)
			flags, recovered := types.SynAckFlagSet, uint32(0)
			switch name {
			case "reset":
				measurement.TcpEstablishConnection = true
				flags, recovered = sets.New(types.TCPFlagRST, types.TCPFlagACK), 1001
			case "dns":
				payload.Active, flags = payload.UdpDns, sets.New(types.DNSFlagRA)
			case "mass":
				p.strict, flags = false, types.AckFlagSet
			}
			before := stats.TCPBadFlagsSummary()
			accepted := FulfillReply(key, sender.SenderA.IPBytes, 40000, recovered, 2000, 99, flags, 200, 0)
			if accepted != (name == "accepted") || stats.TCPBadFlagsSummary() != before {
				t.Fatal("acceptance changed or unrelated event entered TCP Base diagnostics")
			}
		})
	}
}
