package receiver

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
)

func ipv4Frame(t *testing.T, protocol layers.IPProtocol, body []byte) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(198, 51, 100, 1), DstIP: net.IPv4(192, 0, 2, 1), Protocol: protocol},
		gopacket.Payload(body))
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestIPv4CaptureFilter(t *testing.T) {
	filter, err := pcap.NewBPF(layers.LinkTypeEthernet, 1500, captureFilter(net.HardwareAddr{2, 0, 0, 0, 0, 2}, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []layers.IPProtocol{layers.IPProtocolTCP, layers.IPProtocolUDP, layers.IPProtocolICMPv4, layers.IPProtocol(253)} {
		data := ipv4Frame(t, protocol, make([]byte, 20))
		info := gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}
		if !filter.Matches(info, data) {
			t.Fatal("IPv4 protocol filtered out", protocol)
		}
		data[33] = 2
		if filter.Matches(info, data) {
			t.Fatal("wrong local IP captured")
		}
		data[33] = 1
		data[0] = 3
		if filter.Matches(info, data) {
			t.Fatal("wrong MAC captured")
		}
	}
}

func TestDecoderAttributesBeforeTransport(t *testing.T) {
	previous := payload.Active
	payload.Active = payload.TCP
	t.Cleanup(func() { payload.Active = previous })
	d := newPacketDecoder()
	key := [4]byte{198, 51, 100, 1}
	data := ipv4Frame(t, layers.IPProtocolTCP, []byte{1})
	beforeDecode, beforeMissing := atomic.LoadInt64(&stats.DropDecode), atomic.LoadInt64(&stats.DropNoEntry)
	d.process(data)
	if atomic.LoadInt64(&stats.DropDecode) != beforeDecode || atomic.LoadInt64(&stats.DropNoEntry) != beforeMissing+1 {
		t.Fatal("unregistered source reached transport decoder")
	}
	entry := &probe.InflightEntry{Probe: &probe.Probe{}}
	probe.Inflight.Register(key, entry)
	t.Cleanup(func() { probe.Inflight.Deregister(key, entry) })
	d.process(data)
	if atomic.LoadInt64(&stats.DropDecode) != beforeDecode+1 {
		t.Fatal("malformed TCP was not decoded for registered target")
	}
	beforeProto := atomic.LoadInt64(&stats.DropProto)
	d.process(ipv4Frame(t, layers.IPProtocolICMPv4, nil))
	if atomic.LoadInt64(&stats.DropProto) != beforeProto+1 || atomic.LoadInt64(&stats.DropDecode) != beforeDecode+1 {
		t.Fatal("unexpected protocol was not detected before transport parsing")
	}
	d.process([]byte{0})
	if atomic.LoadInt64(&stats.DropProto) != beforeProto+1 {
		t.Fatal("stale IP attributed after malformed frame")
	}
}

func TestRouterICMPDoesNotUseQuotedTarget(t *testing.T) {
	previous := payload.Active
	payload.Active = payload.TCP
	t.Cleanup(func() { payload.Active = previous })
	key := [4]byte{192, 0, 2, 1}
	entry := &probe.InflightEntry{Probe: &probe.Probe{}}
	probe.Inflight.Register(key, entry)
	t.Cleanup(func() { probe.Inflight.Deregister(key, entry) })
	quoted := ipv4Frame(t, layers.IPProtocolTCP, make([]byte, 20))[14:]
	data := ipv4Frame(t, layers.IPProtocolICMPv4, append([]byte{3, 1, 0, 0, 0, 0, 0, 0}, quoted...))
	beforeMissing, beforeProto := atomic.LoadInt64(&stats.DropNoEntry), atomic.LoadInt64(&stats.DropProto)
	newPacketDecoder().process(data)
	if atomic.LoadInt64(&stats.DropNoEntry) != beforeMissing+1 || atomic.LoadInt64(&stats.DropProto) != beforeProto {
		t.Fatal("router error was attributed through quoted packet")
	}
}

func TestCaptureStatsAccumulateResettingCounters(t *testing.T) {
	packets, drops, failures := atomic.LoadInt64(&stats.CapturePackets), atomic.LoadInt64(&stats.CaptureDrops), atomic.LoadInt64(&stats.CaptureStatsErrors)
	for _, delta := range []unix.TpacketStats{{Packets: 12, Drops: 2}, {Packets: 8, Drops: 1}} {
		collectCaptureStats(func() (*unix.TpacketStats, error) { return &delta, nil })
	}
	collectCaptureStats(func() (*unix.TpacketStats, error) { return nil, errors.New("stats unavailable") })
	if atomic.LoadInt64(&stats.CapturePackets) != packets+20 || atomic.LoadInt64(&stats.CaptureDrops) != drops+3 || atomic.LoadInt64(&stats.CaptureStatsErrors) != failures+1 {
		t.Fatal("capture counters lost deltas or read errors")
	}
}

func TestExpectedTransportDecoding(t *testing.T) {
	previousPayload, previousConfig := payload.Active, measurement.Config
	previousPorts, previousConnection, previousOffset := measurement.HasPorts, measurement.TcpEstablishConnection, measurement.TcpSequenceNumOffset
	t.Cleanup(func() {
		payload.Active, measurement.Config = previousPayload, previousConfig
		measurement.HasPorts, measurement.TcpEstablishConnection, measurement.TcpSequenceNumOffset = previousPorts, previousConnection, previousOffset
	})
	measurement.Config = &config.IPIDConfig{}
	measurement.HasPorts, measurement.TcpEstablishConnection, measurement.TcpSequenceNumOffset = false, false, 0
	key := [4]byte{198, 51, 100, 1}
	entry := &probe.InflightEntry{Probe: &probe.Probe{}}
	probe.Inflight.Register(key, entry)
	t.Cleanup(func() { probe.Inflight.Deregister(key, entry) })
	for _, test := range []struct {
		payload *payload.Payload
		body    []byte
	}{
		{payload.TCP, []byte{0, 80, 156, 64, 0, 0, 0, 1, 0, 0, 0, 5, 80, 18, 2, 0, 0, 0, 0, 0}},
		{payload.UdpDns, []byte{0, 53, 156, 64, 0, 20, 0, 0, 0, 4, 132, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{payload.ICMP, []byte{0, 0, 0, 0, 0, 1, 0, 4}},
	} {
		t.Run(string(test.payload.ID), func(t *testing.T) {
			payload.Active = test.payload
			before := atomic.LoadInt64(&stats.DropBadDst)
			d := newPacketDecoder()
			d.process(ipv4Frame(t, test.payload.ProtocolID, test.body))
			if atomic.LoadInt64(&stats.DropBadDst) != before+1 {
				t.Fatal("valid transport did not reach sample validation")
			}
			switch test.payload {
			case payload.TCP:
				if d.tcp.Ack != 5 || !d.tcp.SYN || !d.tcp.ACK {
					t.Fatal("wrong TCP decode")
				}
			case payload.UdpDns:
				if d.dns.ID != 4 || !d.dns.QR || !d.dns.AA {
					t.Fatal("wrong DNS decode")
				}
			case payload.ICMP:
				if d.icmp.Seq != 4 {
					t.Fatal("wrong ICMP decode")
				}
			}
		})
	}
}
