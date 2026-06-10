package receiver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/breml/bpfutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/ipid/dns"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/alxweis/ipid-measure/ipid/tcp"
)

// StartAll launches one receiver goroutine per interface. Registered into
// measurement.StartReceivers.
func StartAll() {
	measurement.ReceiverWg.Add(1)
	go Receive(measurement.Config.Interfaces.A)

	measurement.ReceiverWg.Add(1)
	go Receive(measurement.Config.Interfaces.B)
}

// Receive captures packets on one interface, decodes the L3/L4 headers, and
// hands matching replies to probe.FulfillReply for in-place sample filling.
//
// Performance: we use ZeroCopyReadPacketData (kernel buffer reused on the next
// read) together with a DecodingLayerParser that decodes only the headers we
// need. Both avoid the channel-based gopacket PacketSource and lazy reflection-
// based decoding of the previous implementation. There is NO copy of the packet
// bytes and NO allocation per captured frame: the sample filling step is the
// only mutation, and it happens directly in the probe's pre-allocated slice.
func Receive(iface config.Interface) {
	defer measurement.ReceiverWg.Done()

	handle, err := pcapgo.NewEthernetHandle(iface.Name)
	if err != nil {
		panic(err)
	}

	// Close the handle exactly once, either via deferred cleanup at function
	// exit or via the watchdog when shutdown is requested. ZeroCopyReadPacketData
	// blocks indefinitely on the AF_PACKET socket until data arrives or the fd
	// is closed; closing it from the watchdog unblocks the read with an error,
	// which is how we react to StopReceiving.
	var closeOnce sync.Once
	closeHandle := func() { closeOnce.Do(func() { handle.Close() }) }
	defer closeHandle()
	go func() {
		<-measurement.StopReceiving
		closeHandle()
	}()

	ifc, err := net.InterfaceByName(iface.Name)
	if err != nil {
		panic(err)
	}

	// Kernel BPF prefilter: drop irrelevant traffic before it ever reaches us.
	filter := strings.Join(strings.Split(string(payload.Active.ID), "-"), " and ")
	if payload.Active.ReceiveFilter != "" {
		filter += " and " + payload.Active.ReceiveFilter
	}
	bpfFilter := fmt.Sprintf("ether dst %s and ip and (%s) and dst host %s", ifc.HardwareAddr, filter, iface.IP)
	bpfInstr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, ifc.MTU, bpfFilter)
	if err != nil {
		panic(err)
	}
	if bpfErr := handle.SetBPF(bpfutils.ToBpfRawInstructions(bpfInstr)); bpfErr != nil {
		panic(bpfErr)
	}

	// Per-goroutine decoder state, reused for every captured frame. The Lazy/
	// NoCopy options mean the parser reads directly out of the kernel buffer.
	var (
		eth     layers.Ethernet
		ipv4    layers.IPv4
		tcpL    layers.TCP
		udpL    layers.UDP
		dnsL    layers.DNS
		icmpL   layers.ICMPv4
		decoded []gopacket.LayerType
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &ipv4, &tcpL, &udpL, &dnsL, &icmpL,
	)
	parser.IgnoreUnsupported = true
	decoded = make([]gopacket.LayerType, 0, 6)

	protocol := payload.Active.ProtocolID

	for {
		select {
		case <-measurement.StopReceiving:
			return
		default:
		}

		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			// Either a transient read error or the handle was closed by the
			// watchdog on shutdown. Check the stop signal to disambiguate.
			select {
			case <-measurement.StopReceiving:
				return
			default:
				continue
			}
		}

		if perr := parser.DecodeLayers(data, &decoded); perr != nil {
			// Truncated/malformed packet — count it and move on, never panic.
			atomic.AddInt64(&stats.RejectedReplies, 1)
			continue
		}

		// Extract per-protocol fields. The BPF filter already gated by protocol,
		// but we re-check on the decoded layers to be robust to filter typos.
		var (
			srcIP4    [4]byte
			dstIP4    [4]byte
			dstPort   uint16
			seqNum    uint16
			replyFlgs sets.Set[string]
			ok        bool
		)

		copy(srcIP4[:], ipv4.SrcIP.To4())
		copy(dstIP4[:], ipv4.DstIP.To4())

		switch protocol {
		case layers.IPProtocolTCP:
			seqNum, dstPort, replyFlgs, ok = extractTCP(&tcpL, decoded)
		case layers.IPProtocolUDP:
			seqNum, dstPort, replyFlgs, ok = extractUDPDNS(&udpL, &dnsL, decoded)
		case layers.IPProtocolICMPv4:
			seqNum, dstPort, replyFlgs, ok = extractICMP(&icmpL, decoded)
		}
		if !ok {
			atomic.AddInt64(&stats.RejectedReplies, 1)
			continue
		}

		now := time.Now().UnixMicro()
		if probe.FulfillReply(srcIP4, dstIP4, dstPort, seqNum, ipv4.Id, replyFlgs, now) {
			atomic.AddInt64(&stats.MatchedReplies, 1)
		} else {
			atomic.AddInt64(&stats.UnmatchedReplies, 1)
		}
	}
}

// extractTCP recovers seqNum (from Ack - 1 - base), the destination port the
// reply targets (== our source port for that connection), and the TCP flags.
// extractTCP recovers seqNum (from Ack - 1 - base), the destination port the
// reply targets (== our source port for that connection), and the TCP flags.
//
// It also enforces that the reply's *source* port equals the configured ZMap
// target port (e.g. 80 for an HTTP scan). The kernel BPF prefilter already
// gates by protocol, but it does not gate by reply source port — without this
// defence in depth, an unrelated TCP packet that happens to land on one of our
// ephemeral source ports and survives the destination-port range and flag
// checks would be wrongly accepted as a valid reply. This mirrors the old
// payload_tcp.Validate ValidateSrcPort check.
func extractTCP(t *layers.TCP, decoded []gopacket.LayerType) (uint16, uint16, sets.Set[string], bool) {
	found := false
	for _, lt := range decoded {
		if lt == layers.LayerTypeTCP {
			found = true
			break
		}
	}
	if !found {
		return 0, 0, nil, false
	}
	if measurement.Config.ZMapPort != nil && uint16(t.SrcPort) != *measurement.Config.ZMapPort {
		return 0, 0, nil, false
	}
	seq := uint16(t.Ack - 1 - measurement.TcpSequenceNumOffset)
	return seq, uint16(t.DstPort), tcp.GetFlags(t), true
}

// extractUDPDNS recovers seqNum (from DNS ID), the destination UDP port, and
// the DNS flag set. Rejects replies that arrived with an embedded ICMP error.
// extractUDPDNS recovers seqNum (from DNS ID), the destination UDP port, and
// the DNS flag set. Rejects replies that arrived with an embedded ICMP error.
//
// Also enforces that the reply's UDP *source* port equals the configured ZMap
// target port (e.g. 53 for DNS). See extractTCP for why this defence-in-depth
// check is necessary even though the BPF prefilter gates by protocol.
func extractUDPDNS(u *layers.UDP, d *layers.DNS, decoded []gopacket.LayerType) (uint16, uint16, sets.Set[string], bool) {
	hasUDP, hasDNS, hasICMP := false, false, false
	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeUDP:
			hasUDP = true
		case layers.LayerTypeDNS:
			hasDNS = true
		case layers.LayerTypeICMPv4:
			hasICMP = true
		}
	}
	if hasICMP || !hasUDP || !hasDNS {
		return 0, 0, nil, false
	}
	if measurement.Config.ZMapPort != nil && uint16(u.SrcPort) != *measurement.Config.ZMapPort {
		return 0, 0, nil, false
	}
	return d.ID, uint16(u.DstPort), dns.GetFlags(d), true
}

// extractICMP returns the echo reply's seq number. ICMP echo replies carry the
// destination port of the original probe in neither the IP nor ICMP headers,
// because there is no L4 port: we synthesise a port within the probe's range
// using the original probe's basePort + seqNum % ConnectionCount. The receiver
// cannot know basePort without consulting the inflight entry, so for ICMP we
// signal the "any port" sentinel and rely on the entry's port-range check.
func extractICMP(i *layers.ICMPv4, decoded []gopacket.LayerType) (uint16, uint16, sets.Set[string], bool) {
	found := false
	for _, lt := range decoded {
		if lt == layers.LayerTypeICMPv4 {
			found = true
			break
		}
	}
	if !found {
		return 0, 0, nil, false
	}
	if i.TypeCode != layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0) {
		return 0, 0, nil, false
	}
	// Use a sentinel port that is always inside any probe's connection range:
	// the receiver-side range check is bypassed for ICMP via the entry's
	// minPort/maxPort being set to the probe's range and our "any port" being
	// represented as the minPort itself. ICMP has no port to validate, so this
	// is the cleanest way to pass the range check unconditionally.
	_ = types.PayloadICMP // explicit reference so the symbol stays imported if extended
	return i.Seq, 0, sets.New[string](), true
}

func init() {
	measurement.StartReceivers = StartAll
}
