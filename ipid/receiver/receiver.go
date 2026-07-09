package receiver

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/breml/bpfutils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/ipid/dns"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/payload"
	"github.com/alxweis/ipid-measure/ipid/probe"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/alxweis/ipid-measure/ipid/tcp"
)

const receiveTimeoutMs = 200

func StartAll() {
	measurement.ReceiverWg.Add(1)
	go Receive(measurement.Config.Interfaces.A())

	measurement.ReceiverWg.Add(1)
	go Receive(measurement.Config.Interfaces.B())
}

// Receive captures packets on one interface, decodes the L3/L4 headers, and
// hands matching replies to probe.FulfillReply for in-place sample filling.
func Receive(iface config.Interface) {
	defer measurement.ReceiverWg.Done()

	handle, err := pcapgo.NewEthernetHandle(iface.Name)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Set a periodic read timeout so the blocking recvmsg() in ZeroCopyReadPacketData returns
	// regularly and the loop can observe StopReceiving.
	fd := *(*int)(unsafe.Pointer(handle))
	tv := unix.Timeval{Sec: 0, Usec: int64((receiveTimeoutMs * time.Millisecond) / time.Microsecond)}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		panic(fmt.Errorf("set SO_RCVTIMEO on %s: %w", iface.Name, err))
	}

	ifc, err := net.InterfaceByName(iface.Name)
	if err != nil {
		panic(err)
	}

	// Kernel BPF prefilter: drop irrelevant traffic before it ever reaches us.
	bpfFilter := fmt.Sprintf("ether dst %s and ip and (%s) and dst host %s", ifc.HardwareAddr,
		payload.Active.ReceiveFilter, iface.IP)
	bpfInstr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, ifc.MTU, bpfFilter)
	if err != nil {
		panic(err)
	}
	if bpfErr := handle.SetBPF(bpfutils.ToBpfRawInstructions(bpfInstr)); bpfErr != nil {
		panic(bpfErr)
	}

	// Per-goroutine decoder state, reused for every captured frame.
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
			// Either no packet arrived within the SO_RCVTIMEO window (EAGAIN) or a transient read error.
			select {
			case <-measurement.StopReceiving:
				return
			default:
				continue
			}
		}

		if perr := parser.DecodeLayers(data, &decoded); perr != nil {
			// Truncated/malformed packet; count it and move on, never panic.
			atomic.AddInt64(&stats.DropDecode, 1)
			continue
		}

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
			atomic.AddInt64(&stats.DropProto, 1)
			continue
		}

		now := time.Now().UnixMicro()
		probe.FulfillReply(srcIP4, dstIP4, dstPort, seqNum, ipv4.Id, replyFlgs, now)
	}
}

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
	return i.Seq, 0, sets.New[string](), true
}

func init() {
	measurement.StartReceivers = StartAll
}
