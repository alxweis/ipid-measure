package receiver

import (
	"errors"
	"fmt"
	"log"
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
	"github.com/alxweis/ipid-measure/ipid/diagnostics"
	"github.com/alxweis/ipid-measure/ipid/dns"
	"github.com/alxweis/ipid-measure/ipid/measurement"
	"github.com/alxweis/ipid-measure/ipid/stats"
	"github.com/alxweis/ipid-measure/ipid/tcp"
)

const receiveTimeoutMs = 200
const receiveBufferBytes = 4 << 20

func StartAll() {
	diagnostics.Begin()
	measurement.ReceiverWg.Add(1)
	go Receive(measurement.Config.Interfaces.A())

	measurement.ReceiverWg.Add(1)
	go Receive(measurement.Config.Interfaces.B())
}

// Receive captures packets on one interface, decodes the L3/L4 headers, and
// hands matching replies to probe.FulfillReply for in-place sample filling.
func Receive(iface config.Interface) {
	defer measurement.ReceiverWg.Done()
	index := 0
	if iface.IP == measurement.Config.Interfaces.IPB {
		index = 1
	}
	diag := &diagnostics.Captures[index]

	handle, err := pcapgo.NewEthernetHandle(iface.Name)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Set a periodic read timeout so the blocking recvmsg() in ZeroCopyReadPacketData returns
	// regularly and the loop can observe StopReceiving.
	fd := *(*int)(unsafe.Pointer(handle))
	buffer, bufferErr := configureReceiveBuffer(fd)
	if bufferErr != nil {
		diag.SocketErrors.Add(1)
		log.Printf("WARNING receive buffer for %s (%s): requested_bytes=%d effective_bytes=%d: %v", iface.Name, iface.IP, receiveBufferBytes, buffer, bufferErr)
	} else if buffer < 2*receiveBufferBytes {
		log.Printf("WARNING receive buffer for %s (%s): requested_bytes=%d effective_bytes=%d expected_bytes=%d; net.core.rmem_max may limit SO_RCVBUF; configure net.core.rmem_max to at least %d to grant the full request", iface.Name, iface.IP, receiveBufferBytes, buffer, 2*receiveBufferBytes, receiveBufferBytes)
	}
	diag.ReceiveBuffer.Store(int64(buffer))
	tv := unix.Timeval{Sec: 0, Usec: int64((receiveTimeoutMs * time.Millisecond) / time.Microsecond)}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		panic(fmt.Errorf("set SO_RCVTIMEO on %s: %w", iface.Name, err))
	}

	ifc, err := net.InterfaceByName(iface.Name)
	if err != nil {
		panic(err)
	}

	// Kernel BPF prefilter: drop irrelevant traffic before it ever reaches us.
	bpfFilter := captureFilter(ifc.HardwareAddr, iface.IP)
	bpfInstr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, ifc.MTU, bpfFilter)
	if err != nil {
		panic(err)
	}
	if bpfErr := handle.SetBPF(bpfutils.ToBpfRawInstructions(bpfInstr)); bpfErr != nil {
		panic(bpfErr)
	}

	decoder := newPacketDecoder()
	diag.Snaplen.Store(int64(handle.GetCaptureLength()))
	timestampNS, nsErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS)
	timestampUS, usErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP)
	if timestampNS > 0 || timestampUS > 0 {
		diag.KernelTimestamp.Store(1)
	} else if nsErr != nil || usErr != nil {
		diag.KernelTimestamp.Store(-1)
		diag.SocketErrors.Add(1)
	}
	readStats := func() (*unix.TpacketStats, error) {
		snapshot, err := handle.Stats()
		if err == nil {
			diag.Record(snapshot.Packets, snapshot.Drops)
		}
		return snapshot, err
	}
	lastStats := time.Now()
	packetsSinceStats := 0
	defer collectCaptureStats(readStats)
	diag.ReadyNS.Store(diagnostics.NowNS())

	for {
		select {
		case <-measurement.StopReceiving:
			return
		default:
		}

		readStart := diag.Read.Start()
		data, info, err := handle.ZeroCopyReadPacketData()
		diag.Read.End(readStart)
		if err == nil && !readStart.IsZero() && diag.KernelTimestamp.Load() == 1 {
			diag.Age.Observe(time.Since(info.Timestamp))
		}
		packetsSinceStats++
		if err != nil || packetsSinceStats >= 256 {
			packetsSinceStats = 0
			if time.Since(lastStats) >= time.Second {
				collectCaptureStats(readStats)
				lastStats = time.Now()
			}
		}
		if err == nil {
			processStart := diag.Process.Start()
			decoder.process(data)
			diag.Process.End(processStart)
		}
	}
}

func configureReceiveBuffer(fd int) (int, error) {
	current, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return -1, fmt.Errorf("read SO_RCVBUF: %w", err)
	}
	if current >= 2*receiveBufferBytes {
		return current, nil
	}
	var setErr error
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, receiveBufferBytes); err != nil {
		setErr = fmt.Errorf("set SO_RCVBUF: %w", err)
	}
	actual, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return -1, errors.Join(setErr, fmt.Errorf("read configured SO_RCVBUF: %w", err))
	}
	return actual, setErr
}

func captureFilter(mac net.HardwareAddr, ip string) string {
	return fmt.Sprintf("ether dst %s and ip and dst host %s", mac, ip)
}

func collectCaptureStats(read func() (*unix.TpacketStats, error)) {
	snapshot, err := read()
	if err != nil {
		atomic.AddInt64(&stats.CaptureStatsErrors, 1)
		return
	}
	atomic.AddInt64(&stats.CapturePackets, int64(snapshot.Packets))
	atomic.AddInt64(&stats.CaptureDrops, int64(snapshot.Drops))
}

func extractTCP(t *layers.TCP, decoded []gopacket.LayerType) (uint32, uint32, uint16, sets.Set[string], bool) {
	found := false
	for _, lt := range decoded {
		if lt == layers.LayerTypeTCP {
			found = true
			break
		}
	}
	if !found {
		return 0, 0, 0, nil, false
	}
	if measurement.Config.ZMapPort != nil && uint16(t.SrcPort) != *measurement.Config.ZMapPort {
		return 0, 0, 0, nil, false
	}
	if measurement.TcpEstablishConnection {
		return t.Ack, t.Seq, uint16(t.DstPort), tcp.GetFlags(t), true
	}
	if t.Ack <= measurement.TcpSequenceNumOffset {
		return 0, 0, 0, nil, false
	}
	seq := t.Ack - 1 - measurement.TcpSequenceNumOffset
	return seq, t.Seq, uint16(t.DstPort), tcp.GetFlags(t), true
}

func extractUDPDNS(u *layers.UDP, d *layers.DNS, decoded []gopacket.LayerType) (uint32, uint16, sets.Set[string], bool) {
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
	return uint32(d.ID), uint16(u.DstPort), dns.GetFlags(d), true
}

func extractICMP(i *layers.ICMPv4, decoded []gopacket.LayerType) (uint32, uint16, sets.Set[string], bool) {
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
	return uint32(i.Seq), 0, sets.New[string](), true
}

func init() {
	measurement.StartReceivers = StartAll
}
