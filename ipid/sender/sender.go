package sender

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/ipid/measurement"
)

// Sender owns one AF_PACKET raw socket bound to a single egress interface and
// the pre-built 14-byte Ethernet header prepended to every frame.
type Sender struct {
	IP        net.IP
	EthHeader []byte
	Fd        int
	Addr      syscall.SockaddrLinklayer

	// mu serialises writes on this socket. sendmsg on an AF_PACKET socket is not
	// guaranteed safe for concurrent callers, and we additionally build the
	// frame into a reusable buffer, so a per-sender lock is required.
	mu  sync.Mutex
	buf []byte
}

// SenderA and SenderB are the two egress sockets. Requests are striped across
// them by sequence-number parity to roughly double send throughput. Owned by
// this package.
var (
	SenderA *Sender
	SenderB *Sender
)

// ErrStopped is returned by Send if the rate limiter was stopped (shutdown).
var ErrStopped = errors.New("sender: rate limiter stopped")

// Send transmits a single L3 packet by prepending the cached Ethernet header.
//
// The previous implementation did `append(l2.EthHeader, packet...)`, which
// mutated/aliased the shared EthHeader backing array and was a data race under
// concurrency. We instead copy into a per-sender reusable buffer under a lock,
// avoiding both the race and a per-packet heap allocation.
//
// Send blocks on the global rate limiter before transmitting, so the configured
// bandwidth/pps cap is enforced regardless of how many goroutines call Send.
func (s *Sender) Send(packet []byte) error {
	total := len(s.EthHeader) + len(packet)

	// Throttle BEFORE we acquire the per-sender lock so a blocked rate-limit
	// wait does not also block the other senders.
	if Limiter != nil {
		if !Limiter.Acquire(total) {
			return ErrStopped
		}
	}

	s.mu.Lock()
	if cap(s.buf) < total {
		s.buf = make([]byte, total)
	}
	frame := s.buf[:total]
	copy(frame, s.EthHeader)
	copy(frame[len(s.EthHeader):], packet)

	err := syscall.Sendmsg(s.Fd, frame, nil, &s.Addr, 0)
	s.mu.Unlock()
	return err
}

// Setup wires up both senders. Registered into measurement.SetupSenders.
func Setup() {
	SenderA = setupOne(measurement.Config.Interfaces.A)
	SenderB = setupOne(measurement.Config.Interfaces.B)
}

func setupOne(iface config.Interface) *Sender {
	ifc, err := net.InterfaceByName(iface.Name)
	if err != nil {
		panic(fmt.Errorf("sender %s: %w", iface.Name, err))
	}
	srcMac := ifc.HardwareAddr
	if len(srcMac) == 0 {
		panic(fmt.Errorf("sender %s: no source MAC address", iface.Name))
	}

	gwIP, err := getDefGateway()
	if err != nil {
		panic(fmt.Errorf("sender %s: %w", iface.Name, err))
	}
	dstMac, err := getMacAddr(gwIP)
	if err != nil {
		panic(fmt.Errorf("sender %s: %w", iface.Name, err))
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(hToNs(syscall.ETH_P_IP)))
	if err != nil {
		panic(fmt.Errorf("sender %s: open AF_PACKET socket: %w", iface.Name, err))
	}

	// Enlarge the kernel send buffer so high-rate bursts are not dropped locally.
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 8*1024*1024)

	addr := syscall.SockaddrLinklayer{
		Ifindex: ifc.Index,
		Halen:   6, // Ethernet address length is 6 bytes
		Addr: [8]uint8{
			dstMac[0], dstMac[1], dstMac[2],
			dstMac[3], dstMac[4], dstMac[5],
		},
	}

	ethHeader := []byte{
		dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5],
		srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5],
		0x08, 0x00, // EtherType IPv4
	}

	return &Sender{
		IP:        net.ParseIP(iface.IP),
		EthHeader: ethHeader,
		Addr:      addr,
		Fd:        fd,
	}
}

func getDefGateway() (net.IP, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1]), nil
		}
	}
	return nil, errors.New("default gateway not found")
}

func getMacAddr(ip net.IP) (net.HardwareAddr, error) {
	out, err := exec.Command("ip", "neigh", "show", ip.String()).Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if net.ParseIP(f).Equal(ip) && i+4 < len(fields) {
			return net.ParseMAC(fields[i+4])
		}
	}
	return nil, errors.New("MAC address not found")
}

func hToNs(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// GetSender returns the egress socket for a request, striping by parity.
func GetSender(seqNum uint16) *Sender {
	if seqNum%2 == 0 {
		return SenderA
	}
	return SenderB
}

// Close releases this sender's AF_PACKET file descriptor. Safe to call once;
// further calls are no-ops because the kernel-managed fd is already closed.
func (s *Sender) Close() {
	if s == nil || s.Fd <= 0 {
		return
	}
	_ = syscall.Close(s.Fd)
	s.Fd = -1
}

// CloseSenders closes both egress sockets. Registered into measurement.CloseSenders.
func CloseSenders() {
	if SenderA != nil {
		SenderA.Close()
	}
	if SenderB != nil {
		SenderB.Close()
	}
}

func init() {
	measurement.SetupSenders = Setup
	measurement.CloseSenders = CloseSenders
	measurement.SetupRateLimiter = SetupRateLimiter
	measurement.StopRateLimiter = func() {
		if Limiter != nil {
			Limiter.Stop()
		}
	}
}
