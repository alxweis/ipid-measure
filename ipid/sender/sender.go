package sender

import (
	"errors"
	"fmt"
	"github.com/alxweis/ipid-measure/internal/consts"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/ipid/measurement"
)

type Sender struct {
	IP        net.IP
	IPBytes   [4]byte
	EthHeader []byte
	Fd        int
	Addr      syscall.SockaddrLinklayer

	mu  sync.Mutex
	buf []byte
}

var (
	SenderA *Sender
	SenderB *Sender
)

// Send transmits a single L3 packet by prepending the cached Ethernet header.
func (s *Sender) Send(packet []byte) error {
	total := len(s.EthHeader) + len(packet)
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
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, consts.IPIDSocketSendBufferBytes)

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

	ip := net.ParseIP(iface.IP)
	var ipBytes [4]byte
	copy(ipBytes[:], ip.To4())

	return &Sender{
		IP:        ip,
		IPBytes:   ipBytes,
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

func GetSender(seqNum uint16) *Sender {
	if seqNum%2 == 0 {
		return SenderA
	}
	return SenderB
}

func (s *Sender) Close() {
	if s == nil || s.Fd <= 0 {
		return
	}
	_ = syscall.Close(s.Fd)
	s.Fd = -1
}

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
