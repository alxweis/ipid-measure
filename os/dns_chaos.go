package os

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsClassCHAOS dnsmessage.Class = 3

// DNSChaosResult is the per-IP outcome of the two DNS CHAOS queries.
type DNSChaosResult struct {
	IP           string
	VersionBind  string
	HostnameBind string
}

// DNSChaosProbe sends version.bind and hostname.bind TXT queries directly to
// each target. Unlike the external ZDNS JSON stream, it always retains the
// input IP and therefore emits exactly one completion result per target,
// including timeouts and malformed responses.
type DNSChaosProbe struct {
	timeout time.Duration
}

func NewDNSChaosProbe(timeout time.Duration) *DNSChaosProbe {
	return &DNSChaosProbe{timeout: timeout}
}

// Run fans targets out to reusable UDP workers. Every consumed target emits
// exactly one result, which keeps merger memory and progress bounded.
func (p *DNSChaosProbe) Run(ctx context.Context, in <-chan string, workers int) <-chan DNSChaosResult {
	out := make(chan DNSChaosResult, 1024)
	var wg sync.WaitGroup
	var socketErrorOnce sync.Once

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenUDP("udp4", nil)
			if err != nil {
				socketErrorOnce.Do(func() {
					log.Printf("os: DNS CHAOS worker socket failed: %v", err)
				})
			}
			if conn != nil {
				defer conn.Close()
			}

			// CHAOS version/hostname TXT answers are tiny; a small reusable
			// buffer keeps 1K workers from reserving tens of megabytes.
			buf := make([]byte, 4096)
			for target := range in {
				select {
				case <-ctx.Done():
					return
				default:
				}
				result := DNSChaosResult{IP: target}
				if conn != nil {
					result.VersionBind = p.query(ctx, conn, target, "version.bind.", buf)
					result.HostnameBind = p.query(ctx, conn, target, "hostname.bind.", buf)
				}
				select {
				case out <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (p *DNSChaosProbe) query(
	ctx context.Context,
	conn *net.UDPConn,
	target, name string,
	buf []byte,
) string {
	if ctx.Err() != nil {
		return ""
	}
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil {
		return ""
	}

	id := nextDNSQueryID()
	packet, err := buildChaosTXTQuery(name, id)
	if err != nil {
		return ""
	}

	deadline := time.Now().Add(p.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return ""
	}

	dst := &net.UDPAddr{IP: ip, Port: 53}
	if _, err := conn.WriteToUDP(packet, dst); err != nil {
		return ""
	}

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return ""
		}
		if src == nil || !src.IP.Equal(ip) {
			continue
		}
		if txt, matched := parseChaosTXTReply(buf[:n], id); matched {
			return CleanBanner(txt)
		}
	}
}

var dnsQueryIDCounter atomic.Uint32

func nextDNSQueryID() uint16 {
	return uint16(dnsQueryIDCounter.Add(1))
}

func buildChaosTXTQuery(name string, id uint16) ([]byte, error) {
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  qname,
			Type:  dnsmessage.TypeTXT,
			Class: dnsClassCHAOS,
		}},
	}
	return msg.Pack()
}

func parseChaosTXTReply(packet []byte, expectedID uint16) (string, bool) {
	var msg dnsmessage.Message
	if err := msg.Unpack(packet); err != nil {
		return "", false
	}
	if !msg.Response || msg.ID != expectedID {
		return "", false
	}
	if msg.RCode != dnsmessage.RCodeSuccess {
		return "", true
	}
	for _, answer := range msg.Answers {
		if answer.Header.Type != dnsmessage.TypeTXT ||
			answer.Header.Class != dnsClassCHAOS {
			continue
		}
		txt, ok := answer.Body.(*dnsmessage.TXTResource)
		if !ok || len(txt.TXT) == 0 {
			continue
		}
		return strings.Join(txt.TXT, ""), true
	}
	// A valid response without a TXT answer still completes the query.
	return "", true
}
