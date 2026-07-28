package os

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBuildChaosTXTQuery(t *testing.T) {
	packet, err := buildChaosTXTQuery("version.bind.", 42)
	if err != nil {
		t.Fatal(err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(packet); err != nil {
		t.Fatal(err)
	}
	if msg.ID != 42 || len(msg.Questions) != 1 {
		t.Fatalf("unexpected query: %+v", msg)
	}
	q := msg.Questions[0]
	if q.Name.String() != "version.bind." ||
		q.Type != dnsmessage.TypeTXT ||
		q.Class != dnsClassCHAOS {
		t.Fatalf("unexpected question: %+v", q)
	}
}

func TestParseChaosTXTReply(t *testing.T) {
	name, err := dnsmessage.NewName("version.bind.")
	if err != nil {
		t.Fatal(err)
	}
	reply := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       77,
			Response: true,
		},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  name,
				Type:  dnsmessage.TypeTXT,
				Class: dnsClassCHAOS,
			},
			Body: &dnsmessage.TXTResource{TXT: []string{"BIND ", "9.18"}},
		}},
	}
	packet, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}

	got, matched := parseChaosTXTReply(packet, 77)
	if !matched || got != "BIND 9.18" {
		t.Fatalf("parseChaosTXTReply() = %q, %v", got, matched)
	}
	if _, matched := parseChaosTXTReply(packet, 78); matched {
		t.Fatal("reply with wrong transaction ID matched")
	}
}

func TestDNSChaosProbeEmitsOnceForEveryInvalidTarget(t *testing.T) {
	in := make(chan string, 3)
	for _, target := range []string{"invalid-1", "invalid-2", "invalid-3"} {
		in <- target
	}
	close(in)

	probe := NewDNSChaosProbe(time.Millisecond)
	out := probe.Run(context.Background(), in, 2)
	seen := make(map[string]int)
	for result := range out {
		seen[result.IP]++
	}
	if len(seen) != 3 {
		t.Fatalf("emitted targets = %v", seen)
	}
	for ip, count := range seen {
		if count != 1 {
			t.Fatalf("%s emitted %d times", ip, count)
		}
	}
}
