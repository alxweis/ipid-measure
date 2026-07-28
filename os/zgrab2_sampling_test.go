package os

import (
	"strconv"
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/records"
)

func TestParseZGrab2LineClassifiesSecondaryResult(t *testing.T) {
	secondary, ok := parseZGrab2Line(
		`{"ip":"192.0.2.1","data":{"smtp":{"status":"connection-timeout"}}}`,
	)
	if !ok || !secondary.TriggeredSecondary {
		t.Fatalf("secondary result = %+v, %v", secondary, ok)
	}

	core, ok := parseZGrab2Line(
		`{"ip":"192.0.2.1","data":{"ssh":{"status":"connection-timeout"}}}`,
	)
	if !ok || core.TriggeredSecondary {
		t.Fatalf("core result = %+v, %v", core, ok)
	}
}

func TestMergerWaitsForAndCombinesCoreAndSecondaryZGrab2(t *testing.T) {
	const rate = 0.5
	var sampledIP string
	for i := 1; i < 256; i++ {
		candidate := "192.0.2." + strconv.Itoa(i)
		if selectSecondary(candidate, rate) {
			sampledIP = candidate
			break
		}
	}
	if sampledIP == "" {
		t.Fatal("could not find deterministic sampled IP")
	}

	out := make(chan records.OSRecord, 1)
	c := &config.OSConfig{
		Modules: config.OSModules{
			SSH:  true,
			SMTP: true,
		},
		SecondarySampleRate: rate,
	}
	m := newMerger(c, out)
	m.integrate(sampledIP, scannerZGrab2Default, applyZGrab2(ZGrab2Result{
		IP:          sampledIP,
		SSHServerID: "OpenSSH_9.6 Ubuntu",
	}))
	select {
	case got := <-out:
		t.Fatalf("record emitted before secondary result: %+v", got)
	default:
	}

	m.integrate(sampledIP, scannerZGrab2Secondary, applyZGrab2(ZGrab2Result{
		IP:         sampledIP,
		SMTPBanner: "Postfix",
	}))
	got := <-out
	if got.SSHServerID != "OpenSSH_9.6 Ubuntu" || got.SMTPBanner != "Postfix" {
		t.Fatalf("combined record = %+v", got)
	}
}
