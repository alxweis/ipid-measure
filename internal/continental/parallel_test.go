package continental

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func parallelFixture(t *testing.T, p string) (*Runner, *memoryStore, *[]string) {
	r, store, calls := fixture(t)
	r.Protocol = p
	r.Workspace = filepath.Join(r.Repo, "parallel", r.Campaign, r.Site, p)
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r, store, calls
}

func TestParallelProtocolStartsWithoutOtherDiscoveriesOrOS(t *testing.T) {
	for _, p := range []string{"icmp", "tcp"} {
		t.Run(p, func(t *testing.T) {
			r, s, calls := parallelFixture(t, p)
			if err := r.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := 9
			if p == "tcp" {
				want = 11
			}
			if len(*calls) != want {
				t.Fatalf("got %d measurements, want %d: %v", len(*calls), want, *calls)
			}
			for _, call := range *calls {
				if !strings.Contains(call, ":"+map[string]string{"icmp": "icmp", "tcp": "tcp-80"}[p]+":") {
					t.Fatalf("foreign protocol: %s", call)
				}
			}
			flow := r.flowPrefix()
			if _, ok := s.values[Join(flow, "discovery.json")]; !ok {
				t.Fatal("missing discovery")
			}
			discoveryIndex := -1
			streamCount := 0
			for i, u := range s.writes {
				if u == Join(flow, "discovery.json") {
					discoveryIndex = i
				}
				if strings.Contains(u, "/measurement-jobs/") {
					streamCount++
					if discoveryIndex < 0 {
						t.Fatal("stream before discovery")
					}
				}
			}
			if streamCount != want-1 {
				t.Fatalf("stream count=%d", streamCount)
			}
			if err := r.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(*calls) != want {
				t.Fatal("resume repeated probes")
			}
			if _, ok := s.values[Join(r.sitePrefix(), "final", "request.json")]; ok {
				t.Fatal("ICMP/TCP must not publish continent final")
			}
		})
	}
}

func TestParallelUDPWaitsOnlyAfterItsOwnMeasurements(t *testing.T) {
	r, _, calls := parallelFixture(t, "udp-dns")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Run(ctx); err == nil {
		t.Fatal("missing other protocols should wait/fail")
	}
	if len(*calls) != 9 {
		t.Fatalf("UDP did not complete own discovery and eight measurements: %v", *calls)
	}
}

func TestParallelUDPAloneOwnsInterprotocol(t *testing.T) {
	r, s, calls := parallelFixture(t, "udp-dns")
	for _, p := range []string{"icmp", "tcp"} {
		job := map[string]string{"icmp": "icmp_2026-01-01_00-00-00", "tcp": "tcp-80_2026-01-01_00-00-00"}[p]
		flow := Join(r.sitePrefix(), "protocols", p)
		uri := Join(flow, "analysis-jobs", job, "manifest.json")
		s.values[uri] = []byte("{}")
		s.values[Join(flow, "done.json")] = Encode(map[string]any{"version": 1, "campaign_id": r.Campaign, "site": r.Site, "protocol": p, "manifest_uri": uri, "job_id": job})
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 17 {
		t.Fatalf("want one discovery + eight UDP + eight interprotocol: %v", *calls)
	}
	if _, ok := s.values[Join(r.sitePrefix(), "final", "request.json")]; !ok {
		t.Fatal("missing continent final")
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 17 {
		t.Fatal("UDP resume repeated interprotocol")
	}
}

func TestParallelFailuresAndConfigurationCannotBeSilentlyReused(t *testing.T) {
	r, s, _ := parallelFixture(t, "icmp")
	if err := r.PublishProtocolFailure(context.Background(), errors.New("test")); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("terminal controller failure was ignored")
	}
	delete(s.values, Join(r.flowPrefix(), "controller", "failed.json"))
	mustWrite(t, filepath.Join(r.Repo, "config", "ipid.yaml"), []byte("changed: true"))
	if err := r.Prepare(context.Background()); err == nil {
		t.Fatal("changed resume configuration accepted")
	}
}
