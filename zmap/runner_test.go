package zmap

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/types"
)

func TestOutputFilterUsesProtocolResponseSemantics(t *testing.T) {
	tests := []struct {
		name    string
		payload types.Payload
		want    string
	}{
		{
			name:    "TCP keeps SYN-ACK and RST",
			payload: types.PayloadTCP,
			want:    `(classification = synack || classification = rst) && repeat = 0`,
		},
		{
			name:    "UDP DNS keeps matching DNS responses independent of flags",
			payload: types.PayloadUDPDNS,
			want:    "success = 1 && repeat = 0",
		},
		{
			name:    "ICMP keeps echo replies",
			payload: types.PayloadICMP,
			want:    "success = 1 && repeat = 0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := outputFilter(&config.ZMapConfig{Payload: test.payload})
			if got != test.want {
				t.Fatalf("outputFilter() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBuildArgsIncludesPayloadSpecificOutputFilter(t *testing.T) {
	port := uint16(80)
	config := &config.ZMapConfig{
		Payload:   types.PayloadTCP,
		Port:      &port,
		Interface: config.Interface{Name: "eth0", IP: "192.0.2.1"},
	}

	args, err := BuildArgs(config)
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--output-filter" {
			want := `(classification = synack || classification = rst) && repeat = 0`
			if args[i+1] != want {
				t.Fatalf("output filter = %q, want %q", args[i+1], want)
			}
			return
		}
	}
	t.Fatal("BuildArgs() omitted --output-filter")
}
