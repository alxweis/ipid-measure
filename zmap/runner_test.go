package zmap

import (
	"strconv"
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
			want:    TCPResponseFilter,
		},
		{
			name:    "UDP DNS keeps matching DNS responses independent of flags",
			payload: types.PayloadUDPDNS,
			want:    SuccessfulResponseFilter,
		},
		{
			name:    "ICMP keeps echo replies",
			payload: types.PayloadICMP,
			want:    SuccessfulResponseFilter,
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
	targets := config.ScaledNumber(100)
	port := uint16(80)
	config := &config.ZMapConfig{
		Payload:                   types.PayloadTCP,
		Port:                      &port,
		Interface:                 config.Interface{Name: "eth0", IP: "192.0.2.1"},
		NumberOfTargetIPAddresses: &targets,
	}

	args, err := BuildArgs(config)
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	if got := argumentValue(args, "--output-filter"); got != TCPResponseFilter {
		t.Fatalf("output filter = %q, want %q", got, TCPResponseFilter)
	}
	if got := argumentValue(args, "--dedup-method"); got != NoDedupMethod {
		t.Fatalf("dedup method = %q, want %q", got, NoDedupMethod)
	}
	if got := argumentValue(args, "-N"); got != "" {
		t.Fatalf("TCP args contain ZMap max-results %q; unique limit must be application-owned", got)
	}
}

func TestBuildArgsKeepsZMapFullDedupAndTargetLimitForSuccessfulResponses(t *testing.T) {
	targets := config.ScaledNumber(100)
	config := &config.ZMapConfig{
		Payload:                   types.PayloadICMP,
		Interface:                 config.Interface{Name: "eth0", IP: "192.0.2.1"},
		NumberOfTargetIPAddresses: &targets,
	}

	args, err := BuildArgs(config)
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	if got := argumentValue(args, "--dedup-method"); got != FullDedupMethod {
		t.Fatalf("dedup method = %q, want %q", got, FullDedupMethod)
	}
	if got := argumentValue(args, "-N"); got != strconv.FormatUint(uint64(targets), 10) {
		t.Fatalf("max-results = %q, want %d", got, targets)
	}
}

func argumentValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}
