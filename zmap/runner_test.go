package zmap

import (
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"

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

func TestBuildArgsSeedForAllProtocols(t *testing.T) {
	for _, payload := range []types.Payload{types.PayloadICMP, types.PayloadTCP, types.PayloadUDPDNS} {
		for _, test := range []struct{ input, want string }{
			{"{}", ""},
			{"seed: null", ""},
			{"seed: 0", "0"},
			{"seed: 42", "42"},
			{"seed: 18446744073709551615", "18446744073709551615"},
		} {
			t.Run(string(payload)+"/"+test.input, func(t *testing.T) {
				var cfg config.ZMapConfig
				if err := yaml.Unmarshal([]byte(test.input), &cfg); err != nil {
					t.Fatal(err)
				}
				port, probeArgs := uint16(53), "A,www.example.com"
				cfg.Payload, cfg.Port, cfg.ProbeArgs = payload, &port, &probeArgs
				args, err := BuildArgs(&cfg)
				if err != nil {
					t.Fatal(err)
				}
				if got := argumentValue(args, "--seed"); got != test.want {
					t.Fatalf("--seed = %q, want %q (args: %v)", got, test.want, args)
				}
			})
		}
	}
}
