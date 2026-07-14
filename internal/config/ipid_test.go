package config

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/sets"
	"github.com/alxweis/ipid-measure/internal/types"
	"gopkg.in/yaml.v3"
)

func TestTCPConfigYAMLRoundTrip(t *testing.T) {
	want := TCPConfig{
		EstablishConnection: true,
		RequestFlags:        sets.New(types.TCPFlagPSH, types.TCPFlagACK),
		ReplyFlags: []types.TCPFlagSet{
			sets.New(types.TCPFlagSYN, types.TCPFlagACK),
			sets.New(types.TCPFlagRST),
		},
	}

	data, err := yaml.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got TCPConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.EstablishConnection != want.EstablishConnection {
		t.Fatalf("EstablishConnection = %v, want %v", got.EstablishConnection, want.EstablishConnection)
	}
	if !got.RequestFlags.Equal(want.RequestFlags) {
		t.Fatalf("RequestFlags = %v, want %v", got.RequestFlags, want.RequestFlags)
	}
	if len(got.ReplyFlags) != len(want.ReplyFlags) {
		t.Fatalf("len(ReplyFlags) = %d, want %d", len(got.ReplyFlags), len(want.ReplyFlags))
	}
	for i := range want.ReplyFlags {
		if !got.ReplyFlags[i].Equal(want.ReplyFlags[i]) {
			t.Fatalf("ReplyFlags[%d] = %v, want %v", i, got.ReplyFlags[i], want.ReplyFlags[i])
		}
	}
}
