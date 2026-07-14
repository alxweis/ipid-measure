package config

import (
	"os"
	"path/filepath"
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

func TestZMapReferenceUsesExplicitTargetFile(t *testing.T) {
	target := filepath.Join(t.TempDir(), "zmap_unclassified.pq")
	if err := os.WriteFile(target, []byte("parquet"), 0644); err != nil {
		t.Fatal(err)
	}

	reference := ZMapReference{
		ZMapID:     "tcp-80_2026-01-01_00-00-00",
		TargetFile: target,
	}
	if err := reference.ValidateAndParseZMap(); err != nil {
		t.Fatalf("ValidateAndParseZMap() error = %v", err)
	}
	if reference.ZMapFilePath != target {
		t.Fatalf("ZMapFilePath = %q, want %q", reference.ZMapFilePath, target)
	}
	if reference.ZMapPayload != types.PayloadTCP {
		t.Fatalf("ZMapPayload = %q, want %q", reference.ZMapPayload, types.PayloadTCP)
	}
}
