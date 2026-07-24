package zmap

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alxweis/ipid-measure/internal/records"
)

type collectingAppender struct {
	rows []records.ZMap
}

func (a *collectingAppender) Append(row records.ZMap) error {
	a.rows = append(a.rows, row)
	return nil
}

func TestStreamRowsDeduplicatesTCPByIPAddressAndStopsAtUniqueLimit(t *testing.T) {
	input := strings.Join(
		[]string{
			"saddr,classification",
			"0.0.0.1,rst",
			"0.0.0.1,rst",
			"0.0.0.2,rst",
			"0.0.0.2,synack",
			"0.0.0.3,synack",
			"0.0.0.4,rst",
			"",
		},
		"\n",
	)
	parser := NewParser(strings.NewReader(input), false)
	writer := &collectingAppender{}
	deduplicator := newIPv4Deduplicator(256)
	var written atomic.Uint64
	stopCalls := 0

	err := streamRows(
		context.Background(),
		parser,
		writer,
		&written,
		deduplicator,
		3,
		func() { stopCalls++ },
	)
	if err != nil {
		t.Fatalf("streamRows() error = %v", err)
	}

	want := []records.ZMap{
		{IPAddress: "0.0.0.1", ReplyType: "rst"},
		{IPAddress: "0.0.0.2", ReplyType: "rst"},
		{IPAddress: "0.0.0.3", ReplyType: "synack"},
	}
	if len(writer.rows) != len(want) {
		t.Fatalf("wrote %d rows, want %d: %#v", len(writer.rows), len(want), writer.rows)
	}
	for i := range want {
		if writer.rows[i] != want[i] {
			t.Fatalf("row %d = %#v, want %#v", i, writer.rows[i], want[i])
		}
	}
	if got := written.Load(); got != uint64(len(want)) {
		t.Fatalf("written = %d, want %d", got, len(want))
	}
	if stopCalls != 1 {
		t.Fatalf("stop called %d times, want 1", stopCalls)
	}
}

func TestIPv4DeduplicatorRejectsInvalidAddresses(t *testing.T) {
	deduplicator := newIPv4Deduplicator(256)
	for _, address := range []string{"not-an-ip", "::1", "0.0.1.0"} {
		if _, err := deduplicator.Add(address); err == nil {
			t.Fatalf("Add(%q) succeeded, want error", address)
		}
	}
}
