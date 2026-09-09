package zmapsample

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/records"
)

func TestFixedBaseSampleSize(t *testing.T) {
	tests := []struct {
		total int64
		want  int64
	}{
		{500_000, 500_000},
		{1_000_000, 1_000_000},
		{5_000_000, 1_000_000},
		{10_000_001, 1_000_001},
	}
	for _, test := range tests {
		if got := FixedBaseSampleSize(test.total, 1_000_000, 10); got != test.want {
			t.Fatalf("total=%d: got %d, want %d", test.total, got, test.want)
		}
	}
}

func TestWriteUniformSampleIsExactAndReproducible(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "zmap.pq")
	writeZMapRows(t, input, 100)

	first := filepath.Join(root, "first.pq")
	second := filepath.Join(root, "second.pq")
	stats, err := WriteUniformSample(input, first, 20, 10, 42, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.SourceRows != 100 || stats.SampleRows != 20 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if _, err := WriteUniformSample(input, second, 20, 10, 42, ""); err != nil {
		t.Fatal(err)
	}

	firstRows := readZMapRows(t, first)
	secondRows := readZMapRows(t, second)
	if len(firstRows) != 20 {
		t.Fatalf("got %d sampled rows, want 20", len(firstRows))
	}
	if !reflect.DeepEqual(firstRows, secondRows) {
		t.Fatal("same seed did not reproduce the same sample")
	}
}

func TestSYNACKSampleFiltersBeforeSizing(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "zmap.pq")
	rows := make([]records.ZMap, 100)
	for i := range rows {
		rows[i] = records.ZMap{IPAddress: fmt.Sprintf("192.0.2.%d", i+1), ReplyType: "rst"}
		if i < 20 {
			rows[i].ReplyType = "synack"
		}
	}
	rows[99].ReplyType = ""
	if err := parquet.WriteFile(input, rows); err != nil {
		t.Fatal(err)
	}
	first, second := filepath.Join(root, "first.pq"), filepath.Join(root, "second.pq")
	stats, err := WriteUniformSample(input, first, 1, 50, 42, "synack")
	if err != nil {
		t.Fatal(err)
	}
	if stats.SourceRows != 100 || stats.EligibleRows != 20 || stats.SampleRows != 10 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if _, err := WriteUniformSample(input, second, 1, 50, 42, "synack"); err != nil {
		t.Fatal(err)
	}
	selected := readZMapRows(t, first)
	if len(selected) != 10 || !reflect.DeepEqual(selected, readZMapRows(t, second)) {
		t.Fatal("incorrect or non-reproducible sample")
	}
	for _, row := range selected {
		if row.ReplyType != "synack" {
			t.Fatalf("ineligible target: %+v", row)
		}
	}
	if err := parquet.WriteFile(input, rows[20:]); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(root, "empty.pq")
	if _, err := WriteUniformSample(input, empty, 1000000, 10, 42, "synack"); err == nil {
		t.Fatal("expected error without SYN-ACK targets")
	}
	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Fatal("empty target sample was published")
	}
}

func writeZMapRows(t *testing.T, path string, count int) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := parquet.NewGenericWriter[records.ZMap](file)
	rows := make([]records.ZMap, count)
	for i := range rows {
		rows[i] = records.ZMap{
			IPAddress: fmt.Sprintf("192.0.2.%d", i+1),
			ReplyType: "synack",
		}
	}
	if _, err := writer.Write(rows); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func readZMapRows(t *testing.T, path string) []records.ZMap {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := parquet.NewGenericReader[records.ZMap](file)
	defer reader.Close()
	rows := make([]records.ZMap, reader.NumRows())
	n, err := reader.Read(rows)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	return rows[:n]
}
