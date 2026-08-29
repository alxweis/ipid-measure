package os

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/parquet-go/parquet-go"

	"github.com/alxweis/ipid-measure/internal/records"
)

func TestWriterPersistsExactNullableSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "os.pq")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	ubuntu := "ubuntu"
	server := "Apache/2.4 (Ubuntu)"
	if err := w.Append(records.OSRecord{
		IPAddress: "192.0.2.1", OSStatus: statusResolved, OSTag: &ubuntu,
		HTTPOS: &ubuntu, HTTPServer: &server,
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := parquet.NewGenericReader[records.OSRecord](file)
	defer reader.Close()
	if got, want := reader.Schema().Columns(), [][]string{
		{"IP_ADDR"}, {"OS_STATUS"}, {"OS_TAG"},
		{"SSH_OS_TAG"}, {"SMB_OS_TAG"}, {"HTTP_OS_TAG"}, {"HTTPS_OS_TAG"},
		{"SNMP_OS_TAG"}, {"DNS_OS_TAG"}, {"SSH_SERVER_ID"}, {"SMB_NATIVE_OS"},
		{"HTTP_SERVER"}, {"HTTPS_SERVER"}, {"SNMP_SYS_DESCR"}, {"DNS_VERSION_BIND"},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("columns = %v, want %v", got, want)
	}
	rows := make([]records.OSRecord, 1)
	if n, err := reader.Read(rows); (!errors.Is(err, io.EOF) && err != nil) || n != 1 {
		t.Fatalf("read = %d, %v", n, err)
	}
	if rows[0].SSHOS != nil || rows[0].HTTPOS == nil || *rows[0].HTTPOS != "ubuntu" {
		t.Fatalf("nullable row = %+v", rows[0])
	}
}
