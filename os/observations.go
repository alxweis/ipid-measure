package os

import (
	"context"
	"fmt"
	osstd "os"
	"sort"
	"strings"
	"sync"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/compress/snappy"
)

// Optional sidecar preserves the response-only targets omitted by os.pq. Bits
// use this fixed service order: SSH, SMB, HTTP, HTTPS, SNMP, DNS.
type observation struct {
	IP       string `parquet:"IP_ADDR,plain"`
	Response int32  `parquet:"RESPONSE_MASK"`
	Evidence int32  `parquet:"EVIDENCE_MASK"`
	Tagged   int32  `parquet:"TAG_MASK"`
	Status   string `parquet:"OS_STATUS,dict"`
	Conflict string `parquet:"CONFLICT,dict"`
}

type observationWriter struct {
	mu     sync.Mutex
	file   *osstd.File
	writer *parquet.GenericWriter[observation]
	buffer []observation
	count  uint64
	err    error
	cancel context.CancelFunc
}

func newObservationWriter(path string, cancel context.CancelFunc) (*observationWriter, error) {
	f, err := osstd.Create(path)
	if err != nil {
		return nil, err
	}
	return &observationWriter{file: f, writer: parquet.NewGenericWriter[observation](f, parquet.Compression(&snappy.Codec{}), parquet.MaxRowsPerRowGroup(200000)), cancel: cancel}, nil
}

func mask(values ...bool) int32 {
	var result int32
	for i, value := range values {
		if value {
			result |= 1 << i
		}
	}
	return result
}

func (w *observationWriter) observe(e evidenceRecord, t serviceTags, d decision) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return
	}
	conflicts := append([]string(nil), d.conflicts...)
	sort.Strings(conflicts)
	w.buffer = append(w.buffer, observation{e.IPAddress,
		mask(e.SSHResponded, e.SMBResponded, e.HTTPResponded, e.HTTPSResponded, e.SNMPResponded, e.DNSResponded),
		mask(e.SSHServerID != "", e.SMBNativeOS != "", e.HTTPServer != "", e.HTTPSServer != "", e.SNMPSysDescr != "", e.DNSVersionBind != ""),
		mask(t.SSH != "", t.SMB != "", t.HTTP != "", t.HTTPS != "", t.SNMP != "", t.DNS != ""), d.status, strings.Join(conflicts, "|")})
	w.count++
	if len(w.buffer) >= 10000 {
		w.flush()
	}
}

func (w *observationWriter) flush() {
	if w.err != nil {
		return
	}
	_, w.err = w.writer.Write(w.buffer)
	w.buffer = w.buffer[:0]
	if w.err != nil {
		w.cancel()
	}
}

func (w *observationWriter) close(expected uint64) error {
	w.flush()
	closeErr := w.writer.Close()
	fileErr := w.file.Close()
	if w.err != nil {
		return fmt.Errorf("write OS observations: %w", w.err)
	}
	if closeErr != nil {
		w.cancel()
		return closeErr
	}
	if fileErr != nil {
		w.cancel()
		return fileErr
	}
	if w.count != expected {
		return fmt.Errorf("OS observations: completed %d of %d targets", w.count, expected)
	}
	return nil
}
