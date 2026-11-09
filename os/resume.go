package os

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	osstd "os"
	"path/filepath"

	"github.com/parquet-go/parquet-go"
	"gopkg.in/yaml.v3"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/upload"
)

// Lazy 64K-address pages: at most 512 MiB for all IPv4, usually far less for
// a geographically sorted partial scan. Membership never uses string hashes.
type ipv4Set struct {
	pages map[uint16]*[1024]uint64
	count uint64
}

func addressNumber(value string) (uint32, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || !a.Is4() {
		return 0, fmt.Errorf("invalid IPv4 address %q", value)
	}
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}
func (s *ipv4Set) has(n uint32) bool {
	p := s.pages[uint16(n>>16)]
	return p != nil && p[(n&65535)>>6]&(uint64(1)<<(n&63)) != 0
}
func (s *ipv4Set) add(n uint32) bool {
	if s.pages == nil {
		s.pages = make(map[uint16]*[1024]uint64)
	}
	k := uint16(n >> 16)
	p := s.pages[k]
	if p == nil {
		p = new([1024]uint64)
		s.pages[k] = p
	}
	i, bit := (n&65535)>>6, uint64(1)<<(n&63)
	if p[i]&bit != 0 {
		return false
	}
	p[i] |= bit
	s.count++
	return true
}
func (s *ipv4Set) remove(n uint32) bool {
	if !s.has(n) {
		return false
	}
	s.pages[uint16(n>>16)][(n&65535)>>6] &^= uint64(1) << (n & 63)
	s.count--
	return true
}

type resumeState struct {
	completed ipv4Set
	evidence  uint64
}
type ResumeEvidence struct {
	Version        int                            `json:"version"`
	Status         string                         `json:"status"`
	Source         string                         `json:"source"`
	Target         upload.FileEvidence            `json:"target"`
	Files          map[string]upload.FileEvidence `json:"files"`
	Completed      uint64                         `json:"completed"`
	Evidence       uint64                         `json:"evidence"`
	SourceSnapshot string                         `json:"source_snapshot_yaml"`
}

func readParquetRows[T any](ctx context.Context, path string, use func(T) error) error {
	f, err := osstd.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	// OpenFile returns an error for unclosed files, rather than the generic
	// reader's constructor panic. Never salvage a truncated live Parquet file.
	if _, err = parquet.OpenFile(f, st.Size()); err != nil {
		return fmt.Errorf("closed Parquet required: %s: %w", path, err)
	}
	r := parquet.NewGenericReader[T](f)
	defer r.Close()
	batch := make([]T, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := r.Read(batch)
		for _, row := range batch[:n] {
			if e := use(row); e != nil {
				return e
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ValidateResumeSource rejects incompatible settings before a worker changes
// its scan state. Concurrency and Go heap budgets may change; sampling,
// modules, timeouts, classifier and the exact pinned target file may not.
func ValidateResumeSource(c *config.OSConfig, source string) error {
	data, err := osstd.ReadFile(filepath.Join(source, "os.snapshot.yaml"))
	if err != nil {
		return err
	}
	var old config.OSConfig
	if err = yaml.Unmarshal(data, &old); err != nil {
		return err
	}
	if !c.RecordTargetStatus || !old.RecordTargetStatus || old.SchemaVersion != SchemaVersion || old.ClassifierVersion != ClassifierVersion ||
		old.ZMapID != c.ZMapID || old.TargetFile == "" || filepath.Clean(old.TargetFile) != filepath.Clean(c.TargetFile) ||
		old.Modules != c.Modules || old.ConnectTimeout != c.ConnectTimeout || old.ReadTimeout != c.ReadTimeout ||
		old.DNSChaosTimeout != c.DNSChaosTimeout || old.SNMPTimeout != c.SNMPTimeout || old.SNMPCommunity != c.SNMPCommunity {
		return fmt.Errorf("OS resume changes input, modules, timeouts or schema/classifier")
	}
	if old.ResumeFrom != "" {
		// A second resume may use the newer cumulative partial output only if
		// importing its predecessor finished before scanning began.
		data, err := osstd.ReadFile(filepath.Join(source, "os-resume.json"))
		if err != nil {
			return fmt.Errorf("previous resume import not committed: %w", err)
		}
		var evidence ResumeEvidence
		if json.Unmarshal(data, &evidence) != nil || evidence.Status != "imported" || evidence.Version != 1 {
			return fmt.Errorf("previous resume import not committed")
		}
		actual, err := upload.Evidence(c.TargetFile)
		if err != nil {
			return err
		}
		if actual != evidence.Target {
			return fmt.Errorf("resumed input digest changed")
		}
	}
	for _, name := range []string{"os.pq", "os-observations.pq"} {
		f, err := osstd.Open(filepath.Join(source, name))
		if err != nil {
			return err
		}
		st, e := f.Stat()
		if e == nil {
			_, e = parquet.OpenFile(f, st.Size())
		}
		f.Close()
		if e != nil {
			return fmt.Errorf("resume requires closed %s: %w", name, e)
		}
	}
	return nil
}

func restoreOS(ctx context.Context, c *config.OSConfig, output string, w *Writer, obs *observationWriter, coverage *coverageStats, total uint64) (*resumeState, error) {
	if c.ResumeFrom == "" {
		return nil, nil
	}
	source, err := filepath.Abs(c.ResumeFrom)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(source) == filepath.Clean(filepath.Dir(output)) {
		return nil, fmt.Errorf("resume source must not be output directory")
	}
	if err = ValidateResumeSource(c, source); err != nil {
		return nil, err
	}
	if obs == nil {
		return nil, fmt.Errorf("resume requires target observations")
	}
	manifest := ResumeEvidence{Version: 1, Status: "imported", Source: source, Files: map[string]upload.FileEvidence{}}
	snapshot, err := osstd.ReadFile(filepath.Join(source, "os.snapshot.yaml"))
	if err != nil {
		return nil, err
	}
	manifest.SourceSnapshot = string(snapshot)
	manifest.Target, err = upload.Evidence(c.TargetFile)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"os.pq", "os-observations.pq", "os.snapshot.yaml"} {
		manifest.Files[name], err = upload.Evidence(filepath.Join(source, name))
		if err != nil {
			return nil, err
		}
	}
	s := &resumeState{}
	var evidenceIPs ipv4Set
	var observationDigest, recordDigest [32]byte
	err = readParquetRows[observation](ctx, filepath.Join(source, "os-observations.pq"), func(o observation) error {
		n, err := addressNumber(o.IP)
		if err != nil {
			return err
		}
		if !s.completed.add(n) {
			return fmt.Errorf("duplicate resumed target %s", o.IP)
		}
		if s.completed.count > total || o.Response < 0 || o.Response > 63 || o.Evidence < 0 || o.Evidence > 63 || o.Tagged < 0 || o.Tagged > 63 || o.Tagged & ^o.Evidence != 0 {
			return fmt.Errorf("invalid resumed observation %s", o.IP)
		}
		if o.Evidence == 0 {
			if o.Status != "no-evidence" {
				return fmt.Errorf("invalid no-evidence status %s", o.IP)
			}
		} else {
			if o.Status != statusResolved && o.Status != statusAmbiguous && o.Status != statusUnclassified {
				return fmt.Errorf("invalid evidence status %s", o.IP)
			}
			evidenceIPs.add(n)
			s.evidence++
			xorResumeDigest(&observationDigest, o.IP, o.Evidence, o.Tagged, o.Status)
		}
		coverage.restore(o)
		obs.append(o)
		return obs.err
	})
	if err != nil {
		return nil, err
	}
	err = readParquetRows[records.OSRecord](ctx, filepath.Join(source, "os.pq"), func(row records.OSRecord) error {
		n, err := addressNumber(row.IPAddress)
		if err != nil {
			return err
		}
		if !evidenceIPs.remove(n) {
			return fmt.Errorf("duplicate or unmatched resumed evidence %s", row.IPAddress)
		}
		if row.OSStatus != statusResolved && row.OSStatus != statusAmbiguous && row.OSStatus != statusUnclassified {
			return fmt.Errorf("invalid resumed evidence status %s", row.IPAddress)
		}
		evidence := mask(nonempty(row.SSHServerID), nonempty(row.SMBNativeOS), nonempty(row.HTTPServer), nonempty(row.HTTPSServer), nonempty(row.SNMPSysDescr), nonempty(row.DNSVersionBind))
		tags := mask(nonempty(row.SSHOS), nonempty(row.SMBOS), nonempty(row.HTTPOS), nonempty(row.HTTPSOS), nonempty(row.SNMPOS), nonempty(row.DNSOS))
		xorResumeDigest(&recordDigest, row.IPAddress, evidence, tags, row.OSStatus)
		return w.Append(row)
	})
	if err != nil {
		return nil, err
	}
	if evidenceIPs.count != 0 {
		return nil, fmt.Errorf("resumed observations missing %d evidence records", evidenceIPs.count)
	}
	if observationDigest != recordDigest {
		return nil, fmt.Errorf("resumed evidence masks/status differ from observations")
	}
	var matched uint64
	err = readParquetRows[records.ZMap](ctx, c.TargetFile, func(row records.ZMap) error {
		n, err := addressNumber(row.IPAddress)
		if err != nil {
			return err
		}
		if s.completed.has(n) {
			matched++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if matched != s.completed.count {
		return nil, fmt.Errorf("resumed targets are not an exact subset of input")
	}
	// Verify the retained source did not change while it was copied.
	for name, expected := range manifest.Files {
		actual, err := upload.Evidence(filepath.Join(source, name))
		if err != nil {
			return nil, err
		}
		if actual != expected {
			return nil, fmt.Errorf("resume source changed: %s", name)
		}
	}
	manifest.Completed, manifest.Evidence = s.completed.count, s.evidence
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err = osstd.WriteFile(filepath.Join(filepath.Dir(output), "os-resume.json"), append(data, '\n'), 0644); err != nil {
		return nil, err
	}
	return s, nil
}

func nonempty(value *string) bool { return value != nil && *value != "" }

// The two sinks can have different row order. IP membership is checked exactly
// with the bitmap; this order-independent digest also binds stored per-IP
// evidence/tag masks and classification status across the two retained sinks.
func xorResumeDigest(total *[32]byte, ip string, evidence, tags int32, status string) {
	part := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%d\x00%s", ip, evidence, tags, status)))
	for i := range total {
		total[i] ^= part[i]
	}
}

// Rebuild coverage from the retained response/evidence/tag masks. Do not
// reclassify old banners or treat no-evidence targets as unmeasured.
func (c *coverageStats) restore(o observation) {
	t := &c.document.Detail.Targets
	if o.Response != 0 {
		t.WithResponse++
	} else {
		t.WithoutResponse++
	}
	if o.Evidence != 0 {
		t.WithEvidence++
	} else {
		t.WithoutEvidence++
	}
	if o.Tagged != 0 {
		t.WithTag++
	} else {
		t.WithoutTag++
	}
	for i, name := range []string{"ssh", "smb", "http", "https", "snmp", "dns"} {
		bit := int32(1 << i)
		updateService(c.document.Detail.Services, name, o.Response&bit != 0, o.Evidence&bit != 0, o.Tagged&bit != 0)
	}
	switch o.Status {
	case statusResolved:
		c.document.Detail.Classification.Resolved++
	case statusAmbiguous:
		c.document.Detail.Classification.Ambiguous++
		c.document.Detail.Conflicts[o.Conflict]++
	case statusUnclassified:
		c.document.Detail.Classification.Unclassified++
	}
}
