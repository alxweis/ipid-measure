// Package rtresume admits the four retained November 2026 ICMP RT prefixes.
// Admission is read-only and sends no probes. A backup receipt is not itself
// measurement completion or a resumable checkpoint.
package rtresume

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/records"
	"github.com/alxweis/ipid-measure/internal/types"
	"github.com/alxweis/ipid-measure/internal/upload"
	"github.com/parquet-go/parquet-go"
	"gopkg.in/yaml.v3"
)

const Campaign = "geo-full-20261107-r1"
const recoveryRoot = "s3://netds3o:aweis/ipid-2/raw/recovery/" + Campaign

type original struct {
	ID, ZMap, SHA256 string
	Rows, Started    int64
}

var originals = map[string]original{
	"sa": {"icmp_2026-11-08_03-04-51", "icmp_2026-11-07_03-50-17", "2b38049e65adfa9d24e77969760d1c0008e86bc9e1052ebf7f08527c8e57fcb7", 226076245, 256450684},
	"af": {"icmp_2026-11-08_03-27-48", "icmp_2026-11-07_04-10-15", "6bfa396641ca2b64ddf16d76c05e45eaa6173660d0a7ae6233833cdf2724e3fd", 184485006, 210584916},
	"as": {"icmp_2026-11-08_03-15-32", "icmp_2026-11-07_04-00-21", "93031197b2bcbe903a0c8e371a11d3fd4ae72c80664b004f35be87fa5288e110", 255977459, 290556575},
	"au": {"icmp_2026-11-08_03-37-59", "icmp_2026-11-07_04-20-21", "02e63b09de9530c8aea5a7d45c2b0222448df5b66c6088a4fb1eb4af496d7aae", 221077388, 248279897},
}

type File struct {
	upload.FileEvidence
	URI       string `json:"uri"`
	LocalPath string `json:"local_path"`
}
type Receipt struct {
	Version  int             `json:"version"`
	Purpose  string          `json:"purpose"`
	Campaign string          `json:"campaign_id"`
	Site     string          `json:"site"`
	ID       string          `json:"measurement_id"`
	ZMap     string          `json:"zmap_id"`
	Binding  string          `json:"state_binding"`
	Files    map[string]File `json:"files"`
}
type Fetch func(context.Context, string) ([]byte, error)

func FetchS3(ctx context.Context, uri string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "s3cmd", "get", "--no-progress", uri, "-")
	var stderr bytes.Buffer
	c.Stderr = &stderr
	data, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("read recovery metadata %s: %w: %.2000s", uri, err, stderr.String())
	}
	return data, nil
}

type Plan struct {
	Version        int                 `json:"version"`
	Source         string              `json:"source"`
	Target         string              `json:"target"`
	ReceiptURI     string              `json:"receipt_uri"`
	ReceiptSHA256  string              `json:"receipt_sha256"`
	SourceEvidence upload.FileEvidence `json:"source_evidence"`
	TargetEvidence upload.FileEvidence `json:"target_evidence"`
	Saved          int64               `json:"saved_rows"`
	Started        int64               `json:"started_targets"`
	Total          int64               `json:"total_targets"`
	Failures       map[string]int64    `json:"terminal_failures"`
	Interpretation string              `json:"interpretation"`
	SourceInfo     os.FileInfo         `json:"-"`
	TargetInfo     os.FileInfo         `json:"-"`
}

func hash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func regular(path string) (os.FileInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	if resolved != abs {
		return nil, fmt.Errorf("linked recovery source: %s", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular recovery file: %s", path)
	}
	return st, nil
}

// ReadReceipt verifies the small receipt against its independently fetched S3
// copy before a controller changes its step ID. Bulk verification comes later.
func ReadReceipt(ctx context.Context, path, workspace, site, id, binding string, fetch Fetch) (Receipt, string, string, error) {
	var r Receipt
	if st, err := regular(path); err != nil {
		return r, "", "", err
	} else if st.Size() > 1<<20 {
		return r, "", "", fmt.Errorf("oversized recovery receipt")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return r, "", "", err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, "", "", err
	}
	want, ok := originals[site]
	if !ok || id != want.ID || r.Version != 1 || r.Purpose != "interrupted-rt-preservation-not-measurement-completion" ||
		r.Campaign != Campaign || r.Site != site || r.ID != id || r.ZMap != want.ZMap || r.Binding != binding || binding == "" {
		return r, "", "", fmt.Errorf("unexpected original recovery receipt/binding")
	}
	root := recoveryRoot + "/" + site + "/icmp/" + id
	if len(r.Files) != 6 {
		return r, "", "", fmt.Errorf("recovery receipt must bind all six preserved files")
	}
	for _, name := range []string{"ipid.pq", "ipid.snapshot.yaml", "state.json", "zmap.pq", "zmap.snapshot.yaml", "original-scanner.journal.jsonl"} {
		f, ok := r.Files[name]
		if !ok || f.Size <= 0 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(f.SHA256) || f.URI != root+"/sha256-"+f.SHA256+"/"+name {
			return r, "", "", fmt.Errorf("invalid recovery file binding: %s", name)
		}
	}
	if r.Files["ipid.pq"].SHA256 != want.SHA256 {
		return r, "", "", fmt.Errorf("not the known retained RT source")
	}
	for name, expected := range map[string]string{
		"ipid.pq":            filepath.Join(workspace, "ipid", "raw", id, "ipid.pq"),
		"ipid.snapshot.yaml": filepath.Join(workspace, "ipid", "raw", id, "ipid.snapshot.yaml"),
		"state.json":         filepath.Join(workspace, "state.json"),
		"zmap.pq":            filepath.Join(workspace, "zmap", "raw", want.ZMap, "zmap.pq"),
		"zmap.snapshot.yaml": filepath.Join(workspace, "zmap", "raw", want.ZMap, "zmap.snapshot.yaml"),
	} {
		if r.Files[name].LocalPath != expected {
			return r, "", "", fmt.Errorf("unexpected local recovery path: %s", name)
		}
	}
	journal := r.Files["original-scanner.journal.jsonl"].LocalPath
	if filepath.Dir(journal) != filepath.Join(workspace, "recovery-backup", id) {
		return r, "", "", fmt.Errorf("unexpected journal source")
	}
	digest := hash(data)
	uri := root + "/receipts/sha256-" + digest + "/backup-verified.json"
	remote, err := fetch(ctx, uri)
	if err != nil {
		return r, "", "", err
	}
	if !bytes.Equal(data, remote) {
		return r, "", "", fmt.Errorf("recovery receipt differs from published S3 copy")
	}
	return r, uri, digest, nil
}

var finalCounters = regexp.MustCompile(`probes_final\[([^]]*)\]`)
var writtenRows = regexp.MustCompile(`wrote ([0-9]+) records before error`)
var allowedFailures = map[string]bool{"proto": true, "limiter_stop": true, "send_err": true, "timeout": true, "interrupt": true, "not_recv": true, "bad_dst": true, "bad_port": true, "seq_oor": true, "unsent": true, "dup": true, "late": true}

func Counters(data []byte) (int64, int64, map[string]int64, error) {
	var rows int64 = -1
	var failures map[string]int64
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry struct {
			Message string `json:"MESSAGE"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			return 0, 0, nil, err
		}
		if m := writtenRows.FindStringSubmatch(entry.Message); m != nil {
			if rows != -1 {
				return 0, 0, nil, fmt.Errorf("ambiguous saved-row logs")
			}
			var err error
			rows, err = strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				return 0, 0, nil, err
			}
		}
		if m := finalCounters.FindStringSubmatch(entry.Message); m != nil {
			if failures != nil {
				return 0, 0, nil, fmt.Errorf("ambiguous final probe counters")
			}
			failures = map[string]int64{}
			if m[1] == "none" {
				continue
			}
			for _, field := range strings.Fields(m[1]) {
				pair := strings.Split(field, "=")
				if len(pair) != 2 || !allowedFailures[pair[0]] {
					return 0, 0, nil, fmt.Errorf("unsupported strict ICMP terminal counter: %s", field)
				}
				if _, exists := failures[pair[0]]; exists {
					return 0, 0, nil, fmt.Errorf("duplicate terminal counter")
				}
				n, err := strconv.ParseInt(pair[1], 10, 64)
				if err != nil || n < 0 || n > 1<<32 {
					return 0, 0, nil, fmt.Errorf("invalid counter: %s", field)
				}
				failures[pair[0]] = n
			}
		}
	}
	if rows <= 0 || failures == nil {
		return 0, 0, nil, fmt.Errorf("missing original final counters or saved-row log")
	}
	started := rows
	for _, n := range failures {
		started += n
	}
	if started > 1<<32 {
		return 0, 0, nil, fmt.Errorf("started population exceeds IPv4")
	}
	return rows, started, failures, nil
}

func verifyFile(f File) error {
	if _, err := regular(f.LocalPath); err != nil {
		return err
	}
	log.Printf("RT recovery: verifying local source %s", f.LocalPath)
	actual, err := upload.Evidence(f.LocalPath)
	if err != nil {
		return err
	}
	if actual != f.FileEvidence {
		return fmt.Errorf("source differs from verified backup: %s", f.LocalPath)
	}
	return nil
}

// Admit verifies the known legacy prefix without creating any measurement file.
// It deliberately rejects other campaigns, modes, configurations and populations.
func Admit(ctx context.Context, receiptPath, workspace, site, id, binding string, current *config.IPIDConfig, fetch Fetch) (*Plan, error) {
	r, uri, digest, err := ReadReceipt(ctx, receiptPath, workspace, site, id, binding, fetch)
	if err != nil {
		return nil, err
	}
	identities := map[string]os.FileInfo{}
	for name, f := range r.Files {
		if name == "state.json" {
			continue
		}
		st, err := regular(f.LocalPath)
		if err != nil {
			return nil, err
		}
		identities[f.LocalPath] = st
	}
	if current.ZMapPayload != types.PayloadICMP || current.MeasurementMode != types.MeasurementModeRTBased || current.ConnectionCount != 4 || current.RequestsPerConnection != 4 || current.TCPConfig.EstablishConnection {
		return nil, fmt.Errorf("legacy resume is only admitted for single-protocol ICMP 4x4 RT")
	}
	// Refuse insufficient output space before scanning the large population.
	targetFile, err := os.Open(r.Files["zmap.pq"].LocalPath)
	if err != nil {
		return nil, err
	}
	targetInfo, err := targetFile.Stat()
	if err != nil {
		targetFile.Close()
		return nil, err
	}
	targetMetadata, err := parquet.OpenFile(targetFile, targetInfo.Size())
	targetFile.Close()
	if err != nil {
		return nil, err
	}
	if err := CheckSpace(workspace, &Plan{Saved: originals[site].Rows, Total: targetMetadata.NumRows(), SourceEvidence: r.Files["ipid.pq"].FileEvidence}); err != nil {
		return nil, err
	}
	for _, name := range []string{"ipid.pq", "ipid.snapshot.yaml", "zmap.pq", "zmap.snapshot.yaml", "original-scanner.journal.jsonl"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := verifyFile(r.Files[name]); err != nil {
			return nil, err
		}
	}
	// The controller's new step ID changes state.json. Compare the original S3
	// state and its binding instead of pretending that mutable file is unchanged.
	stateBytes, err := fetch(ctx, r.Files["state.json"].URI)
	if err != nil {
		return nil, err
	}
	if int64(len(stateBytes)) != r.Files["state.json"].Size || hash(stateBytes) != r.Files["state.json"].SHA256 {
		return nil, fmt.Errorf("original state backup mismatch")
	}
	var originalState struct {
		Version int    `json:"version"`
		Binding string `json:"binding"`
		Steps   map[string]struct {
			ID string `json:"id"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(stateBytes, &originalState); err != nil {
		return nil, err
	}
	if originalState.Version != 1 || originalState.Binding != binding || len(originalState.Steps) != 2 || originalState.Steps["icmp-rt"].ID != id || originalState.Steps["zmap-icmp"].ID != r.ZMap {
		return nil, fmt.Errorf("original state does not bind the retained RT attempt")
	}
	oldBytes, err := os.ReadFile(r.Files["ipid.snapshot.yaml"].LocalPath)
	if err != nil {
		return nil, err
	}
	var old config.IPIDConfig
	if err := yaml.Unmarshal(oldBytes, &old); err != nil {
		return nil, err
	}
	a, err := yaml.Marshal(&old)
	if err != nil {
		return nil, err
	}
	b, err := yaml.Marshal(current)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(a, b) || current.ZMapFilePath != r.Files["zmap.pq"].LocalPath {
		return nil, fmt.Errorf("effective scientific configuration or target changed")
	}
	journal, err := os.ReadFile(r.Files["original-scanner.journal.jsonl"].LocalPath)
	if err != nil {
		return nil, err
	}
	rows, started, failures, err := Counters(journal)
	if err != nil {
		return nil, err
	}
	want := originals[site]
	if rows != want.Rows || started != want.Started {
		return nil, fmt.Errorf("final counters differ from the audited original run")
	}
	total, err := ValidatePopulation(ctx, r.Files["zmap.pq"].LocalPath, r.Files["ipid.pq"].LocalPath, rows, started)
	if err != nil {
		return nil, err
	}
	for path, before := range identities {
		if err := sameIdentity(path, before); err != nil {
			return nil, err
		}
	}
	return &Plan{Version: 1, Source: r.Files["ipid.pq"].LocalPath, Target: r.Files["zmap.pq"].LocalPath, ReceiptURI: uri, ReceiptSHA256: digest,
		SourceEvidence: r.Files["ipid.pq"].FileEvidence, TargetEvidence: r.Files["zmap.pq"].FileEvidence,
		Saved: rows, Started: started, Total: total, Failures: failures, SourceInfo: identities[r.Files["ipid.pq"].LocalPath], TargetInfo: identities[r.Files["zmap.pq"].LocalPath],
		Interpretation: "Original successes and attempted failures retained; shutdown-related failures remain unsuccessful. No reconstruction of lost partial samples. Measurements span an interruption."}, nil
}

func sameIdentity(path string, before os.FileInfo) error {
	now, err := regular(path)
	if err != nil {
		return err
	}
	if before == nil || !os.SameFile(before, now) || before.Size() != now.Size() || !before.ModTime().Equal(now.ModTime()) {
		return fmt.Errorf("recovery source changed after admission: %s", path)
	}
	return nil
}

func Stable(p *Plan) error {
	if err := sameIdentity(p.Source, p.SourceInfo); err != nil {
		return err
	}
	return sameIdentity(p.Target, p.TargetInfo)
}

func Copy(p *Plan, writer *parquet.GenericWriter[records.IPIDRecord], stop <-chan struct{}) error {
	if err := Stable(p); err != nil {
		return err
	}
	f, err := os.Open(p.Source)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	pf, err := parquet.OpenFile(f, st.Size())
	if err != nil {
		return err
	}
	var copied int64
	for i, group := range pf.RowGroups() {
		select {
		case <-stop:
			return fmt.Errorf("interrupted while copying retained RT prefix")
		default:
		}
		n, err := writer.WriteRowGroup(group)
		if err != nil {
			return err
		}
		copied += n
		if i%100 == 0 {
			log.Printf("RT recovery: copied %d/%d retained rows", copied, p.Saved)
		}
	}
	if copied != p.Saved {
		return fmt.Errorf("copied source row count changed")
	}
	return Stable(p)
}

// Ensure all readers return a terminal error, rather than silently accepting a
// short read. The caller supplies the bounded-memory per-row validation.
func readRows[T any](ctx context.Context, path string, use func(T) error) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	pf, err := parquet.OpenFile(f, st.Size())
	if err != nil {
		return 0, err
	}
	reader := parquet.NewGenericReader[T](pf)
	defer reader.Close()
	buffer := make([]T, 1024)
	var rows int64
	for {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		n, err := reader.Read(buffer)
		for _, row := range buffer[:n] {
			if e := use(row); e != nil {
				return rows, e
			}
			rows++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return rows, err
		}
		if n == 0 {
			return rows, fmt.Errorf("unexpected zero-row read")
		}
	}
	if rows != pf.NumRows() {
		return rows, fmt.Errorf("Parquet row count differs from footer")
	}
	return rows, nil
}

type ipSet struct{ pages map[uint16]*[1024]uint64 }

func address(value string) (uint32, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || !a.Is4() || a.String() != value {
		return 0, fmt.Errorf("noncanonical IPv4 address %q", value)
	}
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}
func (s *ipSet) has(n uint32) bool {
	p := s.pages[uint16(n>>16)]
	return p != nil && p[(n&65535)>>6]&(1<<(n&63)) != 0
}
func (s *ipSet) add(n uint32) bool {
	if s.has(n) {
		return false
	}
	if s.pages == nil {
		s.pages = map[uint16]*[1024]uint64{}
	}
	k := uint16(n >> 16)
	if s.pages[k] == nil {
		s.pages[k] = new([1024]uint64)
	}
	s.pages[k][(n&65535)>>6] |= 1 << (n & 63)
	return true
}
func (s *ipSet) remove(n uint32) bool {
	if !s.has(n) {
		return false
	}
	s.pages[uint16(n>>16)][(n&65535)>>6] &^= 1 << (n & 63)
	return true
}

// ValidatePopulation uses one IPv4 bitset (at most 512 MiB), not a string map
// for hundreds of millions of rows. Removing saved IPs allows a second input
// pass to prove every saved result belongs to the started prefix.
func ValidatePopulation(ctx context.Context, target, source string, saved, started int64) (int64, error) {
	var pending ipSet
	total, err := readRows[records.ZMap](ctx, target, func(row records.ZMap) error {
		n, err := address(row.IPAddress)
		if err != nil {
			return err
		}
		if !pending.add(n) {
			return fmt.Errorf("duplicate target IP %s", row.IPAddress)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if saved <= 0 || started < saved || started > total {
		return 0, fmt.Errorf("invalid saved/started/total population")
	}
	n, err := readRows[records.IPIDRecord](ctx, source, func(row records.IPIDRecord) error {
		n, err := address(row.IPAddress)
		if err != nil {
			return err
		}
		if !pending.remove(n) {
			return fmt.Errorf("duplicate or non-target saved IP %s", row.IPAddress)
		}
		return validateRecord(row)
	})
	if err != nil {
		return 0, err
	}
	if n != saved {
		return 0, fmt.Errorf("saved rows %d differ from logged %d", n, saved)
	}
	var index, found int64
	_, err = readRows[records.ZMap](ctx, target, func(row records.ZMap) error {
		n, err := address(row.IPAddress)
		if err != nil {
			return err
		}
		if !pending.has(n) {
			if index >= started {
				return fmt.Errorf("saved IP lies outside claimed started prefix")
			}
			found++
		}
		index++
		return nil
	})
	if err != nil {
		return 0, err
	}
	if found != saved {
		return 0, fmt.Errorf("saved prefix membership mismatch")
	}
	return total, nil
}

func validateRecord(row records.IPIDRecord) error {
	ids, sent, recv, df := strings.Split(row.IPIDSequence, ","), strings.Split(row.SendTimestampSequence, ","), strings.Split(row.ReceiveTimestampSequence, ","), strings.Split(row.DFSequence, ",")
	if len(ids) != 16 || len(sent) != 16 || len(recv) != 16 || len(df) != 16 {
		return fmt.Errorf("saved RT record lacks 16 complete aligned samples")
	}
	for i := range ids {
		_, e := strconv.ParseUint(ids[i], 10, 16)
		a, e1 := strconv.ParseInt(sent[i], 10, 64)
		b, e2 := strconv.ParseInt(recv[i], 10, 64)
		if e != nil || e1 != nil || e2 != nil || a <= 0 || b < a || (df[i] != "0" && df[i] != "1") {
			return fmt.Errorf("invalid complete RT sample")
		}
	}
	return nil
}
