package os

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/records"
)

// pending tracks per-IP merge state; emitted once all enabled scanners reported.
type pending struct {
	rec     records.OSRecord
	flags   uint8 // bit-flags: which scanners have reported
	started time.Time
}

// merger joins ZGrab2/ZDNS/SNMP streams into one records.OSRecord per IP,
// fingerprints it, and forwards records with useful evidence.
type merger struct {
	enabledOrig   uint8 // initial mask -- never changes
	mu            sync.Mutex
	enabled       uint8 // current mask -- shrinks if a scanner dies mid-run
	pendings      map[string]*pending
	out           chan<- records.OSRecord
	totalEmitted  atomic.Uint64
	totalDropped  atomic.Uint64 // rows without any usable scanner evidence
	totalReceived atomic.Uint64
	// Per-scanner integrate counters; useful to spot a silent scanner.
	rxZGrab2 atomic.Uint64
	rxZDNS   atomic.Uint64
	rxSNMP   atomic.Uint64
}

// Scanner-mask bits. Adding a scanner means adding a bit and accounting for
// it in newMerger's `enabled` field.
const (
	scannerZGrab2 uint8 = 1 << 0
	scannerZDNS   uint8 = 1 << 1
	scannerSNMP   uint8 = 1 << 2
)

// enabledMask returns the bitmask of scanners that will actually emit per-IP
// results given the user's modules configuration.
func enabledMask(modules config.OSModules) uint8 {
	var m uint8
	if config.HasZGrab2Module(modules) {
		m |= scannerZGrab2
	}
	if config.HasZDNSModule(modules) {
		m |= scannerZDNS
	}
	if config.HasSNMPModule(modules) {
		m |= scannerSNMP
	}
	return m
}

func newMerger(modules config.OSModules, out chan<- records.OSRecord) *merger {
	mask := enabledMask(modules)
	return &merger{
		enabledOrig: mask,
		enabled:     mask,
		pendings:    make(map[string]*pending, 1<<14),
		out:         out,
	}
}

// markScannerDead drops the scanner's bit from `enabled` and flushes pending
// entries that are now complete under the reduced mask.
func (m *merger) markScannerDead(scanner uint8) {
	m.mu.Lock()
	if (m.enabled & scanner) == 0 {
		m.mu.Unlock()
		return // already marked dead
	}
	m.enabled &^= scanner
	newEnabled := m.enabled
	// Collect pending entries that are now complete under the new mask.
	var toEmit []records.OSRecord
	for ip, p := range m.pendings {
		if (p.flags & newEnabled) == newEnabled {
			toEmit = append(toEmit, p.rec)
			delete(m.pendings, ip)
		}
	}
	m.mu.Unlock()
	for _, rec := range toEmit {
		m.emit(rec)
	}
}

// integrate folds one scanner's result into the per-IP pending entry and
// emits + fingerprints once all enabled scanners have reported.
func (m *merger) integrate(ip string, sourceFlag uint8, applyFn func(*records.OSRecord)) {
	m.totalReceived.Add(1)
	switch sourceFlag {
	case scannerZGrab2:
		m.rxZGrab2.Add(1)
	case scannerZDNS:
		m.rxZDNS.Add(1)
	case scannerSNMP:
		m.rxSNMP.Add(1)
	}

	m.mu.Lock()
	p, ok := m.pendings[ip]
	if !ok {
		p = &pending{
			rec:     records.OSRecord{IPAddress: ip},
			started: time.Now(),
		}
		m.pendings[ip] = p
	}
	applyFn(&p.rec)
	p.flags |= sourceFlag

	done := (p.flags & m.enabled) == m.enabled
	if !done {
		m.mu.Unlock()
		return
	}
	rec := p.rec
	delete(m.pendings, ip)
	m.mu.Unlock()

	m.emit(rec)
}

// emit runs the fingerprint heuristic on a complete record and forwards it
// to the writer. Records are retained when only a vendor, software product,
// or device type could be inferred; only records without usable evidence are
// dropped.
func (m *merger) emit(rec records.OSRecord) {
	result := DetectFingerprint(&rec)
	if result.DetectedName == "" {
		m.totalDropped.Add(1)
		return
	}
	rec.OSName = result.OSName
	rec.DetectedName = result.DetectedName
	rec.DetectedType = result.DetectedType
	rec.OSSource = result.Source
	m.out <- rec
	m.totalEmitted.Add(1)
}

// flushAll emits every pending entry regardless of scanner completion; called
// once after all input streams are closed. Collect under lock, emit without.
func (m *merger) flushAll() {
	m.mu.Lock()
	toEmit := make([]records.OSRecord, 0, len(m.pendings))
	for ip, p := range m.pendings {
		toEmit = append(toEmit, p.rec)
		delete(m.pendings, ip)
	}
	m.mu.Unlock()
	for _, rec := range toEmit {
		m.emit(rec)
	}
}

// applyZGrab2 transfers all zgrab2 module fields into the record.
func applyZGrab2(in ZGrab2Result) func(*records.OSRecord) {
	return func(r *records.OSRecord) {
		r.SSHServerID = in.SSHServerID
		r.SMBNativeOS = in.SMBNativeOS
		r.HTTPServer = in.HTTPServer
		r.HTTPSServer = in.HTTPSServer
		r.HTTPSCertIssuer = in.HTTPSCertIssuer
		r.HTTPSCertSubject = in.HTTPSCertSubject
		r.SMTPBanner = in.SMTPBanner
		r.SMTPEHLO = in.SMTPEHLO
		r.MSSQLVersion = in.MSSQLVersion
		r.POP3Banner = in.POP3Banner
		r.IMAPBanner = in.IMAPBanner
		r.FTPBanner = in.FTPBanner
		r.TelnetBanner = in.TelnetBanner
	}
}

func applyZDNS(in ZDNSResult) func(*records.OSRecord) {
	return func(r *records.OSRecord) {
		// Take the union; never overwrite a non-empty field with empty.
		if in.VersionBind != "" {
			r.DNSVersionBind = in.VersionBind
		}
		if in.HostnameBind != "" {
			r.DNSHostnameBind = in.HostnameBind
		}
	}
}

func applySNMP(in SNMPResult) func(*records.OSRecord) {
	return func(r *records.OSRecord) {
		if in.OK && in.SysDescr != "" {
			r.SNMPSysDescr = CleanBanner(in.SysDescr)
		}
	}
}
