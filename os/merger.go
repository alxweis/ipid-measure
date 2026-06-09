package os

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/alxweis/ipid-measure/internal/records"
)

// pending is the per-IP merge state. We track which of the enabled scanners
// have already reported for this IP -- once all of them have, the row is
// emitted to the writer.
type pending struct {
	rec     records.OSRecord
	flags   uint8 // bit-flags: which scanners have reported
	started time.Time
}

// merger joins ZGrab2Result, ZDNSResult, SNMPResult streams into one
// records.OSRecord per IP. It also runs the OS-name fingerprint heuristic
// and only forwards rows that produced a non-empty match.
type merger struct {
	enabledOrig   uint8 // initial mask -- never changes
	mu            sync.Mutex
	enabled       uint8 // current mask -- shrinks if a scanner dies mid-run
	pendings      map[string]*pending
	out           chan<- records.OSRecord
	totalEmitted  atomic.Uint64
	totalDropped  atomic.Uint64 // rows where fingerprint returned ""
	totalReceived atomic.Uint64
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
func enabledMask(modules map[string]bool) uint8 {
	var m uint8
	if anyZGrab2Module(modules) {
		m |= scannerZGrab2
	}
	if modules["dns_chaos"] {
		m |= scannerZDNS
	}
	if modules["snmp"] {
		m |= scannerSNMP
	}
	return m
}

func anyZGrab2Module(modules map[string]bool) bool {
	for _, k := range []string{"http", "https", "ssh", "smb", "smtp", "mssql", "pop3", "imap", "ftp", "telnet"} {
		if modules[k] {
			return true
		}
	}
	return false
}

func newMerger(modules map[string]bool, out chan<- records.OSRecord) *merger {
	mask := enabledMask(modules)
	return &merger{
		enabledOrig: mask,
		enabled:     mask,
		pendings:    make(map[string]*pending, 1<<14),
		out:         out,
	}
}

// markScannerDead tells the merger that the given scanner will no longer
// produce results for any IP. We drop the bit from `enabled` so that the
// per-IP "all scanners reported" check uses the reduced mask. Any pending
// entries that were waiting only on the dead scanner become eligible for
// emission and are flushed.
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

// integrate adds one scanner-source's data to the per-IP pending entry. If
// the entry now has all enabled scanners accounted for, it is fingerprinted
// and the result is forwarded (or dropped if no OS name could be inferred).
//
// applyFn mutates the OSRecord with the data from this scanner.
func (m *merger) integrate(ip string, sourceFlag uint8, ts int64, applyFn func(*records.OSRecord)) {
	m.totalReceived.Add(1)

	m.mu.Lock()
	p, ok := m.pendings[ip]
	if !ok {
		p = &pending{
			rec:     records.OSRecord{IPAddress: ip, TimestampUS: ts},
			started: time.Now(),
		}
		m.pendings[ip] = p
	}
	applyFn(&p.rec)
	p.flags |= sourceFlag

	// Use the latest timestamp; the writer column should reflect when the
	// fingerprint was completed, not when the first scanner saw the IP.
	if ts > p.rec.TimestampUS {
		p.rec.TimestampUS = ts
	}

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
// to the writer, or drops it if no OS could be inferred.
func (m *merger) emit(rec records.OSRecord) {
	osName, src := Fingerprint(&rec)
	if osName == "" {
		m.totalDropped.Add(1)
		return
	}
	rec.OSName = osName
	rec.OSSource = src
	m.out <- rec
	m.totalEmitted.Add(1)
}

// flushAll forces emission of every pending entry, regardless of whether all
// scanners reported. Called once after all input streams are closed, so any
// IP for which one of the scanners silently dropped output still gets
// fingerprinted on the data we did receive.
func (m *merger) flushAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, p := range m.pendings {
		rec := p.rec
		delete(m.pendings, ip)
		// Unlock briefly so emit -> writer doesn't deadlock on a slow consumer.
		m.mu.Unlock()
		m.emit(rec)
		m.mu.Lock()
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
		// zdns emits separate lines for version.bind and hostname.bind that
		// the zdns parser already merges into one ZDNSResult per IP. We
		// take the union: never overwrite a non-empty field with empty.
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
