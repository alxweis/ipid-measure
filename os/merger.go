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

// merger joins ZGrab2/DNS-CHAOS/SNMP streams into one records.OSRecord per IP,
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
	// Per-scanner completion counters; useful to spot a silent scanner.
	rxZGrab2Default   atomic.Uint64
	rxZGrab2Secondary atomic.Uint64
	rxDNSChaos        atomic.Uint64
	rxSNMP            atomic.Uint64

	secondarySampleRate float64
	hasSecondary        bool
}

// Scanner-mask bits. Adding a scanner means adding a bit and accounting for
// it in newMerger's `enabled` field.
const (
	scannerZGrab2Default   uint8 = 1 << 0
	scannerZGrab2Secondary uint8 = 1 << 1
	scannerDNSChaos        uint8 = 1 << 2
	scannerSNMP            uint8 = 1 << 3
)

func usesDefaultZGrab2(c *config.OSConfig) bool {
	return config.HasCoreZGrab2Module(c.Modules) ||
		(config.HasSecondaryZGrab2Module(c.Modules) && c.SecondarySampleRate >= 1)
}

func usesTriggeredSecondaryZGrab2(c *config.OSConfig) bool {
	return config.HasSecondaryZGrab2Module(c.Modules) &&
		c.SecondarySampleRate > 0 && c.SecondarySampleRate < 1
}

// enabledMask returns the bitmask of scanners that will actually emit per-IP
// results given the effective configuration.
func enabledMask(c *config.OSConfig) uint8 {
	var m uint8
	if usesDefaultZGrab2(c) {
		m |= scannerZGrab2Default
	}
	if usesTriggeredSecondaryZGrab2(c) {
		m |= scannerZGrab2Secondary
	}
	if config.HasZDNSModule(c.Modules) && c.SecondarySampleRate > 0 {
		m |= scannerDNSChaos
	}
	if config.HasSNMPModule(c.Modules) {
		m |= scannerSNMP
	}
	return m
}

func newMerger(c *config.OSConfig, out chan<- records.OSRecord) *merger {
	mask := enabledMask(c)
	return &merger{
		enabledOrig:         mask,
		enabled:             mask,
		pendings:            make(map[string]*pending, 1<<14),
		out:                 out,
		secondarySampleRate: c.SecondarySampleRate,
		hasSecondary:        config.HasSecondaryModule(c.Modules),
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
	case scannerZGrab2Default:
		m.rxZGrab2Default.Add(1)
	case scannerZGrab2Secondary:
		m.rxZGrab2Secondary.Add(1)
	case scannerDNSChaos:
		m.rxDNSChaos.Add(1)
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
	rec.SecondarySampled = m.hasSecondary &&
		selectSecondary(rec.IPAddress, m.secondarySampleRate)
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
		// Core and sampled secondary ZGrab2 results arrive independently.
		// Merge their non-empty fields instead of allowing the second result
		// to erase evidence collected by the first.
		setIfNonEmpty(&r.SSHServerID, in.SSHServerID)
		setIfNonEmpty(&r.SMBNativeOS, in.SMBNativeOS)
		setIfNonEmpty(&r.HTTPServer, in.HTTPServer)
		setIfNonEmpty(&r.HTTPSServer, in.HTTPSServer)
		setIfNonEmpty(&r.HTTPSCertIssuer, in.HTTPSCertIssuer)
		setIfNonEmpty(&r.HTTPSCertSubject, in.HTTPSCertSubject)
		setIfNonEmpty(&r.SMTPBanner, in.SMTPBanner)
		setIfNonEmpty(&r.SMTPEHLO, in.SMTPEHLO)
		setIfNonEmpty(&r.MSSQLVersion, in.MSSQLVersion)
		setIfNonEmpty(&r.POP3Banner, in.POP3Banner)
		setIfNonEmpty(&r.IMAPBanner, in.IMAPBanner)
		setIfNonEmpty(&r.FTPBanner, in.FTPBanner)
		setIfNonEmpty(&r.TelnetBanner, in.TelnetBanner)
	}
}

func setIfNonEmpty(dst *string, value string) {
	if value != "" {
		*dst = value
	}
}

func applyDNSChaos(in DNSChaosResult) func(*records.OSRecord) {
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
