package os

import (
	"sync"
	"sync/atomic"

	"github.com/alxweis/ipid-measure/internal/records"
)

const (
	scannerZGrab2 uint8 = 1 << iota
	scannerDNSChaos
	scannerSNMP
	allScanners = scannerZGrab2 | scannerDNSChaos | scannerSNMP
)

type pending struct {
	record evidenceRecord
	flags  uint8
}

// merger joins the three scanner streams. Every scanner emits exactly one
// completion per target, so the pending map stays bounded by pipeline latency.
type merger struct {
	mu       sync.Mutex
	pendings map[string]*pending
	out      chan<- records.OSRecord
	coverage *coverageStats

	totalEmitted  atomic.Uint64
	totalDropped  atomic.Uint64
	totalReceived atomic.Uint64
	rxZGrab2      atomic.Uint64
	rxDNSChaos    atomic.Uint64
	rxSNMP        atomic.Uint64
}

func newMerger(out chan<- records.OSRecord, coverage *coverageStats) *merger {
	return &merger{
		pendings: make(map[string]*pending, 1<<14),
		out:      out,
		coverage: coverage,
	}
}

func (m *merger) integrate(ip string, source uint8, apply func(*evidenceRecord)) {
	m.totalReceived.Add(1)
	switch source {
	case scannerZGrab2:
		m.rxZGrab2.Add(1)
	case scannerDNSChaos:
		m.rxDNSChaos.Add(1)
	case scannerSNMP:
		m.rxSNMP.Add(1)
	}

	m.mu.Lock()
	p, ok := m.pendings[ip]
	if !ok {
		p = &pending{record: evidenceRecord{IPAddress: ip}}
		m.pendings[ip] = p
	}
	apply(&p.record)
	p.flags |= source
	if p.flags != allScanners {
		m.mu.Unlock()
		return
	}
	record := p.record
	delete(m.pendings, ip)
	m.mu.Unlock()

	m.emit(record)
}

func (m *merger) emit(evidence evidenceRecord) {
	if !evidence.hasEvidence() {
		m.coverage.recordWithoutEvidence(evidence)
		m.totalDropped.Add(1)
		return
	}
	tags := classifyServices(evidence)
	decision := resolveTags(tags)
	m.coverage.record(evidence, tags, decision)
	m.out <- evidence.toOutput(tags, decision)
	m.totalEmitted.Add(1)
}

func (m *merger) pendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pendings)
}

func applyZGrab2(in ZGrab2Result) func(*evidenceRecord) {
	return func(r *evidenceRecord) {
		r.SSHServerID = CleanBanner(in.SSHServerID)
		r.SMBNativeOS = CleanBanner(in.SMBNativeOS)
		r.HTTPServer = CleanBanner(in.HTTPServer)
		r.HTTPSServer = CleanBanner(in.HTTPSServer)
		r.SSHResponded = in.SSHResponded
		r.SMBResponded = in.SMBResponded
		r.HTTPResponded = in.HTTPResponded
		r.HTTPSResponded = in.HTTPSResponded
	}
}

func applyDNSChaos(in DNSChaosResult) func(*evidenceRecord) {
	return func(r *evidenceRecord) {
		r.DNSVersionBind = CleanBanner(in.VersionBind)
		r.DNSResponded = in.Responded
	}
}

func applySNMP(in SNMPResult) func(*evidenceRecord) {
	return func(r *evidenceRecord) {
		r.SNMPSysDescr = CleanBanner(in.SysDescr)
		r.SNMPResponded = in.Responded
	}
}
