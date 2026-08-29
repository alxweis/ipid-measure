package os

import (
	"encoding/json"
	"fmt"
	osstd "os"
	"sort"
	"strings"
	"sync"
)

type coverageTargets struct {
	Total           uint64 `json:"total"`
	WithResponse    uint64 `json:"with_response"`
	WithoutResponse uint64 `json:"without_response"`
	WithEvidence    uint64 `json:"with_evidence"`
	WithoutEvidence uint64 `json:"without_evidence"`
	WithTag         uint64 `json:"with_tag"`
	WithoutTag      uint64 `json:"without_tag"`
}

type coverageClassification struct {
	Resolved     uint64 `json:"resolved"`
	Ambiguous    uint64 `json:"ambiguous"`
	Unclassified uint64 `json:"unclassified"`
}

type serviceCoverage struct {
	Attempted uint64 `json:"attempted"`
	Responded uint64 `json:"responded"`
	Evidence  uint64 `json:"evidence"`
	Tagged    uint64 `json:"tagged"`
}

type serviceCoverageOverview struct {
	Attempted                 uint64  `json:"attempted"`
	Responded                 uint64  `json:"responded"`
	RespondedCoverage         float64 `json:"responded_coverage"`
	Evidence                  uint64  `json:"evidence"`
	EvidenceCoverage          float64 `json:"evidence_coverage"`
	Tagged                    uint64  `json:"tagged"`
	TaggedCoverage            float64 `json:"tagged_coverage"`
	EvidenceRateAmongResponse float64 `json:"evidence_rate_among_responses"`
	TaggedRateAmongEvidence   float64 `json:"tagged_rate_among_evidence"`
}

type coverageOverview struct {
	TotalTargets                  uint64                             `json:"total_targets"`
	RespondedTargets              uint64                             `json:"responded_targets"`
	RespondedCoverage             float64                            `json:"responded_coverage"`
	EvidenceTargets               uint64                             `json:"evidence_targets"`
	EvidenceCoverage              float64                            `json:"evidence_coverage"`
	TaggedTargets                 uint64                             `json:"tagged_targets"`
	TaggedCoverage                float64                            `json:"tagged_coverage"`
	ResolvedTargets               uint64                             `json:"resolved_targets"`
	ResolvedCoverage              float64                            `json:"resolved_coverage"`
	AmbiguousTargets              uint64                             `json:"ambiguous_targets"`
	AmbiguousCoverage             float64                            `json:"ambiguous_coverage"`
	UnclassifiedTargets           uint64                             `json:"unclassified_targets"`
	UnclassifiedCoverage          float64                            `json:"unclassified_coverage"`
	ResolvedRateAmongEvidence     float64                            `json:"resolved_rate_among_evidence"`
	AmbiguousRateAmongEvidence    float64                            `json:"ambiguous_rate_among_evidence"`
	UnclassifiedRateAmongEvidence float64                            `json:"unclassified_rate_among_evidence"`
	Services                      map[string]serviceCoverageOverview `json:"services"`
}

type coverageDetail struct {
	Targets        coverageTargets            `json:"targets"`
	Classification coverageClassification     `json:"classification"`
	Services       map[string]serviceCoverage `json:"services"`
	Conflicts      map[string]uint64          `json:"conflicts"`
}

type coverageDocument struct {
	SchemaVersion     string           `json:"schema_version"`
	ClassifierVersion string           `json:"classifier_version"`
	Overview          coverageOverview `json:"overview"`
	Detail            coverageDetail   `json:"detail"`
}

type coverageStats struct {
	mu       sync.Mutex
	document coverageDocument
}

func newCoverageStats(total uint64) *coverageStats {
	services := make(map[string]serviceCoverage, 6)
	for _, name := range []string{"ssh", "smb", "http", "https", "snmp", "dns"} {
		services[name] = serviceCoverage{Attempted: total}
	}
	return &coverageStats{document: coverageDocument{
		SchemaVersion:     SchemaVersion,
		ClassifierVersion: ClassifierVersion,
		Detail: coverageDetail{
			Targets:   coverageTargets{Total: total},
			Services:  services,
			Conflicts: make(map[string]uint64),
		},
	}}
}

func (c *coverageStats) recordWithoutEvidence(e evidenceRecord) {
	c.mu.Lock()
	tags := serviceTags{}
	c.recordTarget(e, tags, false)
	c.recordServices(e, tags)
	c.mu.Unlock()
}

func (c *coverageStats) record(e evidenceRecord, tags serviceTags, d decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recordTarget(e, tags, true)

	c.recordServices(e, tags)

	switch d.status {
	case statusResolved:
		c.document.Detail.Classification.Resolved++
	case statusAmbiguous:
		c.document.Detail.Classification.Ambiguous++
		conflicts := append([]string(nil), d.conflicts...)
		sort.Strings(conflicts)
		c.document.Detail.Conflicts[strings.Join(conflicts, "|")]++
	case statusUnclassified:
		c.document.Detail.Classification.Unclassified++
	}
}

func (c *coverageStats) recordTarget(e evidenceRecord, tags serviceTags, hasEvidence bool) {
	targets := &c.document.Detail.Targets
	if e.hasResponse() {
		targets.WithResponse++
	} else {
		targets.WithoutResponse++
	}
	if hasEvidence {
		targets.WithEvidence++
	} else {
		targets.WithoutEvidence++
	}
	if tags.hasAny() {
		targets.WithTag++
	} else {
		targets.WithoutTag++
	}
}

func (c *coverageStats) recordServices(e evidenceRecord, tags serviceTags) {
	services := c.document.Detail.Services
	updateService(services, "ssh", e.SSHResponded, e.SSHServerID != "", tags.SSH != "")
	updateService(services, "smb", e.SMBResponded, e.SMBNativeOS != "", tags.SMB != "")
	updateService(services, "http", e.HTTPResponded, e.HTTPServer != "", tags.HTTP != "")
	updateService(services, "https", e.HTTPSResponded, e.HTTPSServer != "", tags.HTTPS != "")
	updateService(services, "snmp", e.SNMPResponded, e.SNMPSysDescr != "", tags.SNMP != "")
	updateService(services, "dns", e.DNSResponded, e.DNSVersionBind != "", tags.DNS != "")
}

func updateService(services map[string]serviceCoverage, name string, responded, evidence, tagged bool) {
	value := services[name]
	if responded {
		value.Responded++
	}
	if evidence {
		value.Evidence++
	}
	if tagged {
		value.Tagged++
	}
	services[name] = value
}

func (c *coverageStats) write(path string) error {
	c.mu.Lock()
	document := c.document
	document.Overview = buildCoverageOverview(document.Detail)
	c.mu.Unlock()

	file, err := osstd.Create(path)
	if err != nil {
		return fmt.Errorf("create OS coverage: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(document)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write OS coverage: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close OS coverage: %w", closeErr)
	}
	return nil
}

func buildCoverageOverview(detail coverageDetail) coverageOverview {
	targets := detail.Targets
	classification := detail.Classification
	services := make(map[string]serviceCoverageOverview, len(detail.Services))
	for name, service := range detail.Services {
		services[name] = serviceCoverageOverview{
			Attempted:                 service.Attempted,
			Responded:                 service.Responded,
			RespondedCoverage:         ratio(service.Responded, service.Attempted),
			Evidence:                  service.Evidence,
			EvidenceCoverage:          ratio(service.Evidence, service.Attempted),
			Tagged:                    service.Tagged,
			TaggedCoverage:            ratio(service.Tagged, service.Attempted),
			EvidenceRateAmongResponse: ratio(service.Evidence, service.Responded),
			TaggedRateAmongEvidence:   ratio(service.Tagged, service.Evidence),
		}
	}
	return coverageOverview{
		TotalTargets:                  targets.Total,
		RespondedTargets:              targets.WithResponse,
		RespondedCoverage:             ratio(targets.WithResponse, targets.Total),
		EvidenceTargets:               targets.WithEvidence,
		EvidenceCoverage:              ratio(targets.WithEvidence, targets.Total),
		TaggedTargets:                 targets.WithTag,
		TaggedCoverage:                ratio(targets.WithTag, targets.Total),
		ResolvedTargets:               classification.Resolved,
		ResolvedCoverage:              ratio(classification.Resolved, targets.Total),
		AmbiguousTargets:              classification.Ambiguous,
		AmbiguousCoverage:             ratio(classification.Ambiguous, targets.Total),
		UnclassifiedTargets:           classification.Unclassified,
		UnclassifiedCoverage:          ratio(classification.Unclassified, targets.Total),
		ResolvedRateAmongEvidence:     ratio(classification.Resolved, targets.WithEvidence),
		AmbiguousRateAmongEvidence:    ratio(classification.Ambiguous, targets.WithEvidence),
		UnclassifiedRateAmongEvidence: ratio(classification.Unclassified, targets.WithEvidence),
		Services:                      services,
	}
}

func ratio(numerator, denominator uint64) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
