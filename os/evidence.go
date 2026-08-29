package os

import (
	"strings"

	"github.com/alxweis/ipid-measure/internal/records"
)

const maxEvidenceRunes = 1024

type evidenceRecord struct {
	IPAddress string

	SSHServerID    string
	SMBNativeOS    string
	HTTPServer     string
	HTTPSServer    string
	SNMPSysDescr   string
	DNSVersionBind string

	SSHResponded   bool
	SMBResponded   bool
	HTTPResponded  bool
	HTTPSResponded bool
	SNMPResponded  bool
	DNSResponded   bool
}

func (e evidenceRecord) hasEvidence() bool {
	return e.SSHServerID != "" || e.SMBNativeOS != "" || e.HTTPServer != "" ||
		e.HTTPSServer != "" || e.SNMPSysDescr != "" || e.DNSVersionBind != ""
}

func (e evidenceRecord) hasResponse() bool {
	return e.SSHResponded || e.SMBResponded || e.HTTPResponded ||
		e.HTTPSResponded || e.SNMPResponded || e.DNSResponded
}

func (e evidenceRecord) toOutput(tags serviceTags, d decision) records.OSRecord {
	return records.OSRecord{
		IPAddress:      e.IPAddress,
		OSStatus:       d.status,
		OSTag:          optionalString(d.tag),
		SSHOS:          optionalString(tags.SSH),
		SMBOS:          optionalString(tags.SMB),
		HTTPOS:         optionalString(tags.HTTP),
		HTTPSOS:        optionalString(tags.HTTPS),
		SNMPOS:         optionalString(tags.SNMP),
		DNSOS:          optionalString(tags.DNS),
		SSHServerID:    optionalString(e.SSHServerID),
		SMBNativeOS:    optionalString(e.SMBNativeOS),
		HTTPServer:     optionalString(e.HTTPServer),
		HTTPSServer:    optionalString(e.HTTPSServer),
		SNMPSysDescr:   optionalString(e.SNMPSysDescr),
		DNSVersionBind: optionalString(e.DNSVersionBind),
	}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	copy := value
	return &copy
}

// CleanBanner normalizes external evidence and bounds its retained size.
func CleanBanner(value string) string {
	if value == "" {
		return ""
	}
	var b strings.Builder
	if len(value) < maxEvidenceRunes {
		b.Grow(len(value))
	} else {
		b.Grow(maxEvidenceRunes)
	}
	count := 0
	for _, r := range value {
		if count == maxEvidenceRunes {
			break
		}
		switch {
		case r == '\n', r == '\r', r == '\t':
			b.WriteByte(' ')
			count++
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
			count++
		}
	}
	return strings.TrimSpace(b.String())
}
