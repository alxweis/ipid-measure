package os

import (
	"regexp"
	"strings"

	"github.com/alxweis/ipid-measure/internal/records"
)

const (
	detectionOS             = "os"
	detectionOSFamily       = "os-family"
	detectionVendor         = "vendor"
	detectionServerSoftware = "server-software"
	detectionDeviceType     = "device-type"
	detectionHostnameHint   = "hostname-hint"
	detectionUnknown        = "unknown"
)

// FingerprintResult separates a supported OS inference from the normalized
// observation that produced it. For example, nginx is useful evidence but is
// server software rather than proof of Linux.
type FingerprintResult struct {
	OSName       string
	DetectedName string
	DetectedType string
	Source       string
}

// Fingerprint derives the OS family from the per-service raw strings populated
// in an OSRecord. It is retained as the narrow, backwards-compatible API.
func Fingerprint(r *records.OSRecord) (osName, osSource string) {
	result := DetectFingerprint(r)
	if result.OSName == "" {
		return "", ""
	}
	return result.OSName, result.Source
}

// DetectFingerprint returns the strongest supported OS inference and preserves
// the best weaker observation when no OS can be inferred. OS matches outrank
// vendor, software, and device-type fallbacks even when a fallback occurs in a
// higher-priority source.
func DetectFingerprint(r *records.OSRecord) FingerprintResult {
	var fallback FingerprintResult
	for _, rule := range rules {
		field := rule.fieldFn(r)
		if field == "" {
			continue
		}
		if name := rule.match(field); name != "" {
			detectedType := detectionType(name)
			result := FingerprintResult{
				DetectedName: name,
				DetectedType: detectedType,
				Source:       rule.source,
			}
			if detectedType == detectionOS {
				result.OSName = name
				return result
			}
			if fallback.DetectedName == "" {
				fallback = result
			}
		}
	}
	if fallback.DetectedName != "" {
		return fallback
	}
	for _, rule := range rules {
		if strings.TrimSpace(rule.fieldFn(r)) != "" {
			return FingerprintResult{
				DetectedName: detectionUnknown,
				DetectedType: detectionUnknown,
				Source:       rule.source,
			}
		}
	}
	return FingerprintResult{}
}

// detectionTypes lists normalized observations which are deliberately not
// treated as operating systems. Names absent from this map are OS names.
var detectionTypes = map[string]string{
	"apache":           detectionServerSoftware,
	"arista":           detectionVendor,
	"bind":             detectionServerSoftware,
	"busybox":          detectionServerSoftware,
	"caddy":            detectionServerSoftware,
	"check-point":      detectionVendor,
	"cisco":            detectionVendor,
	"courier":          detectionServerSoftware,
	"cyrus":            detectionServerSoftware,
	"dlink":            detectionVendor,
	"dnsmasq":          detectionServerSoftware,
	"dovecot":          detectionServerSoftware,
	"draytek":          detectionVendor,
	"dropbear":         detectionServerSoftware,
	"embedded":         detectionDeviceType,
	"enterprise-linux": detectionOSFamily,
	"exim":             detectionServerSoftware,
	"f5":               detectionVendor,
	"filezilla-server": detectionServerSoftware,
	"fortinet":         detectionVendor,
	"hostname-debian":  detectionHostnameHint,
	"hostname-fedora":  detectionHostnameHint,
	"hostname-freebsd": detectionHostnameHint,
	"hostname-ubuntu":  detectionHostnameHint,
	"huawei":           detectionVendor,
	"hp-procurve":      detectionVendor,
	"iredmail":         detectionServerSoftware,
	"juniper":          detectionVendor,
	"knot-dns":         detectionServerSoftware,
	"lighttpd":         detectionServerSoftware,
	"microsoft-sql":    detectionServerSoftware,
	"microsoft":        detectionVendor,
	"mikrotik":         detectionVendor,
	"nginx":            detectionServerSoftware,
	"opensmtpd":        detectionServerSoftware,
	"palo-alto":        detectionVendor,
	"postfix":          detectionServerSoftware,
	"powerdns":         detectionServerSoftware,
	"printer":          detectionDeviceType,
	"proftpd":          detectionServerSoftware,
	"pure-ftpd":        detectionServerSoftware,
	"qnap":             detectionVendor,
	"router":           detectionDeviceType,
	"samba":            detectionServerSoftware,
	"sendmail":         detectionServerSoftware,
	"server":           detectionDeviceType,
	"serv-u":           detectionServerSoftware,
	"sonicwall":        detectionVendor,
	"sophos":           detectionVendor,
	"synology":         detectionVendor,
	"tp-link":          detectionVendor,
	"ubiquiti":         detectionVendor,
	"unbound":          detectionServerSoftware,
	"vsftpd":           detectionServerSoftware,
	"watchguard":       detectionVendor,
	"zyxel":            detectionVendor,
	"zimbra":           detectionServerSoftware,
	"zte":              detectionVendor,
}

func detectionType(name string) string {
	if kind, ok := detectionTypes[name]; ok {
		return kind
	}
	return detectionOS
}

// rule is one extraction attempt
type rule struct {
	source   string
	fieldFn  func(*records.OSRecord) string
	patterns []pattern
}

type pattern struct {
	re     *regexp.Regexp
	osName string
}

func (r rule) match(s string) string {
	for _, p := range r.patterns {
		if p.re.MatchString(s) {
			return p.osName
		}
	}
	return ""
}

// re compiles a case-insensitive regex.
func re(s string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + s)
}

// rules is the global priority-ordered rule list.
var rules []rule

func init() {
	rules = []rule{
		// ===== Tier 1: SSH server-id is the gold standard. =====
		{
			source:  "ssh",
			fieldFn: func(r *records.OSRecord) string { return r.SSHServerID },
			patterns: []pattern{
				// Distro suffixes after "OpenSSH_X.Y": "Ubuntu-3ubuntu0.10", "Debian-2+deb12u1", etc.
				{re(`ubuntu`), "ubuntu"},
				{re(`debian`), "debian"},
				{re(`raspbian`), "raspbian"},
				{re(`centos`), "centos"},
				{re(`\.rhel|rhel|red.?hat`), "rhel"},
				{re(`fedora`), "fedora"},
				{re(`rocky`), "rocky"},
				{re(`almalinux|alma`), "alma"},
				{re(`amazon|amzn`), "amazon-linux"},
				{re(`oracle.*linux|oraclelinux`), "oracle-linux"},
				{re(`(?:^|[._+-])el(?:7|8|9|10)(?:[._+-]|$)`), "enterprise-linux"},
				{re(`suse|sles`), "suse"},
				{re(`alpine`), "alpine"},
				{re(`arch`), "arch"},
				{re(`gentoo`), "gentoo"},
				// BSDs (often embedded in SSH server-id)
				{re(`freebsd`), "freebsd"},
				{re(`openbsd`), "openbsd"},
				{re(`netbsd`), "netbsd"},
				// Windows OpenSSH
				{re(`for.?windows|windows`), "windows"},
				// macOS
				{re(`darwin|mac.?os`), "macos"},
				// Network-gear SSH banners
				{re(`cisco.*ios.?xe`), "cisco-iosxe"},
				{re(`cisco.*ios.?xr`), "cisco-iosxr"},
				{re(`cisco.*nx.?os|nxos`), "cisco-nxos"},
				{re(`cisco.*(asa|adaptive\s+security)`), "cisco-asa"},
				{re(`firepower\s+threat\s+defense|cisco.?ftd`), "cisco-ftd"},
				{re(`cisco.*\bios\b`), "cisco-ios"},
				{re(`cisco`), "cisco"},
				{re(`routeros`), "mikrotik-routeros"},
				{re(`\bswos\b`), "mikrotik-swos"},
				{re(`mikrotik`), "mikrotik"},
				{re(`junos\s+evolved`), "juniper-junos-evolved"},
				{re(`screenos|netscreen`), "juniper-screenos"},
				{re(`junos`), "juniper-junos"},
				{re(`juniper`), "juniper"},
				{re(`versatile routing platform|(?:^|\s)vrp(?:\s|$)`), "huawei-vrp"},
				{re(`huawei`), "huawei"},
				{re(`fortios|fortigate`), "fortinet-fortios"},
				{re(`fortinet`), "fortinet"},
				{re(`pan.?os`), "paloalto-panos"},
				{re(`palo.?alto`), "palo-alto"},
				{re(`vyos|vyatta`), "vyos"},
				{re(`pfsense`), "pfsense"},
				{re(`opnsense`), "opnsense"},
				{re(`arista.*\beos\b|\beos\b.*arista`), "arista-eos"},
				{re(`arista`), "arista"},
				{re(`big.?ip`), "f5-bigip"},
				{re(`\bf5\b`), "f5"},
				{re(`gaia`), "checkpoint-gaia"},
				{re(`checkpoint|check\s+point`), "check-point"},
				{re(`dray.?os`), "drayos"},
				{re(`draytek`), "draytek"},
				{re(`sonic.?os`), "sonicos"},
				{re(`sonicwall`), "sonicwall"},
				{re(`zy.?nos`), "zynos"},
				{re(`zyxel.*\bzld\b|\bzld\b.*zyxel`), "zyxel-zld"},
				{re(`zyxel.*\buos\b|\buos\b.*zyxel`), "zyxel-uos"},
				{re(`zyxel`), "zyxel"},
				{re(`fireware`), "watchguard-fireware"},
				{re(`watchguard.*firebox|firebox.*watchguard`), "watchguard-fireware"},
				{re(`watchguard`), "watchguard"},
				{re(`sophos.*(?:sfos|firewall|xg)|\bsfos\b`), "sophos-sfos"},
				{re(`sophos`), "sophos"},
				{re(`fritz!?os`), "fritzos"},
				{re(`asuswrt`), "asuswrt"},
				{re(`edgeos`), "edgeos"},
				{re(`unifi.?os`), "unifi-os"},
				{re(`\bairos\b`), "airos"},
				{re(`arubaos.?cx|aos.?cx`), "arubaos-cx"},
				{re(`arubaos`), "arubaos"},
				{re(`nokia.*sr.?os|service router operating system|\btimos\b`), "nokia-sros"},
				{re(`smartfabric.*os10|dell.*\bos10\b`), "dell-os10"},
				{re(`cumulus.*linux`), "cumulus-linux"},
				{re(`\bsonic\b.*(?:software|version)`), "sonic"},
				// NAS / appliances
				{re(`synology.*(?:\bdsm\b|diskstation manager)|diskstation manager`), "synology-dsm"},
				{re(`synology.*(?:\bsrm\b|router manager)|synology router manager`), "synology-srm"},
				{re(`synology`), "synology"},
				{re(`qnap.*quts|quts.?hero`), "qnap-quts-hero"},
				{re(`qnap.*\bqts\b|\bqts\b.*qnap`), "qnap-qts"},
				{re(`qnap`), "qnap"},
				{re(`truenas.*core`), "truenas-core"},
				{re(`truenas.*scale`), "truenas-scale"},
				{re(`truenas|freenas`), "truenas"},
				{re(`vmware.*esxi|\besxi\b`), "vmware-esxi"},
				{re(`proxmox.*(?:virtual environment|\bve\b)`), "proxmox-ve"},
				{re(`openwrt|lede`), "openwrt"},
				{re(`dd.?wrt`), "dd-wrt"},
				// Software-only fallback.
				{re(`dropbear`), "dropbear"},
			},
		},

		// ===== Tier 1: SMB Native OS field. Direct Windows version string. =====
		{
			source:  "smb-native-os",
			fieldFn: func(r *records.OSRecord) string { return r.SMBNativeOS },
			patterns: []pattern{
				{re(`windows`), "windows"},
				{re(`samba`), "samba"},
			},
		},

		// ===== Tier 1: SNMP sysDescr.0 is a free-text OS description string. =====
		{
			source:  "snmp-sysdescr",
			fieldFn: func(r *records.OSRecord) string { return r.SNMPSysDescr },
			patterns: []pattern{
				// Cisco product lines often visible verbatim
				{re(`cisco.*ios.?xe`), "cisco-iosxe"},
				{re(`cisco.*ios.?xr`), "cisco-iosxr"},
				{re(`cisco.*nx.?os|nxos`), "cisco-nxos"},
				{re(`cisco.*(asa|adaptive\s+security)`), "cisco-asa"},
				{re(`firepower\s+threat\s+defense|cisco.?ftd`), "cisco-ftd"},
				{re(`cisco.*\bios\b`), "cisco-ios"},
				{re(`cisco`), "cisco"},
				{re(`routeros`), "mikrotik-routeros"},
				{re(`\bswos\b`), "mikrotik-swos"},
				{re(`mikrotik`), "mikrotik"},
				{re(`junos\s+evolved`), "juniper-junos-evolved"},
				{re(`screenos|netscreen`), "juniper-screenos"},
				{re(`junos`), "juniper-junos"},
				{re(`juniper`), "juniper"},
				{re(`(?:^|\s)vrp(?:\s|$)|versatile routing platform`), "huawei-vrp"},
				{re(`huawei`), "huawei"},
				{re(`fortios|fortigate`), "fortinet-fortios"},
				{re(`fortinet`), "fortinet"},
				{re(`pan.?os`), "paloalto-panos"},
				{re(`palo.?alto`), "palo-alto"},
				{re(`arista.*\beos\b|\beos\b.*arista`), "arista-eos"},
				{re(`arista`), "arista"},
				{re(`extreme.*exos`), "extreme-exos"},
				{re(`big.?ip`), "f5-bigip"},
				{re(`\bf5\b`), "f5"},
				{re(`gaia`), "checkpoint-gaia"},
				{re(`checkpoint|check\s+point`), "check-point"},
				{re(`dray.?os`), "drayos"},
				{re(`draytek`), "draytek"},
				{re(`sonic.?os`), "sonicos"},
				{re(`sonicwall`), "sonicwall"},
				{re(`zy.?nos`), "zynos"},
				{re(`zyxel.*\bzld\b|\bzld\b.*zyxel`), "zyxel-zld"},
				{re(`zyxel.*\buos\b|\buos\b.*zyxel`), "zyxel-uos"},
				{re(`zyxel`), "zyxel"},
				{re(`fireware`), "watchguard-fireware"},
				{re(`watchguard.*firebox|firebox.*watchguard`), "watchguard-fireware"},
				{re(`watchguard`), "watchguard"},
				{re(`sophos.*(?:sfos|firewall|xg)|\bsfos\b`), "sophos-sfos"},
				{re(`sophos`), "sophos"},
				{re(`fritz!?os`), "fritzos"},
				{re(`asuswrt`), "asuswrt"},
				{re(`edgeos`), "edgeos"},
				{re(`unifi.?os`), "unifi-os"},
				{re(`\bairos\b`), "airos"},
				{re(`arubaos.?cx|aos.?cx`), "arubaos-cx"},
				{re(`arubaos`), "arubaos"},
				{re(`nokia.*sr.?os|service router operating system|\btimos\b`), "nokia-sros"},
				{re(`smartfabric.*os10|dell.*\bos10\b`), "dell-os10"},
				{re(`cumulus.*linux`), "cumulus-linux"},
				{re(`\bsonic\b.*(?:software|version)`), "sonic"},
				// General-purpose OSes
				{re(`ubuntu`), "ubuntu"},
				{re(`debian`), "debian"},
				{re(`red.?hat|rhel`), "rhel"},
				{re(`centos`), "centos"},
				{re(`fedora`), "fedora"},
				{re(`suse|sles`), "suse"},
				{re(`freebsd`), "freebsd"},
				{re(`openbsd`), "openbsd"},
				{re(`netbsd`), "netbsd"},
				{re(`darwin|mac.?os`), "macos"},
				{re(`solaris|sunos`), "solaris"},
				{re(`aix`), "aix"},
				{re(`hp.?ux`), "hpux"},
				{re(`windows`), "windows"},
				{re(`vmware.*esxi|\besxi\b`), "vmware-esxi"},
				{re(`proxmox.*(?:virtual environment|\bve\b)`), "proxmox-ve"},
				{re(`synology.*(?:\bdsm\b|diskstation manager)|diskstation manager`), "synology-dsm"},
				{re(`synology.*(?:\bsrm\b|router manager)|synology router manager`), "synology-srm"},
				{re(`synology`), "synology"},
				{re(`qnap.*quts|quts.?hero`), "qnap-quts-hero"},
				{re(`qnap.*\bqts\b|\bqts\b.*qnap`), "qnap-qts"},
				{re(`qnap`), "qnap"},
				{re(`truenas.*core`), "truenas-core"},
				{re(`truenas.*scale`), "truenas-scale"},
				{re(`truenas|freenas`), "truenas"},
				// Printers (very common in SNMP sysDescr)
				{re(`hp\b.*(jetdirect|laserjet|officejet)`), "printer"},
				{re(`brother|epson|canon\s+(printer|imagerunner)`), "printer"},
				// Generic Linux signal
				{re(`linux`), "linux"},
			},
		},

		// ===== Tier 1: HTTP Server header (port 80). =====
		{
			source:   "http-server",
			fieldFn:  func(r *records.OSRecord) string { return r.HTTPServer },
			patterns: httpServerPatterns,
		},

		// ===== Tier 1: HTTPS Server header (port 443). =====
		{
			source:   "https-server",
			fieldFn:  func(r *records.OSRecord) string { return r.HTTPSServer },
			patterns: httpServerPatterns,
		},

		// ===== Tier 1: SMTP banner. =====
		{
			source:  "smtp",
			fieldFn: func(r *records.OSRecord) string { return r.SMTPBanner + " " + r.SMTPEHLO },
			patterns: []pattern{
				{re(`exchange|microsoft.*smtp|microsoft\s+esmtp`), "windows"},
				{re(`postfix.*\(ubuntu|\(ubuntu.*postfix`), "ubuntu"},
				{re(`postfix.*\(debian|\(debian.*postfix`), "debian"},
				{re(`exim.*\(ubuntu`), "ubuntu"},
				{re(`exim.*\(debian`), "debian"},
				{re(`mailenable`), "windows"},
				{re(`mdaemon`), "windows"},
				{re(`smartermail`), "windows"},
				{re(`opensmtpd`), "opensmtpd"},
				{re(`sendmail`), "sendmail"},
				{re(`postfix`), "postfix"},
				{re(`exim`), "exim"},
				{re(`iredmail|iredapd`), "iredmail"},
				{re(`zimbra`), "zimbra"},
			},
		},

		// ===== Tier 2: MSSQL product detection (not an OS signal). =====
		{
			source:  "mssql",
			fieldFn: func(r *records.OSRecord) string { return r.MSSQLVersion },
			patterns: []pattern{
				{re(`.+`), "microsoft-sql"},
			},
		},

		// ===== Tier 2: POP3 / IMAP banners. =====
		{
			source:   "pop3",
			fieldFn:  func(r *records.OSRecord) string { return r.POP3Banner },
			patterns: mailBannerPatterns,
		},
		{
			source:   "imap",
			fieldFn:  func(r *records.OSRecord) string { return r.IMAPBanner },
			patterns: mailBannerPatterns,
		},

		// ===== Tier 2: FTP banner. =====
		{
			source:  "ftp",
			fieldFn: func(r *records.OSRecord) string { return r.FTPBanner },
			patterns: []pattern{
				{re(`microsoft\s+ftp`), "windows"},
				{re(`filezilla.*server`), "filezilla-server"},
				{re(`serv.?u\s+ftp`), "serv-u"},
				{re(`proftpd.*\(debian`), "debian"},
				{re(`proftpd.*\(ubuntu`), "ubuntu"},
				{re(`proftpd`), "proftpd"},
				{re(`vsftpd`), "vsftpd"},
				{re(`pure.?ftpd`), "pure-ftpd"},
				{re(`routeros`), "mikrotik-routeros"},
				{re(`mikrotik`), "mikrotik"},
				{re(`cisco`), "cisco"},
			},
		},

		// ===== Tier 2: Telnet banner. Often network-gear. =====
		{
			source:  "telnet",
			fieldFn: func(r *records.OSRecord) string { return r.TelnetBanner },
			patterns: []pattern{
				{re(`cisco.*ios.?xe`), "cisco-iosxe"},
				{re(`cisco.*ios.?xr`), "cisco-iosxr"},
				{re(`cisco.*nx.?os`), "cisco-nxos"},
				{re(`cisco.*\bios\b`), "cisco-ios"},
				{re(`cisco`), "cisco"},
				{re(`routeros`), "mikrotik-routeros"},
				{re(`\bswos\b`), "mikrotik-swos"},
				{re(`mikrotik`), "mikrotik"},
				{re(`(?:^|\s)vrp(?:\s|$)`), "huawei-vrp"},
				{re(`huawei`), "huawei"},
				{re(`junos\s+evolved`), "juniper-junos-evolved"},
				{re(`screenos|netscreen`), "juniper-screenos"},
				{re(`junos`), "juniper-junos"},
				{re(`juniper`), "juniper"},
				{re(`dray.?os`), "drayos"},
				{re(`draytek`), "draytek"},
				{re(`sonic.?os`), "sonicos"},
				{re(`sonicwall`), "sonicwall"},
				{re(`zy.?nos`), "zynos"},
				{re(`zyxel`), "zyxel"},
				{re(`fireware`), "watchguard-fireware"},
				{re(`fritz!?os`), "fritzos"},
				{re(`hp.*comware`), "hp-comware"},
				{re(`hp.*procurve`), "hp-procurve"},
				{re(`zte`), "zte"},
				{re(`dlink|d-link`), "dlink"},
				{re(`tp.?link`), "tp-link"},
				{re(`ubuntu`), "ubuntu"},
				{re(`debian`), "debian"},
				{re(`busybox`), "busybox"},
			},
		},

		// ===== Tier 2: DNS CHAOS software detection. =====
		{
			source:  "dns-chaos",
			fieldFn: func(r *records.OSRecord) string { return r.DNSVersionBind },
			patterns: []pattern{
				{re(`unbound`), "unbound"},
				{re(`powerdns|pdns`), "powerdns"},
				// BIND on Windows has explicit "ms" in the version sometimes.
				{re(`bind.*microsoft|bind.*windows`), "windows"},
				{re(`bind`), "bind"},
				{re(`dnsmasq`), "dnsmasq"},
				{re(`knot.dns`), "knot-dns"},
			},
		},
		{
			source:  "dns-chaos-hostname",
			fieldFn: func(r *records.OSRecord) string { return r.DNSHostnameBind },
			patterns: []pattern{
				{re(`\.ubuntu\.|^ubuntu`), "hostname-ubuntu"},
				{re(`\.debian\.|^debian`), "hostname-debian"},
				{re(`\.fedora\.|^fedora`), "hostname-fedora"},
				{re(`\.freebsd\.|^freebsd`), "hostname-freebsd"},
			},
		},

		// ===== Last-resort fallbacks. Weak but better than nothing. =====
		{
			source:  "https-cert",
			fieldFn: func(r *records.OSRecord) string { return r.HTTPSCertIssuer + " " + r.HTTPSCertSubject },
			patterns: []pattern{
				{re(`microsoft.*tls|microsoft.*it.*ca`), "microsoft"},
				{re(`synology.*(?:\bdsm\b|diskstation manager)|diskstation manager`), "synology-dsm"},
				{re(`synology`), "synology"},
				{re(`qnap.*quts|quts.?hero`), "qnap-quts-hero"},
				{re(`qnap.*\bqts\b|\bqts\b.*qnap`), "qnap-qts"},
				{re(`qnap`), "qnap"},
				{re(`pfsense`), "pfsense"},
				{re(`opnsense`), "opnsense"},
				{re(`routeros`), "mikrotik-routeros"},
				{re(`mikrotik`), "mikrotik"},
				{re(`fortios|fortigate`), "fortinet-fortios"},
				{re(`fortinet`), "fortinet"},
				{re(`pan.?os`), "paloalto-panos"},
				{re(`palo.?alto`), "palo-alto"},
				{re(`sonic.?os`), "sonicos"},
				{re(`sonicwall.*(?:firewall|\btz\d|\bnsa?\d|\bnssp?\d|\bnsv\b)`), "sonicos"},
				{re(`sonicwall`), "sonicwall"},
				{re(`dray.?os`), "drayos"},
				{re(`draytek`), "draytek"},
				{re(`zy.?nos`), "zynos"},
				{re(`zyxel`), "zyxel"},
				{re(`fireware`), "watchguard-fireware"},
				{re(`watchguard.*firebox|firebox.*watchguard`), "watchguard-fireware"},
				{re(`watchguard`), "watchguard"},
				{re(`sophos.*(?:sfos|firewall|xg)|\bsfos\b`), "sophos-sfos"},
				{re(`sophos`), "sophos"},
				{re(`unifi.?os`), "unifi-os"},
				{re(`unifi`), "ubiquiti"},
				{re(`vmware.*esxi|\besxi\b`), "vmware-esxi"},
				{re(`proxmox.*(?:virtual environment|\bve\b)`), "proxmox-ve"},
			},
		},

		// ===== HTTP Server header generic fallback (if first run above didn't match). =====
		{
			source:   "http-server-fallback",
			fieldFn:  func(r *records.OSRecord) string { return r.HTTPServer + " " + r.HTTPSServer },
			patterns: httpServerFallbackPatterns,
		},
	}
}

// httpServerPatterns are the high-confidence HTTP Server header rules.
// Order matters: more specific patterns first.
var httpServerPatterns = []pattern{
	// Windows / IIS
	{re(`microsoft.?iis|microsoft.?httpapi`), "windows"},
	// Distro-tagged nginx/apache builds (the parenthesised distro)
	{re(`\(ubuntu`), "ubuntu"},
	{re(`\(debian`), "debian"},
	{re(`\(raspbian`), "raspbian"},
	{re(`\(centos`), "centos"},
	{re(`\(red.?hat|\(rhel`), "rhel"},
	{re(`\(fedora`), "fedora"},
	{re(`\(rocky`), "rocky"},
	{re(`\(alma|\(almalinux`), "alma"},
	{re(`\(amazon|amzn`), "amazon-linux"},
	{re(`\(oracle`), "oracle-linux"},
	{re(`\(suse|\(sles`), "suse"},
	{re(`\(alpine`), "alpine"},
	{re(`\(arch`), "arch"},
	{re(`\(freebsd`), "freebsd"},
	{re(`\(openbsd`), "openbsd"},
	{re(`\(netbsd`), "netbsd"},
	{re(`\(darwin|\(macos|\(mac.?os.x`), "macos"},
	// Network gear & appliances
	{re(`router.?os|routeros`), "mikrotik-routeros"},
	{re(`\bswos\b`), "mikrotik-swos"},
	{re(`mikrotik`), "mikrotik"},
	{re(`cisco.*ios.?xe`), "cisco-iosxe"},
	{re(`cisco.*ios.?xr`), "cisco-iosxr"},
	{re(`cisco.*nx.?os|nxos`), "cisco-nxos"},
	{re(`cisco.*(?:asa|adaptive\s+security)`), "cisco-asa"},
	{re(`firepower\s+threat\s+defense|cisco.?ftd`), "cisco-ftd"},
	{re(`cisco.*\bios\b`), "cisco-ios"},
	{re(`cisco`), "cisco"},
	{re(`fortios|fortigate`), "fortinet-fortios"},
	{re(`fortinet`), "fortinet"},
	{re(`pan.?os`), "paloalto-panos"},
	{re(`palo.?alto`), "palo-alto"},
	{re(`junos\s+evolved`), "juniper-junos-evolved"},
	{re(`screenos|netscreen`), "juniper-screenos"},
	{re(`junos`), "juniper-junos"},
	{re(`juniper`), "juniper"},
	{re(`dray.?os`), "drayos"},
	{re(`draytek`), "draytek"},
	{re(`sonic.?os`), "sonicos"},
	{re(`sonicwall.*(?:firewall|\btz\d|\bnsa?\d|\bnssp?\d|\bnsv\b)`), "sonicos"},
	{re(`sonicwall`), "sonicwall"},
	{re(`zy.?nos`), "zynos"},
	{re(`zyxel.*\bzld\b|\bzld\b.*zyxel`), "zyxel-zld"},
	{re(`zyxel.*\buos\b|\buos\b.*zyxel`), "zyxel-uos"},
	{re(`zyxel`), "zyxel"},
	{re(`fireware`), "watchguard-fireware"},
	{re(`watchguard.*firebox|firebox.*watchguard`), "watchguard-fireware"},
	{re(`watchguard`), "watchguard"},
	{re(`sophos.*(?:sfos|firewall|xg)|\bsfos\b`), "sophos-sfos"},
	{re(`sophos`), "sophos"},
	{re(`fritz!?os`), "fritzos"},
	{re(`asuswrt`), "asuswrt"},
	{re(`edgeos`), "edgeos"},
	{re(`unifi.?os`), "unifi-os"},
	{re(`\bairos\b`), "airos"},
	{re(`arubaos.?cx|aos.?cx`), "arubaos-cx"},
	{re(`arubaos`), "arubaos"},
	{re(`nokia.*sr.?os|service router operating system|\btimos\b`), "nokia-sros"},
	{re(`smartfabric.*os10|dell.*\bos10\b`), "dell-os10"},
	{re(`cumulus.*linux`), "cumulus-linux"},
	{re(`\bsonic\b.*(?:software|version)`), "sonic"},
	{re(`synology.*(?:\bdsm\b|diskstation manager)|diskstation manager`), "synology-dsm"},
	{re(`synology.*(?:\bsrm\b|router manager)|synology router manager`), "synology-srm"},
	{re(`synology`), "synology"},
	{re(`qnap.*quts|quts.?hero`), "qnap-quts-hero"},
	{re(`qnap.*\bqts\b|\bqts\b.*qnap`), "qnap-qts"},
	{re(`qnap`), "qnap"},
	{re(`truenas.*core`), "truenas-core"},
	{re(`truenas.*scale`), "truenas-scale"},
	{re(`truenas|freenas`), "truenas"},
	{re(`vmware.*esxi|\besxi\b`), "vmware-esxi"},
	{re(`proxmox.*(?:virtual environment|\bve\b)`), "proxmox-ve"},
	{re(`pfsense`), "pfsense"},
	{re(`opnsense`), "opnsense"},
	{re(`openwrt|luci`), "openwrt"},
	{re(`unifi`), "ubiquiti"},
}

// httpServerFallbackPatterns are very generic indicators.
var httpServerFallbackPatterns = []pattern{
	{re(`jetdirect|laserjet|officejet|hp printer`), "printer"},
	{re(`brother|epson|canon\s+printer`), "printer"},
	// Server software is useful evidence but does not identify the host OS.
	{re(`^nginx(/|$|\s)`), "nginx"},
	{re(`^apache`), "apache"},
	{re(`^lighttpd`), "lighttpd"},
	{re(`^caddy`), "caddy"},
	// Generic "Server: " with the literal "linux" / "unix" string
	{re(`linux`), "linux"},
	{re(`unix`), "unix"},
	// Generic router web-interface markers
	{re(`router|gateway`), "router"},
	{re(`server`), "server"},
}

// mailBannerPatterns is shared between POP3 and IMAP rules.
var mailBannerPatterns = []pattern{
	{re(`microsoft.*(pop3|imap)|microsoft\s+exchange`), "windows"},
	{re(`dovecot.*(ubuntu)`), "ubuntu"},
	{re(`dovecot.*(debian)`), "debian"},
	{re(`dovecot`), "dovecot"},
	{re(`cyrus.*(ubuntu)`), "ubuntu"},
	{re(`cyrus.*(debian)`), "debian"},
	{re(`cyrus`), "cyrus"},
	{re(`courier`), "courier"},
	{re(`mdaemon|mailenable`), "windows"},
	{re(`zimbra`), "zimbra"},
}

// CleanBanner used by tests and the merger to normalise / clean banner text.
func CleanBanner(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f:
			// drop other control chars
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
