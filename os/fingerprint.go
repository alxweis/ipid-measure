package os

import (
	"regexp"
	"strings"

	"github.com/netd-tud/ipid-measure/internal/records"
)

// Fingerprint derives the OS family from the per-service raw strings populated
// in an OSRecord. Returns "" + "" when no rule matched -- in that case the
// caller MUST NOT write the record (we keep os.pq dense in useful data).
//
// Rules are ordered from "very high confidence" to "very low / fallback".
// First match wins. The rule's name is returned as OS_SOURCE so analytics
// can attribute coverage to data sources.
//
// All regexes are pre-compiled at package init.
func Fingerprint(r *records.OSRecord) (osName, osSource string) {
	for _, rule := range rules {
		field := rule.fieldFn(r)
		if field == "" {
			continue
		}
		if name := rule.match(field); name != "" {
			return name, rule.source
		}
	}
	return "", ""
}

// rule is one extraction attempt: pull a string out of the record via fieldFn,
// run all the rule's regex patterns over it, return the first match's
// normalised OS name.
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

// re compiles a case-insensitive regex (fingerprint banners are unreliable
// about casing). Panics on bad pattern -- those are bugs caught at init time.
func re(s string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + s)
}

// rules is the global priority-ordered rule list. Built once at init. The
// order is from "most specific, highest signal" to "least specific, fallback".
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
				{re(`el(7|8|9|10)|centos|\.rhel|red.?hat`), "rhel"},
				{re(`fedora`), "fedora"},
				{re(`rocky`), "rocky"},
				{re(`almalinux|alma`), "alma"},
				{re(`amazon|amzn`), "amazon-linux"},
				{re(`oracle.*linux|oraclelinux`), "oracle-linux"},
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
				{re(`cisco`), "cisco-ios"},
				{re(`mikrotik|routeros`), "mikrotik-routeros"},
				{re(`juniper|junos`), "juniper-junos"},
				{re(`huawei|^vrp`), "huawei-vrp"},
				{re(`fortinet|fortigate|fortios`), "fortinet-fortios"},
				{re(`paloalto|panos`), "paloalto-panos"},
				{re(`vyos|vyatta`), "vyos"},
				{re(`pfsense`), "pfsense"},
				{re(`opnsense`), "opnsense"},
				{re(`arista|eos`), "arista-eos"},
				{re(`f5|big.?ip`), "f5-bigip"},
				{re(`checkpoint|gaia`), "checkpoint-gaia"},
				// NAS / appliances
				{re(`synology`), "synology"},
				{re(`qnap`), "qnap"},
				{re(`truenas|freenas`), "truenas"},
				{re(`openwrt|lede`), "openwrt"},
				{re(`dd.?wrt`), "dd-wrt"},
				// Generic Linux fallback (Dropbear is common on embedded Linux)
				{re(`dropbear`), "linux"},
			},
		},

		// ===== Tier 1: SMB Native OS field. Direct Windows version string. =====
		{
			source:  "smb-native-os",
			fieldFn: func(r *records.OSRecord) string { return r.SMBNativeOS },
			patterns: []pattern{
				{re(`windows`), "windows"},
				{re(`samba`), "linux"}, // Samba runs almost exclusively on Linux/BSD
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
				{re(`cisco`), "cisco-ios"},
				{re(`mikrotik|routeros`), "mikrotik-routeros"},
				{re(`juniper|junos`), "juniper-junos"},
				{re(`huawei|^vrp|versatile routing platform`), "huawei-vrp"},
				{re(`fortinet|fortigate`), "fortinet-fortios"},
				{re(`palo.?alto|panos`), "paloalto-panos"},
				{re(`arista`), "arista-eos"},
				{re(`extreme.*exos`), "extreme-exos"},
				{re(`f5|big.?ip`), "f5-bigip"},
				{re(`checkpoint|gaia`), "checkpoint-gaia"},
				// General-purpose OSes
				{re(`ubuntu`), "ubuntu"},
				{re(`debian`), "debian"},
				{re(`red.?hat|rhel`), "rhel"},
				{re(`centos`), "rhel"},
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
				{re(`opensmtpd`), "openbsd"},
				{re(`sendmail`), "linux"},
				{re(`postfix`), "linux"},
				{re(`exim`), "linux"},
				{re(`iredmail|iredapd`), "linux"},
				{re(`zimbra`), "linux"},
			},
		},

		// ===== Tier 2: MSSQL is always Windows. =====
		{
			source:  "mssql",
			fieldFn: func(r *records.OSRecord) string { return r.MSSQLVersion },
			patterns: []pattern{
				{re(`.+`), "windows"}, // any non-empty MSSQL version field
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
				{re(`filezilla.*server`), "windows"},
				{re(`serv.?u\s+ftp`), "windows"},
				{re(`proftpd.*\(debian`), "debian"},
				{re(`proftpd.*\(ubuntu`), "ubuntu"},
				{re(`proftpd`), "linux"},
				{re(`vsftpd`), "linux"},
				{re(`pure.?ftpd`), "linux"},
				{re(`mikrotik`), "mikrotik-routeros"},
				{re(`cisco`), "cisco-ios"},
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
				{re(`cisco`), "cisco-ios"},
				{re(`mikrotik|routeros`), "mikrotik-routeros"},
				{re(`huawei|^vrp`), "huawei-vrp"},
				{re(`juniper`), "juniper-junos"},
				{re(`hp.*procurve|hp.*comware`), "hp-comware"},
				{re(`zte`), "zte"},
				{re(`dlink|d-link`), "embedded"},
				{re(`tp.?link`), "embedded"},
				{re(`ubuntu`), "ubuntu"},
				{re(`debian`), "debian"},
				{re(`busybox`), "linux"},
			},
		},

		// ===== Tier 2: DNS CHAOS. Lowest priority -- indirect OS signal. =====
		{
			source:  "dns-chaos",
			fieldFn: func(r *records.OSRecord) string { return r.DNSVersionBind },
			patterns: []pattern{
				// Unbound is the default base resolver on FreeBSD and OpenBSD,
				// so when CHAOS version.bind reports Unbound on an otherwise
				// unfingerprinted host this is a (weak) BSD signal.
				{re(`unbound`), "bsd"},
				// PowerDNS is a strong Linux signal.
				{re(`powerdns|pdns`), "linux"},
				// BIND on Windows has explicit "ms" in the version sometimes.
				{re(`bind.*microsoft|bind.*windows`), "windows"},
				// dnsmasq is overwhelmingly Linux.
				{re(`dnsmasq`), "linux"},
				// Knot is Linux-default but cross-platform; weak signal.
				{re(`knot.dns`), "linux"},
			},
		},
		{
			source:  "dns-chaos-hostname",
			fieldFn: func(r *records.OSRecord) string { return r.DNSHostnameBind },
			patterns: []pattern{
				{re(`\.ubuntu\.|^ubuntu`), "ubuntu"},
				{re(`\.debian\.|^debian`), "debian"},
				{re(`\.fedora\.|^fedora`), "fedora"},
				{re(`\.freebsd\.|^freebsd`), "freebsd"},
			},
		},

		// ===== Last-resort fallbacks. Weak but better than nothing. =====
		// HTTPS cert metadata sometimes hints at OS family.
		{
			source:  "https-cert",
			fieldFn: func(r *records.OSRecord) string { return r.HTTPSCertIssuer + " " + r.HTTPSCertSubject },
			patterns: []pattern{
				{re(`microsoft.*tls|microsoft.*it.*ca`), "windows"},
				{re(`synology`), "synology"},
				{re(`qnap`), "qnap"},
				{re(`pfsense`), "pfsense"},
				{re(`opnsense`), "opnsense"},
				{re(`mikrotik`), "mikrotik-routeros"},
				{re(`fortigate|fortinet`), "fortinet-fortios"},
				{re(`paloalto`), "paloalto-panos"},
				{re(`unifi`), "embedded"},
			},
		},

		// ===== HTTP Server header generic fallback (if first run above didn't match). =====
		// We run httpServerFallbackPatterns last so very generic strings only
		// trigger when nothing more specific did.
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
	{re(`\(centos`), "rhel"},
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
	{re(`mikrotik`), "mikrotik-routeros"},
	{re(`cisco`), "cisco-ios"},
	{re(`fortinet|fortigate`), "fortinet-fortios"},
	{re(`paloalto|panos`), "paloalto-panos"},
	{re(`synology`), "synology"},
	{re(`qnap`), "qnap"},
	{re(`pfsense`), "pfsense"},
	{re(`opnsense`), "opnsense"},
	{re(`openwrt|luci`), "openwrt"},
	{re(`unifi`), "embedded"},
	{re(`router.?os|routeros`), "mikrotik-routeros"},
}

// httpServerFallbackPatterns are very generic indicators -- used only when
// nothing more specific matched anywhere else.
var httpServerFallbackPatterns = []pattern{
	{re(`jetdirect|laserjet|officejet|hp printer`), "printer"},
	{re(`brother|epson|canon\s+printer`), "printer"},
	// "Server: nginx" alone gives no distro; treat as linux (statistically very likely)
	{re(`^nginx(/|$|\s)`), "linux"},
	{re(`^apache`), "linux"},
	{re(`^lighttpd`), "linux"},
	{re(`^caddy`), "linux"},
	// Generic "Server: " with the literal "linux" / "unix" string
	{re(`linux`), "linux"},
	{re(`unix`), "unix"},
	// Generic router web-interface markers
	{re(`router|gateway`), "router"},
}

// mailBannerPatterns is shared between POP3 and IMAP rules. The same software
// names appear in both.
var mailBannerPatterns = []pattern{
	{re(`microsoft.*(pop3|imap)|microsoft\s+exchange`), "windows"},
	{re(`dovecot.*(ubuntu)`), "ubuntu"},
	{re(`dovecot.*(debian)`), "debian"},
	{re(`dovecot`), "linux"},
	{re(`cyrus.*(ubuntu)`), "ubuntu"},
	{re(`cyrus.*(debian)`), "debian"},
	{re(`cyrus`), "linux"},
	{re(`courier`), "linux"},
	{re(`mdaemon|mailenable`), "windows"},
	{re(`zimbra`), "linux"},
}

// Helper used by tests and the merger to normalise / clean banner text before
// it lands in the parquet (trim, single-line, strip control chars).
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
