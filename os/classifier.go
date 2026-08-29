package os

import (
	"regexp"
	"sort"
)

const (
	SchemaVersion     = "3"
	ClassifierVersion = "3"

	statusResolved     = "resolved"
	statusAmbiguous    = "ambiguous"
	statusUnclassified = "unclassified"
)

type tagRule struct {
	tag string
	re  *regexp.Regexp
}

func tagRE(expression string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + expression)
}

// tagRules is deliberately ordered from specific product/OS names to broader
// families. The first match within one service evidence string wins. Distinctive
// indicators longer than three letters may match as substrings. Indicators of
// at most three letters use non-letter boundaries, so digits and punctuation
// remain valid neighbours. Ambiguous short indicators additionally require
// vendor context.
var tagRules = []tagRule{
	// Cisco product families.
	{"cisco-iosxe", tagRE(`(?:cisco[^a-z0-9]*)?ios[-_. ]?xe`)},
	{"cisco-iosxr", tagRE(`(?:cisco[^a-z0-9]*)?ios[-_. ]?xr`)},
	{"cisco-nxos", tagRE(`(?:cisco[^a-z0-9]*)?nx[-_. ]?os`)},
	{"cisco-ftd", tagRE(`firepower\s+threat\s+defense|cisco[-_. ]?ftd`)},
	{"cisco-asa", tagRE(`cisco.*(?:adaptive\s+security|(?:^|[^\p{L}])asa(?:[^\p{L}]|$))`)},
	{"cisco-ios", tagRE(`cisco.*(?:^|[^a-z0-9])ios(?:[^a-z0-9]|$)`)},

	// Network operating systems and appliance products.
	{"juniper-junos-evolved", tagRE(`junos\s+evolved`)},
	{"juniper-screenos", tagRE(`screen[-_. ]?os|netscreen`)},
	{"juniper-junos", tagRE(`junos`)},
	{"mikrotik-routeros", tagRE(`router[-_. ]?os`)},
	{"mikrotik-swos", tagRE(`sw[-_. ]?os`)},
	{"huawei-vrp", tagRE(`versatile\s+routing\s+platform|(?:^|[^\p{L}])vrp(?:[^\p{L}]|$)`)},
	{"fortinet-fortios", tagRE(`forti[-_. ]?os|fortigate`)},
	{"paloalto-panos", tagRE(`pan[-_. ]?os`)},
	{"checkpoint-gaia", tagRE(`gaia`)},
	{"f5-bigip", tagRE(`f5.*big[-_. ]?ip|big[-_. ]?ip`)},
	{"arubaos-cx", tagRE(`aruba[-_. ]?os[-_. ]?cx|aos[-_. ]?cx`)},
	{"arubaos", tagRE(`aruba[-_. ]?os`)},
	{"arista-eos", tagRE(`arista.*(?:^|[^\p{L}])eos(?:[^\p{L}]|$)`)},
	{"extreme-exos", tagRE(`extreme.*ex[-_. ]?os`)},
	{"nokia-sros", tagRE(`nokia.*sr[-_. ]?os|service\s+router\s+operating\s+system|timos`)},
	{"dell-os10", tagRE(`dell.*(?:^|[^a-z0-9])os[-_. ]?10(?:[^a-z0-9]|$)|smartfabric.*os[-_. ]?10`)},
	{"brocade-fos", tagRE(`brocade.*fabric[-_. ]?os|fabric[-_. ]?os.*brocade`)},
	{"hpe-comware", tagRE(`comware`)},
	{"hpe-procurve", tagRE(`procurve`)},
	{"cumulus-linux", tagRE(`cumulus\s+linux`)},
	{"sonicos", tagRE(`sonic[-_. ]?os|sonicwall.*(?:firewall|tz[0-9]|nsa?[0-9]|nssp?[0-9]|nsv)`)},
	{"sonic", tagRE(`^sonic$|(?:^|[^a-z0-9])sonic(?:[^a-z0-9]|$).*(?:software|version)|(?:software|version).*(?:^|[^a-z0-9])sonic(?:[^a-z0-9]|$)`)},
	{"zynos", tagRE(`zy[-_. ]?nos`)},
	{"zyxel-zld", tagRE(`zyxel.*(?:^|[^\p{L}])zld(?:[^\p{L}]|$)`)},
	{"zyxel-uos", tagRE(`zyxel.*(?:^|[^\p{L}])uos(?:[^\p{L}]|$)`)},
	{"drayos", tagRE(`dray[-_. ]?os`)},
	{"watchguard-fireware", tagRE(`fireware|watchguard.*firebox|firebox.*watchguard`)},
	{"sophos-sfos", tagRE(`sfos|sophos.*(?:firewall|xg)`)},
	{"fritzos", tagRE(`fritz`)},
	{"asuswrt", tagRE(`asus[-_. ]?wrt`)},
	{"edgeos", tagRE(`edge[-_. ]?os`)},
	{"unifi-os", tagRE(`unifi[-_. ]?os`)},
	{"airos", tagRE(`air[-_. ]?os`)},
	{"openwrt", tagRE(`open[-_. ]?wrt|lede`)},
	{"dd-wrt", tagRE(`dd[-_. ]?wrt`)},
	{"wrt", tagRE(`(?:^|[^\p{L}])wrt(?:[^\p{L}]|$)`)},
	{"pfsense", tagRE(`pf[-_. ]?sense`)},
	{"opnsense", tagRE(`opn[-_. ]?sense`)},
	{"vyos", tagRE(`vyos`)},
	{"vyatta", tagRE(`vyatta`)},

	// NAS, virtualization, and appliance operating systems.
	{"synology-dsm", tagRE(`synology.*(?:^|[^\p{L}])dsm(?:[^\p{L}]|$)|diskstation\s+manager`)},
	{"synology-srm", tagRE(`synology.*(?:^|[^\p{L}])srm(?:[^\p{L}]|$)|synology\s+router\s+manager`)},
	{"qnap-quts-hero", tagRE(`qnap.*quts|quts[-_. ]?hero`)},
	{"qnap-qts", tagRE(`qnap.*(?:^|[^\p{L}])qts(?:[^\p{L}]|$)`)},
	{"truenas-core", tagRE(`truenas.*core`)},
	{"truenas-scale", tagRE(`truenas.*scale`)},
	{"vmware-esxi", tagRE(`esxi`)},
	{"proxmox-ve", tagRE(`proxmox.*(?:virtual\s+environment|(?:^|[^\p{L}])ve(?:[^\p{L}]|$))`)},

	// General-purpose distributions: specific distributions precede Linux.
	{"raspbian", tagRE(`rasp`)},
	{"ubuntu", tagRE(`ubuntu`)},
	{"debian", tagRE(`debian|(?:^|[._+-])deb[0-9]+(?:[._+-]|$)`)},
	{"almalinux", tagRE(`alma`)},
	{"rocky-linux", tagRE(`rocky`)},
	{"oracle-linux", tagRE(`oracle.*linux`)},
	{"amazon-linux", tagRE(`amazon\s+linux|(?:^|[._+-])amzn(?:[0-9._+-]|$)`)},
	{"kali-linux", tagRE(`kali`)},
	{"linux-mint", tagRE(`linux[-_. ]?mint`)},
	{"manjaro", tagRE(`manjaro`)},
	{"nixos", tagRE(`nix[-_. ]?os`)},
	{"clear-linux", tagRE(`clear[-_. ]?linux`)},
	{"photon-os", tagRE(`vmware.*photon|photon[-_. ]?os`)},
	{"flatcar", tagRE(`flatcar`)},
	{"coreos", tagRE(`core[-_. ]?os`)},
	{"slackware", tagRE(`slackware`)},
	{"centos", tagRE(`cent[-_. ]?os`)},
	{"rhel", tagRE(`red\s*hat|ret\s*hat|rhel|(?:^|[._+-])el(?:7|8|9|10)(?:[._+-]|$)`)},
	{"fedora", tagRE(`fedora`)},
	{"opensuse", tagRE(`open[-_. ]?suse`)},
	{"suse", tagRE(`suse|sles`)},
	{"euleros", tagRE(`euler[-_. ]?os`)},
	{"zorin", tagRE(`zorin`)},
	{"alpine", tagRE(`alpine`)},
	{"arch-linux", tagRE(`arch\s+linux`)},
	{"gentoo", tagRE(`gentoo`)},
	{"openembedded", tagRE(`openembedded`)},
	{"yocto", tagRE(`yocto`)},

	// BSD/Unix/RTOS families.
	{"freebsd", tagRE(`free[-_. ]?bsd`)},
	{"openbsd", tagRE(`open[-_. ]?bsd`)},
	{"netbsd", tagRE(`net[-_. ]?bsd`)},
	{"macos", tagRE(`mac[-_. ]?os|darwin`)},
	{"apple-ios", tagRE(`apple.*(?:^|[^a-z0-9])ios(?:[^a-z0-9]|$)`)},
	{"android", tagRE(`android`)},
	{"chromeos", tagRE(`chrome[-_. ]?os`)},
	{"solaris", tagRE(`solaris|sun[-_. ]?os`)},
	{"aix", tagRE(`(?:^|[^\p{L}])aix(?:[^\p{L}]|$)`)},
	{"hpux", tagRE(`hp[-_. ]?ux`)},
	{"zos", tagRE(`(?:^|[^\p{L}])z/?os(?:[^\p{L}]|$)`)},
	{"openvms", tagRE(`open[-_. ]?vms|(?:^|[^\p{L}])vms(?:[^\p{L}]|$)`)},
	{"vxworks", tagRE(`vx[-_. ]?works`)},
	{"qnx", tagRE(`(?:^|[^\p{L}])qnx(?:[^\p{L}]|$)`)},
	{"freertos", tagRE(`free[-_. ]?rtos`)},

	// Windows products and known bounded abbreviations.
	{"windows", tagRE(`windows|microsoft|lanman|(?:^|[^\p{L}])win(?:[^\p{L}]|$)`)},

	// Generic vendor/family tags follow their product-specific variants.
	{"apple", tagRE(`apple`)},
	{"cisco", tagRE(`cisco`)},
	{"juniper", tagRE(`juniper`)},
	{"mikrotik", tagRE(`mikrotik`)},
	{"huawei", tagRE(`huawei`)},
	{"fortinet", tagRE(`forti`)},
	{"palo-alto", tagRE(`palo[-_. ]?alto`)},
	{"check-point", tagRE(`check\s*point`)},
	{"f5", tagRE(`(?:^|[^\p{L}])f5(?:[^\p{L}]|$)`)},
	{"aruba", tagRE(`aruba`)},
	{"arista", tagRE(`arista`)},
	{"sonicwall", tagRE(`sonicwall`)},
	{"zyxel", tagRE(`zyxel`)},
	{"draytek", tagRE(`draytek|vigor|dray`)},
	{"watchguard", tagRE(`watchguard`)},
	{"sophos", tagRE(`sophos`)},
	{"ubiquiti", tagRE(`ubiquiti|unifi`)},
	{"synology", tagRE(`synology`)},
	{"qnap", tagRE(`qnap`)},
	{"truenas", tagRE(`truenas|freenas`)},
	{"zte", tagRE(`(?:^|[^\p{L}])zte(?:[^\p{L}]|$)`)},
	{"d-link", tagRE(`d[-_. ]?link`)},
	{"tp-link", tagRE(`tp[-_. ]?link`)},
	{"netgear", tagRE(`netgear`)},

	// Broad OS families are deliberately last.
	{"busybox", tagRE(`busybox`)},
	{"bsd", tagRE(`(?:^|[^\p{L}])bsd(?:[^\p{L}]|$)`)},
	{"linux", tagRE(`linux`)},
	{"utm", tagRE(`(?:^|[^\p{L}])utm(?:[^\p{L}]|$)`)},
	{"embedded", tagRE(`embedded`)},
	{"printer", tagRE(`printer`)},
	{"router", tagRE(`router`)},
	{"server", tagRE(`server`)},
}

func detectTag(evidence string) string {
	if evidence == "" {
		return ""
	}
	for _, rule := range tagRules {
		if rule.re.MatchString(evidence) {
			return rule.tag
		}
	}
	return ""
}

type serviceTags struct {
	SSH, SMB, HTTP, HTTPS, SNMP, DNS string
}

func classifyServices(e evidenceRecord) serviceTags {
	return serviceTags{
		SSH:   detectTag(e.SSHServerID),
		SMB:   detectTag(e.SMBNativeOS),
		HTTP:  detectTag(e.HTTPServer),
		HTTPS: detectTag(e.HTTPSServer),
		SNMP:  detectTag(e.SNMPSysDescr),
		DNS:   detectTag(e.DNSVersionBind),
	}
}

func (t serviceTags) values() []string {
	values := []string{t.SSH, t.SMB, t.HTTP, t.HTTPS, t.SNMP, t.DNS}
	out := values[:0]
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func (t serviceTags) hasAny() bool {
	return t.SSH != "" || t.SMB != "" || t.HTTP != "" ||
		t.HTTPS != "" || t.SNMP != "" || t.DNS != ""
}

type decision struct {
	status    string
	tag       string
	conflicts []string
}

func resolveTags(tags serviceTags) decision {
	values := tags.values()
	if len(values) == 0 {
		return decision{status: statusUnclassified}
	}
	selected := values[0]
	for _, candidate := range values[1:] {
		switch {
		case candidate == selected, isAncestor(candidate, selected):
			// selected is already at least as specific.
		case isAncestor(selected, candidate):
			selected = candidate
		default:
			conflicts := uniqueSorted(values)
			return decision{status: statusAmbiguous, conflicts: conflicts}
		}
	}
	return decision{status: statusResolved, tag: selected}
}

func isAncestor(ancestor, descendant string) bool {
	for current := parentTag[descendant]; current != ""; current = parentTag[current] {
		if current == ancestor {
			return true
		}
	}
	return false
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// parentTag encodes compatibility/specificity across independent services.
var parentTag = map[string]string{
	"raspbian": "debian", "ubuntu": "linux", "debian": "linux",
	"almalinux": "rhel", "rocky-linux": "rhel", "oracle-linux": "rhel",
	"centos": "rhel", "rhel": "linux", "fedora": "linux",
	"amazon-linux": "linux", "opensuse": "suse", "suse": "linux",
	"euleros": "linux", "zorin": "ubuntu", "alpine": "linux",
	"arch-linux": "linux", "gentoo": "linux", "openembedded": "linux",
	"yocto": "linux", "cumulus-linux": "linux", "kali-linux": "debian",
	"linux-mint": "ubuntu", "manjaro": "linux", "nixos": "linux",
	"clear-linux": "linux", "photon-os": "linux", "flatcar": "linux",
	"coreos": "linux", "slackware": "linux", "busybox": "linux",
	"android": "linux", "chromeos": "linux", "proxmox-ve": "debian",
	"linux": "server", "windows": "server", "bsd": "server",

	"freebsd": "bsd", "openbsd": "bsd", "netbsd": "bsd",
	"apple-ios": "apple", "macos": "apple",

	"cisco-iosxe": "cisco-ios", "cisco-iosxr": "cisco-ios",
	"cisco-ios": "cisco", "cisco-nxos": "cisco", "cisco-asa": "cisco",
	"cisco-ftd":     "cisco",
	"juniper-junos": "juniper", "juniper-junos-evolved": "juniper",
	"juniper-screenos":  "juniper",
	"mikrotik-routeros": "mikrotik", "mikrotik-swos": "mikrotik",
	"huawei-vrp": "huawei", "fortinet-fortios": "fortinet",
	"paloalto-panos": "palo-alto", "checkpoint-gaia": "check-point",
	"f5-bigip": "f5", "arubaos": "aruba", "arubaos-cx": "aruba",
	"arista-eos": "arista", "sonicos": "sonicwall",
	"zynos": "zyxel", "zyxel-zld": "zyxel", "zyxel-uos": "zyxel",
	"drayos": "draytek", "watchguard-fireware": "watchguard",
	"sophos-sfos": "sophos", "edgeos": "ubiquiti", "unifi-os": "ubiquiti",
	"airos": "ubiquiti", "synology-dsm": "synology", "synology-srm": "synology",
	"qnap-qts": "qnap", "qnap-quts-hero": "qnap",
	"truenas-core": "truenas", "truenas-scale": "truenas",
	"cisco": "router", "juniper": "router", "mikrotik": "router",
	"huawei": "router", "fortinet": "router", "palo-alto": "router",
	"check-point": "router", "f5": "router", "aruba": "router",
	"arista": "router", "sonicwall": "router", "zyxel": "router",
	"draytek": "router", "watchguard": "router", "sophos": "router",
	"ubiquiti": "router", "openwrt": "router", "dd-wrt": "router",
	"wrt": "router", "vyos": "router", "vyatta": "router",
	"pfsense": "router", "opnsense": "router",
	"brocade-fos": "router", "hpe-comware": "router", "hpe-procurve": "router",
	"extreme-exos": "router", "nokia-sros": "router", "dell-os10": "router",
	"zte": "router", "d-link": "router", "tp-link": "router", "netgear": "router",
}
