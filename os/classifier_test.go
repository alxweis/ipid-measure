package os

import "testing"

func TestDetectTagSpecificBeforeBroad(t *testing.T) {
	tests := map[string]string{
		"9.18.12-0ubuntu0.22.04.1-Ubuntu": "ubuntu",
		"Linux Ubuntu server":             "ubuntu",
		"Cisco IOS XE Software":           "cisco-iosxe",
		"Cisco NX-OS(tm) Software":        "cisco-nxos",
		"Microsoft-IIS/10.0":              "windows",
		"OpenSSH_9.6 FreeBSD-20240104":    "freebsd",
		"OpenSSH_9.6 OpenBSD":             "openbsd",
		"SONiC Software Version 202505":   "sonic",
		"SonicWall SonicOS 7.1":           "sonicos",
		"win10":                           "windows",
		"win2003":                         "windows",
		"ijni-win10":                      "windows",
		"Darwin Kernel Version":           "macos",
	}
	for evidence, want := range tests {
		if got := detectTag(evidence); got != want {
			t.Errorf("detectTag(%q) = %q, want %q", evidence, got, want)
		}
	}
}

func TestDetectTagRequiresNonLetterBoundariesForShortTags(t *testing.T) {
	for _, evidence := range []string{"swing", "ijniwin10", "myqnx7"} {
		if got := detectTag(evidence); got != "" {
			t.Errorf("detectTag(%q) = %q, want no tag", evidence, got)
		}
	}
}

func TestDetectTagMatchesDistinctiveLongIndicatorsAsSubstrings(t *testing.T) {
	tests := map[string]string{
		"werubuntu332": "ubuntu",
		"rhel232":      "rhel",
		"sles15sp5":    "suse",
		"esxi8u2":      "vmware-esxi",
		"junos23r1":    "juniper-junos",
		"android14":    "android",
		"linux515":     "linux",
		"busybox136":   "busybox",
	}
	for evidence, want := range tests {
		if got := detectTag(evidence); got != want {
			t.Errorf("detectTag(%q) = %q, want %q", evidence, got, want)
		}
	}
}

func TestDetectTagKeepsIOSAmbiguousWithoutVendor(t *testing.T) {
	tests := map[string]string{
		"ios":          "",
		"ios12":        "",
		"Apple ios12":  "apple",
		"Cisco ios17":  "cisco",
		"Apple iOS":    "apple-ios",
		"Cisco IOS":    "cisco-ios",
		"Apple device": "apple",
	}
	for evidence, want := range tests {
		if got := detectTag(evidence); got != want {
			t.Errorf("detectTag(%q) = %q, want %q", evidence, got, want)
		}
	}
}

func TestReferenceRepositoryIndicatorsMapToCanonicalTags(t *testing.T) {
	tests := map[string]string{
		"redhat": "rhel", "ret hat": "rhel", "win": "windows",
		"microsoft": "windows", "lanman": "windows", "rasp": "raspbian",
		"lede": "openwrt", "ddwrt": "dd-wrt", "wrt": "wrt",
		"vyatta": "vyatta", "routeros": "mikrotik-routeros",
		"ios-xe": "cisco-iosxe", "nx-os": "cisco-nxos", "forti": "fortinet",
		"sonic": "sonic", "vigor": "draytek", "dray": "draytek",
		"vms": "openvms", "vrp": "huawei-vrp", "gaia": "checkpoint-gaia",
		"busybox": "busybox", "utm": "utm", "router": "router", "server": "server",
	}
	for evidence, want := range tests {
		if got := detectTag(evidence); got != want {
			t.Errorf("detectTag(%q) = %q, want %q", evidence, got, want)
		}
	}
}

func TestCollapsedRegexAlternativesPreserveClassification(t *testing.T) {
	tests := map[string]string{
		"RouterOS":                 "mikrotik-routeros",
		"DDWRT":                    "dd-wrt",
		"Raspbian":                 "raspbian",
		"Raspberry Pi OS":          "raspbian",
		"OracleLinux":              "oracle-linux",
		"Microsoft-IIS/10.0":       "windows",
		"Microsoft-HTTPAPI/2.0":    "windows",
		"Fortinet security device": "fortinet",
		"CheckPoint appliance":     "check-point",
		"fritz":                    "fritzos",
		"FRITZ!Box 7590":           "fritzos",
	}
	for evidence, want := range tests {
		if got := detectTag(evidence); got != want {
			t.Errorf("detectTag(%q) = %q, want %q", evidence, got, want)
		}
	}
}

func TestResolveTagsUsesMostSpecificCompatibleTag(t *testing.T) {
	got := resolveTags(serviceTags{SSH: "linux", HTTP: "ubuntu", DNS: "ubuntu"})
	if got.status != statusResolved || got.tag != "ubuntu" {
		t.Fatalf("decision = %+v", got)
	}
}

func TestResolveTagsUsesSpecificAppleTagOverVendorFallback(t *testing.T) {
	got := resolveTags(serviceTags{SSH: "apple", HTTP: "apple-ios"})
	if got.status != statusResolved || got.tag != "apple-ios" {
		t.Fatalf("decision = %+v", got)
	}
}

func TestResolveTagsMarksIncompatibleTagsAmbiguous(t *testing.T) {
	got := resolveTags(serviceTags{SSH: "ubuntu", HTTP: "windows"})
	if got.status != statusAmbiguous || got.tag != "" || len(got.conflicts) != 2 {
		t.Fatalf("decision = %+v", got)
	}
}

func TestResolveTagsLeavesEvidenceWithoutMatchUnclassified(t *testing.T) {
	got := resolveTags(serviceTags{})
	if got.status != statusUnclassified || got.tag != "" {
		t.Fatalf("decision = %+v", got)
	}
}
