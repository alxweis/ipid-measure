package os

import (
	"testing"

	"github.com/alxweis/ipid-measure/internal/records"
)

func TestDetectFingerprintKeepsOSAndFallbacksDistinct(t *testing.T) {
	tests := []struct {
		name         string
		record       records.OSRecord
		wantOS       string
		wantDetected string
		wantType     string
	}{
		{
			name:         "centos is not collapsed into rhel",
			record:       records.OSRecord{SSHServerID: "OpenSSH_8.7 CentOS"},
			wantOS:       "centos",
			wantDetected: "centos",
			wantType:     detectionOS,
		},
		{
			name:         "explicit junos",
			record:       records.OSRecord{SNMPSysDescr: "Juniper Networks, Inc. junos 23.4R1"},
			wantOS:       "juniper-junos",
			wantDetected: "juniper-junos",
			wantType:     detectionOS,
		},
		{
			name:         "juniper vendor only",
			record:       records.OSRecord{TelnetBanner: "Juniper Networks"},
			wantDetected: "juniper",
			wantType:     detectionVendor,
		},
		{
			name:         "explicit drayos",
			record:       records.OSRecord{HTTPServer: "DrayOS HTTP Server"},
			wantOS:       "drayos",
			wantDetected: "drayos",
			wantType:     detectionOS,
		},
		{
			name:         "draytek vendor only",
			record:       records.OSRecord{HTTPServer: "DrayTek Embedded Web Server"},
			wantDetected: "draytek",
			wantType:     detectionVendor,
		},
		{
			name:         "explicit sonicos",
			record:       records.OSRecord{SNMPSysDescr: "SonicWall SonicOS 7.1"},
			wantOS:       "sonicos",
			wantDetected: "sonicos",
			wantType:     detectionOS,
		},
		{
			name:         "sonicwall firewall inference",
			record:       records.OSRecord{HTTPSServer: "SonicWall TZ270 Firewall"},
			wantOS:       "sonicos",
			wantDetected: "sonicos",
			wantType:     detectionOS,
		},
		{
			name:         "sonicwall vendor only",
			record:       records.OSRecord{HTTPSCertSubject: "SonicWall"},
			wantDetected: "sonicwall",
			wantType:     detectionVendor,
		},
		{
			name:         "explicit zynos",
			record:       records.OSRecord{TelnetBanner: "ZyXEL ZyNOS F/W Version V4.70"},
			wantOS:       "zynos",
			wantDetected: "zynos",
			wantType:     detectionOS,
		},
		{
			name:         "zyxel vendor only",
			record:       records.OSRecord{HTTPServer: "ZyXEL Communications Corp."},
			wantDetected: "zyxel",
			wantType:     detectionVendor,
		},
		{
			name:         "nginx is software not linux",
			record:       records.OSRecord{HTTPServer: "nginx/1.28.0"},
			wantDetected: "nginx",
			wantType:     detectionServerSoftware,
		},
		{
			name:         "distro tagged nginx identifies ubuntu",
			record:       records.OSRecord{HTTPServer: "nginx/1.24.0 (Ubuntu)"},
			wantOS:       "ubuntu",
			wantDetected: "ubuntu",
			wantType:     detectionOS,
		},
		{
			name:         "mssql is software not windows",
			record:       records.OSRecord{MSSQLVersion: "Microsoft SQL Server 2022"},
			wantDetected: "microsoft-sql",
			wantType:     detectionServerSoftware,
		},
		{
			name:         "sonic network os is distinct from sonicos",
			record:       records.OSRecord{SNMPSysDescr: "SONiC Software Version 202505"},
			wantOS:       "sonic",
			wantDetected: "sonic",
			wantType:     detectionOS,
		},
		{
			name:         "unknown banner is retained",
			record:       records.OSRecord{HTTPServer: "AcmeWeb/1.0"},
			wantDetected: detectionUnknown,
			wantType:     detectionUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectFingerprint(&tt.record)
			if got.OSName != tt.wantOS {
				t.Fatalf("OSName = %q, want %q", got.OSName, tt.wantOS)
			}
			if got.DetectedName != tt.wantDetected {
				t.Fatalf("DetectedName = %q, want %q", got.DetectedName, tt.wantDetected)
			}
			if got.DetectedType != tt.wantType {
				t.Fatalf("DetectedType = %q, want %q", got.DetectedType, tt.wantType)
			}
		})
	}
}

func TestDetectFingerprintPrefersOSOverEarlierSoftwareFallback(t *testing.T) {
	record := records.OSRecord{
		SSHServerID:  "SSH-2.0-dropbear_2024.86",
		SNMPSysDescr: "Juniper Networks Junos 23.4R1",
	}

	got := DetectFingerprint(&record)
	if got.OSName != "juniper-junos" {
		t.Fatalf("OSName = %q, want juniper-junos", got.OSName)
	}
	if got.Source != "snmp-sysdescr" {
		t.Fatalf("Source = %q, want snmp-sysdescr", got.Source)
	}
}
