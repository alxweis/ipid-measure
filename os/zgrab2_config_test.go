package os

import (
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
)

func TestBuildZGrab2INISamplesSecondaryModules(t *testing.T) {
	ini := BuildZGrab2INI(
		config.OSModules{SSH: true, SMTP: true, FTP: true},
		config.ScaledNumber(5000),
		time.Second,
		time.Second,
		0.01,
	)

	if strings.Contains(section(ini, "ssh"), "trigger=") {
		t.Fatal("core SSH module unexpectedly has a trigger")
	}
	for _, name := range []string{"smtp", "ftp"} {
		if !strings.Contains(section(ini, name), `trigger="secondary"`) {
			t.Fatalf("%s module does not have the secondary trigger:\n%s", name, ini)
		}
	}
}

func TestBuildZGrab2INIDisablesSecondaryModulesAtZero(t *testing.T) {
	ini := BuildZGrab2INI(
		config.OSModules{SSH: true, SMTP: true},
		config.ScaledNumber(5000),
		time.Second,
		time.Second,
		0,
	)
	if strings.Contains(ini, "[smtp]") {
		t.Fatalf("secondary SMTP module present at zero sample rate:\n%s", ini)
	}
	if !strings.Contains(ini, "[ssh]") {
		t.Fatalf("core SSH module missing:\n%s", ini)
	}
}

func TestBuildZGrab2INIRunsSecondaryModulesExhaustivelyAtOne(t *testing.T) {
	ini := BuildZGrab2INI(
		config.OSModules{SMTP: true},
		config.ScaledNumber(5000),
		time.Second,
		time.Second,
		1,
	)
	smtp := section(ini, "smtp")
	if smtp == "" || strings.Contains(smtp, "trigger=") {
		t.Fatalf("unexpected exhaustive SMTP section:\n%s", ini)
	}
}

func section(ini, name string) string {
	start := strings.Index(ini, "["+name+"]")
	if start < 0 {
		return ""
	}
	rest := ini[start:]
	if next := strings.Index(rest[1:], "\n["); next >= 0 {
		return rest[:next+1]
	}
	return rest
}
