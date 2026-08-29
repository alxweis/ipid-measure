package os

import (
	"strings"
	"testing"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
)

func TestBuildZGrab2INIContainsFourServices(t *testing.T) {
	ini := BuildZGrab2INI(
		config.OSModules{SSH: true, SMB: true, HTTP: true, HTTPS: true},
		config.ScaledNumber(5000), time.Second, time.Second,
	)
	for _, name := range []string{"ssh", "smb", "http"} {
		if section(ini, name) == "" {
			t.Fatalf("missing %s section:\n%s", name, ini)
		}
	}
	if !strings.Contains(ini, `name="https"`) || !strings.Contains(ini, "use-https=true") {
		t.Fatalf("missing HTTPS module:\n%s", ini)
	}
	if !strings.Contains(section(ini, "smb"), "setup-session=true") {
		t.Fatalf("SMB session setup missing:\n%s", ini)
	}
	if strings.Contains(ini, "trigger=") {
		t.Fatalf("unexpected sampling trigger:\n%s", ini)
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
