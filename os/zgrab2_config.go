package os

import (
	"fmt"
	"strings"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
)

// BuildZGrab2INI assembles a multimodule ZGrab2 .ini file.
//
// Flag names verified against `zgrab2 -h` and `zgrab2 <module> -h`. Per-module
// Basic Options accepted everywhere: port, name, connect-timeout, target-timeout.
// blocklisting is owned by zmap upstream, so we point zgrab2 at /dev/null to
// override its $HOME/.config/zgrab2/blocklist.conf default which crashes if absent.
func BuildZGrab2INI(
	modules config.OSModules,
	senders config.ScaledNumber,
	connectTimeout, readTimeout time.Duration,
	secondarySampleRate float64,
) string {
	var b strings.Builder

	fmt.Fprintf(&b, "[Application Options]\n")
	fmt.Fprintf(&b, "senders=%d\n", senders)
	fmt.Fprintf(&b, "output-file=-\n")
	fmt.Fprintf(&b, "input-file=-\n")
	fmt.Fprintf(&b, "blocklist-file=/dev/null\n")
	fmt.Fprintf(&b, "flush=true\n") // flush stdout per result so parser sees lines promptly

	ctStr := connectTimeout.String()
	ttStr := (connectTimeout + readTimeout).String()
	secondaryTrigger := ""
	if secondarySampleRate > 0 && secondarySampleRate < 1 {
		secondaryTrigger = fmt.Sprintf("trigger=%q\n", secondaryZGrab2Trigger)
	}

	if modules.HTTP {
		fmt.Fprintf(&b, "\n[http]\nname=\"http\"\nport=80\nendpoint=\"/\"\nconnect-timeout=%s\ntarget-timeout=%s\n", ctStr, ttStr)
	}
	if modules.HTTPS {
		fmt.Fprintf(&b, "\n[http]\nname=\"https\"\nport=443\nendpoint=\"/\"\nuse-https=true\nconnect-timeout=%s\ntarget-timeout=%s\n", ctStr, ttStr)
	}
	if modules.SSH {
		fmt.Fprintf(&b, "\n[ssh]\nname=\"ssh\"\nport=22\nconnect-timeout=%s\ntarget-timeout=%s\n", ctStr, ttStr)
	}
	if modules.SMB {
		fmt.Fprintf(&b, "\n[smb]\nname=\"smb\"\nport=445\nconnect-timeout=%s\ntarget-timeout=%s\n", ctStr, ttStr)
	}
	if modules.SMTP && secondarySampleRate > 0 {
		// Default: read banner, send EHLO if ESMTP advertised, HELO otherwise.
		fmt.Fprintf(&b, "\n[smtp]\nname=\"smtp\"\n%sport=25\nconnect-timeout=%s\ntarget-timeout=%s\n", secondaryTrigger, ctStr, ttStr)
	}
	if modules.MSSQL && secondarySampleRate > 0 {
		fmt.Fprintf(&b, "\n[mssql]\nname=\"mssql\"\n%sport=1433\nconnect-timeout=%s\ntarget-timeout=%s\n", secondaryTrigger, ctStr, ttStr)
	}
	if modules.POP3 && secondarySampleRate > 0 {
		fmt.Fprintf(&b, "\n[pop3]\nname=\"pop3\"\n%sport=110\nconnect-timeout=%s\ntarget-timeout=%s\n", secondaryTrigger, ctStr, ttStr)
	}
	if modules.IMAP && secondarySampleRate > 0 {
		fmt.Fprintf(&b, "\n[imap]\nname=\"imap\"\n%sport=143\nconnect-timeout=%s\ntarget-timeout=%s\n", secondaryTrigger, ctStr, ttStr)
	}
	if modules.FTP && secondarySampleRate > 0 {
		fmt.Fprintf(&b, "\n[ftp]\nname=\"ftp\"\n%sport=21\nconnect-timeout=%s\ntarget-timeout=%s\n", secondaryTrigger, ctStr, ttStr)
	}
	if modules.TELNET && secondarySampleRate > 0 {
		fmt.Fprintf(&b, "\n[telnet]\nname=\"telnet\"\n%sport=23\nconnect-timeout=%s\ntarget-timeout=%s\n", secondaryTrigger, ctStr, ttStr)
	}

	return b.String()
}
