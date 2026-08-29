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
		// The session setup is what exposes NTLM/native-OS metadata. Without
		// it, many servers only yield protocol/version negotiation details.
		fmt.Fprintf(&b, "\n[smb]\nname=\"smb\"\nport=445\nsetup-session=true\nconnect-timeout=%s\ntarget-timeout=%s\n", ctStr, ttStr)
	}
	return b.String()
}
