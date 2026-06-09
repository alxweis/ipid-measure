package os

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	osstd "os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/netd-tud/ipid-measure/internal/consts"
)

// ZGrab2Result is the per-IP outcome of the multi-module zgrab2 scan. Each
// field corresponds to a probe module configured in the run; empty strings
// mean "module disabled or no useful field returned".
type ZGrab2Result struct {
	IP               string
	SSHServerID      string
	SMBNativeOS      string
	HTTPServer       string
	HTTPSServer      string
	HTTPSCertIssuer  string
	HTTPSCertSubject string
	SMTPBanner       string
	SMTPEHLO         string
	MSSQLVersion     string
	POP3Banner       string
	IMAPBanner       string
	FTPBanner        string
	TelnetBanner     string
}

// ZGrab2Runner manages one zgrab2 child process configured to run the union
// of all enabled modules in a single pass.
type ZGrab2Runner struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdoutPipe io.ReadCloser
	stderrPipe io.ReadCloser
	iniPath    string
}

// BuildZGrab2INI assembles a multi-module zgrab2 .ini file. Only modules with
// Modules[name]=true are included.
//
// Note: we deliberately do NOT emit `source-ip=` here. Recent zgrab2 versions
// rejected it as an unknown application option, and even on older builds
// the GitHub issue tracker reports it as broken for all modules except http.
// If you need to bind to a specific source address, route via the OS
// (set the default route on the desired interface, or use `ip rule add from
// <ip> table <T>` plus `ip route add default dev <if> table <T>`).
func BuildZGrab2INI(modules map[string]bool, senders uint32, connectTimeout, readTimeout time.Duration, sourceIP string) string {
	_ = sourceIP // intentionally unused; see doc comment above
	var b strings.Builder

	// Application options apply to all subsequent sections.
	fmt.Fprintf(&b, "[Application Options]\n")
	fmt.Fprintf(&b, "senders=%d\n", senders)
	fmt.Fprintf(&b, "output-file=-\n")
	fmt.Fprintf(&b, "input-file=-\n")

	// Common per-module flags: timeouts in seconds (zgrab2 uses duration).
	connectSecs := int(connectTimeout.Seconds())
	if connectSecs < 1 {
		connectSecs = 1
	}
	readSecs := int(readTimeout.Seconds())
	if readSecs < 1 {
		readSecs = 1
	}

	if modules["http"] {
		fmt.Fprintf(&b, "\n[http]\nname=\"http\"\nport=80\nendpoint=\"/\"\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["https"] {
		fmt.Fprintf(&b, "\n[http]\nname=\"https\"\nport=443\nendpoint=\"/\"\nuse-https=true\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["ssh"] {
		fmt.Fprintf(&b, "\n[ssh]\nname=\"ssh\"\nport=22\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["smb"] {
		fmt.Fprintf(&b, "\n[smb]\nname=\"smb\"\nport=445\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["smtp"] {
		fmt.Fprintf(&b, "\n[smtp]\nname=\"smtp\"\nport=25\nsend-ehlo=true\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["mssql"] {
		fmt.Fprintf(&b, "\n[mssql]\nname=\"mssql\"\nport=1433\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["pop3"] {
		fmt.Fprintf(&b, "\n[pop3]\nname=\"pop3\"\nport=110\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["imap"] {
		fmt.Fprintf(&b, "\n[imap]\nname=\"imap\"\nport=143\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["ftp"] {
		fmt.Fprintf(&b, "\n[ftp]\nname=\"ftp\"\nport=21\ntimeout=%ds\n", connectSecs+readSecs)
	}
	if modules["telnet"] {
		fmt.Fprintf(&b, "\n[telnet]\nname=\"telnet\"\nport=23\ntimeout=%ds\n", connectSecs+readSecs)
	}

	return b.String()
}

// StartZGrab2 spawns zgrab2 in multi-module mode. Writing IPs (one per line)
// to the returned stdin causes zgrab2 to scan them; reading from the output
// channel yields parsed per-IP results as they complete.
func StartZGrab2(ctx context.Context, binary, iniPath string) (*ZGrab2Runner, error) {
	cmd := exec.CommandContext(ctx, binary, "multiple", "-c", iniPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", binary, err)
	}
	return &ZGrab2Runner{cmd: cmd, stdin: stdin, stdoutPipe: stdout, stderrPipe: stderr, iniPath: iniPath}, nil
}

func (r *ZGrab2Runner) Stdin() io.WriteCloser { return r.stdin }
func (r *ZGrab2Runner) Stdout() io.ReadCloser { return r.stdoutPipe }
func (r *ZGrab2Runner) Stderr() io.ReadCloser { return r.stderrPipe }
func (r *ZGrab2Runner) Wait() error           { return r.cmd.Wait() }

func (r *ZGrab2Runner) Shutdown() error {
	if r.cmd.Process == nil {
		return nil
	}
	pgid := r.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(consts.OSShutdownGraceSeconds * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return <-done
	}
}

// ParseZGrab2Stream consumes zgrab2's JSON-lines stdout and emits ZGrab2Result.
// One input line = one target's result, containing per-module sub-results.
//
// We treat parse failures per line as warnings (skip the line) rather than as
// hard errors -- some zgrab2 builds emit non-JSON status lines occasionally.
func ParseZGrab2Stream(r io.Reader, out chan<- ZGrab2Result) error {
	br := bufio.NewReaderSize(r, consts.OSStdoutReadBufferBytes)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if res, ok := parseZGrab2Line(line); ok {
				out <- res
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// parseZGrab2Line decodes one JSON-line into a structured ZGrab2Result.
// Returns ok=false on JSON errors or on input that has no IP.
//
// zgrab2 emits one JSON object per scan target, with shape:
//
//	{ "ip": "1.2.3.4",
//	  "data": {
//	      "ssh":   { "status": "success", "result": { "server_id": { "raw": "SSH-2.0-..." } } },
//	      "http":  { "status": "success", "result": { "response": { "headers": { "server": ["nginx ..."] } } } },
//	      ...
//	  }}
//
// Module sub-results have status "success", "io-timeout", "connection-refused",
// "application-error", etc. We only mine the success ones.
func parseZGrab2Line(line string) (ZGrab2Result, bool) {
	var raw struct {
		IP   string                     `json:"ip"`
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil || raw.IP == "" {
		return ZGrab2Result{}, false
	}
	res := ZGrab2Result{IP: raw.IP}
	for name, blob := range raw.Data {
		extractZGrab2Module(name, blob, &res)
	}
	return res, true
}

// extractZGrab2Module is a switch over the module names we configured. Each
// case is tolerant of missing nested fields -- the goal is to extract any
// OS-relevant string and silently skip anything that's not there.
func extractZGrab2Module(name string, blob json.RawMessage, out *ZGrab2Result) {
	switch name {
	case "ssh":
		var v struct {
			Result struct {
				ServerID struct {
					Raw string `json:"raw"`
				} `json:"server_id"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.SSHServerID = CleanBanner(v.Result.ServerID.Raw)
		}
	case "smb":
		var v struct {
			Result struct {
				NTLM struct {
					ProductName string `json:"target_name"`
					NativeOS    string `json:"native_os"`
				} `json:"ntlm,omitempty"`
				SMBVersions struct {
					NativeOS string `json:"native_os"`
				} `json:"smb_versions,omitempty"`
				NativeOS string `json:"native_os"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			// Different zgrab2 versions surface the field in slightly different
			// nested paths. Take the first non-empty.
			switch {
			case v.Result.NativeOS != "":
				out.SMBNativeOS = CleanBanner(v.Result.NativeOS)
			case v.Result.NTLM.NativeOS != "":
				out.SMBNativeOS = CleanBanner(v.Result.NTLM.NativeOS)
			case v.Result.SMBVersions.NativeOS != "":
				out.SMBNativeOS = CleanBanner(v.Result.SMBVersions.NativeOS)
			case v.Result.NTLM.ProductName != "":
				out.SMBNativeOS = CleanBanner(v.Result.NTLM.ProductName)
			}
		}
	case "http", "https":
		var v struct {
			Result struct {
				Response struct {
					Headers map[string][]string `json:"headers"`
				} `json:"response"`
				TLSLog struct {
					HandshakeLog struct {
						ServerCertificates struct {
							Certificate struct {
								Parsed struct {
									Issuer struct {
										CommonName []string `json:"common_name"`
									} `json:"issuer"`
									Subject struct {
										CommonName []string `json:"common_name"`
									} `json:"subject"`
								} `json:"parsed"`
							} `json:"certificate"`
						} `json:"server_certificates"`
					} `json:"handshake_log"`
				} `json:"tls_log"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			server := firstNonEmpty(v.Result.Response.Headers["server"])
			cn := joined(v.Result.TLSLog.HandshakeLog.ServerCertificates.Certificate.Parsed.Issuer.CommonName)
			sub := joined(v.Result.TLSLog.HandshakeLog.ServerCertificates.Certificate.Parsed.Subject.CommonName)
			if name == "http" {
				out.HTTPServer = CleanBanner(server)
			} else {
				out.HTTPSServer = CleanBanner(server)
				out.HTTPSCertIssuer = CleanBanner(cn)
				out.HTTPSCertSubject = CleanBanner(sub)
			}
		}
	case "smtp":
		var v struct {
			Result struct {
				Banner string `json:"banner"`
				EHLO   string `json:"ehlo"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.SMTPBanner = CleanBanner(v.Result.Banner)
			out.SMTPEHLO = CleanBanner(v.Result.EHLO)
		}
	case "mssql":
		var v struct {
			Result struct {
				Version string `json:"version"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.MSSQLVersion = CleanBanner(v.Result.Version)
		}
	case "pop3":
		var v struct {
			Result struct {
				Banner string `json:"banner"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.POP3Banner = CleanBanner(v.Result.Banner)
		}
	case "imap":
		var v struct {
			Result struct {
				Banner string `json:"banner"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.IMAPBanner = CleanBanner(v.Result.Banner)
		}
	case "ftp":
		var v struct {
			Result struct {
				Banner string `json:"banner"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.FTPBanner = CleanBanner(v.Result.Banner)
		}
	case "telnet":
		var v struct {
			Result struct {
				Banner string `json:"banner"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.TelnetBanner = CleanBanner(v.Result.Banner)
		}
	}
}

func firstNonEmpty(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func joined(ss []string) string {
	return strings.Join(ss, ", ")
}

// WriteIniFile writes the .ini contents to a temp file and returns its path.
// Caller is responsible for removing it after the run.
func WriteIniFile(contents string, path string) error {
	f, err := osstd.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.WriteString(f, contents)
	return err
}

// drainPipe is a small helper for stderr: forwards lines to a logger function.
// Used both for zgrab2 and zdns.
func drainPipe(r io.Reader, logFn func(string)) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			logFn(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			return
		}
	}
}

// pipelinerSpawnGroup is a small helper for goroutine bookkeeping across the
// three scanners in pipeline.go.
type spawnGroup struct {
	wg sync.WaitGroup
}

func (g *spawnGroup) Go(fn func()) {
	g.wg.Add(1)
	go func() { defer g.wg.Done(); fn() }()
}

func (g *spawnGroup) Wait() { g.wg.Wait() }
