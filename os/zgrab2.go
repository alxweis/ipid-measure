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
	"time"
)

// ZGrab2Result is the per-IP outcome of the multimodule ZGrab2 scan.
type ZGrab2Result struct {
	IP             string
	SSHResponded   bool
	SMBResponded   bool
	HTTPResponded  bool
	HTTPSResponded bool
	SSHServerID    string
	SMBNativeOS    string
	HTTPServer     string
	HTTPSServer    string
}

// ZGrab2Runner manages one ZGrab2 child process configured to run the union
// of all enabled modules in a single pass.
type ZGrab2Runner struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdoutPipe io.ReadCloser
	stderrPipe io.ReadCloser
}

// StartZGrab2 spawns ZGrab2 in multimodule mode.
func StartZGrab2(ctx context.Context, binary, iniPath string) (*ZGrab2Runner, error) {
	cmd := exec.CommandContext(ctx, binary, "multiple", "-c", iniPath)
	configureProcessGroup(cmd)
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
	return &ZGrab2Runner{cmd: cmd, stdin: stdin, stdoutPipe: stdout, stderrPipe: stderr}, nil
}

func (r *ZGrab2Runner) Stdin() io.WriteCloser { return r.stdin }
func (r *ZGrab2Runner) Stdout() io.ReadCloser { return r.stdoutPipe }
func (r *ZGrab2Runner) Stderr() io.ReadCloser { return r.stderrPipe }
func (r *ZGrab2Runner) Wait() error           { return r.cmd.Wait() }

func (r *ZGrab2Runner) Shutdown() error {
	if r.cmd.Process == nil {
		return nil
	}
	_ = terminateProcessGroup(r.cmd)
	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(ShutdownGraceSeconds * time.Second):
		_ = killProcessGroup(r.cmd)
		return <-done
	}
}

// ParseZGrab2Stream consumes ZGrab2's JSON-lines stdout and emits ZGrab2Result.
func ParseZGrab2Stream(r io.Reader, out chan<- ZGrab2Result) error {
	br := bufio.NewReaderSize(r, StdoutReadBufferBytes)
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

// extractZGrab2Module is a switch over the module names we configured.
func extractZGrab2Module(name string, blob json.RawMessage, out *ZGrab2Result) {
	succeeded := zgrab2ModuleSucceeded(blob)
	switch name {
	case "ssh":
		out.SSHResponded = succeeded
		var v struct {
			Result struct {
				ServerID struct {
					Raw string `json:"raw"`
				} `json:"server_id"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			out.SSHServerID = CleanBanner(v.Result.ServerID.Raw)
			out.SSHResponded = out.SSHResponded || out.SSHServerID != ""
		}
	case "smb":
		out.SMBResponded = succeeded
		// ZGrab2 releases have used both strings and objects for NTLM/session
		// metadata. Decode only the paths we need so a schema change in an
		// unrelated field cannot discard the complete SMB result.
		if root := decodeJSONObject(blob); root != nil {
			out.SMBNativeOS = CleanBanner(firstJSONText(root,
				[]string{"result", "native_os"},
				[]string{"result", "ntlm", "native_os"},
				[]string{"result", "smb_versions", "native_os"},
				[]string{"result", "ntlm", "product_name"},
				[]string{"result", "ntlm", "target_name"},
				[]string{"result", "ntlm"},
			))
			out.SMBResponded = out.SMBResponded || out.SMBNativeOS != ""
		}
	case "http", "https":
		var v struct {
			Result struct {
				Response struct {
					Headers map[string]json.RawMessage `json:"headers"`
				} `json:"response"`
			} `json:"result"`
		}
		if json.Unmarshal(blob, &v) == nil {
			server := headerText(v.Result.Response.Headers, "server")
			if name == "http" {
				out.HTTPServer = CleanBanner(server)
				out.HTTPResponded = succeeded || out.HTTPServer != ""
			} else {
				out.HTTPSServer = CleanBanner(server)
				out.HTTPSResponded = succeeded || out.HTTPSServer != ""
			}
		}
	}
}

func zgrab2ModuleSucceeded(blob json.RawMessage) bool {
	var envelope struct {
		Status string `json:"status"`
	}
	return json.Unmarshal(blob, &envelope) == nil && envelope.Status == "success"
}

func decodeJSONObject(blob json.RawMessage) map[string]any {
	var value map[string]any
	if json.Unmarshal(blob, &value) != nil {
		return nil
	}
	return value
}

func jsonValueAt(root any, path ...string) any {
	value := root
	for _, part := range path {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value, ok = object[part]
		if !ok {
			return nil
		}
	}
	return value
}

func jsonText(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := jsonText(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

func firstJSONText(root map[string]any, paths ...[]string) string {
	for _, path := range paths {
		if text := jsonText(jsonValueAt(root, path...)); text != "" {
			return text
		}
	}
	return ""
}

func headerText(headers map[string]json.RawMessage, wanted string) string {
	for name, raw := range headers {
		if !strings.EqualFold(name, wanted) {
			continue
		}
		var value any
		if json.Unmarshal(raw, &value) == nil {
			return jsonText(value)
		}
	}
	return ""
}

// WriteIniFile writes the .ini contents to a temp file and returns its path.
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
