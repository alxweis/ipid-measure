package os

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/alxweis/ipid-measure/internal/config"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/alxweis/ipid-measure/internal/consts"
)

// ZDNSResult is the per-IP outcome of CHAOS-class DNS queries against
// version.bind and hostname.bind.
type ZDNSResult struct {
	IP           string
	VersionBind  string
	HostnameBind string
}

// ZDNSRunner manages one zdns subprocess that issues CHAOS TXT queries against
// each target IP as the DNS resolver.
type ZDNSRunner struct {
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdoutPipe io.ReadCloser
	stderrPipe io.ReadCloser
}

// StartZDNS spawns zdns. Input format per line: "<query-name>,<target-ip>".
// Output: one JSON line per query on stdout.
func StartZDNS(
	ctx context.Context,
	binary string,
	threads config.ScaledNumber,
	timeout time.Duration) (*ZDNSRunner, error) {

	args := []string{
		"TXT",
		"--class=CHAOS",
		"--input-file=-",
		"--output-file=-",
		fmt.Sprintf("--threads=%d", threads),
		fmt.Sprintf("--timeout=%d", int(timeout.Seconds())),
		"--retries=0",
		"--iterative=false",
	}
	cmd := exec.CommandContext(ctx, binary, args...)
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
	return &ZDNSRunner{cmd: cmd, stdin: stdin, stdoutPipe: stdout, stderrPipe: stderr}, nil
}

func (r *ZDNSRunner) Stdin() io.WriteCloser { return r.stdin }
func (r *ZDNSRunner) Stdout() io.ReadCloser { return r.stdoutPipe }
func (r *ZDNSRunner) Stderr() io.ReadCloser { return r.stderrPipe }
func (r *ZDNSRunner) Wait() error           { return r.cmd.Wait() }

func (r *ZDNSRunner) Shutdown() error {
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

// ParseZDNSStream pairs the two CHAOS queries per IP (version.bind +
// hostname.bind) and emits exactly one ZDNSResult per IP -- contract required
// by the merger to avoid pending-entry leaks.
func ParseZDNSStream(r io.Reader, out chan<- ZDNSResult) error {
	br := bufio.NewReaderSize(r, consts.OSStdoutReadBufferBytes)

	// Per-IP merge state. Two queries expected per IP.
	type partial struct {
		rec  ZDNSResult
		seen int // count of distinct query types reported (0, 1, or 2)
		v    bool
		h    bool
	}
	const expectedQueries = 2
	partials := make(map[string]*partial, 1<<14)

	emit := func(p *partial) {
		out <- p.rec
	}

	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if name, ip, txt := parseZDNSLine(line); ip != "" {
				p, ok := partials[ip]
				if !ok {
					p = &partial{rec: ZDNSResult{IP: ip}}
					partials[ip] = p
				}
				switch name {
				case "version.bind":
					if !p.v {
						p.v = true
						p.seen++
						p.rec.VersionBind = CleanBanner(txt)
					}
				case "hostname.bind":
					if !p.h {
						p.h = true
						p.seen++
						p.rec.HostnameBind = CleanBanner(txt)
					}
				}
				if p.seen >= expectedQueries {
					emit(p)
					delete(partials, ip)
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				// Flush any remaining partials.
				for ip, p := range partials {
					emit(p)
					delete(partials, ip)
				}
				return nil
			}
			return err
		}
	}
}

// parseZDNSLine extracts (query-name, name-server-IP, txt-answer) from one zdns
// JSON output line. Returns ip="" if the line is malformed.
func parseZDNSLine(line string) (queryName, ip, txt string) {
	var raw struct {
		Name       string `json:"name"`
		NameServer string `json:"name_server"`
		Results    struct {
			TXT struct {
				Status string `json:"status"`
				Data   struct {
					Answers []struct {
						Type   string `json:"type"`
						Answer string `json:"answer"`
					} `json:"answers"`
				} `json:"data"`
			} `json:"TXT"`
		} `json:"results"`
		// Older zdns versions place the answers one level higher
		Data struct {
			Answers []struct {
				Type   string `json:"type"`
				Answer string `json:"answer"`
			} `json:"answers"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return "", "", ""
	}
	// Strip "host:port" -> "host" for the name-server field.
	server := raw.NameServer
	if idx := strings.LastIndex(server, ":"); idx >= 0 && strings.Count(server, ":") == 1 {
		server = server[:idx]
	}
	if server == "" {
		return "", "", ""
	}
	// Pick first non-empty TXT answer; fall back to legacy schema if needed.
	var answers []struct {
		Type   string `json:"type"`
		Answer string `json:"answer"`
	}
	if len(raw.Results.TXT.Data.Answers) > 0 {
		answers = raw.Results.TXT.Data.Answers
	} else if len(raw.Data.Answers) > 0 {
		answers = raw.Data.Answers
	}
	for _, a := range answers {
		if a.Type == "TXT" && a.Answer != "" {
			return strings.TrimSuffix(strings.ToLower(raw.Name), "."), server, a.Answer
		}
	}
	// No usable answer; still return the (name, server) pair with empty txt.
	return strings.TrimSuffix(strings.ToLower(raw.Name), "."), server, ""
}

// ZDNSInputLine formats one stdin line for zdns: "<query-name>,<target-ip>".
func ZDNSInputLine(queryName, ip string) string {
	return queryName + "," + ip + "\n"
}
