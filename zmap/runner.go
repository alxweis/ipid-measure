package zmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/types"
)

const (
	Binary       = "zmap"
	OutputFields = "saddr,timestamp-ts,timestamp-us"
	OutputFormat = "csv"
	OutputFilter = "success = 1 && repeat = 0"

	ShutdownGraceSeconds = 5
)

// BuildArgs translates a validated ZMapConfig into a zmap argument vector.
func BuildArgs(c *config.ZMapConfig) ([]string, error) {
	args := []string{
		"-C", "/dev/null", // ignore the global /etc/zmap/zmap.conf
		"-O", OutputFormat,
		"-f", OutputFields,
		"--output-filter", OutputFilter,
	}

	// Module / port / probe-args mapping
	switch c.Payload {
	case types.PayloadICMP:
		args = append(args, "-M", "icmp_echoscan")
	case types.PayloadTCP:
		args = append(args, "-M", "tcp_synscan", "-p", strconv.Itoa(int(*c.Port)))
	case types.PayloadUDPDNS:
		args = append(args, "-M", "dns", "-p", strconv.Itoa(int(*c.Port)),
			"--probe-args", *c.ProbeArgs)
	default:
		return nil, fmt.Errorf("zmap: unsupported payload %q", c.Payload)
	}

	// Interface
	args = append(args, "-i", c.Interface.Name, "-S", c.Interface.IP)

	// Result count
	if c.NumberOfTargetIPAddresses != nil {
		args = append(args, "-N", strconv.FormatUint(uint64(*c.NumberOfTargetIPAddresses), 10))
	}

	// Speed
	if c.Bandwidth != nil {
		args = append(args, "-B", strconv.FormatUint(uint64(*c.Bandwidth), 10))
	}
	if c.PacketsPerSecond != nil {
		args = append(args, "-r", strconv.FormatUint(uint64(*c.PacketsPerSecond), 10))
	}

	if c.SenderThreads != nil {
		args = append(args, "-T", strconv.FormatUint(uint64(*c.SenderThreads), 10))
	}

	// Additional
	if c.Dryrun {
		args = append(args, "--dryrun")
	}
	if c.BlacklistFile != nil {
		args = append(args, "-b", *c.BlacklistFile)
	}
	if c.WhitelistFile != nil {
		args = append(args, "-w", *c.WhitelistFile)
	}

	return args, nil
}

// Runner manages one zmap subprocess.
type Runner struct {
	cmd        *exec.Cmd
	stdoutPipe io.ReadCloser
	stderrPipe io.ReadCloser
}

// Start spawns ZMap with the given args.
func Start(ctx context.Context, args []string) (*Runner, error) {
	finalArgs := make([]string, 0, len(args)+2)
	finalArgs = append(finalArgs, args...)
	finalArgs = append(finalArgs, "-o", "-")

	cmd := exec.CommandContext(ctx, Binary, finalArgs...)

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// On ctx cancellation: graceful SIGTERM to the whole group...
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil &&
			!errors.Is(err, syscall.ESRCH) {
			return err
		}
		return nil
	}
	// ...then a forced kill if ZMap ignores SIGTERM for too long.
	cmd.WaitDelay = ShutdownGraceSeconds * time.Second

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("zmap stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("zmap stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", Binary, err)
	}

	return &Runner{
		cmd:        cmd,
		stdoutPipe: stdoutPipe,
		stderrPipe: stderrPipe,
	}, nil
}

// Stdout returns the running ZMap's stdout pipe (CSV stream).
func (r *Runner) Stdout() io.ReadCloser { return r.stdoutPipe }

// Stderr returns ZMap's stderr pipe so callers can drain it.
func (r *Runner) Stderr() io.ReadCloser { return r.stderrPipe }

// Wait blocks until ZMap exits and returns its exit error (nil on exit 0).
func (r *Runner) Wait() error { return r.cmd.Wait() }
