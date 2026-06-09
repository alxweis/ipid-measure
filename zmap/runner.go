package zmap

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/netd-tud/ipid-measure/internal/config"
	"github.com/netd-tud/ipid-measure/internal/consts"
	"github.com/netd-tud/ipid-measure/internal/types"
)

// BuildArgs translates a validated ZMapConfig into a zmap argument vector.
func BuildArgs(c *config.ZMapConfig) ([]string, error) {
	args := []string{
		"-C", "/dev/null", // ignore the global /etc/zmap/zmap.conf
		"-O", consts.ZMapOutputFormat,
		"-f", consts.ZMapOutputFields,
	}

	// Module / port mapping
	switch c.Payload {
	case types.PayloadICMP:
		args = append(args, "-M", "icmp_echoscan")
	case types.PayloadTCP:
		args = append(args, "-M", "tcp_synscan", "-p", strconv.Itoa(int(*c.Port)))
	case types.PayloadUDPDNS:
		args = append(args, "-M", "udp", "-p", strconv.Itoa(int(*c.Port)))
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
	if c.PacketsPerSecond != nil {
		args = append(args, "-r", strconv.FormatUint(uint64(*c.PacketsPerSecond), 10))
	}
	if c.Bandwidth != nil {
		args = append(args, "-B", strconv.FormatUint(uint64(*c.Bandwidth), 10))
	}
	args = append(args, "-T", strconv.FormatUint(uint64(c.SenderThreads), 10))

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

	cmd := exec.CommandContext(ctx, consts.ZMapBinary, finalArgs...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("zmap stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("zmap stderr pipe: %w", err)
	}

	// Put ZMap into its own process group
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", consts.ZMapBinary, err)
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

// Wait blocks until ZMap exits and returns its exit error (nil if exit 0).
func (r *Runner) Wait() error {
	return r.cmd.Wait()
}

// Shutdown attempts a graceful stop.
func (r *Runner) Shutdown() error {
	if r.cmd.Process == nil {
		return nil
	}

	// negative pid -> signals the whole process group.
	pgid := r.cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()

	select {
	case err := <-done:
		return err
	case <-time.After(consts.ZMapShutdownGraceSeconds * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return <-done
	}
}
