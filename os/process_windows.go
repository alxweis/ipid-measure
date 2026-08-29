//go:build windows

package os

import "os/exec"

func configureProcessGroup(_ *exec.Cmd) {}

func terminateProcessGroup(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}

func killProcessGroup(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
