package iptables

import (
	"fmt"
	"os/exec"
)

func Setup(dstPort uint16, ifaceIPs ...string) error {
	for _, ip := range ifaceIPs {
		for _, args := range rulesFor("-A", ip, dstPort) {
			if err := run(args); err != nil {
				// Best-effort rollback of anything already installed.
				_ = Teardown(dstPort, ifaceIPs...)
				return err
			}
		}
	}
	return nil
}

func Teardown(dstPort uint16, ifaceIPs ...string) error {
	var firstErr error
	for _, ip := range ifaceIPs {
		for _, args := range rulesFor("-D", ip, dstPort) {
			if err := run(args); err != nil {
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	return firstErr
}

func rulesFor(action, ip string, dstPort uint16) [][]string {
	port := fmt.Sprintf("%d", dstPort)
	return [][]string{
		// 1) Bypass conntrack on outgoing scan packets.
		{"-t", "raw", action, "OUTPUT",
			"-p", "tcp", "-s", ip, "--dport", port, "-j", "NOTRACK"},

		// 2) Bypass conntrack on incoming replies.
		{"-t", "raw", action, "PREROUTING",
			"-p", "tcp", "-d", ip, "--sport", port, "-j", "NOTRACK"},

		// 3) Drop the outbound RST the kernel would emit to scan targets.
		{action, "OUTPUT",
			"-p", "tcp", "--tcp-flags", "RST", "RST",
			"-s", ip, "--dport", port, "-j", "DROP"},
	}
}

func run(args []string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w: %s", args, err, string(out))
	}
	return nil
}
