//go:build unix

package os

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
)

func validateProbeResources(c *config.OSConfig) error {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return err
	}
	low, high := 0, 0
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
		if err != nil {
			return err
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return fmt.Errorf("invalid ephemeral port range")
		}
		low, err = strconv.Atoi(fields[0])
		if err != nil {
			return err
		}
		high, err = strconv.Atoi(fields[1])
		if err != nil {
			return err
		}
	}
	dns, snmp, senders, modules := uint64(0), uint64(0), uint64(0), uint64(0)
	if c.DNSChaosWorkers != nil {
		dns = uint64(*c.DNSChaosWorkers)
	}
	if c.SNMPWorkers != nil {
		snmp = uint64(*c.SNMPWorkers)
	}
	if c.ZGrab2Senders != nil {
		senders = uint64(*c.ZGrab2Senders)
	}
	for _, enabled := range []bool{c.Modules.SSH, c.Modules.SMB, c.Modules.HTTP, c.Modules.HTTPS} {
		if enabled {
			modules++
		}
	}
	if err := checkProbeResources(dns, snmp, senders, modules, lim.Cur, low, high); err != nil {
		return err
	}
	// Go may raise its own nofile limit but restore the original shell limit
	// for exec children. Reaffirm the admitted value so zgrab2 inherits it.
	// This does not raise either numeric limit beyond the current values.
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return err
	}
	log.Printf("os: resource preflight: nofile=%d UDP-workers=%d TCP-senders=%d ephemeral_ports=%d-%d", lim.Cur, dns+snmp, senders, low, high)
	return nil
}

func checkProbeResources(dns, snmp, senders, modules, nofile uint64, low, high int) error {
	if dns+snmp+256 > nofile {
		return fmt.Errorf("OS concurrency needs at least %d open files; limit=%d", dns+snmp+256, nofile)
	}
	// Reserve conservatively for every enabled TCP module in the child too.
	if senders*modules+256 > nofile {
		return fmt.Errorf("zgrab2 concurrency needs at least %d open files; limit=%d", senders*modules+256, nofile)
	}
	if high > 0 && (high < low || dns+snmp+1024 > uint64(high-low+1)) {
		return fmt.Errorf("OS UDP concurrency exceeds ephemeral port headroom: workers=%d range=%d-%d", dns+snmp, low, high)
	}
	// This is a conservative active-sender allowance, not a count of every
	// host-wide TIME_WAIT tuple. TCP source ports can be reused across peers.
	if high > 0 && modules > 0 && senders+1024 > uint64(high-low+1) {
		return fmt.Errorf("OS TCP concurrency exceeds ephemeral port headroom: senders=%d range=%d-%d", senders, low, high)
	}
	return nil
}
