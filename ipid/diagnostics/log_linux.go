package diagnostics

import (
	"log"
	"runtime"
	"syscall"
	"time"
)

var previousTime time.Time
var previousCPU float64
var previousMemory runtime.MemStats

func cpuSeconds(usage syscall.Rusage) float64 {
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
}

func Begin() {
	previousTime = time.Now()
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
		previousCPU = cpuSeconds(usage)
	}
	runtime.ReadMemStats(&previousMemory)
}

func Log(ms runtime.MemStats, final bool) {
	suffix := ""
	if final {
		suffix = "_final"
	}
	log.Printf("receive_timing%s[sample_every=%d headers={%s} transport={%s} lookup={%s} reply_lock={%s} fail_lock={%s} send_lock={%s} sendmsg={%s} send_probe_hold={%s}]", suffix, SampleEvery, &Headers, &Transport, &Lookup, &ReplyLock, &FailLock, &SendLock, &Sendmsg, &SendProbeHold)
	for index := range Captures {
		c := &Captures[index]
		ready, sent := c.ReadyNS.Load(), c.FirstSendNS.Load()
		log.Printf("receiver_diag%s[receiver=%d ready_ms=%.3f first_send_ms=%.3f send_before_ready=%t rcvbuf_bytes=%d snaplen_bytes=%d kernel_timestamp=%d socket_errors=%d packets=%d dropped=%d first_drop_observed_ms=%.3f last_drop_observed_ms=%.3f read={%s} capture_age={%s} process={%s}]", suffix, index, float64(ready)/1e6, float64(sent)/1e6, sent > 0 && (ready == 0 || sent < ready), c.ReceiveBuffer.Load(), c.Snaplen.Load(), c.KernelTimestamp.Load(), c.SocketErrors.Load(), c.Packets.Load(), c.Drops.Load(), float64(c.FirstDropNS.Load())/1e6, float64(c.LastDropNS.Load())/1e6, &c.Read, &c.Age, &c.Process)
	}
	now := time.Now()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		log.Printf("receive_runtime%s[error=%q]", suffix, err)
		return
	}
	seconds := now.Sub(previousTime).Seconds()
	if previousTime.IsZero() || seconds <= 0 {
		return
	}
	cpu := cpuSeconds(usage)
	log.Printf("receive_runtime%s[interval_s=%.3f cpu_pct=%.1f max_rss_kib=%d alloc_mib=%.3f gc_cycles=%d gc_pause_ms=%.3f gomaxprocs=%d goroutines=%d]", suffix, seconds, 100*(cpu-previousCPU)/seconds, usage.Maxrss, float64(ms.TotalAlloc-previousMemory.TotalAlloc)/(1<<20), ms.NumGC-previousMemory.NumGC, float64(ms.PauseTotalNs-previousMemory.PauseTotalNs)/1e6, runtime.GOMAXPROCS(0), runtime.NumGoroutine())
	previousTime, previousCPU, previousMemory = now, cpu, ms
}
