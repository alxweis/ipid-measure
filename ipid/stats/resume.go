package stats

import "sync/atomic"

// RestoreTerminalFailures runs before any new workers/receivers exist. It is
// fed only the admitted strict ICMP counters; reply-level counters stay zero.
func RestoreTerminalFailures(values map[string]int64) {
	fields := map[string]*int64{"proto": &AbortProto, "limiter_stop": &DropLimiterStop, "send_err": &DropSendErr, "timeout": &DropTimeout, "interrupt": &DropInterrupt, "not_recv": &DropNotRecv, "bad_dst": &AbortBadDst, "bad_port": &AbortBadPort, "seq_oor": &AbortSeqOOR, "unsent": &AbortUnsent, "dup": &AbortDup, "late": &AbortLate}
	for name, field := range fields {
		atomic.StoreInt64(field, values[name])
	}
}
