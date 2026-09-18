package stats

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/alxweis/ipid-measure/internal/types"
)

type TCPReplyPhase uint8

const (
	TCPNoConnection TCPReplyPhase = iota
	TCPHandshake
	TCPData
)

var tcpFlagNames = [...]string{
	types.TCPFlagFIN, types.TCPFlagSYN, types.TCPFlagRST,
	types.TCPFlagPSH, types.TCPFlagACK, types.TCPFlagURG,
	types.TCPFlagECE, types.TCPFlagCWR, types.TCPFlagNS,
}

var tcpBadFlags [3][1 << len(tcpFlagNames)]atomic.Int64

func RecordTCPBadFlags(phase TCPReplyPhase, flags types.TCPFlagSet) {
	mask := 0
	for bit, flag := range tcpFlagNames {
		if flags.Contains(flag) {
			mask |= 1 << bit
		}
	}
	tcpBadFlags[phase][mask].Add(1)
}

func TCPBadFlagsSummary() string {
	var result strings.Builder
	for phase, name := range [...]string{"no_connection", "handshake", "data"} {
		for mask := range tcpBadFlags[phase] {
			count := tcpBadFlags[phase][mask].Load()
			if count == 0 {
				continue
			}
			var flags strings.Builder
			for bit, flag := range tcpFlagNames {
				if mask&(1<<bit) != 0 {
					flags.WriteString(flag)
				}
			}
			if mask == 0 {
				flags.WriteString("NONE")
			}
			if result.Len() > 0 {
				result.WriteByte(' ')
			}
			fmt.Fprintf(&result, "%s:%s=%d", name, flags.String(), count)
		}
	}
	return result.String()
}
