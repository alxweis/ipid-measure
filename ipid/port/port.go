package port

import (
	"math"
	"math/rand/v2"
	"sync/atomic"

	"github.com/alxweis/ipid-measure/ipid/measurement"
)

// Pool is a pre-shuffled ring of source base-ports handed out round-robin to concurrent probes.
type Pool struct {
	ports []uint16
	index atomic.Uint64
}

var pool *Pool

func Setup() {
	minPort := uint16(1024)
	maxPort := math.MaxUint16 - (measurement.Config.ConnectionCount - 1)

	size := int(maxPort-minPort) + 1

	ports := make([]uint16, size)
	for i := 0; i < size; i++ {
		ports[i] = minPort + uint16(i)
	}

	// Fisher-Yates shuffle so consecutive probes use spread-out port ranges.
	rand.Shuffle(size, func(i, j int) {
		ports[i], ports[j] = ports[j], ports[i]
	})

	pool = &Pool{ports: ports}
}

func Next() uint16 {
	i := pool.index.Add(1) - 1
	return pool.ports[i%uint64(len(pool.ports))]
}

func GetSrcPort(seqNum uint16, basePort uint16) uint16 {
	return basePort + seqNum%measurement.Config.ConnectionCount
}

func init() {
	measurement.SetupPortPool = Setup
}
