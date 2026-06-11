package probe

import (
	"github.com/alxweis/ipid-measure/internal/sets"
	"sync"
	"sync/atomic"

	"github.com/parquet-go/parquet-go/bloom/xxhash"
)

type InflightEntry struct {
	Probe *Probe

	expectedCount uint16

	expectedSenders sets.Set[[4]byte]

	expectedMinPort uint16
	expectedMaxPort uint16

	expectedFlags FlagExpectation

	expectedMinSeq uint16
	expectedMaxSeq uint16

	validCount atomic.Uint32

	done     chan struct{}
	doneOnce sync.Once
}

type FlagExpectation uint8

const (
	FlagsDefault FlagExpectation = 0
	FlagsSynAck  FlagExpectation = 1
	FlagsPshAck  FlagExpectation = 2
)

func (e *InflightEntry) markDone() {
	e.doneOnce.Do(func() { close(e.done) })
}

type inflightShard struct {
	mu      sync.RWMutex
	entries map[[4]byte]*InflightEntry
}

const numInflightShards = 1024
const inflightShardMask = numInflightShards - 1

var Inflight = func() *inflightRegistry {
	r := &inflightRegistry{}
	for i := range r.shards {
		r.shards[i].entries = make(map[[4]byte]*InflightEntry, 256)
	}
	return r
}()

type inflightRegistry struct {
	shards [numInflightShards]inflightShard
}

func (r *inflightRegistry) shardFor(ip [4]byte) *inflightShard {
	// xxhash gives a good spread for the small 4-byte input.
	h := xxhash.Sum64(ip[:])
	return &r.shards[h&inflightShardMask]
}

func (r *inflightRegistry) Register(target [4]byte, entry *InflightEntry) {
	sh := r.shardFor(target)
	sh.mu.Lock()
	if prev, ok := sh.entries[target]; ok {
		prev.markDone()
	}
	sh.entries[target] = entry
	sh.mu.Unlock()
}

func (r *inflightRegistry) Deregister(target [4]byte, entry *InflightEntry) {
	sh := r.shardFor(target)
	sh.mu.Lock()
	if cur, ok := sh.entries[target]; ok && cur == entry {
		delete(sh.entries, target)
	}
	sh.mu.Unlock()
}

func (r *inflightRegistry) Lookup(target [4]byte) *InflightEntry {
	sh := r.shardFor(target)
	sh.mu.RLock()
	e := sh.entries[target]
	sh.mu.RUnlock()
	return e
}
