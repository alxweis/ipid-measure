package probe

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/parquet-go/parquet-go/bloom/xxhash"
)

// InflightEntry is one in-flight probe waiting for replies. Lives in a single
// registry shard; the prober that owns it pins it during the probe and removes
// it when done. The receiver looks the entry up by target IP, validates the
// reply, fills the matching sample, and signals the waiter if the entry's
// completion condition is satisfied.
//
// Why a struct (not a map<seq, chan>): one entry per target means the receiver
// performs exactly one map lookup per captured reply, irrespective of how many
// samples are outstanding. At 500M targets this is the single hottest read.
type InflightEntry struct {
	Probe *Probe

	// expectedCount is how many valid samples the prober is waiting for. It is
	// RequestCount in FixedInterval mode, or 1 in RT-based mode (the prober
	// re-registers/replaces it between successive seq numbers).
	expectedCount uint32

	// validCount counts samples already filled by the receiver. When it reaches
	// expectedCount, done is closed to wake the waiting prober.
	validCount atomic.Uint32

	// expectedSeq is set in RT-based mode to constrain matching to one specific
	// seqNum. sentinelAnySeq means "any seqNum within the probe is acceptable"
	// (FixedInterval mode).
	expectedSeq uint32

	// FlagMode tells the receiver-side validator which protocol flag set this
	// entry expects. Lets the entry encode the TCP handshake special case
	// (expect SYN+ACK) without referring to the prober.
	FlagMode FlagExpectation

	// done is closed exactly once when expectedCount is reached. Probers select
	// on done together with their own timeout.
	done     chan struct{}
	doneOnce sync.Once

	// portRange validates that the reply's destination port (== our source port)
	// belongs to this probe's connection range. minPort..minPort+ConnectionCount-1.
	minPort uint16
	maxPort uint16

	// senderIPs is the pair (A, B) so the receiver can check the reply's
	// destination IP without consulting any global. Stored as [4]byte for
	// allocation-free comparison.
	senderA, senderB [4]byte
}

// FlagExpectation enumerates the protocol-flag patterns the receiver expects
// from a matching reply for a given entry.
type FlagExpectation int32

const (
	// FlagsDefault: use the active payload's default reply flag set
	// (Config.TCPConfig.ReplyFlags for TCP, DNS QR for UDP/DNS, no flags for ICMP).
	FlagsDefault FlagExpectation = 0
	// FlagsSynAck: expect the TCP handshake SYN+ACK reply. Used for the seq=0
	// requests when EstablishConnection is set.
	FlagsSynAck FlagExpectation = 1
	// FlagsPshAck: expect the established-connection data reply (PSH+ACK).
	FlagsPshAck FlagExpectation = 2
)

// markDone closes the done channel exactly once. Safe under concurrent calls.
func (e *InflightEntry) markDone() {
	e.doneOnce.Do(func() { close(e.done) })
}

// inflightShard is one shard of the registry. Sharding cuts lock contention at
// high reply rates: every reply only touches one shard, chosen by hash(targetIP).
type inflightShard struct {
	mu      sync.RWMutex
	entries map[[4]byte]*InflightEntry
}

// numInflightShards is a power of two so the shard index is a cheap bitmask.
// 1024 shards keeps each shard's map small (a few hundred entries at most for
// any reasonable concurrency) and contention negligible.
const numInflightShards = 1024
const inflightShardMask = numInflightShards - 1

// Inflight is the process-wide registry. Owned by this package.
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

// shardFor returns the shard owning the given IPv4 address.
func (r *inflightRegistry) shardFor(ip [4]byte) *inflightShard {
	// xxhash gives a good spread for the small 4-byte input.
	h := xxhash.Sum64(ip[:])
	return &r.shards[h&inflightShardMask]
}

// Register installs entry for the given target and returns the entry. If a
// previous entry exists for the same target (should not happen with correct
// pool usage, but be defensive), it is replaced and its done channel signalled
// so the previous owner unblocks promptly.
func (r *inflightRegistry) Register(target [4]byte, entry *InflightEntry) {
	sh := r.shardFor(target)
	sh.mu.Lock()
	if prev, ok := sh.entries[target]; ok {
		prev.markDone()
	}
	sh.entries[target] = entry
	sh.mu.Unlock()
}

// Deregister removes the entry for the given target. Called by the prober when
// the probe is complete (success or timeout). Safe even if the entry was already
// replaced.
func (r *inflightRegistry) Deregister(target [4]byte, entry *InflightEntry) {
	sh := r.shardFor(target)
	sh.mu.Lock()
	if cur, ok := sh.entries[target]; ok && cur == entry {
		delete(sh.entries, target)
	}
	sh.mu.Unlock()
}

// Lookup returns the current entry for target, or nil. The returned pointer is
// safe to read; callers must hold no shard lock while doing protocol decode.
func (r *inflightRegistry) Lookup(target [4]byte) *InflightEntry {
	sh := r.shardFor(target)
	sh.mu.RLock()
	e := sh.entries[target]
	sh.mu.RUnlock()
	return e
}

// ipv4Key converts a net.IP (any representation) to a fixed [4]byte. Returns
// ok=false for non-IPv4 inputs.
func ipv4Key(ip net.IP) ([4]byte, bool) {
	var k [4]byte
	v4 := ip.To4()
	if v4 == nil {
		return k, false
	}
	copy(k[:], v4)
	return k, true
}
