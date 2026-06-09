package measurement

import (
	"context"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/alxweis/ipid-measure/internal/config"
	"github.com/alxweis/ipid-measure/internal/paths"
)

// The measurement package is the central, dependency-free state holder and
// orchestrator. It intentionally imports NO ipid/* sub-package so that every
// sub-package may import it without creating an import cycle. Sub-packages wire
// their behaviour into the orchestration through the function hooks below, which
// they populate from their own package-level setup code.

var (
	// Config and Paths describe the immutable parameters of the running
	// measurement. They are written once before any goroutine starts and only
	// read afterwards, so they require no synchronisation.
	Config *config.IPIDConfig
	Paths  *paths.IPIDMeasurement

	// RequestCount is ConnectionCount * RequestsPerConnection. It is a hot value
	// read on every probe, so it is cached here as a plain field.
	RequestCount uint16

	// TcpSequenceNumOffset is fixed random offset for assigned TCP sequence numbers, to appear less suspicious
	TcpSequenceNumOffset uint32

	// TcpEstablishConnection caches the (Payload==TCP && EstablishConnection)
	// decision so the hot path avoids repeating the comparison.
	TcpEstablishConnection bool
)

// WaitGroups used by cleanup() to drain the pipeline stages in order.
var (
	SaveWg     sync.WaitGroup
	WorkerWg   sync.WaitGroup
	ReceiverWg sync.WaitGroup
	LogsWg     sync.WaitGroup
)

// Lifecycle signals. They are closed (never sent to) so that every reader
// observes the shutdown via a receive on a closed channel.
var (
	StopSignal    = make(chan struct{})
	StopReceiving = make(chan struct{})
	StopLogs      = make(chan struct{})
)

// stopOnce guards the lifecycle channels against a double close when both an
// interrupt and the normal completion path race.
var stopOnce sync.Once

// Hooks. Each sub-package assigns the relevant hook during Run's setup phase via
// the exported Setup* functions it owns. Using hooks (instead of importing the
// sub-packages here) is what keeps this package a dependency leaf.
var (
	SetupSenders     func()
	SetupRateLimiter func()
	StopRateLimiter  func()
	SetupPayload     func()
	SetupRawPackets  func()
	SetupPortPool    func()
	SetupSaveChannel func()
	StartSaver       func()
	StartReceivers   func()
	StartWorkers     func()
	StartStats       func()
	StreamTargets    func() error
	CloseTargetChans func()
	CloseSaveChan    func()
)

// Run wires the pipeline together and blocks until the whole target stream has
// been probed (or an interrupt is received), then performs an ordered shutdown.
func Run(c *config.IPIDConfig, m *paths.IPIDMeasurement) error {
	runtime.GOMAXPROCS(runtime.NumCPU())

	Config = c
	Paths = m
	RequestCount = Config.ConnectionCount * Config.RequestsPerConnection
	TcpSequenceNumOffset = uint32(rand.Uint64() % (math.MaxUint32 - uint64(RequestCount)))

	printConfig()

	// Build immutable, shared resources before any goroutine starts.
	// Order matters: SetupRawPackets builds template packets per seqNum and
	// for each one looks up the corresponding sender via sender.GetSender(),
	// reading sender.SenderA / sender.SenderB. We therefore have to set up
	// the senders FIRST and only then the raw packet templates.
	//
	// SetupPayload also sets TcpEstablishConnection (it owns the protocol type).
	SetupPayload()
	SetupSenders()
	SetupRawPackets()
	SetupPortPool()
	SetupRateLimiter()
	SetupSaveChannel()

	// Allow Ctrl+C to trigger a graceful shutdown: stop feeding new targets and
	// let the in-flight stages drain through cleanup().
	//
	// Note: signal.NotifyContext also cancels ctx when our own deferred stop()
	// runs at function return. The watcher goroutine below therefore prints
	// "interrupt received" both on real signals and at normal end-of-run --
	// the latter is cosmetic noise but harmless (triggerStop() is idempotent
	// via sync.Once, and at end-of-run cleanup() has already finished).
	//
	// An earlier attempt at "fixing" this via a runFinished atomic flag
	// introduced a subtle interaction with cleanup() that caused the program
	// to hang after probing completed. Until we understand the root cause,
	// the cosmetic log line is the lesser evil.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Printf("interrupt received: finishing in-flight probes and flushing results...")
		triggerStop()
	}()

	// Start the consumer stages first so producers never block on startup.
	SaveWg.Add(1)
	StartSaver()

	StartReceivers()

	StartWorkers()

	LogsWg.Add(1)
	StartStats()

	// Feed targets until the source is exhausted or shutdown is requested.
	if err := StreamTargets(); err != nil {
		triggerStop()
		cleanup()
		return err
	}

	cleanup()

	log.Printf("IPID measurement completed: %s", Paths.Path)
	return nil
}

// triggerStop closes the lifecycle channels exactly once.
func triggerStop() {
	stopOnce.Do(func() {
		close(StopSignal)
	})
}

// cleanup drains the pipeline stages strictly in producer->consumer order so no
// stage is closed while another may still write to it.
func cleanup() {
	// 0. Release any goroutines currently blocked on the rate limiter so they
	//    can observe the stop signal and exit promptly. This is safe to do
	//    before closing the target channels because the prober loop checks the
	//    stop signal between probes.
	if StopRateLimiter != nil {
		StopRateLimiter()
	}

	// 1. No more targets will be produced: close worker input channels and wait
	//    for all probing to finish.
	CloseTargetChans()
	WorkerWg.Wait()

	// 2. Probing finished: close the save channel and wait for the writer to
	//    flush every buffered record to disk.
	CloseSaveChan()
	SaveWg.Wait()

	// 3. No probe can reference a reply any more: stop the receivers.
	close(StopReceiving)
	ReceiverWg.Wait()

	// 4. Finally stop the stats logger.
	close(StopLogs)
	LogsWg.Wait()
}
