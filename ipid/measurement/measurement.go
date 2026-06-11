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

var (
	Config *config.IPIDConfig
	Paths  *paths.IPIDMeasurement

	RequestCount uint16

	TcpSequenceNumOffset uint32

	TcpEstablishConnection bool

	HasPorts bool
)

var (
	SaveWg     sync.WaitGroup
	WorkerWg   sync.WaitGroup
	ReceiverWg sync.WaitGroup
	LogsWg     sync.WaitGroup
)

var (
	StopSignal    = make(chan struct{})
	StopReceiving = make(chan struct{})
	StopLogs      = make(chan struct{})
)

var stopOnce sync.Once

var (
	SetupSenders     func()
	CloseSenders     func()
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
	GetRecordCount   func() int64
)

// Run wires the pipeline together and blocks until the whole
// target stream has been probed (or an interrupt is received)
func Run(c *config.IPIDConfig, m *paths.IPIDMeasurement) (int64, error) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	Config = c
	Paths = m
	RequestCount = Config.ConnectionCount * Config.RequestsPerConnection
	TcpSequenceNumOffset = uint32(rand.Uint64() % (math.MaxUint32 - uint64(RequestCount)))

	printConfig()

	// Build immutable, shared resources before any goroutine starts.
	SetupPayload()
	SetupSenders()
	SetupRawPackets()
	SetupPortPool()
	SetupRateLimiter()
	SetupSaveChannel()

	// Allow Ctrl+C to trigger a graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			log.Printf("interrupt received: finishing in-flight probes and flushing results...")
			triggerStop()
		case <-finished:
			// Normal end-of-run, nothing to do.
		}
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
		return records(), err
	}

	cleanup()
	return records(), nil
}

// records returns the final record count, or 0 if the stats hook is not wired.
func records() int64 {
	if GetRecordCount == nil {
		return 0
	}
	return GetRecordCount()
}

// triggerStop closes the lifecycle channels exactly once.
func triggerStop() {
	stopOnce.Do(func() {
		close(StopSignal)
	})
}

// cleanup drains the pipeline
func cleanup() {
	isInterrupt := false
	select {
	case <-StopSignal:
		isInterrupt = true
	default:
	}

	// Release any goroutines currently blocked on the rate limiter so they observe the stop signal and exit promptly.
	if isInterrupt && StopRateLimiter != nil {
		StopRateLimiter()
	}

	// No more targets will be produced: close worker input channels and wait for all probing to finish.
	CloseTargetChans()
	WorkerWg.Wait()

	// Probing finished: close the save channel and wait for the writer to flush every buffered record to disk.
	CloseSaveChan()
	SaveWg.Wait()

	// No probe can reference a reply any more: stop the receivers.
	close(StopReceiving)
	ReceiverWg.Wait()

	// All sockets idle: release the AF_PACKET file descriptors.
	if CloseSenders != nil {
		CloseSenders()
	}

	// On normal completion: stop the rate limiter now.
	if !isInterrupt && StopRateLimiter != nil {
		StopRateLimiter()
	}

	// Stop the stats logger.
	close(StopLogs)
	LogsWg.Wait()
}
