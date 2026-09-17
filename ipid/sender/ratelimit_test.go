package sender

import (
	"testing"
	"time"
)

func TestRateLimiterChargesEveryPacket(t *testing.T) {
	rl := newRateLimiter(0, 1_000, time.Second)
	rl.mu.Lock()
	rl.availPackets = 3
	rl.last = time.Now().Add(time.Hour) // disable refill during the assertions
	rl.mu.Unlock()

	for i := 0; i < 3; i++ {
		if !rl.Acquire(64) {
			t.Fatal("Acquire returned false before Stop")
		}
	}

	rl.mu.Lock()
	remaining := rl.availPackets
	rl.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remaining packet tokens = %v, want 0", remaining)
	}
}

func TestRateLimiterStopUnblocksAcquire(t *testing.T) {
	rl := newRateLimiter(0, 1, time.Second)
	rl.mu.Lock()
	rl.availPackets = 0
	rl.last = time.Now().Add(time.Hour)
	rl.mu.Unlock()

	result := make(chan bool, 1)
	go func() { result <- rl.Acquire(64) }()
	rl.Stop()

	select {
	case acquired := <-result:
		if acquired {
			t.Fatal("Acquire succeeded after Stop")
		}
	case <-time.After(time.Second):
		t.Fatal("Acquire remained blocked after Stop")
	}
}

func TestRateLimiterTargetCancellation(t *testing.T) {
	rl := newRateLimiter(0, 1, time.Second)
	rl.availPackets = 0
	rl.last = time.Now().Add(time.Hour)
	cancelled := make(chan struct{})
	result := make(chan bool, 1)
	go func() { result <- rl.AcquireUntil(64, cancelled) }()
	close(cancelled)
	select {
	case ok := <-result:
		if ok {
			t.Fatal("cancelled target acquired tokens")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled target remained blocked")
	}
	rl.mu.Lock()
	rl.availPackets = 1
	rl.mu.Unlock()
	if rl.AcquireUntil(64, cancelled) {
		t.Fatal("cancelled target consumed available tokens")
	}
	if !rl.Acquire(64) {
		t.Fatal("target cancellation stopped shared limiter")
	}
}

func TestSenderCancelledWhileWaitingForSocket(t *testing.T) {
	s := &Sender{Fd: -1}
	s.mu.Lock()
	ready := true
	result := make(chan error, 1)
	go func() {
		_, err := s.SendIf([]byte{1}, func() bool { return ready })
		result <- err
	}()
	ready = false
	s.mu.Unlock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("cancelled send reached invalid socket: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled send remained blocked")
	}
}
