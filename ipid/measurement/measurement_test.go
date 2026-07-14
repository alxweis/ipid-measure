package measurement

import (
	"errors"
	"sync"
	"testing"
)

func TestFailRecordsFirstErrorAndStopsRun(t *testing.T) {
	runErrorChannel = make(chan error, 1)
	runErrorOnce = sync.Once{}
	StopSignal = make(chan struct{})
	stopOnce = sync.Once{}

	first := errors.New("first")
	Fail(first)
	Fail(errors.New("second"))

	select {
	case <-StopSignal:
	default:
		t.Fatal("StopSignal was not closed")
	}
	if got := currentRunError(); !errors.Is(got, first) {
		t.Fatalf("currentRunError() = %v, want first error", got)
	}
}
