package os

import (
	"context"
	"errors"
	"testing"

	"github.com/alxweis/ipid-measure/internal/records"
)

func TestDrainWriterContinuesAfterFailure(t *testing.T) {
	in := make(chan records.OSRecord)
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		defer close(in)
		for i := 0; i < 3; i++ {
			in <- records.OSRecord{IPAddress: "192.0.2.1", OSName: "Linux"}
		}
	}()

	want := errors.New("disk full")
	appendCalls := 0
	_, cancel := context.WithCancel(context.Background())
	err := drainWriter(in, func(records.OSRecord) error {
		appendCalls++
		return want
	}, cancel)

	<-producerDone
	if !errors.Is(err, want) {
		t.Fatalf("drainWriter() error = %v, want %v", err, want)
	}
	if appendCalls != 1 {
		t.Fatalf("append calls = %d, want 1", appendCalls)
	}
}
