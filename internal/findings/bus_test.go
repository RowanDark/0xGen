package findings

import (
	"context"
	"testing"
	"time"
)

func TestBusEmitDeliversToSubscribers(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := bus.Subscribe(ctx)
	finding := Finding{
		ID:         NewID(),
		Plugin:     "p",
		Type:       "demo",
		Message:    "demo message",
		Severity:   SeverityInfo,
		DetectedAt: NewTimestamp(time.Now()),
	}

	done := make(chan struct{})
	go func() {
		bus.Emit(finding)
		close(done)
	}()

	select {
	case got := <-ch:
		if got.ID != finding.ID || got.Plugin != finding.Plugin {
			t.Fatalf("unexpected finding: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for finding")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("emit did not return")
	}
}

func TestBusSubscribeCancelClosesChannel(t *testing.T) {
	bus := NewBus()
	ctx, cancel := context.WithCancel(context.Background())

	ch := bus.Subscribe(ctx)
	cancel()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for channel close")
	}
}
