package findings

import (
	"context"
	"sync"
)

// Bus provides an in-process pub/sub system for findings. Multiple subscribers
// can listen for emitted findings concurrently.
type Bus struct {
	mu   sync.RWMutex
	subs map[int]chan Finding
	next int
}

// NewBus returns a new, empty findings bus.
func NewBus() *Bus {
	return &Bus{
		subs: make(map[int]chan Finding),
	}
}

// Subscribe registers a new subscriber that will receive emitted findings. The
// returned channel is closed when the provided context is cancelled.
func (b *Bus) Subscribe(ctx context.Context) <-chan Finding {
	ch := make(chan Finding, 16)

	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if sub, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(sub)
		}
		b.mu.Unlock()
	}()

	return ch
}

// Emit publishes a finding to all registered subscribers. If no subscribers are
// present the call is a no-op.
func (b *Bus) Emit(f Finding) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, ch := range b.subs {
		ch <- f
	}
}
