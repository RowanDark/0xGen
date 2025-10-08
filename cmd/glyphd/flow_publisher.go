package main

import (
	"context"
	"sync"

	"github.com/RowanDark/Glyph/internal/bus"
	"github.com/RowanDark/Glyph/internal/flows"
)

type busFlowPublisher struct {
	mu  sync.RWMutex
	bus *bus.Server
}

func newBusFlowPublisher() *busFlowPublisher {
	return &busFlowPublisher{}
}

func (p *busFlowPublisher) SetBus(server *bus.Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bus = server
}

func (p *busFlowPublisher) PublishFlowEvent(ctx context.Context, event flows.Event) error {
	p.mu.RLock()
	server := p.bus
	p.mu.RUnlock()
	if server == nil {
		return nil
	}
	server.PublishFlowEvent(ctx, event)
	return nil
}
