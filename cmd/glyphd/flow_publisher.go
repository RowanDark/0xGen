package main

import (
	"context"
	"sync"

	"github.com/RowanDark/Glyph/internal/bus"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
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

func (p *busFlowPublisher) PublishFlowEvent(ctx context.Context, flowType pb.FlowEvent_Type, payload []byte) error {
	p.mu.RLock()
	server := p.bus
	p.mu.RUnlock()
	if server == nil {
		return nil
	}
	server.PublishFlowEvent(ctx, flowType, payload)
	return nil
}
