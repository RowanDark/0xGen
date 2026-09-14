package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/RowanDark/0xgen/internal/bus"
	"github.com/RowanDark/0xgen/internal/flows"
)

// maxPendingFlowEvents bounds how many flow events busFlowPublisher will hold
// while no bus is attached. The window this covers is the brief daemon
// startup race between the proxy accepting traffic and SetBus being called;
// it is not meant as a general-purpose queue.
const maxPendingFlowEvents = 256

type pendingFlowEvent struct {
	ctx   context.Context
	event flows.Event
}

type busFlowPublisher struct {
	mu      sync.Mutex
	bus     *bus.Server
	pending []pendingFlowEvent
}

func newBusFlowPublisher() *busFlowPublisher {
	return &busFlowPublisher{}
}

// SetBus attaches (or detaches, if server is nil) the bus used to deliver
// flow events. Attaching flushes any events buffered while the bus was
// unset.
func (p *busFlowPublisher) SetBus(server *bus.Server) {
	p.mu.Lock()
	p.bus = server
	var pending []pendingFlowEvent
	if server != nil {
		pending, p.pending = p.pending, nil
	}
	p.mu.Unlock()

	for _, pe := range pending {
		server.PublishFlowEvent(pe.ctx, pe.event)
	}
}

// PublishFlowEvent delivers event to the attached bus, or buffers it if no
// bus is attached yet. It never silently discards an event: once the buffer
// is full it reports an error instead of dropping the event without a trace.
func (p *busFlowPublisher) PublishFlowEvent(ctx context.Context, event flows.Event) error {
	p.mu.Lock()
	server := p.bus
	if server == nil {
		if len(p.pending) >= maxPendingFlowEvents {
			p.mu.Unlock()
			return fmt.Errorf("flow publisher: bus not attached and pending buffer full (%d events)", maxPendingFlowEvents)
		}
		p.pending = append(p.pending, pendingFlowEvent{ctx: ctx, event: event})
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	server.PublishFlowEvent(ctx, event)
	return nil
}
