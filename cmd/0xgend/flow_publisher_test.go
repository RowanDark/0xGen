package main

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/RowanDark/0xgen/internal/bus"
	"github.com/RowanDark/0xgen/internal/flows"
	pb "github.com/RowanDark/0xgen/proto/gen/go/proto/oxg"
	"google.golang.org/grpc"
)

// mockEventStream is a minimal pb.PluginBus_EventStreamServer implementation
// used to observe events broadcast by a bus.Server without spinning up a
// real gRPC connection.
type mockEventStream struct {
	grpc.ServerStream
	RecvChan chan *pb.PluginEvent
	SendChan chan *pb.HostEvent
	ctx      context.Context
}

func newMockEventStream(ctx context.Context) *mockEventStream {
	return &mockEventStream{
		RecvChan: make(chan *pb.PluginEvent, 1),
		SendChan: make(chan *pb.HostEvent, 1),
		ctx:      ctx,
	}
}

func (m *mockEventStream) Send(event *pb.HostEvent) error {
	m.SendChan <- event
	return nil
}

func (m *mockEventStream) Recv() (*pb.PluginEvent, error) {
	event, ok := <-m.RecvChan
	if !ok {
		return nil, io.EOF
	}
	return event, nil
}

func (m *mockEventStream) Context() context.Context {
	return m.ctx
}

// TestBusFlowPublisherBuffersUntilBusAttached reproduces the daemon startup
// race described in Issue 21: a flow event published before SetBus is called
// must not be silently dropped. It must either be buffered and delivered
// once the bus is attached, or reported as an error.
func TestBusFlowPublisherBuffersUntilBusAttached(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := bus.NewServer("token", nil)
	stream := newMockEventStream(ctx)

	grant, err := server.GrantCapabilities(context.Background(), &pb.PluginCapabilityRequest{
		AuthToken:    "token",
		PluginName:   "proxy-listener",
		Capabilities: []string{bus.CapFlowInspect},
	})
	if err != nil {
		t.Fatalf("grant capabilities: %v", err)
	}

	stream.RecvChan <- &pb.PluginEvent{
		Event: &pb.PluginEvent_Hello{
			Hello: &pb.PluginHello{
				AuthToken:       "token",
				PluginName:      "proxy-listener",
				Pid:             1,
				Subscriptions:   []string{"FLOW_RESPONSE"},
				Capabilities:    []string{bus.CapFlowInspect},
				CapabilityToken: grant.GetCapabilityToken(),
			},
		},
	}

	streamErrCh := make(chan error, 1)
	go func() {
		streamErrCh <- server.EventStream(stream)
	}()

	// Give the plugin time to complete its handshake and subscribe before we
	// publish anything.
	time.Sleep(50 * time.Millisecond)

	publisher := newBusFlowPublisher()

	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	event := flows.Event{Type: pb.FlowEvent_FLOW_RESPONSE, Sanitized: payload}

	// Publish before the bus is attached: this must not be a silent discard.
	if err := publisher.PublishFlowEvent(context.Background(), event); err != nil {
		t.Fatalf("PublishFlowEvent before SetBus returned unexpected error: %v", err)
	}

	select {
	case <-stream.SendChan:
		t.Fatal("event delivered before the bus was attached")
	case <-time.After(50 * time.Millisecond):
	}

	// Attaching the bus must flush the buffered event to the already
	// connected plugin.
	publisher.SetBus(server)

	select {
	case sent := <-stream.SendChan:
		flow := sent.GetFlowEvent()
		if flow == nil {
			t.Fatal("expected flow event")
		}
		if string(flow.GetData()) != string(payload) {
			t.Fatalf("flow payload mismatch: got %q want %q", flow.GetData(), payload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for buffered event to be delivered")
	}

	cancel()
	close(stream.RecvChan)
	if err := <-streamErrCh; err != nil && err != io.EOF {
		t.Fatalf("event stream error: %v", err)
	}
}

// TestBusFlowPublisherReportsErrorWhenBufferFull ensures that once the
// pending buffer is exhausted, further events are reported as errors rather
// than silently discarded.
func TestBusFlowPublisherReportsErrorWhenBufferFull(t *testing.T) {
	publisher := newBusFlowPublisher()

	for i := 0; i < maxPendingFlowEvents; i++ {
		if err := publisher.PublishFlowEvent(context.Background(), flows.Event{Type: pb.FlowEvent_FLOW_RESPONSE}); err != nil {
			t.Fatalf("unexpected error filling buffer at index %d: %v", i, err)
		}
	}

	if err := publisher.PublishFlowEvent(context.Background(), flows.Event{Type: pb.FlowEvent_FLOW_RESPONSE}); err == nil {
		t.Fatal("expected an error once the pending buffer is full, got nil")
	}
}
