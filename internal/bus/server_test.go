package bus

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockEventStream is a mock implementation of the PluginBus_EventStreamServer interface.
type mockEventStream struct {
	grpc.ServerStream
	RecvChan chan *pb.PluginEvent
	SendChan chan *pb.HostEvent
	ctx      context.Context
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

func newMockStream(ctx context.Context) *mockEventStream {
	return &mockEventStream{
		RecvChan: make(chan *pb.PluginEvent, 1),
		SendChan: make(chan *pb.HostEvent, 1),
		ctx:      ctx,
	}
}

func TestEventStream_ValidAuth(t *testing.T) {
	server := NewServer("test-token")
	mockStream := newMockStream(context.Background())

	// Simulate the client sending a valid hello message
	go func() {
		mockStream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Hello{
				Hello: &pb.PluginHello{
					AuthToken:     "test-token",
					PluginName:    "test-plugin",
					Pid:           123,
					Subscriptions: []string{"FLOW_RESPONSE"},
				},
			},
		}
		// Keep the stream open by not closing the channel, but do nothing else.
		// In a real test, we might test event broadcast here.
	}()

	// The EventStream call will block. We run it in a goroutine and expect it not to return an error immediately.
	// A more complex test would involve closing the stream and checking the final error (which should be io.EOF).
	// For this test, we just want to ensure authentication passes.
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.EventStream(mockStream)
	}()

	// If authentication fails, an error will be sent quickly.
	// If it succeeds, the server will block on Recv(), and we won't get an error.
	select {
	case err := <-errChan:
		t.Fatalf("EventStream() returned an unexpected error: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Success: No error was returned, meaning authentication passed and the server is waiting for more messages.
		t.Log("Authentication successful as expected.")
	}
}

func TestEventStream_InvalidAuth(t *testing.T) {
	server := NewServer("test-token")
	mockStream := newMockStream(context.Background())

	// Simulate the client sending an invalid hello message
	go func() {
		mockStream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Hello{
				Hello: &pb.PluginHello{
					AuthToken:  "wrong-token",
					PluginName: "test-plugin",
					Pid:        123,
				},
			},
		}
	}()

	err := server.EventStream(mockStream)
	if err == nil {
		t.Fatal("EventStream() did not return an error for invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected a gRPC status error, but got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected status code %v, but got %v", codes.Unauthenticated, st.Code())
	}
	t.Logf("Received expected error: %v", err)
}

func TestEventStream_MissingHello(t *testing.T) {
	server := NewServer("test-token")
	mockStream := newMockStream(context.Background())

	// Simulate the client sending a finding instead of a hello message
	go func() {
		mockStream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Finding{
				Finding: &pb.Finding{Type: "some-finding"},
			},
		}
	}()

	err := server.EventStream(mockStream)
	if err == nil {
		t.Fatal("EventStream() did not return an error for missing hello")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected a gRPC status error, but got: %v", err)
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected status code %v, but got %v", codes.Unauthenticated, st.Code())
	}
	t.Logf("Received expected error: %v", err)
}
