package bus

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/logging"
	"github.com/RowanDark/Glyph/internal/netgate"
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

func TestWithGateOptionsApplied(t *testing.T) {
	applied := false
	server := NewServer("token", nil, WithGateOptions(func(*netgate.Gate) {
		applied = true
	}))
	if server == nil {
		t.Fatal("expected server instance")
	}
	if !applied {
		t.Fatal("expected gate option to be applied")
	}
}

func TestEventStream_ValidAuth(t *testing.T) {
	server := NewServer("test-token", nil)
	mockStream := newMockStream(context.Background())

	grant, err := server.GrantCapabilities(context.Background(), &pb.PluginCapabilityRequest{
		AuthToken:    "test-token",
		PluginName:   "test-plugin",
		Capabilities: []string{"CAP_EMIT_FINDINGS"},
	})
	if err != nil {
		t.Fatalf("grant capabilities: %v", err)
	}

	// Simulate the client sending a valid hello message
	go func() {
		mockStream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Hello{
				Hello: &pb.PluginHello{
					AuthToken:       "test-token",
					PluginName:      "test-plugin",
					Pid:             123,
					Subscriptions:   []string{"FLOW_RESPONSE"},
					Capabilities:    []string{"CAP_EMIT_FINDINGS"},
					CapabilityToken: grant.GetCapabilityToken(),
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
	server := NewServer("test-token", nil)
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

func TestPublishFlowEventBroadcasts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := NewServer("token", nil)
	stream := newMockStream(ctx)

	go func() {
		stream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Hello{
				Hello: &pb.PluginHello{
					AuthToken:     "token",
					PluginName:    "proxy-listener",
					Pid:           42,
					Subscriptions: []string{"FLOW_RESPONSE"},
				},
			},
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.EventStream(stream)
	}()

	select {
	case <-time.After(50 * time.Millisecond):
	case err := <-errCh:
		t.Fatalf("event stream terminated early: %v", err)
	}

	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	server.PublishFlowEvent(context.Background(), pb.FlowEvent_FLOW_RESPONSE, payload)

	select {
	case event := <-stream.SendChan:
		flow := event.GetFlowEvent()
		if flow == nil {
			t.Fatal("expected flow event")
		}
		if flow.GetType() != pb.FlowEvent_FLOW_RESPONSE {
			t.Fatalf("flow type = %v, want FLOW_RESPONSE", flow.GetType())
		}
		if string(flow.GetData()) != string(payload) {
			t.Fatalf("flow payload mismatch: %q", string(flow.GetData()))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published event")
	}

	cancel()
	close(stream.RecvChan)
	if err := <-errCh; err != nil && err != io.EOF {
		t.Fatalf("event stream error: %v", err)
	}
}

func TestServerDisconnectPlugin(t *testing.T) {
	server := NewServer("token", findings.NewBus())
	pluginConn := &plugin{
		eventChan:     make(chan *pb.HostEvent, 1),
		subscriptions: make(map[string]struct{}),
		capabilities:  make(map[string]struct{}),
	}

	server.addConnection("demo-123", pluginConn)
	server.gate.Register("demo-123", []string{"CAP_EMIT_FINDINGS"})

	if got := server.DisconnectPlugin("demo", "test"); got != 1 {
		t.Fatalf("expected 1 disconnected plugin, got %d", got)
	}
	if len(server.connections) != 0 {
		t.Fatalf("expected connections map to be empty, got %d", len(server.connections))
	}
	if _, ok := <-pluginConn.eventChan; ok {
		t.Fatal("expected event channel to be closed")
	}

	if got := server.DisconnectPlugin("demo", "test"); got != 0 {
		t.Fatalf("expected subsequent disconnect to return 0, got %d", got)
	}
}

func TestEventStream_MissingHello(t *testing.T) {
	server := NewServer("test-token", nil)
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

func TestPublishFindingEmitsToBus(t *testing.T) {
	bus := findings.NewBus()
	server := NewServer("token", bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := bus.Subscribe(ctx)
	incoming := &pb.Finding{
		Type:     "missing-header",
		Message:  "Missing security header",
		Severity: pb.Severity_HIGH,
		Metadata: map[string]string{
			"id":       "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4",
			"target":   "https://example.com",
			"evidence": "Header X-Test missing",
		},
	}

	server.publishFinding(ctx, "plugin-1", incoming)

	select {
	case finding := <-ch:
		if finding.ID != "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4" {
			t.Fatalf("unexpected id: %s", finding.ID)
		}
		if finding.Version != findings.SchemaVersion {
			t.Fatalf("unexpected version: %s", finding.Version)
		}
		if finding.Plugin != "plugin-1" {
			t.Fatalf("unexpected plugin: %s", finding.Plugin)
		}
		if finding.Target != "https://example.com" {
			t.Fatalf("unexpected target: %s", finding.Target)
		}
		if finding.Evidence != "Header X-Test missing" {
			t.Fatalf("unexpected evidence: %s", finding.Evidence)
		}
		if finding.Severity != findings.SeverityHigh {
			t.Fatalf("unexpected severity: %s", finding.Severity)
		}
		if finding.DetectedAt.IsZero() {
			t.Fatal("expected detected_at to be populated")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for finding from bus")
	}
}

func TestEventStreamDeniesCapabilityEscalation(t *testing.T) {
	server := NewServer("test-token", nil)
	mockStream := newMockStream(context.Background())

	grant, err := server.GrantCapabilities(context.Background(), &pb.PluginCapabilityRequest{
		AuthToken:    "test-token",
		PluginName:   "test-plugin",
		Capabilities: []string{"CAP_EMIT_FINDINGS"},
	})
	if err != nil {
		t.Fatalf("grant capabilities: %v", err)
	}

	go func() {
		mockStream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Hello{
				Hello: &pb.PluginHello{
					AuthToken:       "test-token",
					PluginName:      "test-plugin",
					Pid:             42,
					Capabilities:    []string{"CAP_EMIT_FINDINGS", "CAP_HTTP_ACTIVE"},
					CapabilityToken: grant.GetCapabilityToken(),
				},
			},
		}
	}()

	err = server.EventStream(mockStream)
	if err == nil {
		t.Fatal("expected escalation attempt to be rejected")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.PermissionDenied {
		t.Fatalf("expected permission denied, got %v", st.Code())
	}
}

func TestAuditLogEmittedOnDeniedAuth(t *testing.T) {
	buf := &bytes.Buffer{}
	audit, err := logging.NewAuditLogger("plugin_bus_test", logging.WithoutStdout(), logging.WithWriter(buf))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	server := NewServer("secure-token", nil, WithAuditLogger(audit))
	stream := newMockStream(context.Background())

	go func() {
		stream.RecvChan <- &pb.PluginEvent{
			Event: &pb.PluginEvent_Hello{
				Hello: &pb.PluginHello{
					AuthToken:  "invalid",
					PluginName: "audit-tester",
					Pid:        100,
				},
			},
		}
	}()

	if err := server.EventStream(stream); err == nil {
		t.Fatalf("expected authentication failure")
	}

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) == 0 {
		t.Fatalf("expected audit log entries, got none")
	}

	var event logging.AuditEvent
	if err := json.Unmarshal(lines[0], &event); err != nil {
		t.Fatalf("failed to decode audit event: %v", err)
	}
	if event.EventType != logging.EventPluginLoad {
		t.Fatalf("expected plugin_load event, got %s", event.EventType)
	}
	if event.Decision != logging.DecisionDeny {
		t.Fatalf("expected decision deny, got %s", event.Decision)
	}
	if event.Reason == "" {
		t.Fatal("expected reason to be populated")
	}
}

func TestEventStreamRejectsMalformedFinding(t *testing.T) {
	buf := &bytes.Buffer{}
	audit, err := logging.NewAuditLogger("plugin_bus_test", logging.WithoutStdout(), logging.WithWriter(buf))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	findingsBus := findings.NewBus()
	server := NewServer("secure-token", findingsBus, WithAuditLogger(audit))

	grant, err := server.GrantCapabilities(context.Background(), &pb.PluginCapabilityRequest{
		AuthToken:    "secure-token",
		PluginName:   "malformed",
		Capabilities: []string{"CAP_EMIT_FINDINGS"},
	})
	if err != nil {
		t.Fatalf("grant capabilities: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newMockStream(ctx)
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.EventStream(stream)
	}()

	stream.RecvChan <- &pb.PluginEvent{
		Event: &pb.PluginEvent_Hello{
			Hello: &pb.PluginHello{
				AuthToken:       "secure-token",
				PluginName:      "malformed",
				Pid:             7,
				Subscriptions:   []string{"FLOW_RESPONSE"},
				Capabilities:    []string{"CAP_EMIT_FINDINGS"},
				CapabilityToken: grant.GetCapabilityToken(),
			},
		},
	}

	findingsCtx, findingsCancel := context.WithCancel(context.Background())
	defer findingsCancel()
	sub := findingsBus.Subscribe(findingsCtx)

	stream.RecvChan <- &pb.PluginEvent{
		Event: &pb.PluginEvent_Finding{
			Finding: &pb.Finding{Message: "missing type"},
		},
	}
	close(stream.RecvChan)

	if err := <-errCh; err != nil {
		t.Fatalf("EventStream returned error: %v", err)
	}

	select {
	case f := <-sub:
		t.Fatalf("unexpected finding published: %+v", f)
	default:
	}

	entries := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	var rejected bool
	for _, line := range entries {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event logging.AuditEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("decode audit event: %v", err)
		}
		if event.EventType == logging.EventFindingRejected {
			rejected = true
			if event.PluginID == "" {
				t.Fatalf("expected plugin id on rejection event")
			}
			break
		}
	}
	if !rejected {
		t.Fatal("expected malformed finding to trigger audit rejection event")
	}
}
