package bus

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/Glyph/internal/findings"
	"github.com/RowanDark/Glyph/internal/logging"
	"github.com/RowanDark/Glyph/internal/netgate"
	obsmetrics "github.com/RowanDark/Glyph/internal/observability/metrics"
	"github.com/RowanDark/Glyph/internal/observability/tracing"
	"github.com/RowanDark/Glyph/internal/plugins/capabilities"
	pb "github.com/RowanDark/Glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	coreVersion     = "v0.1.0"
	CapEmitFindings = "CAP_EMIT_FINDINGS"
)

// plugin holds the information about a connected plugin.
type plugin struct {
	eventChan     chan *pb.HostEvent
	subscriptions map[string]struct{}
	capabilities  map[string]struct{}
}

// Server implements the PluginBus service.
type Server struct {
	pb.UnimplementedPluginBusServer
	audit       *logging.AuditLogger
	authToken   string
	mu          sync.RWMutex
	connections map[string]*plugin
	findings    *findings.Bus
	gate        *netgate.Gate
	caps        *capabilities.Manager
	gateOpts    []netgate.Option
}

// NewServer creates a new bus server.
type Option func(*Server)

func WithAuditLogger(logger *logging.AuditLogger) Option {
	return func(s *Server) {
		if logger != nil {
			s.audit = logger
		}
	}
}

// WithGateOptions applies custom netgate options when constructing the gate.
func WithGateOptions(opts ...netgate.Option) Option {
	return func(s *Server) {
		if len(opts) == 0 {
			return
		}
		s.gateOpts = append(s.gateOpts, opts...)
	}
}

func NewServer(authToken string, findingsBus *findings.Bus, opts ...Option) *Server {
	if findingsBus == nil {
		findingsBus = findings.NewBus()
	}
	srv := &Server{
		audit:       logging.MustNewAuditLogger("plugin_bus"),
		authToken:   authToken,
		connections: make(map[string]*plugin),
		findings:    findingsBus,
		caps:        capabilities.NewManager(),
	}
	for _, opt := range opts {
		opt(srv)
	}
	var gateAudit *logging.AuditLogger
	if srv.audit != nil {
		gateAudit = srv.audit.WithComponent("netgate")
	}
	gateOpts := append([]netgate.Option{netgate.WithAuditLogger(gateAudit)}, srv.gateOpts...)
	srv.gate = netgate.New(nil, gateOpts...)
	return srv
}

// EventStream is the main bi-directional stream for plugin communication.
func (s *Server) EventStream(stream pb.PluginBus_EventStreamServer) error {
	ctx := stream.Context()
	obsmetrics.RecordRPCRequest("plugin_bus", "EventStream")
	start := time.Now()
	code := codes.OK.String()
	defer func() {
		obsmetrics.ObserveRPCLatency("plugin_bus", "EventStream", code, time.Since(start))
	}()

	rpcSpan := tracing.SpanFromContext(ctx)
	rpcSpan.SetAttribute("glyph.component", "plugin_bus")
	rpcSpan.SetAttribute("glyph.rpc.method", "EventStream")

	authCtx, authSpan := tracing.StartSpan(ctx, "plugin_bus.authenticate", tracing.WithSpanKind(tracing.SpanKindInternal))
	hello, err := s.authenticate(stream)
	if err != nil {
		code = status.Code(err).String()
		authSpan.RecordError(err)
		authSpan.End()
		s.emit(authCtx, logging.AuditEvent{
			EventType: logging.EventPluginLoad,
			Decision:  logging.DecisionDeny,
			Reason:    err.Error(),
			Metadata: map[string]any{
				"stage": "authenticate",
			},
		})
		return err
	}
	authSpan.EndWithStatus(tracing.StatusOK, "")

	pluginID := fmt.Sprintf("%s-%d", hello.GetPluginName(), hello.GetPid())
	rpcSpan.SetAttribute("glyph.plugin.name", hello.GetPluginName())
	rpcSpan.SetAttribute("glyph.plugin.pid", hello.GetPid())

	validatedCaps, err := s.caps.Validate(hello.GetCapabilityToken(), hello.GetPluginName(), hello.GetCapabilities())
	if err != nil {
		obsmetrics.RecordRPCError("plugin_bus", "EventStream", codes.PermissionDenied.String())
		code = codes.PermissionDenied.String()
		s.emit(ctx, logging.AuditEvent{
			EventType: logging.EventCapabilityDenied,
			Decision:  logging.DecisionDeny,
			PluginID:  pluginID,
			Reason:    err.Error(),
			Metadata: map[string]any{
				"plugin": hello.GetPluginName(),
				"pid":    hello.GetPid(),
			},
		})
		rpcSpan.RecordError(err)
		return status.Errorf(codes.PermissionDenied, "capability validation failed: %v", err)
	}

	s.emit(ctx, logging.AuditEvent{
		EventType: logging.EventPluginLoad,
		Decision:  logging.DecisionAllow,
		PluginID:  pluginID,
		Metadata: map[string]any{
			"subscriptions": hello.GetSubscriptions(),
			"capabilities":  validatedCaps,
		},
	})

	subs := make(map[string]struct{})
	for _, sub := range hello.GetSubscriptions() {
		subs[sub] = struct{}{}
	}
	caps := make(map[string]struct{})
	for _, cap := range validatedCaps {
		caps[cap] = struct{}{}
	}

	p := &plugin{
		eventChan:     make(chan *pb.HostEvent, 100),
		subscriptions: subs,
		capabilities:  caps,
	}
	s.addConnection(pluginID, p)
	s.gate.Register(pluginID, validatedCaps)
	defer s.removeConnection(ctx, pluginID)

	go s.sendEvents(ctx, stream, p.eventChan, pluginID)

	if err := s.receiveEvents(ctx, stream, p, pluginID); err != nil {
		code = status.Code(err).String()
		rpcSpan.RecordError(err)
		return err
	}
	return nil
}

// GrantCapabilities issues a short-lived capability token for a plugin invocation.
func (s *Server) GrantCapabilities(ctx context.Context, req *pb.PluginCapabilityRequest) (*pb.PluginCapabilityGrant, error) {
	obsmetrics.RecordRPCRequest("plugin_bus", "GrantCapabilities")
	start := time.Now()
	code := codes.OK.String()
	defer func() {
		obsmetrics.ObserveRPCLatency("plugin_bus", "GrantCapabilities", code, time.Since(start))
	}()
	span := tracing.SpanFromContext(ctx)
	if req == nil {
		obsmetrics.RecordRPCError("plugin_bus", "GrantCapabilities", codes.InvalidArgument.String())
		code = codes.InvalidArgument.String()
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	span.SetAttribute("glyph.plugin.name", strings.TrimSpace(req.GetPluginName()))
	if req.GetAuthToken() != s.authToken {
		obsmetrics.RecordRPCError("plugin_bus", "GrantCapabilities", codes.PermissionDenied.String())
		code = codes.PermissionDenied.String()
		s.emit(ctx, logging.AuditEvent{
			EventType: logging.EventCapabilityDenied,
			Decision:  logging.DecisionDeny,
			Reason:    "invalid auth token",
		})
		return nil, status.Error(codes.PermissionDenied, "invalid auth token")
	}
	pluginName := strings.TrimSpace(req.GetPluginName())
	if pluginName == "" {
		obsmetrics.RecordRPCError("plugin_bus", "GrantCapabilities", codes.InvalidArgument.String())
		code = codes.InvalidArgument.String()
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	token, expires, err := s.caps.Issue(pluginName, req.GetCapabilities())
	if err != nil {
		obsmetrics.RecordRPCError("plugin_bus", "GrantCapabilities", codes.InvalidArgument.String())
		code = codes.InvalidArgument.String()
		s.emit(ctx, logging.AuditEvent{
			EventType: logging.EventCapabilityDenied,
			Decision:  logging.DecisionDeny,
			PluginID:  pluginName,
			Reason:    err.Error(),
			Metadata: map[string]any{
				"requested_capabilities": req.GetCapabilities(),
			},
		})
		return nil, status.Errorf(codes.InvalidArgument, "issue token: %v", err)
	}
	s.emit(ctx, logging.AuditEvent{
		EventType: logging.EventCapabilityGrant,
		Decision:  logging.DecisionAllow,
		PluginID:  pluginName,
		Metadata: map[string]any{
			"capabilities": req.GetCapabilities(),
			"expires_at":   expires.UTC(),
		},
	})
	return &pb.PluginCapabilityGrant{CapabilityToken: token, ExpiresAtUnix: expires.UTC().Unix()}, nil
}

// authenticate waits for the first message, which must be PluginHello, and validates it.
func (s *Server) authenticate(stream pb.PluginBus_EventStreamServer) (*pb.PluginHello, error) {
	msg, err := stream.Recv()
	if err != nil {
		obsmetrics.RecordRPCError("plugin_bus", "EventStream", codes.Unauthenticated.String())
		return nil, status.Errorf(codes.Unauthenticated, "failed to receive auth message: %v", err)
	}

	hello := msg.GetHello()
	if hello == nil {
		obsmetrics.RecordRPCError("plugin_bus", "EventStream", codes.Unauthenticated.String())
		return nil, status.Errorf(codes.Unauthenticated, "expected PluginHello as first message")
	}

	if hello.GetPluginName() == "" || hello.GetPid() == 0 {
		obsmetrics.RecordRPCError("plugin_bus", "EventStream", codes.InvalidArgument.String())
		return nil, status.Errorf(codes.InvalidArgument, "PluginHello must include plugin_name and pid")
	}

	if hello.GetAuthToken() != s.authToken {
		obsmetrics.RecordRPCError("plugin_bus", "EventStream", codes.Unauthenticated.String())
		return nil, status.Errorf(codes.Unauthenticated, "invalid auth token")
	}

	return hello, nil
}

// sendEvents forwards events from the central bus to this specific plugin's stream.
func (s *Server) sendEvents(ctx context.Context, stream pb.PluginBus_EventStreamServer, eventChan <-chan *pb.HostEvent, pluginID string) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case <-ctx.Done():
			s.emit(ctx, logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionInfo,
				PluginID:  pluginID,
				Reason:    "context done",
			})
			return
		case event, ok := <-eventChan:
			if !ok {
				s.emit(ctx, logging.AuditEvent{
					EventType: logging.EventPluginDisconnect,
					Decision:  logging.DecisionInfo,
					PluginID:  pluginID,
					Reason:    "event stream closed",
				})
				obsmetrics.SetPluginQueueLength(pluginID, 0)
				return
			}
			sendCtx, span := tracing.StartSpan(ctx, "plugin_bus.dispatch_event", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(map[string]any{
				"glyph.plugin.id":  pluginID,
				"glyph.event.type": getEventType(event),
			}))
			if err := stream.Send(event); err != nil {
				span.RecordError(err)
				span.End()
				obsmetrics.RecordRPCError("plugin_bus", "EventStreamSend", codes.Internal.String())
				s.emit(sendCtx, logging.AuditEvent{
					EventType: logging.EventRPCDenied,
					Decision:  logging.DecisionDeny,
					PluginID:  pluginID,
					Reason:    err.Error(),
				})
				return
			}
			span.EndWithStatus(tracing.StatusOK, "")
			obsmetrics.SetPluginQueueLength(pluginID, len(eventChan))
		}
	}
}

// receiveEvents handles incoming messages from the plugin.
func (s *Server) receiveEvents(ctx context.Context, stream pb.PluginBus_EventStreamServer, p *plugin, pluginID string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		recvCtx, span := tracing.StartSpan(ctx, "plugin_bus.receive_event", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(map[string]any{
			"glyph.plugin.id": pluginID,
		}))
		event, err := stream.Recv()
		if err == io.EOF {
			span.EndWithStatus(tracing.StatusOK, "")
			s.emit(recvCtx, logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionInfo,
				PluginID:  pluginID,
				Reason:    "graceful disconnect",
			})
			return nil
		}
		if err != nil {
			span.RecordError(err)
			span.End()
			s.emit(recvCtx, logging.AuditEvent{
				EventType: logging.EventRPCDenied,
				Decision:  logging.DecisionDeny,
				PluginID:  pluginID,
				Reason:    err.Error(),
			})
			obsmetrics.RecordRPCError("plugin_bus", "EventStreamRecv", codes.Internal.String())
			return err
		}

		switch e := event.Event.(type) {
		case *pb.PluginEvent_Finding:
			span.SetAttribute("glyph.event.type", "finding")
			start := time.Now()
			if _, ok := p.capabilities[CapEmitFindings]; !ok {
				obsmetrics.RecordRPCError("plugin_bus", "EventStreamRecv", codes.PermissionDenied.String())
				span.RecordError(fmt.Errorf("missing capability %s", CapEmitFindings))
				span.End()
				s.emit(recvCtx, logging.AuditEvent{
					EventType: logging.EventScopeViolation,
					Decision:  logging.DecisionDeny,
					PluginID:  pluginID,
					Reason:    "missing CAP_EMIT_FINDINGS",
					Metadata: map[string]any{
						"attempted_capability": CapEmitFindings,
					},
				})
				continue
			}
			s.emit(recvCtx, logging.AuditEvent{
				EventType: logging.EventFindingReceived,
				Decision:  logging.DecisionAllow,
				PluginID:  pluginID,
				Metadata: map[string]any{
					"finding_type":    e.Finding.Type,
					"finding_message": e.Finding.Message,
				},
			})
			s.publishFinding(recvCtx, pluginID, e.Finding)
			obsmetrics.ObservePluginEventDuration(pluginID, "finding", time.Since(start))
			span.EndWithStatus(tracing.StatusOK, "")
		default:
			span.SetAttribute("glyph.event.type", "unknown")
			span.EndWithStatus(tracing.StatusOK, "")
			s.emit(recvCtx, logging.AuditEvent{
				EventType: logging.EventRPCCall,
				Decision:  logging.DecisionInfo,
				PluginID:  pluginID,
				Reason:    "unknown event type",
			})
		}
	}
}

func (s *Server) addConnection(id string, p *plugin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[id] = p
	obsmetrics.SetPluginQueueLength(id, len(p.eventChan))
	obsmetrics.SetActivePlugins(len(s.connections))
}

func (s *Server) removeConnection(ctx context.Context, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disconnectLocked(ctx, id, "connection closed")
}

// DisconnectPlugin forcibly tears down any active connections for the named plugin.
func (s *Server) DisconnectPlugin(pluginName, reason string) int {
	pluginName = strings.TrimSpace(pluginName)
	if pluginName == "" {
		return 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	prefix := pluginName + "-"
	count := 0
	for id := range s.connections {
		if strings.HasPrefix(id, prefix) {
			if reason == "" {
				reason = "plugin disconnected"
			}
			s.disconnectLocked(context.Background(), id, reason)
			count++
		}
	}
	return count
}

func (s *Server) disconnectLocked(ctx context.Context, id, reason string) {
	p, ok := s.connections[id]
	if !ok {
		s.gate.Unregister(id)
		obsmetrics.RemovePlugin(id)
		return
	}
	close(p.eventChan)
	delete(s.connections, id)
	s.gate.Unregister(id)
	obsmetrics.RemovePlugin(id)
	obsmetrics.SetActivePlugins(len(s.connections))
	s.emit(ctx, logging.AuditEvent{
		EventType: logging.EventPluginDisconnect,
		Decision:  logging.DecisionInfo,
		PluginID:  id,
		Reason:    reason,
		Metadata: map[string]any{
			"total_connections": len(s.connections),
		},
	})
}

// StartEventGenerator starts a ticker to send synthetic events to all connected plugins.
func (s *Server) StartEventGenerator(ctx context.Context) {
	s.emit(ctx, logging.AuditEvent{
		EventType: logging.EventRPCCall,
		Decision:  logging.DecisionInfo,
		Metadata: map[string]any{
			"interval": "2s",
		},
	})
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			event := &pb.HostEvent{
				CoreVersion: coreVersion,
				Event: &pb.HostEvent_FlowEvent{
					FlowEvent: &pb.FlowEvent{
						Type: pb.FlowEvent_FLOW_RESPONSE,
						Data: []byte("HTTP/1.1 200 OK\nContent-Length: 12\n\nHello, world!"),
					},
				},
			}
			s.broadcast(ctx, event)
		}
	}
}

// getEventType returns a string representation of the event type.
func getEventType(event *pb.HostEvent) string {
	if event.GetFlowEvent() != nil {
		return event.GetFlowEvent().GetType().String()
	}
	return "UNKNOWN"
}

func (s *Server) broadcast(ctx context.Context, event *pb.HostEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.connections) == 0 {
		return
	}

	eventType := getEventType(event)
	obsmetrics.RecordRPCRequest("plugin_bus", "Broadcast")
	start := time.Now()
	code := codes.OK.String()
	defer func() {
		obsmetrics.ObserveRPCLatency("plugin_bus", "Broadcast", code, time.Since(start))
	}()
	spanCtx, span := tracing.StartSpan(ctx, "plugin_bus.broadcast", tracing.WithSpanKind(tracing.SpanKindInternal), tracing.WithAttributes(map[string]any{
		"glyph.event.type": eventType,
	}))
	var hadChannelError bool
	s.emit(spanCtx, logging.AuditEvent{
		EventType: logging.EventRPCCall,
		Decision:  logging.DecisionInfo,
		Metadata: map[string]any{
			"event_type": eventType,
		},
	})

	for id, plugin := range s.connections {
		if _, subscribed := plugin.subscriptions[eventType]; subscribed {
			s.emit(spanCtx, logging.AuditEvent{
				EventType: logging.EventRPCCall,
				Decision:  logging.DecisionInfo,
				PluginID:  id,
				Metadata: map[string]any{
					"event_type": eventType,
				},
			})
			select {
			case plugin.eventChan <- event:
				// Event sent
				obsmetrics.SetPluginQueueLength(id, len(plugin.eventChan))
			default:
				obsmetrics.RecordRPCError("plugin_bus", "Broadcast", "channel_full")
				hadChannelError = true
				s.emit(spanCtx, logging.AuditEvent{
					EventType: logging.EventRPCDenied,
					Decision:  logging.DecisionDeny,
					PluginID:  id,
					Reason:    "channel full",
				})
			}
		}
	}
	if hadChannelError {
		code = codes.ResourceExhausted.String()
	}
	if hadChannelError {
		span.RecordError(fmt.Errorf("one or more plugin channels full"))
		span.End()
	} else {
		span.EndWithStatus(tracing.StatusOK, "")
	}
}

func (s *Server) publishFinding(ctx context.Context, pluginID string, incoming *pb.Finding) {
	if s.findings == nil || incoming == nil {
		return
	}

	finding, err := findings.FromProto(pluginID, incoming)
	if err != nil {
		s.emit(ctx, logging.AuditEvent{
			EventType: logging.EventFindingRejected,
			Decision:  logging.DecisionDeny,
			PluginID:  pluginID,
			Reason:    err.Error(),
		})
		return
	}

	s.findings.Emit(finding)
}

func (s *Server) emit(ctx context.Context, event logging.AuditEvent) {
	if s.audit == nil {
		return
	}
	if ctx != nil {
		if traceID := tracing.TraceIDFromContext(ctx); traceID != "" {
			event.TraceID = traceID
		}
	}
	if err := s.audit.Emit(event); err != nil {
		fmt.Fprintf(os.Stderr, "audit log error: %v\n", err)
	}
}
