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

func NewServer(authToken string, findingsBus *findings.Bus, opts ...Option) *Server {
	if findingsBus == nil {
		findingsBus = findings.NewBus()
	}
	srv := &Server{
		audit:       logging.MustNewAuditLogger("plugin_bus"),
		authToken:   authToken,
		connections: make(map[string]*plugin),
		findings:    findingsBus,
		gate:        netgate.New(nil),
		caps:        capabilities.NewManager(),
	}
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

// EventStream is the main bi-directional stream for plugin communication.
func (s *Server) EventStream(stream pb.PluginBus_EventStreamServer) error {
	// 1. Authenticate the plugin
	hello, err := s.authenticate(stream)
	if err != nil {
		s.emit(logging.AuditEvent{
			EventType: logging.EventPluginLoad,
			Decision:  logging.DecisionDeny,
			Reason:    err.Error(),
			Metadata: map[string]any{
				"stage": "authenticate",
			},
		})
		return err
	}
	pluginID := fmt.Sprintf("%s-%d", hello.GetPluginName(), hello.GetPid())
	validatedCaps, err := s.caps.Validate(hello.GetCapabilityToken(), hello.GetPluginName(), hello.GetCapabilities())
	if err != nil {
		s.emit(logging.AuditEvent{
			EventType: logging.EventCapabilityDenied,
			Decision:  logging.DecisionDeny,
			PluginID:  pluginID,
			Reason:    err.Error(),
			Metadata: map[string]any{
				"plugin": hello.GetPluginName(),
				"pid":    hello.GetPid(),
			},
		})
		return status.Errorf(codes.PermissionDenied, "capability validation failed: %v", err)
	}

	s.emit(logging.AuditEvent{
		EventType: logging.EventPluginLoad,
		Decision:  logging.DecisionAllow,
		PluginID:  pluginID,
		Metadata: map[string]any{
			"subscriptions": hello.GetSubscriptions(),
			"capabilities":  validatedCaps,
		},
	})

	// 2. Register the plugin connection
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
	defer s.removeConnection(pluginID)

	// Goroutine to send events from the bus to the plugin
	go s.sendEvents(stream, p.eventChan, pluginID)

	// 3. Receive events from the plugin in a loop
	return s.receiveEvents(stream, p, pluginID)
}

// GrantCapabilities issues a short-lived capability token for a plugin invocation.
func (s *Server) GrantCapabilities(ctx context.Context, req *pb.PluginCapabilityRequest) (*pb.PluginCapabilityGrant, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.GetAuthToken() != s.authToken {
		s.emit(logging.AuditEvent{
			EventType: logging.EventCapabilityDenied,
			Decision:  logging.DecisionDeny,
			Reason:    "invalid auth token",
		})
		return nil, status.Error(codes.PermissionDenied, "invalid auth token")
	}
	pluginName := strings.TrimSpace(req.GetPluginName())
	if pluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	token, expires, err := s.caps.Issue(pluginName, req.GetCapabilities())
	if err != nil {
		s.emit(logging.AuditEvent{
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
	s.emit(logging.AuditEvent{
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
		return nil, status.Errorf(codes.Unauthenticated, "failed to receive auth message: %v", err)
	}

	hello := msg.GetHello()
	if hello == nil {
		return nil, status.Errorf(codes.Unauthenticated, "expected PluginHello as first message")
	}

	if hello.GetPluginName() == "" || hello.GetPid() == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "PluginHello must include plugin_name and pid")
	}

	if hello.GetAuthToken() != s.authToken {
		return nil, status.Errorf(codes.Unauthenticated, "invalid auth token")
	}

	return hello, nil
}

// sendEvents forwards events from the central bus to this specific plugin's stream.
func (s *Server) sendEvents(stream pb.PluginBus_EventStreamServer, eventChan <-chan *pb.HostEvent, pluginID string) {
	for {
		select {
		case <-stream.Context().Done():
			s.emit(logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionInfo,
				PluginID:  pluginID,
				Reason:    "context done",
			})
			return
		case event := <-eventChan:
			if err := stream.Send(event); err != nil {
				s.emit(logging.AuditEvent{
					EventType: logging.EventRPCDenied,
					Decision:  logging.DecisionDeny,
					PluginID:  pluginID,
					Reason:    err.Error(),
				})
				return
			}
		}
	}
}

// receiveEvents handles incoming messages from the plugin.
func (s *Server) receiveEvents(stream pb.PluginBus_EventStreamServer, p *plugin, pluginID string) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			s.emit(logging.AuditEvent{
				EventType: logging.EventPluginDisconnect,
				Decision:  logging.DecisionInfo,
				PluginID:  pluginID,
				Reason:    "graceful disconnect",
			})
			return nil
		}
		if err != nil {
			s.emit(logging.AuditEvent{
				EventType: logging.EventRPCDenied,
				Decision:  logging.DecisionDeny,
				PluginID:  pluginID,
				Reason:    err.Error(),
			})
			return err
		}

		switch e := event.Event.(type) {
		case *pb.PluginEvent_Finding:
			if _, ok := p.capabilities[CapEmitFindings]; !ok {
				s.emit(logging.AuditEvent{
					EventType: logging.EventScopeViolation,
					Decision:  logging.DecisionDeny,
					PluginID:  pluginID,
					Reason:    "missing CAP_EMIT_FINDINGS",
					Metadata: map[string]any{
						"attempted_capability": CapEmitFindings,
					},
				})
				continue // Ignore the finding
			}
			s.emit(logging.AuditEvent{
				EventType: logging.EventFindingReceived,
				Decision:  logging.DecisionAllow,
				PluginID:  pluginID,
				Metadata: map[string]any{
					"finding_type":    e.Finding.Type,
					"finding_message": e.Finding.Message,
				},
			})
			s.publishFinding(pluginID, e.Finding)
		default:
			s.emit(logging.AuditEvent{
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
}

func (s *Server) removeConnection(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.connections[id]; ok {
		close(p.eventChan)
		delete(s.connections, id)
		s.emit(logging.AuditEvent{
			EventType: logging.EventPluginDisconnect,
			Decision:  logging.DecisionInfo,
			PluginID:  id,
			Metadata: map[string]any{
				"total_connections": len(s.connections),
			},
		})
	}
	s.gate.Unregister(id)
}

// StartEventGenerator starts a ticker to send synthetic events to all connected plugins.
func (s *Server) StartEventGenerator(ctx context.Context) {
	s.emit(logging.AuditEvent{
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
			s.broadcast(event)
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

func (s *Server) broadcast(event *pb.HostEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.connections) == 0 {
		return
	}

	eventType := getEventType(event)
	s.emit(logging.AuditEvent{
		EventType: logging.EventRPCCall,
		Decision:  logging.DecisionInfo,
		Metadata: map[string]any{
			"event_type": eventType,
		},
	})

	for id, plugin := range s.connections {
		if _, subscribed := plugin.subscriptions[eventType]; subscribed {
			s.emit(logging.AuditEvent{
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
			default:
				s.emit(logging.AuditEvent{
					EventType: logging.EventRPCDenied,
					Decision:  logging.DecisionDeny,
					PluginID:  id,
					Reason:    "channel full",
				})
			}
		}
	}
}

func (s *Server) publishFinding(pluginID string, incoming *pb.Finding) {
	if s.findings == nil || incoming == nil {
		return
	}

	finding, err := findings.FromProto(pluginID, incoming)
	if err != nil {
		s.emit(logging.AuditEvent{
			EventType: logging.EventFindingRejected,
			Decision:  logging.DecisionDeny,
			PluginID:  pluginID,
			Reason:    err.Error(),
		})
		return
	}

	s.findings.Emit(finding)
}

func (s *Server) emit(event logging.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Emit(event); err != nil {
		fmt.Fprintf(os.Stderr, "audit log error: %v\n", err)
	}
}
