package bus

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	pb "github.com/example/glyph/proto/gen/go/proto/glyph"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	coreVersion = "v0.1.0"
)

// plugin holds the information about a connected plugin.
type plugin struct {
	eventChan     chan *pb.HostEvent
	subscriptions map[string]struct{}
}

// Server implements the PluginBus service.
type Server struct {
	pb.UnimplementedPluginBusServer
	logger      *slog.Logger
	authToken   string
	mu          sync.RWMutex
	connections map[string]*plugin
}

// NewServer creates a new bus server.
func NewServer(authToken string) *Server {
	return &Server{
		logger:      slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		authToken:   authToken,
		connections: make(map[string]*plugin),
	}
}

// EventStream is the main bi-directional stream for plugin communication.
func (s *Server) EventStream(stream pb.PluginBus_EventStreamServer) error {
	// 1. Authenticate the plugin
	hello, err := s.authenticate(stream)
	if err != nil {
		s.logger.Warn("Plugin authentication failed", "error", err)
		return err
	}
	pluginID := fmt.Sprintf("%s-%d", hello.GetPluginName(), hello.GetPid())
	s.logger.Info("Plugin connected and authenticated", "plugin_id", pluginID, "subscriptions", hello.GetSubscriptions())

	// 2. Register the plugin connection
	subs := make(map[string]struct{})
	for _, sub := range hello.GetSubscriptions() {
		subs[sub] = struct{}{}
	}
	p := &plugin{
		eventChan:     make(chan *pb.HostEvent, 100),
		subscriptions: subs,
	}
	s.addConnection(pluginID, p)
	defer s.removeConnection(pluginID)

	// Goroutine to send events from the bus to the plugin
	go s.sendEvents(stream, p.eventChan, pluginID)

	// 3. Receive events from the plugin in a loop
	return s.receiveEvents(stream, pluginID)
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
			s.logger.Info("Client stream context done.", "plugin_id", pluginID)
			return
		case event := <-eventChan:
			if err := stream.Send(event); err != nil {
				s.logger.Warn("Failed to send event to plugin", "plugin_id", pluginID, "error", err)
				return
			}
		}
	}
}

// receiveEvents handles incoming messages from the plugin.
func (s *Server) receiveEvents(stream pb.PluginBus_EventStreamServer, pluginID string) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			s.logger.Info("Plugin disconnected gracefully", "plugin_id", pluginID)
			return nil
		}
		if err != nil {
			s.logger.Warn("Error receiving from plugin", "plugin_id", pluginID, "error", err)
			return err
		}

		switch e := event.Event.(type) {
		case *pb.PluginEvent_Finding:
			s.logger.Info("Received finding from plugin",
				"plugin_id", pluginID,
				"finding_type", e.Finding.Type,
				"finding_message", e.Finding.Message,
			)
		default:
			s.logger.Warn("Received unknown event type from plugin", "plugin_id", pluginID)
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
		s.logger.Info("Plugin unregistered", "plugin_id", id, "total_connections", len(s.connections))
	}
}

// StartEventGenerator starts a ticker to send synthetic events to all connected plugins.
func (s *Server) StartEventGenerator(ctx context.Context) {
	s.logger.Info("Starting synthetic event generator", "interval", "2s")
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
// This is a simple implementation for the known event types.
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
	s.logger.Info("Broadcasting event", "event_type", eventType)

	for id, plugin := range s.connections {
		if _, subscribed := plugin.subscriptions[eventType]; subscribed {
			s.logger.Info("Sending event to subscribed plugin", "plugin_id", id, "event_type", eventType)
			select {
			case plugin.eventChan <- event:
				// Event sent
			default:
				s.logger.Warn("Plugin channel full, skipping event.", "plugin_id", id)
			}
		}
	}
}
