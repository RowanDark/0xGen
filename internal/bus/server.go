package bus

import (
	"context"
	"io"
	"log"
	"sync"
	"time"

	pb "github.com/example/glyph/proto/gen/go/proto/glyph"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	expectedAuthToken = "supersecrettoken"
)

// Server implements the PluginBus service.
type Server struct {
	pb.UnimplementedPluginBusServer
	mu          sync.RWMutex
	connections map[string]chan<- *pb.HostEvent
}

// NewServer creates a new bus server.
func NewServer() *Server {
	return &Server{
		connections: make(map[string]chan<- *pb.HostEvent),
	}
}

// EventStream is the main bi-directional stream for plugin communication.
func (s *Server) EventStream(stream pb.PluginBus_EventStreamServer) error {
	// 1. Authenticate the plugin
	hello, err := s.authenticate(stream)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return err
	}
	log.Printf("Plugin connected: %s", hello.GetAuthToken()) // In a real app, you wouldn't log the token.

	// 2. Register the plugin connection
	id := uuid.New().String()
	eventChan := make(chan *pb.HostEvent, 100)
	s.addConnection(id, eventChan)
	defer s.removeConnection(id)

	log.Printf("Plugin registered with ID: %s", id)

	// Goroutine to send events from the bus to the plugin
	go s.sendEvents(stream, eventChan)

	// 3. Receive events from the plugin in a loop
	return s.receiveEvents(stream)
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

	// In a real implementation, you'd use mTLS or a more robust token system.
	if hello.GetAuthToken() != expectedAuthToken {
		return nil, status.Errorf(codes.Unauthenticated, "invalid auth token")
	}

	return hello, nil
}

// sendEvents forwards events from the central bus to this specific plugin's stream.
func (s *Server) sendEvents(stream pb.PluginBus_EventStreamServer, eventChan <-chan *pb.HostEvent) {
	for {
		select {
		case <-stream.Context().Done():
			log.Printf("Client stream context done.")
			return
		case event := <-eventChan:
			if err := stream.Send(event); err != nil {
				log.Printf("Failed to send event to plugin: %v", err)
				return
			}
		}
	}
}

// receiveEvents handles incoming messages from the plugin.
func (s *Server) receiveEvents(stream pb.PluginBus_EventStreamServer) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			log.Println("Plugin disconnected gracefully.")
			return nil
		}
		if err != nil {
			log.Printf("Error receiving from plugin: %v", err)
			return err
		}

		switch e := event.Event.(type) {
		case *pb.PluginEvent_Finding:
			log.Printf("Received finding from plugin: Type=%s, Message='%s'", e.Finding.Type, e.Finding.Message)
		default:
			log.Printf("Received unknown event type from plugin")
		}
	}
}

func (s *Server) addConnection(id string, eventChan chan<- *pb.HostEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[id] = eventChan
}

func (s *Server) removeConnection(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.connections[id])
	delete(s.connections, id)
	log.Printf("Plugin unregistered with ID: %s. Total connections: %d", id, len(s.connections))
}

// StartEventGenerator starts a ticker to send synthetic events to all connected plugins.
func (s *Server) StartEventGenerator(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			event := &pb.HostEvent{
				Event: &pb.HostEvent_FlowEvent{
					FlowEvent: &pb.FlowEvent{
						Type: pb.FlowEvent_FLOW_RESPONSE,
						Data: []byte("HTTP/1.1 200 OK\nContent-Length: 12\n\nHello, world!"),
					},
				},
			}
			log.Println("Broadcasting synthetic FLOW_RESPONSE event...")
			s.broadcast(event)
		}
	}
}

func (s *Server) broadcast(event *pb.HostEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.connections) == 0 {
		return
	}
	log.Printf("Broadcasting to %d plugins", len(s.connections))
	for id, conn := range s.connections {
		select {
		case conn <- event:
			// Event sent
		default:
			log.Printf("Plugin channel full for ID %s, skipping.", id)
		}
	}
}
