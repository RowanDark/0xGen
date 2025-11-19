// Package local provides a local HTTP server for OAST (Out-of-Application Security Testing)
// callbacks. It captures blind vulnerability interactions (SSRF, blind SQLi, blind XSS)
// without requiring external infrastructure.
package local

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/RowanDark/0xgen/internal/logging"
)

// Interaction represents a single OAST callback interaction.
type Interaction struct {
	ID        string              `json:"id"`
	Type      string              `json:"type"`
	Timestamp time.Time           `json:"timestamp"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Query     string              `json:"query,omitempty"`
	Headers   map[string][]string `json:"headers"`
	Body      string              `json:"body,omitempty"`
	ClientIP  string              `json:"client_ip"`
	UserAgent string              `json:"user_agent,omitempty"`
}

// EventBus defines the interface for publishing OAST events.
type EventBus interface {
	Publish(eventType string, data interface{})
}

// Config holds the configuration for the OAST local server.
type Config struct {
	Port     int    // 0 = random port
	Host     string // Default: localhost
	BasePath string // Default: /callback
}

// Server is the OAST local HTTP server that captures callback interactions.
type Server struct {
	port         int
	host         string
	basePath     string
	httpServer   *http.Server
	storage      *Storage
	eventBus     EventBus
	logger       *logging.AuditLogger
	shuttingDown bool
	mu           sync.RWMutex
}

// New creates a new OAST local server with the given configuration.
func New(cfg Config, eventBus EventBus, logger *logging.AuditLogger) *Server {
	if cfg.Port == 0 {
		cfg.Port = findFreePort()
	}
	if cfg.Host == "" {
		cfg.Host = "localhost"
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/callback"
	}

	return &Server{
		port:     cfg.Port,
		host:     cfg.Host,
		basePath: cfg.BasePath,
		storage:  NewStorage(),
		eventBus: eventBus,
		logger:   logger,
	}
}

// findFreePort finds an available TCP port on the system.
func findFreePort() int {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return 8443 // Fallback
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// Start starts the OAST HTTP server and blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Catch-all callback handler
	mux.HandleFunc(s.basePath+"/", s.handleCallback)

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Admin endpoint (for GUI)
	mux.HandleFunc("/admin/interactions", s.handleAdminInteractions)

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown handler
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.shuttingDown = true
		s.mu.Unlock()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Emit(logging.AuditEvent{
		Timestamp: time.Now().UTC(),
		Component: "oast-local",
		EventType: logging.EventProxyLifecycle,
		Decision:  logging.DecisionInfo,
		Metadata: map[string]any{
			"action":   "start",
			"port":     s.port,
			"host":     s.host,
			"base_url": s.GetBaseURL(),
		},
	})

	// Start server
	if err := s.httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("http server failed: %w", err)
	}

	return nil
}

// handleCallback processes incoming OAST callback requests.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /callback/{id} or /callback/{id}/anything
	id := extractIDFromPath(r.URL.Path, s.basePath)
	if id == "" {
		s.logger.Emit(logging.AuditEvent{
			Timestamp: time.Now().UTC(),
			Component: "oast-local",
			EventType: logging.EventRPCDenied,
			Decision:  logging.DecisionDeny,
			Reason:    "callback received without ID",
			Metadata: map[string]any{
				"path": r.URL.Path,
			},
		})
		http.Error(w, "Missing callback ID", http.StatusBadRequest)
		return
	}

	// Read body (with size limit - 1MB)
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err != nil {
		s.logger.Emit(logging.AuditEvent{
			Timestamp: time.Now().UTC(),
			Component: "oast-local",
			EventType: logging.EventRPCDenied,
			Decision:  logging.DecisionDeny,
			Reason:    fmt.Sprintf("failed to read callback body: %v", err),
			Metadata: map[string]any{
				"id": id,
			},
		})
		body = []byte(fmt.Sprintf("Error reading body: %v", err))
	}

	// Create interaction record
	interaction := &Interaction{
		ID:        id,
		Type:      "http",
		Timestamp: time.Now().UTC(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Headers:   cloneHeaders(r.Header),
		Body:      string(body),
		ClientIP:  extractClientIP(r),
		UserAgent: r.UserAgent(),
	}

	// Store interaction
	if err := s.storage.Store(interaction); err != nil {
		s.logger.Emit(logging.AuditEvent{
			Timestamp: time.Now().UTC(),
			Component: "oast-local",
			EventType: logging.EventRPCDenied,
			Decision:  logging.DecisionDeny,
			Reason:    fmt.Sprintf("failed to store interaction: %v", err),
			Metadata: map[string]any{
				"id": id,
			},
		})
	}

	// Emit event to GUI and plugins
	if s.eventBus != nil {
		s.eventBus.Publish("oast.interaction", interaction)
	}

	s.logger.Emit(logging.AuditEvent{
		Timestamp: time.Now().UTC(),
		Component: "oast-local",
		EventType: logging.EventRPCCall,
		Decision:  logging.DecisionAllow,
		Metadata: map[string]any{
			"action":    "callback_received",
			"id":        id,
			"method":    r.Method,
			"path":      r.URL.Path,
			"client_ip": interaction.ClientIP,
		},
	})

	// Respond
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-OAST-ID", id)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Interaction logged"))
}

// handleHealth returns the server health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	shuttingDown := s.shuttingDown
	s.mu.RUnlock()

	if shuttingDown {
		http.Error(w, "Shutting down", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","port":%d}`, s.port)
}

// handleAdminInteractions returns stored interactions for a given ID.
func (s *Server) handleAdminInteractions(w http.ResponseWriter, r *http.Request) {
	// Query parameter: ?id=abc123
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	interactions := s.storage.GetByID(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":           id,
		"count":        len(interactions),
		"interactions": interactions,
	})
}

// extractIDFromPath extracts the callback ID from the URL path.
// Path format: /callback/{id} or /callback/{id}/anything
func extractIDFromPath(path, basePath string) string {
	// Verify path starts with basePath
	if !strings.HasPrefix(path, basePath) {
		return ""
	}

	// Remove basePath prefix
	trimmed := strings.TrimPrefix(path, basePath)
	trimmed = strings.TrimPrefix(trimmed, "/")

	// Split by / and get the first part
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) >= 1 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

// extractClientIP extracts the client IP address from the request.
func extractClientIP(r *http.Request) string {
	// Try X-Forwarded-For first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// cloneHeaders creates a deep copy of HTTP headers.
func cloneHeaders(h http.Header) map[string][]string {
	clone := make(map[string][]string, len(h))
	for k, v := range h {
		clone[k] = append([]string(nil), v...)
	}
	return clone
}

// loggingMiddleware logs all HTTP requests.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)

		s.logger.Emit(logging.AuditEvent{
			Timestamp: time.Now().UTC(),
			Component: "oast-local",
			EventType: logging.EventRPCCall,
			Decision:  logging.DecisionInfo,
			Metadata: map[string]any{
				"method":      r.Method,
				"path":        r.URL.Path,
				"duration_ms": time.Since(start).Milliseconds(),
			},
		})
	})
}

// GetBaseURL returns the base URL for callbacks.
func (s *Server) GetBaseURL() string {
	return fmt.Sprintf("http://%s:%d%s", s.host, s.port, s.basePath)
}

// GetPort returns the listening port.
func (s *Server) GetPort() int {
	return s.port
}

// GetStorage returns the server's interaction storage.
func (s *Server) GetStorage() *Storage {
	return s.storage
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.shuttingDown = true
	s.mu.Unlock()

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
