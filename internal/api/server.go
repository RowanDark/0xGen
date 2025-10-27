package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/logging"
)

// Config configures the REST API server.
type Config struct {
	Addr            string
	StaticToken     string
	JWTSecret       []byte
	JWTIssuer       string
	DefaultTokenTTL time.Duration
	PluginsDir      string
	AllowlistPath   string
	RepoRoot        string
	ServerAddr      string
	AuthToken       string
	SigningKeyPath  string
	FindingsBus     *findings.Bus
	Logger          *logging.AuditLogger
	ScanTimeout     time.Duration
}

// Server exposes REST endpoints for triggering scans and retrieving results.
type Server struct {
	cfg           Config
	httpServer    *http.Server
	authenticator *Authenticator
	manager       *Manager
	staticToken   string
	logger        *logging.AuditLogger
	managerCancel context.CancelFunc
}

// NewServer constructs a REST API server using the provided configuration.
func NewServer(cfg Config) (*Server, error) {
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		return nil, errors.New("api address must be provided")
	}
	if cfg.FindingsBus == nil {
		return nil, errors.New("findings bus is required")
	}
	staticToken := strings.TrimSpace(cfg.StaticToken)
	if staticToken == "" {
		return nil, errors.New("static management token is required")
	}
	if strings.TrimSpace(cfg.SigningKeyPath) == "" {
		return nil, errors.New("signing key path is required")
	}
	auth, err := NewAuthenticator(cfg.JWTSecret, cfg.JWTIssuer, cfg.DefaultTokenTTL)
	if err != nil {
		return nil, err
	}
	manager := NewManager(ManagerConfig{
		PluginsDir:     cfg.PluginsDir,
		AllowlistPath:  cfg.AllowlistPath,
		RepoRoot:       cfg.RepoRoot,
		ServerAddr:     cfg.ServerAddr,
		AuthToken:      cfg.AuthToken,
		SigningKeyPath: cfg.SigningKeyPath,
		ScanTimeout:    cfg.ScanTimeout,
	}, cfg.FindingsBus, cfg.Logger)
	return &Server{
		cfg:           cfg,
		authenticator: auth,
		manager:       manager,
		staticToken:   staticToken,
		logger:        cfg.Logger,
	}, nil
}

// Run starts the HTTP server and blocks until the provided context is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/api/v1/api-tokens", http.HandlerFunc(s.handleTokenIssue))
	mux.Handle("/api/v1/plugins", s.requireJWT(http.HandlerFunc(s.handleListPlugins)))
	mux.Handle("/api/v1/scans", s.requireJWT(http.HandlerFunc(s.handleScans)))
	mux.Handle("/api/v1/scans/", s.requireJWT(http.HandlerFunc(s.handleScanByID)))

	s.httpServer = &http.Server{
		Addr:    s.cfg.Addr,
		Handler: mux,
	}

	managerCtx, cancel := context.WithCancel(context.Background())
	s.managerCancel = cancel
	s.manager.Start(managerCtx)

	errCh := make(chan error, 1)
	go func() {
		err := s.httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		_ = s.httpServer.Shutdown(shutdownCtx)
		s.stopManager()
		return <-errCh
	case err := <-errCh:
		s.stopManager()
		return err
	}
}

func (s *Server) stopManager() {
	if s.managerCancel != nil {
		s.managerCancel()
	}
	if s.manager != nil {
		s.manager.Stop()
	}
}

func (s *Server) handleTokenIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if token := strings.TrimSpace(r.Header.Get("X-0xgen-Token")); token != s.staticToken {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	var req struct {
		Subject    string  `json:"subject"`
		Audience   string  `json:"audience"`
		TTLSeconds float64 `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLSeconds * float64(time.Second))
	token, expires, err := s.authenticator.Mint(req.Subject, req.Audience, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp := map[string]any{
		"token":      token,
		"expires_at": expires.UTC().Format(time.RFC3339),
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	plugins, err := s.manager.ListPlugins()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"plugins": plugins})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Plugin string `json:"plugin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		scan, err := s.manager.Enqueue(req.Plugin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.writeJSON(w, http.StatusAccepted, map[string]any{
			"scan_id": scan.ID,
			"status":  scan.Status,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleScanByID(w http.ResponseWriter, r *http.Request) {
	clean := path.Clean(r.URL.Path)
	trim := strings.TrimPrefix(clean, "/api/v1/scans")
	trim = strings.TrimPrefix(trim, "/")
	if trim == "" {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(trim, "/")
	if len(parts) == 2 && parts[1] == "results" {
		s.handleScanResults(w, r, parts[0])
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	s.handleScanStatus(w, r, parts[0])
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scan, ok := s.manager.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	resp := map[string]any{
		"id":           scan.ID,
		"plugin":       scan.Plugin,
		"status":       scan.Status,
		"created_at":   scan.CreatedAt,
		"started_at":   scan.StartedAt,
		"completed_at": scan.CompletedAt,
		"error":        scan.Error,
		"logs":         scan.Logs,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	result, signature, digest, err := s.manager.Result(id)
	if err != nil {
		if strings.Contains(err.Error(), "not complete") {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	resp := map[string]any{
		"scan_id":      result.ScanID,
		"plugin":       result.Plugin,
		"generated_at": result.GeneratedAt,
		"findings":     result.Findings,
		"signature":    signature,
		"digest":       digest,
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) requireJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(authHeader[7:])
		if _, err := s.authenticator.Validate(token); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		if s.logger != nil {
			_ = s.logger.Emit(logging.AuditEvent{EventType: logging.EventRPCCall, Decision: logging.DecisionDeny, Reason: err.Error()})
		}
	}
}
