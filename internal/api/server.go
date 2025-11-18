package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/RowanDark/0xgen/internal/cipher"
	"github.com/RowanDark/0xgen/internal/findings"
	"github.com/RowanDark/0xgen/internal/logging"
	"github.com/RowanDark/0xgen/internal/rewrite"
	"github.com/RowanDark/0xgen/internal/team"
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
	OIDCIssuer      string
	OIDCJWKSURL     string
	OIDCAudiences   []string
	WorkspaceStore  *team.Store
	RecipesDir      string
	RewriteEngine   *rewrite.Engine
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
	teams         *team.Store
	recipeManager *cipher.RecipeManager
	rewriteAPI    *RewriteAPI
}

type contextKey string

const claimsContextKey contextKey = "0xgen.api.claims"

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
	var authOpts []AuthOption
	if strings.TrimSpace(cfg.OIDCIssuer) != "" && strings.TrimSpace(cfg.OIDCJWKSURL) != "" {
		authOpts = append(authOpts, WithOIDC(OIDCConfig{
			Issuer:       strings.TrimSpace(cfg.OIDCIssuer),
			JWKSURL:      strings.TrimSpace(cfg.OIDCJWKSURL),
			Audiences:    cfg.OIDCAudiences,
			SyncInterval: time.Minute,
		}))
	}
	auth, err := NewAuthenticator(cfg.JWTSecret, cfg.JWTIssuer, cfg.DefaultTokenTTL, authOpts...)
	if err != nil {
		return nil, err
	}
	store := cfg.WorkspaceStore
	if store == nil {
		var storeLogger *logging.AuditLogger
		if cfg.Logger != nil {
			storeLogger = cfg.Logger.WithComponent("workspace_store")
		}
		store = team.NewStore(storeLogger)
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

	// Initialize recipe manager with configured path (defaults to "./recipes")
	recipesDir := cfg.RecipesDir
	if recipesDir == "" {
		recipesDir = "./recipes"
	}
	recipeManager := cipher.NewRecipeManager(recipesDir)
	if err := recipeManager.LoadRecipes(); err != nil {
		return nil, err
	}

	// Initialize Rewrite API if engine is provided
	var rewriteAPI *RewriteAPI
	if cfg.RewriteEngine != nil {
		var rewriteLogger *slog.Logger
		if cfg.Logger != nil {
			// Convert AuditLogger to slog.Logger
			rewriteLogger = slog.Default()
		} else {
			rewriteLogger = slog.Default()
		}
		rewriteAPI = NewRewriteAPI(cfg.RewriteEngine, rewriteLogger)
	}

	return &Server{
		cfg:           cfg,
		authenticator: auth,
		manager:       manager,
		staticToken:   staticToken,
		logger:        cfg.Logger,
		teams:         store,
		recipeManager: recipeManager,
		rewriteAPI:    rewriteAPI,
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
	mux.Handle("/api/v1/plugins", s.requireRole(team.RoleViewer, http.HandlerFunc(s.handleListPlugins)))
	mux.Handle("/api/v1/scans", s.requireRole(team.RoleAnalyst, http.HandlerFunc(s.handleScans)))
	mux.Handle("/api/v1/scans/", s.requireRole(team.RoleViewer, http.HandlerFunc(s.handleScanByID)))

	// Cipher endpoints
	mux.HandleFunc("/api/v1/cipher/execute", s.handleCipherExecute)
	mux.HandleFunc("/api/v1/cipher/pipeline", s.handleCipherPipeline)
	mux.HandleFunc("/api/v1/cipher/detect", s.handleCipherDetect)
	mux.HandleFunc("/api/v1/cipher/smart-decode", s.handleCipherSmartDecode)
	mux.HandleFunc("/api/v1/cipher/operations", s.handleCipherListOperations)
	mux.HandleFunc("/api/v1/cipher/recipes/save", s.handleRecipeSave)
	mux.HandleFunc("/api/v1/cipher/recipes/list", s.handleRecipeList)
	mux.HandleFunc("/api/v1/cipher/recipes/load", s.handleRecipeLoad)
	mux.HandleFunc("/api/v1/cipher/recipes/delete", s.handleRecipeDelete)

	// Rewrite endpoints
	if s.rewriteAPI != nil {
		s.rewriteAPI.RegisterRoutes(mux)
	}

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
		Subject     string  `json:"subject"`
		Audience    string  `json:"audience"`
		TTLSeconds  float64 `json:"ttl_seconds"`
		WorkspaceID string  `json:"workspace_id"`
		Role        string  `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLSeconds * float64(time.Second))
	trimmedRole := strings.TrimSpace(req.Role)
	var (
		roleClaim  string
		memberRole team.Role
	)
	if trimmedRole != "" {
		parsedRole, err := team.ParseRole(trimmedRole)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		memberRole = parsedRole
		roleClaim = string(parsedRole)
	}
	token, expires, err := s.authenticator.MintWithOptions(req.Subject, TokenOptions{
		Audience:    req.Audience,
		TTL:         ttl,
		WorkspaceID: req.WorkspaceID,
		Role:        roleClaim,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.WorkspaceID) != "" && roleClaim != "" && s.teams != nil {
		if _, err := s.teams.UpsertMembership(req.WorkspaceID, req.Subject, memberRole); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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

func (s *Server) requireRole(minRole team.Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimSpace(authHeader[7:])
		claims, err := s.authenticator.Validate(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if minRole != "" {
			if s.teams == nil {
				http.Error(w, "workspace access unavailable", http.StatusForbidden)
				return
			}
			workspaceID := strings.TrimSpace(claims.WorkspaceID)
			if workspaceID == "" {
				http.Error(w, "workspace claim required", http.StatusForbidden)
				return
			}
			if !s.teams.Authorize(workspaceID, claims.Subject, minRole) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
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
