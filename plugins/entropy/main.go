package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func main() {
	var (
		serverAddr = flag.String("server", "127.0.0.1:50051", "0xgend gRPC address")
		authToken  = flag.String("token", "dev-token", "authentication token")
		dbPath     = flag.String("db", "entropy.db", "SQLite database path")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	capabilityToken := strings.TrimSpace(os.Getenv("0XGEN_CAPABILITY_TOKEN"))
	if capabilityToken == "" {
		logger.Error("missing 0XGEN_CAPABILITY_TOKEN environment variable")
		os.Exit(1)
	}

	// Initialize storage
	storage, err := NewStorage(*dbPath)
	if err != nil {
		logger.Error("failed to initialize storage", "error", err)
		os.Exit(1)
	}
	defer storage.Close()

	cfg := pluginsdk.Config{
		PluginName:      "entropy",
		Host:            *serverAddr,
		AuthToken:       *authToken,
		CapabilityToken: capabilityToken,
		Capabilities: []pluginsdk.Capability{
			pluginsdk.CapabilityEmitFindings,
			pluginsdk.CapabilityHTTPPassive,
		},
		Logger: logger,
	}

	hooks := newEntropyHooks(storage, time.Now)

	if err := pluginsdk.Run(cfg, hooks); err != nil {
		logger.Error("plugin terminated", "error", err)
		os.Exit(1)
	}
}

// entropyHooks implements plugin hooks
type entropyHooks struct {
	sessionManager *SessionManager
	now            func() time.Time

	// Auto-capture session tracking
	autoSessionID int64
}

func newEntropyHooks(storage *Storage, now func() time.Time) *entropyHooks {
	engine := NewEntropyEngine(storage, now)
	sessionManager := NewSessionManager(storage, engine, now)

	hooks := &entropyHooks{
		sessionManager: sessionManager,
		now:            now,
		autoSessionID:  0,
	}

	return hooks
}

// Init is called when the plugin starts
func (h *entropyHooks) Init(ctx *pluginsdk.Context) error {
	ctx.Logger().Info("Entropy plugin initialized")

	// Load active sessions from database (persistence across restarts)
	if err := h.sessionManager.LoadActiveSessions(); err != nil {
		ctx.Logger().Error("failed to load active sessions", "error", err)
	}

	activeSessions := h.sessionManager.GetActiveSessions()
	if len(activeSessions) > 0 {
		ctx.Logger().Info("loaded active sessions", "count", len(activeSessions))
	}

	// Start notification listener
	go h.handleNotifications(ctx)

	// Start periodic cleanup of timed-out sessions
	go h.periodicCleanup(ctx)

	return nil
}

// Shutdown is called when the plugin stops
func (h *entropyHooks) Shutdown(ctx *pluginsdk.Context) error {
	ctx.Logger().Info("Entropy plugin shutting down")

	// Stop all active sessions gracefully
	for _, session := range h.sessionManager.GetActiveSessions() {
		if err := h.sessionManager.StopSession(session.ID, StopReasonManual); err != nil {
			ctx.Logger().Error("failed to stop session", "session_id", session.ID, "error", err)
		}
	}

	return nil
}

// handleNotifications processes session notifications
func (h *entropyHooks) handleNotifications(ctx *pluginsdk.Context) {
	for notification := range h.sessionManager.GetNotifications() {
		ctx.Logger().Info("session event",
			"session", notification.SessionName,
			"event", notification.Event,
			"message", notification.Message)

		// Could emit findings or other actions based on notifications
		if notification.Event == "analyzed" && notification.Data != nil {
			if risk, ok := notification.Data["risk"].(string); ok {
				if risk == string(RiskHigh) || risk == string(RiskCritical) {
					ctx.Logger().Warn("high risk detected",
						"session", notification.SessionName,
						"risk", risk)
				}
			}
		}
	}
}

// periodicCleanup checks for timed-out sessions every minute
func (h *entropyHooks) periodicCleanup(ctx *pluginsdk.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		h.sessionManager.CleanupSessions()
	}
}

// OnHTTPPassive is called for each HTTP request/response (optimized for <5ms overhead)
func (h *entropyHooks) OnHTTPPassive(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
	if event.Response == nil {
		return nil
	}

	// Auto-detect and extract common session tokens
	token := ExtractSessionID(event.Response)
	if token == "" {
		return nil // No token found, skip
	}

	// Check if we have an auto-capture session
	if h.autoSessionID == 0 {
		// Create auto-capture session on first token
		extractor := TokenExtractor{
			Pattern:  "",
			Location: "cookie",
			Name:     "session",
		}

		// Target: 1000 tokens, timeout: 1 hour
		session, err := h.sessionManager.StartSession(
			"Auto-detected Session IDs",
			extractor,
			1000,        // target count
			1*time.Hour, // timeout
		)
		if err != nil {
			ctx.Logger().Error("failed to create auto-capture session", "error", err)
			return nil
		}

		h.autoSessionID = session.ID
		ctx.Logger().Info("started auto-capture session",
			"session_id", session.ID,
			"target", 1000,
			"timeout", "1h")
	}

	// Capture token (low overhead, <5ms)
	requestID := ""
	if event.Request != nil {
		// Generate simple request ID
		requestID = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	if err := h.sessionManager.OnTokenCaptured(h.autoSessionID, token, requestID); err != nil {
		ctx.Logger().Error("failed to capture token", "error", err)
		return nil
	}

	return nil
}
