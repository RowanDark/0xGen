package main

import (
	"flag"
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
	storage *Storage
	engine  *EntropyEngine
	now     func() time.Time

	// Active capture sessions
	activeSessions map[string]*CaptureSession
}

func newEntropyHooks(storage *Storage, now func() time.Time) *entropyHooks {
	return &entropyHooks{
		storage:        storage,
		engine:         NewEntropyEngine(storage, now),
		now:            now,
		activeSessions: make(map[string]*CaptureSession),
	}
}

// Init is called when the plugin starts
func (h *entropyHooks) Init(ctx *pluginsdk.Context) error {
	ctx.Logger().Info("Entropy plugin initialized")
	return nil
}

// Shutdown is called when the plugin stops
func (h *entropyHooks) Shutdown(ctx *pluginsdk.Context) error {
	ctx.Logger().Info("Entropy plugin shutting down")
	return nil
}

// OnHTTPPassive is called for each HTTP request/response
func (h *entropyHooks) OnHTTPPassive(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
	if event.Response == nil {
		return nil
	}

	// Auto-detect and extract common session tokens
	if token := ExtractSessionID(event.Response); token != "" {
		// Check if we have an active session for this type
		sessionKey := "auto_session_id"
		session, exists := h.activeSessions[sessionKey]

		if !exists {
			// Create new capture session
			extractor := TokenExtractor{
				Pattern:  "",
				Location: "cookie",
				Name:     "session",
			}

			var err error
			session, err = h.storage.CreateSession("Auto-detected Session IDs", extractor)
			if err != nil {
				ctx.Logger().Error("failed to create session", "error", err)
				return nil
			}
			h.activeSessions[sessionKey] = session
			ctx.Logger().Info("started token capture session", "session_id", session.ID)
		}

		// Store the token
		sample := TokenSample{
			CaptureSessionID: session.ID,
			TokenValue:       token,
			TokenLength:      len(token),
			CapturedAt:       h.now().UTC(),
		}

		if err := h.storage.StoreToken(sample); err != nil {
			ctx.Logger().Error("failed to store token", "error", err)
			return nil
		}

		// Check if we have enough samples to analyze
		session.TokenCount++
		if session.TokenCount >= 100 && session.TokenCount%50 == 0 {
			// Perform analysis every 50 tokens after reaching 100
			ctx.Logger().Info("analyzing token session", "session_id", session.ID, "count", session.TokenCount)

			analysis, err := h.engine.AnalyzeSession(session.ID)
			if err != nil {
				ctx.Logger().Error("analysis failed", "error", err)
				return nil
			}

			// Emit finding if risk is medium or higher
			if analysis.Risk == RiskMedium || analysis.Risk == RiskHigh || analysis.Risk == RiskCritical {
				finding := h.engine.CreateFinding(analysis, session)
				if err := ctx.EmitFinding(finding); err != nil {
					ctx.Logger().Error("failed to emit finding", "error", err)
					return nil
				}
				ctx.Logger().Info("finding emitted",
					"type", finding.Type,
					"risk", analysis.Risk,
					"score", analysis.RandomnessScore)
			}
		}
	}

	return nil
}
