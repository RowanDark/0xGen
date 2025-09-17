package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"
)

func main() {
	if os.Getenv("GLYPH_E2E_SMOKE") != "1" {
		return
	}

	var (
		serverAddr = flag.String("server", "127.0.0.1:50051", "glyphd gRPC address")
		authToken  = flag.String("token", "supersecrettoken", "authentication token")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := pluginsdk.Config{
		PluginName: "emit-on-start",
		Host:       *serverAddr,
		AuthToken:  *authToken,
		Capabilities: []pluginsdk.Capability{
			pluginsdk.CapabilityEmitFindings,
		},
		Logger: logger,
	}

	hooks := pluginsdk.Hooks{
		OnStart: func(ctx *pluginsdk.Context) error {
			ctx.Logger().Info("emitting startup finding")
			return ctx.EmitFinding(pluginsdk.Finding{
				Type:       "demo.startup",
				Message:    "Demo finding emitted during startup",
				Target:     "demo://startup",
				Evidence:   "Demo finding emitted during startup",
				Severity:   pluginsdk.SeverityLow,
				DetectedAt: time.Now().UTC(),
				Metadata: map[string]string{
					"source": "emit-on-start",
				},
			})
		},
	}

	if err := pluginsdk.Serve(ctx, cfg, hooks); err != nil {
		logger.Error("plugin terminated", "error", err)
		os.Exit(1)
	}
}
