package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func main() {
	if os.Getenv("0XGEN_E2E_SMOKE") != "1" {
		return
	}

	var (
		serverAddr = flag.String("server", "127.0.0.1:50051", "glyphd gRPC address")
		authToken  = flag.String("token", "supersecrettoken", "authentication token")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	capToken := strings.TrimSpace(os.Getenv("0XGEN_CAPABILITY_TOKEN"))
	if capToken == "" {
		logger.Error("missing 0XGEN_CAPABILITY_TOKEN environment variable")
		os.Exit(1)
	}

	cfg := pluginsdk.Config{
		PluginName:      "emit-on-start",
		Host:            *serverAddr,
		AuthToken:       *authToken,
		CapabilityToken: capToken,
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
