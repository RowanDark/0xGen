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
		serverAddr = flag.String("server", "127.0.0.1:50051", "glyphd gRPC address")
		authToken  = flag.String("token", "dev-token", "authentication token")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	capToken := strings.TrimSpace(os.Getenv("GLYPH_CAPABILITY_TOKEN"))
	if capToken == "" {
		logger.Error("missing GLYPH_CAPABILITY_TOKEN environment variable")
		os.Exit(1)
	}

	cfg := pluginsdk.Config{
		PluginName:      "example-hello",
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
			ctx.Logger().Info("sending hello finding")
			return ctx.EmitFinding(pluginsdk.Finding{
				Type:       "example.hello",
				Message:    "Hello from example-hello!",
				Target:     "example://hello",
				Severity:   pluginsdk.SeverityInfo,
				DetectedAt: time.Now().UTC(),
				Metadata: map[string]string{
					"example": "true",
				},
			})
		},
	}

	if err := pluginsdk.Run(cfg, hooks); err != nil {
		logger.Error("plugin terminated", "error", err)
		os.Exit(1)
	}
}
