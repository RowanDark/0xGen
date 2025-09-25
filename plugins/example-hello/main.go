package main

import (
	"flag"
	"log/slog"
	"os"
	"time"

	pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"
)

func main() {
	var (
		serverAddr = flag.String("server", "127.0.0.1:50051", "glyphd gRPC address")
		authToken  = flag.String("token", "dev-token", "authentication token")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cfg := pluginsdk.Config{
		PluginName: "example-hello",
		Host:       *serverAddr,
		AuthToken:  *authToken,
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
