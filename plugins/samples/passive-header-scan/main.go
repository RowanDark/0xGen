package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
)

func main() {
	var (
		serverAddr = flag.String("server", "127.0.0.1:50051", "glyphd gRPC address")
		authToken  = flag.String("token", "supersecrettoken", "authentication token")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	capToken := strings.TrimSpace(os.Getenv("0XGEN_CAPABILITY_TOKEN"))
	if capToken == "" {
		logger.Error("missing 0XGEN_CAPABILITY_TOKEN environment variable")
		os.Exit(1)
	}

	cfg := pluginsdk.Config{
		PluginName:      "passive-header-scan",
		Host:            *serverAddr,
		AuthToken:       *authToken,
		CapabilityToken: capToken,
		Capabilities: []pluginsdk.Capability{
			pluginsdk.CapabilityHTTPPassive,
			pluginsdk.CapabilityEmitFindings,
		},
		Logger: logger,
	}

	hooks := pluginsdk.Hooks{
		OnStart: func(ctx *pluginsdk.Context) error {
			ctx.Logger().Info("plugin started", "addr", *serverAddr)
			if os.Getenv("0XGEN_E2E_SMOKE") == "1" {
				if err := ctx.EmitFinding(pluginsdk.Finding{
					Type:       "e2e-smoke",
					Message:    "e2e smoke marker",
					Target:     "e2e://smoke",
					Evidence:   "e2e smoke marker",
					Severity:   pluginsdk.SeverityLow,
					DetectedAt: time.Now().UTC(),
				}); err != nil {
					return err
				}
			}
			return nil
		},
		OnHTTPPassive: func(ctx *pluginsdk.Context, event pluginsdk.HTTPPassiveEvent) error {
			headers := event.Response.Headers
			missing := []string{}
			checks := map[string]string{
				"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
				"X-Content-Type-Options":    "nosniff",
				"X-Frame-Options":           "DENY",
				"Content-Security-Policy":   "default-src 'none'",
			}
			for header, recommended := range checks {
				if headers.Get(header) == "" {
					missing = append(missing, header)
					if err := ctx.EmitFinding(pluginsdk.Finding{
						Type:       "missing-security-header",
						Message:    fmt.Sprintf("response missing %s header", header),
						Target:     event.Response.Headers.Get("Host"),
						Evidence:   fmt.Sprintf("Missing %s header", header),
						Severity:   pluginsdk.SeverityMedium,
						DetectedAt: time.Now().UTC(),
						Metadata: map[string]string{
							"header":         header,
							"recommendation": recommended,
						},
					}); err != nil {
						return err
					}
				}
			}

			if len(missing) == 0 {
				ctx.Logger().Debug("all monitored headers present")
			} else {
				ctx.Logger().Info("detected insecure response", "missing", strings.Join(missing, ", "))
			}
			return nil
		},
	}

	if err := pluginsdk.Serve(ctx, cfg, hooks); err != nil {
		logger.Error("plugin terminated", "error", err)
		os.Exit(1)
	}

	time.Sleep(100 * time.Millisecond)
}
