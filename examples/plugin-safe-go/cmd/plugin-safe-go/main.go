package main

import (
	"log/slog"
	"os"
	"strings"

	pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"

	"github.com/RowanDark/Glyph/examples/plugin-safe-go/internal/plugin"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg := pluginsdk.Config{
		PluginName:      "plugin-safe-go",
		Host:            envOrDefault("GLYPH_HOST", "127.0.0.1:50051"),
		AuthToken:       os.Getenv("GLYPH_AUTH_TOKEN"),
		CapabilityToken: os.Getenv("GLYPH_CAPABILITY_TOKEN"),
                SecretsToken:    strings.TrimSpace(os.Getenv("GLYPH_SECRETS_TOKEN")),
                SecretsScope:    strings.TrimSpace(os.Getenv("GLYPH_SECRETS_SCOPE")),
                Capabilities: plugin.CapabilityMacros.List(),
		Logger: logger,
	}

	if cfg.AuthToken == "" || cfg.CapabilityToken == "" {
		logger.Error("missing required auth tokens")
		os.Exit(1)
	}

	if err := pluginsdk.Run(cfg, plugin.Hooks()); err != nil {
		logger.Error("plugin exited", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
