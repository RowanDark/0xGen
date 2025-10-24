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
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	capabilityToken := strings.TrimSpace(os.Getenv("0XGEN_CAPABILITY_TOKEN"))
	if capabilityToken == "" {
		logger.Error("missing 0XGEN_CAPABILITY_TOKEN environment variable")
		os.Exit(1)
	}

	cfg := pluginsdk.Config{
		PluginName:      "hydra",
		Host:            *serverAddr,
		AuthToken:       *authToken,
		CapabilityToken: capabilityToken,
		Capabilities: []pluginsdk.Capability{
			pluginsdk.CapabilityEmitFindings,
			pluginsdk.CapabilityHTTPPassive,
			pluginsdk.CapabilityFlowInspect,
			pluginsdk.CapabilityAIAnalysis,
		},
		Logger: logger,
	}

	hooks := newHydraHooks(time.Now)

	if err := pluginsdk.Run(cfg, hooks); err != nil {
		logger.Error("plugin terminated", "error", err)
		os.Exit(1)
	}
}
