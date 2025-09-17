# Glyph Plugins

Glyph plugins are Go binaries that connect to `glyphd` using the SDK in
`sdk/plugin-sdk`. The SDK handles the gRPC transport, lifecycle hooks and safely
emitting findings back to the host.

## Hello world example

The sample below emits a single finding when the plugin starts. It matches the
behaviour of the `emit-on-start` sample bundled with the repository.

```go
package main

import (
    "context"
    "log/slog"
    "os"
    "os/signal"
    "syscall"
    "time"

    pluginsdk "github.com/RowanDark/Glyph/sdk/plugin-sdk"
)

func main() {
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer stop()

    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
    cfg := pluginsdk.Config{
        PluginName:   "hello-world",
        Host:         "127.0.0.1:50051",
        AuthToken:    "supersecrettoken",
        Capabilities: []pluginsdk.Capability{pluginsdk.CapabilityEmitFindings},
        Logger:       logger,
    }

    hooks := pluginsdk.Hooks{
        OnStart: func(ctx *pluginsdk.Context) error {
            return ctx.EmitFinding(pluginsdk.Finding{
                Type:       "demo.startup",
                Message:    "Hello from the Glyph SDK!",
                Target:     "demo://hello",
                Severity:   pluginsdk.SeverityInfo,
                DetectedAt: time.Now().UTC(),
            })
        },
    }

    if err := pluginsdk.Serve(ctx, cfg, hooks); err != nil {
        logger.Error("plugin terminated", "error", err)
        os.Exit(1)
    }
}
```

To run the sample against a local `glyphd`:

```bash
go run ./cmd/glyphctl plugin run --sample emit-on-start --server 127.0.0.1:50051 --token supersecrettoken
```

Set `GLYPH_E2E_SMOKE=1` in the environment to enable the demo sample. The
manifest and source live under `plugins/samples/emit-on-start` and serve as a
compact reference for authoring new plugins.
