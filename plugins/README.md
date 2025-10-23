# 0xgen Plugins

0xgen plugins are Go binaries that connect to `0xgend` using the SDK in
`sdk/plugin-sdk`. The SDK handles the gRPC transport, lifecycle hooks and safely
emitting findings back to the host. Consult [the plugin author guide](https://rowandark.github.io/0xgen/plugins/)
for the full author guide, capability matrix, and JSONL emission rules.

## Hello world example

The sample below emits a single finding when the plugin starts. It matches the
behaviour of the `emit-on-start` sample bundled with the repository. A complete
end-to-end reference (manifest, plugin, and test) lives in
`plugins/example-hello/`.

```go
package main

import (
    "context"
    "log/slog"
    "os"
    "os/signal"
    "syscall"
    "time"

    pluginsdk "github.com/RowanDark/0xgen/sdk/plugin-sdk"
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
                Message:    "Hello from the 0xgen SDK!",
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

To run the sample against a local `0xgend`:

```bash
go run ./cmd/0xgenctl plugin run --sample emit-on-start --server 127.0.0.1:50051 --token supersecrettoken
```

Set `0XGEN_E2E_SMOKE=1` in the environment to enable the demo sample. The
manifest and source live under `plugins/samples/emit-on-start` and serve as a
compact reference for authoring new plugins.

## Signing requirements

All official plugins are signed using [Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/).
Each manifest must include a `signature` block that points to a detached
signature (`<artifact>.sig`) and either a public key or Fulcio certificate.

To generate a signature with a cosign key pair:

```bash
cosign sign-blob \
  --key /path/to/0xgen-plugin.key \
  --output-signature plugin.js.sig \
  --output-certificate plugin.js.pem \
  plugin.js
```

Commit the updated signature file and reference the certificate or public key in
the manifest. 0xgen refuses to run plugins whose signature does not match the
allowlisted hash and public key.
