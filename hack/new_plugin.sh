#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
        echo "usage: hack/new_plugin.sh <plugin-name>" >&2
        exit 1
fi

name="$1"
if [[ -z "$name" ]]; then
        echo "error: plugin name is required" >&2
        exit 1
fi
if [[ "$name" =~ [^a-z0-9-] ]]; then
        echo "error: plugin name must match [a-z0-9-]+" >&2
        exit 1
fi
if [[ "$name" == -* ]]; then
        echo "error: plugin name must not start with '-'" >&2
        exit 1
fi

dir="plugins/${name}"
if [[ -e "$dir" ]]; then
        echo "error: ${dir} already exists" >&2
        exit 1
fi

mkdir -p "$dir"

cat >"${dir}/manifest.json" <<EOF_MANIFEST
{
  "name": "${name}",
  "version": "0.1.0",
  "entry": "${name}",
  "artifact": "plugins/${name}/main.go",
  "capabilities": ["CAP_EMIT_FINDINGS"]
}
EOF_MANIFEST

cat >"${dir}/main.go" <<EOF_MAIN
package main

import (
        "flag"
        "log/slog"
        "os"

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
                PluginName: "${name}",
                Host:       *serverAddr,
                AuthToken:  *authToken,
                Capabilities: []pluginsdk.Capability{
                        pluginsdk.CapabilityEmitFindings,
                },
                Logger: logger,
        }

        hooks := pluginsdk.Hooks{
                OnStart: func(ctx *pluginsdk.Context) error {
                        ctx.Logger().Info("plugin initialised")
                        return nil
                },
        }

        if err := pluginsdk.Run(cfg, hooks); err != nil {
                logger.Error("plugin terminated", "error", err)
                os.Exit(1)
        }
}
EOF_MAIN

gofmt -w "${dir}/main.go"

echo "Created plugin skeleton in ${dir}"
