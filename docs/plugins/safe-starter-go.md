# Go safe starter walkthrough

The `glyph-plugin init --lang go` command scaffolds a plugin that already uses
safe defaults: capability macros, broker clients, and CI-friendly tooling. This
page walks through the generated layout and shows how to adapt it for your own
integrations.

## Generate a project

```bash
go run ./cmd/glyph-plugin init \
  --lang go \
  --name plugin-safe-go \
  --module github.com/RowanDark/Glyph/examples/plugin-safe-go
```

The command creates a directory containing:

- `cmd/<binary>/main.go` – wires capability tokens, logging, and broker hooks
  into `pluginsdk.Run`.
- `internal/plugin/` – plugin logic plus capability macros that determine which
  permissions appear in the manifest and runtime config.
- `Makefile`, `tools.go`, and a pinned `go.mod` – run `make lint` to execute the
  capability linter and `make test` for the generated unit tests.
- `manifest.json` – pre-populated with `CAP_EMIT_FINDINGS`, `CAP_HTTP_PASSIVE`,
  and workspace access. Adjust the list to match `CapabilityMacros`.

You can inspect the repository copy under
[`examples/plugin-safe-go/`]({{ config.repo_url }}/tree/main/examples/plugin-safe-go) for a ready-made
reference implementation.

## Capability macros

`internal/plugin/capabilities.go` centralises the manifest declaration:

```go
var CapabilityMacros = pluginsdk.CapabilitySet{
    EmitFindings:   true,
    HTTPPassive:    true,
    WorkspaceRead:  true,
    WorkspaceWrite: false,
    NetOutbound:    false,
    SecretsRead:    false,
}
```

Toggling a macro updates `pluginsdk.Config.Capabilities`, the generated
`manifest.json`, and the runtime guard rails used throughout
`internal/plugin/plugin.go`. The sample implementation demonstrates how to gate
filesystem, network, and secret access on the macros so the linter can verify
that capabilities are either declared or safely ignored.

## Tests and linting

Run the scaffolded targets from the plugin directory:

```bash
make lint
make test
```

- `make lint` executes `capassert`, which now checks for raw filesystem/network
  calls **and** verifies that broker helpers such as `pluginsdk.UseNetwork`
  respect declared macros.
- `make test` exercises the plugin against the SDK's in-memory fake broker to
  ensure emitted findings and broker usage stay in sync.

These defaults mean new plugins start from a secure, testable baseline that can
ship without additional bootstrap work.
