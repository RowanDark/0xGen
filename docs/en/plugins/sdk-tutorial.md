# Plugin SDK Tutorial

0xgen plugins run out-of-process and exchange events with the core services over a
gRPC-based plugin bus. This tutorial walks through building minimal detectors in
Go, Python, and Rust so you can choose the runtime that best fits your team.
Each language section covers scaffolding a plugin, implementing the lifecycle
hooks, and validating the manifest before shipping.

## Prerequisites

- `go run ./cmd/oxg-plugin` for scaffolding Go skeletons.
- `buf` or `protoc` to generate gRPC bindings for Python and Rust.
- Access to the [`sdk/plugin-sdk/`]({{ config.repo_url }}/tree/main/sdk/plugin-sdk)
  helpers when writing
  Go plugins and when porting broker semantics to other runtimes.
- A running `0xgend` instance or the local test harness exposed by
  `pluginsdk.RunLocal` for offline iterations.

## Go: full SDK with batteries included

1. Scaffold a project using the Go starter template:
   ```bash
   go run ./cmd/oxg-plugin init \
     --lang go \
     --name plugins/hello-go \
     --module github.com/acme/hello-go
   ```
   The command copies the same layout used by the
   [`example-hello` plugin]({{ config.repo_url }}/tree/main/plugins/example-hello).
2. Implement your hooks in `main.go`. The generated entry point wires the
   [`pluginsdk.Run`]({{ config.repo_url }}/blob/main/sdk/plugin-sdk/sdk.go) helper which manages the
   gRPC connection, capability token exchange, and graceful shutdown. Emit a
   finding inside `OnStart` or an HTTP passive callback using
   [`Context.EmitFinding`]({{ config.repo_url }}/blob/main/sdk/plugin-sdk/sdk.go).
3. Declare capabilities in `manifest.json` before running the plugin. The
   example grants `CAP_EMIT_FINDINGS` so the host accepts emitted cases.
4. Exercise the plugin without a running core by invoking the local harness:
   ```go
   result, err := pluginsdk.RunLocal(context.Background(), pluginsdk.LocalRunConfig{
       PluginName:   "hello-go",
       Capabilities: []pluginsdk.Capability{pluginsdk.CapabilityEmitFindings},
       Hooks: pluginsdk.Hooks{OnStart: myStartHook},
   })
   ```
   The helper reuses the same capability checks as the real runtime and records
   findings for assertions.

## Python: talk to the plugin bus directly

Python plugins connect to the same gRPC services exposed by the Go SDK. Generate
bindings from [`proto/oxg/plugin_bus.proto`]({{ config.repo_url }}/blob/main/proto/oxg/plugin_bus.proto)
and [`proto/oxg/secrets.proto`]({{ config.repo_url }}/blob/main/proto/oxg/secrets.proto) with `grpcio-tools`:

```bash
python -m grpc_tools.protoc \
  --proto_path proto \
  --python_out my_plugin \
  --grpc_python_out my_plugin \
  proto/oxg/plugin_bus.proto proto/oxg/secrets.proto
```

Key implementation notes:

- Open a `PluginBusStub.EventStream` and send an initial `PluginHello` message
  that includes the capability token from the environment, the manifest name,
  and desired subscriptions. The protobuf definitions mirror the Go struct used
  by
  [`plugins/example-hello/main.go`]({{ config.repo_url }}/blob/main/plugins/example-hello/main.go).
- Serialize findings using the generated `oxg.common.Finding` message. The
  required fields (`type`, `message`, and severity) match the checks enforced in
  [`Context.EmitFinding`]({{ config.repo_url }}/blob/main/sdk/plugin-sdk/sdk.go).
- Optional: dial the [`SecretsBroker`]({{ config.repo_url }}/blob/main/proto/oxg/secrets.proto)
  service to request scoped credentials when `CAP_SECRETS_READ` is granted.
- Wrap your event loop in `asyncio` or threads and respect cancellation signals.
  The host closes the stream when revoking capabilities.

Testing is as simple as replaying fixture events through the Python
implementation and asserting on emitted protobuf messages. Reuse the Go harness
for parity by generating gRPC fixtures with `pluginsdk.RunLocal` and feeding the
serialized events into your client.

## Rust: async-first integrations

Rust clients follow the same gRPC flow using `tonic` or another async gRPC
library. Generate bindings with `tonic-build` inside a Cargo build script:

```rust
// build.rs
fn main() {
    tonic_build::configure()
        .compile(
            &["proto/oxg/plugin_bus.proto", "proto/oxg/secrets.proto"],
            &["proto"],
        )
        .expect("failed to compile proto files");
}
```

During runtime:

- Establish a `PluginBusClient` channel and immediately send the `PluginHello`
  handshake. You can deserialize findings into the generated structs and reuse
  helper functions to uppercase IDs or stamp timestamps before emitting.
- Stream host events with `while let Some(event) = stream.next().await` and map
  `flow_event` payloads to your detectors.
- Construct capability token requests via `GrantCapabilities` when running
  integration tests. The request format matches the proto definitions referenced
  above, allowing you to mint throwaway tokens in CI.
- Implement a secrets client with the generated `SecretsBrokerClient` to reuse
  scoped credentials.

## Validation and packaging

Regardless of language, complete the following checklist before publishing:

- Validate the manifest against
  [`plugins/manifest.schema.json`]({{ config.repo_url }}/blob/main/plugins/manifest.schema.json).
- Run the [`capassert` helper]({{ config.repo_url }}/tree/main/sdk/plugin-sdk/cmd/capassert)
  manifests only request the capabilities the code needs.
- Document broker usage and sandbox assumptions in `README.md` alongside your
  plugin, mirroring
  [`plugins/example-hello/README.md`]({{ config.repo_url }}/blob/main/plugins/example-hello/README.md).
- Add local regression tests that replay
  [`examples/quickstart`]({{ config.repo_url }}/tree/main/examples/quickstart)
  fixtures or other synthetic data to keep results deterministic.
