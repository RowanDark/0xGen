# Developer Guide

This guide helps contributors set up a development environment, iterate on new
features, and ship releases with confidence.

## Prerequisites

Glyph is written in Go with supporting tooling in Node.js and Python. Install the
following before hacking on the repository:

- Go 1.21+
- Node.js 20+ and npm (used by Playwright fixtures)
- Python 3.11+ for auxiliary scripts
- Make, Git, and Docker (optional but required for container builds)

Clone the repository and run `make deps` to download Go modules and Playwright
browsers used by the integration tests.

## Build and test

The [`Makefile`]({{ config.repo_url }}/blob/main/Makefile) contains convenience targets for the most common
developer workflows:

```bash
# Compile glyphctl into ./out/
make build

# Run unit and integration tests
make test

# Execute the end-to-end quickstart demo
make demo
```

You can also build the CLI manually with `go build ./cmd/glyphctl`. Tests that rely on
Playwright or other external services automatically skip themselves when the
prerequisites are missing, keeping `make test` fast on constrained environments.

## Plugin development loop

Use `make new-plugin name=<id>` to scaffold a new plugin under `plugins/<id>/`. The
scaffolding includes a manifest, Go stubs, and a sample test harness wired to the
[`sdk/plugin-sdk`]({{ config.repo_url }}/tree/main/sdk/plugin-sdk). Run `go test ./plugins/<id>/...` while you
iterate.

When you are ready to exercise the plugin against a running daemon, build it and then
invoke:

```bash
go build ./plugins/<id>
glyphctl plugin run --path ./plugins/<id>/<id> --duration 30s
```

The CLI connects to `glyphd`, streams findings back to `out/findings.jsonl`, and lets
you debug the plugin in real time.

## Release checklist

1. Update [`CHANGELOG.md`]({{ config.repo_url }}/blob/main/CHANGELOG.md) with user-facing notes.
2. Run `make test` and `make demo` to ensure critical paths pass.
3. Execute `scripts/build_release.sh` to produce signed archives and checksums.
4. Follow the prompts in `scripts/update_homebrew_formula.sh` if the Homebrew tap
   needs a new version.
5. Push a Git tag (for example `v1.2.3`) to trigger the release workflows and publish
   versioned documentation.

Refer to [`CONTRIBUTING.md`]({{ config.repo_url }}/blob/main/CONTRIBUTING.md) for coding conventions and code
review expectations.
