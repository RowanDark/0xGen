# Contributing to 0xgen

Thanks for helping shape 0xgen! To keep the project healthy and reproducible, please follow these guidelines before opening a pull request.

## Development environment

- Install Go 1.21+, Node.js 18+, and the Amass binary if you plan to exercise OSINT Well locally.
- `go install golang.org/x/tools/cmd/goimports@latest` helps keep imports tidy.
- Set `0XGEN_OUT` if you want 0xgen services to write artefacts outside of `/out`.

## Working on changes

1. Create focused commits that describe **what** changed and **why**.
2. Run the relevant automated checks:
   - `go test ./...`
   - `npm --prefix plugins/excavator test`
   - `npm --prefix plugins/excavator run crawl -- https://example.com` (optional sanity check)
3. Format Go code with `gofmt -w` (or `goimports`) before committing.
4. Update documentation (README, CHANGELOG, docs/) when behaviour changes or new features land.

## Building 0xgenctl

`go build ./cmd/0xgenctl` (or `go build ./...`) always produces the full CLI,
including the `verify-build` subcommand. `0xgenctl` does not import
`github.com/slsa-framework/slsa-verifier` (which transitively pulls in
cosign, sigstore, rekor, fulcio, docker, kubernetes, trillian, and the
MongoDB driver) — instead, `verify-build` shells out to the standalone
`slsa-verifier` CLI binary at runtime. This keeps 0xgenctl's own dependency
graph small and buildable without network access to `go.mongodb.org`,
`k8s.io`, or `sigs.k8s.io`, which matters for coding agents, air-gapped
builds, and restricted corporate proxies.

If `slsa-verifier` isn't on `PATH`, `0xgenctl verify-build` prints an error
explaining how to install it
(https://github.com/slsa-framework/slsa-verifier#installation) and exits
with status 2. CI installs it via the project's official installer action
before running provenance verification (see `.github/workflows/slsa.yml`).

## Pull request checklist

- [ ] Tests cover new behaviour and existing suites pass.
- [ ] CI and linting results are green.
- [ ] All generated artefacts, secrets, or large binaries are excluded from the diff.
- [ ] Added configuration knobs are documented.

We triage issues via the project board documented in `docs/en/projectboard.md`. Feel free to propose improvements or new automations—just include the motivation and a high-level design sketch.
