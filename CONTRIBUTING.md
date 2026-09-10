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

`0xgenctl` has two build modes, controlled by the `slsa` build tag:

- **Default build** (`go build ./cmd/0xgenctl`, or `go build ./...`): excludes
  the `verify-build` subcommand's implementation. This keeps the CLI's
  dependency graph small (~59 packages) and buildable without network access
  to `go.mongodb.org`, `k8s.io`, or `sigs.k8s.io` — important for coding
  agents, air-gapped builds, and restricted corporate proxies. Running
  `0xgenctl verify-build` in a default build prints an error explaining how
  to rebuild with the `slsa` tag and exits with status 2.
- **Full build** (`go build -tags slsa ./cmd/0xgenctl`): includes the real
  `verify-build` implementation, which verifies SLSA provenance via
  `github.com/slsa-framework/slsa-verifier`. That dependency transitively
  pulls in cosign, sigstore, rekor, fulcio, docker, kubernetes, trillian, and
  the AWS/Azure/MongoDB SDKs (~148 packages), so only use this tag when you
  need `verify-build` locally. Official release builds (goreleaser and
  `scripts/build_release.sh`) always use `-tags slsa`.

## Pull request checklist

- [ ] Tests cover new behaviour and existing suites pass.
- [ ] CI and linting results are green.
- [ ] All generated artefacts, secrets, or large binaries are excluded from the diff.
- [ ] Added configuration knobs are documented.

We triage issues via the project board documented in `docs/en/projectboard.md`. Feel free to propose improvements or new automations—just include the motivation and a high-level design sketch.
