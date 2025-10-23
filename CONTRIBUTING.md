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

## Pull request checklist

- [ ] Tests cover new behaviour and existing suites pass.
- [ ] CI and linting results are green.
- [ ] All generated artefacts, secrets, or large binaries are excluded from the diff.
- [ ] Added configuration knobs are documented.

We triage issues via the project board documented in `docs/en/projectboard.md`. Feel free to propose improvements or new automations—just include the motivation and a high-level design sketch.
