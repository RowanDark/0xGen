# E2E Scenario Suite

Glyph ships an end-to-end scenario harness that exercises the full stack against
realistic, well-known training targets. The goal is to ensure that critical
regressions in detection, proxying, or reporting are caught before a release.

## Covered targets

The current suite reproduces the header profiles of two public, intentionally
insecure web applications that are widely used for capture-the-flag exercises
and security trainings:

- **OWASP Juice Shop** – a Node.js storefront that purposely omits most
  defensive HTTP headers so that learners can explore common misconfigurations.
- **The BodgeIt Store** – a vulnerable Java EE sample that ships with only a
  subset of recommended protections.

The fixtures live in `internal/e2e/testdata/passive_header_scenarios.json` and
mirror the headers observed on the live targets while keeping the responses
small and deterministic for CI.

## How the tests run

1. A dedicated `glyphd` instance is started with the Galdr proxy enabled.
2. The `passive-header-scan` sample plugin is executed via `glyphctl`. The test
   disables the synthetic event generator to ensure that only real proxy flows
   are analysed.
3. Traffic is replayed through the Galdr proxy to the simulated target. This is
   enough for the passive plugin to emit missing-header findings without any
   additional active plugins.
4. The test asserts the findings, verifies that proxy history was recorded, and
   renders a Markdown report for post-run analysis.

All artifacts (findings, history, and report) are written to the temporary
`GLYPH_OUT` directory and surfaced in the test logs.

## Running locally or in CI

Use the Makefile target to execute the suite:

```bash
make e2e-scenarios
```

The command will run `go test ./internal/e2e -run TestPassiveHeaderRealWorldScenarios`
with a three minute timeout window, which is suitable for nightly or gated
execution. Because the fixtures are self-contained, the tests do not require
external network access and can safely run in continuous integration.

Setting `GLYPH_DISABLE_EVENT_GENERATOR=1` for `glyphd` is recommended whenever
replaying captured flows. The helper introduced for these tests ensures that the
synthetic responses are skipped so that the assertions only reflect the chosen
scenario.
