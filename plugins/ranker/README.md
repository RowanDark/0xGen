# Ranker

> **Status: scaffold, not implemented.** `plugin.js` is a stub with `// TODO` hook bodies, and 0xgen's plugin launcher currently only builds and runs Go plugins (`internal/plugins/launcher/launcher.go` always calls `go build`, with no JavaScript dispatch path). This plugin cannot be launched today.

Ranker scores assets, findings, and leads so teams focus on the highest-impact work first.

## Capabilities
- `CAP_STORAGE`
- `CAP_EMIT_FINDINGS`

## Getting started
Wire prioritization logic into `plugin.js` and persist intermediate scoring data as needed. Capture realistic ranking inputs in `tests/sample_fixture.json` to support repeatable evaluations.
