# Cartographer

> **Status: scaffold, not implemented.** `plugin.js` is a stub with `// TODO` hook bodies, and 0xgen's plugin launcher currently only builds and runs Go plugins (`internal/plugins/launcher/launcher.go` always calls `go build`, with no JavaScript dispatch path). This plugin cannot be launched today.

Cartographer charts application surfaces discovered by crawlers and passive sensors so other plugins can prioritize exploration.

## Capabilities
- `CAP_SPIDER`
- `CAP_EMIT_FINDINGS`

## Getting started
Extend `plugin.js` with crawling orchestration that records discovered assets. Use `tests/sample_fixture.json` to capture representative discovery payloads as they become available.
