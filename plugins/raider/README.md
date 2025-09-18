# Raider

Raider coordinates focused offensive testing campaigns once high-value targets are identified by discovery plugins.

## Capabilities
- `CAP_HTTP_ACTIVE`
- `CAP_HTTP_PASSIVE`
- `CAP_EMIT_FINDINGS`

## Getting started
Implement the orchestration logic within `plugin.js` to manage attack playbooks and feed discoveries back to Glyph. Extend `tests/sample_fixture.json` with mock campaign results to support future automated checks.
