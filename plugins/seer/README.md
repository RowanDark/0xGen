# Seer

Seer inspects passive telemetry to spot anomalies and suspicious behaviors before they escalate into incidents.

## Capabilities
- `CAP_HTTP_PASSIVE`
- `CAP_EMIT_FINDINGS`

## Getting started
Add detection logic to `plugin.js` to evaluate HTTP responses and emit findings when heuristics fire. Document expected detections in `tests/sample_fixture.json` as patterns are formalized.
