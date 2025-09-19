# Seer

Seer inspects passive telemetry to spot anomalies and suspicious behaviors before they escalate into incidents.

## Capabilities
- `CAP_HTTP_PASSIVE`
- `CAP_EMIT_FINDINGS`

## Getting started
Seer's detectors live in `internal/seer`. The initial release focuses on high-signal secrets:

- AWS access keys
- Slack tokens
- High-entropy generic API tokens
- Email addresses for triage

Use the helpers in `internal/seer` to expand coverage and keep evidence redacted. Golden tests exercise the detector library directly.
