# Findings Schema

Glyph persists plugin findings as JSON Lines files under `/out`. Each entry in
`findings.jsonl` must comply with the schema below so downstream tooling can
parse findings deterministically.

## JSON Schema

```json
{
  "type": "object",
  "required": ["id", "plugin", "type", "message", "severity", "detected_at"],
  "properties": {
    "id": {
      "type": "string",
      "description": "Globally unique ULID identifying this finding"
    },
    "plugin": { "type": "string" },
    "type": { "type": "string" },
    "message": { "type": "string" },
    "target": { "type": "string" },
    "evidence": { "type": "string" },
    "severity": {
      "type": "string",
      "enum": ["info", "low", "med", "high", "crit"]
    },
    "detected_at": {
      "type": "string",
      "format": "date-time",
      "description": "Timestamp in RFC3339 format"
    },
    "metadata": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    }
  },
  "additionalProperties": false
}
```

## Example

```json
{
  "id": "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4",
  "plugin": "demo",
  "type": "glyph.demo.start",
  "message": "Sample finding emitted during startup",
  "target": "demo://self-test",
  "severity": "low",
  "detected_at": "2024-05-01T12:34:56Z",
  "metadata": {
    "source": "emit-on-start"
  }
}
```

The `id` field must always be a valid ULID string and the `detected_at`
timestamp must be encoded with `time.RFC3339`. Empty optional strings are
omitted to keep the log compact, and `metadata` is only present when the plugin
emits additional key/value pairs.
