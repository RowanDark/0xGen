# Findings Schema

Glyph persists plugin findings as JSON Lines files under `/out`. Each entry in
`findings.jsonl` must comply with the schema below so downstream tooling can
parse findings deterministically. The canonical JSON Schema lives at
`plugins/findings.schema.json` and the `glyphctl findings validate` command can
check an exported log against it.

## JSON Schema

```json
{
  "type": "object",
  "required": ["version", "id", "plugin", "type", "message", "severity", "ts"],
  "properties": {
    "version": {
      "type": "string",
      "const": "0.2",
      "description": "Schema version marker"
    },
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
    "ts": {
      "type": "string",
      "format": "date-time",
      "description": "Timestamp in RFC3339 format"
    },
    "meta": {
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
  "version": "0.2",
  "id": "01HZXK4QAZ3ZKAB1Y7P5Z9Q4C4",
  "plugin": "demo",
  "type": "glyph.demo.start",
  "message": "Sample finding emitted during startup",
  "target": "demo://self-test",
  "severity": "low",
  "ts": "2024-05-01T12:34:56Z",
  "meta": {
    "source": "emit-on-start"
  }
}
```

The `id` field must always be a valid ULID string and the `ts`
timestamp must be encoded with `time.RFC3339`. Empty optional strings are
omitted to keep the log compact, and `meta` is only present when the plugin
emits additional key/value pairs.
