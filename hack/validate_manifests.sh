#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="$ROOT/plugins/manifest.schema.json"

shopt -s nullglob
MANIFESTS=("$ROOT"/plugins/*/manifest.json)

if (( ${#MANIFESTS[@]} == 0 )); then
  echo "No plugin manifests found under plugins/*/manifest.json"
  exit 2
fi

# Guard: stray BOMs / weird unicode (can break jq/ajv)
for mf in "${MANIFESTS[@]}"; do
  if LC_ALL=C grep -q $'\xEF\xBB\xBF' "$mf"; then
    rel="$(realpath --relative-to="$ROOT" "$mf")"
    echo "✗ BOM detected in $rel"
    exit 2
  fi
done

rc=0
for mf in "${MANIFESTS[@]}"; do
  rel="$(realpath --relative-to="$ROOT" "$mf")"
  echo "• validating $rel"
  # 1) Well-formed JSON
  if ! jq -e . "$mf" >/dev/null; then
    echo "  ✗ invalid JSON (parse error)"
    rc=2; continue
  fi
  # 2) Schema validation (ajv v8 via ajv-cli)
  if command -v npx >/dev/null 2>&1; then
    if ! npx -y ajv-cli@5.0.0 validate -s "$SCHEMA" -d "$mf" --strict=true; then
      echo "  ✗ schema validation failed"
      rc=2; continue
    fi
  else
    # Minimal fallback if ajv unavailable
    if ! jq -e 'has("name") and has("version") and has("entry") and (.capabilities|type=="array")' "$mf" >/dev/null; then
      echo "  ✗ missing required fields (name, version, entry, capabilities[])"
      rc=2; continue
    fi
  fi
  echo "  ✓ ok"
done
exit "$rc"
