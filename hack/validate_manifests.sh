#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA_REL="plugins/manifest.schema.json"
SCHEMA="$ROOT/$SCHEMA_REL"

if [[ ! -f "$SCHEMA" ]]; then
  echo "Schema not found at $SCHEMA_REL"
  exit 2
fi

relpath() {
  python3 - <<'PY' "$1" "$2"
import os
import sys
print(os.path.relpath(sys.argv[1], sys.argv[2]))
PY
}

shopt -s nullglob
MANIFESTS=("$ROOT"/plugins/*/manifest.json)
if (( ${#MANIFESTS[@]} == 0 )); then
  echo "No plugin manifests found under plugins/*/manifest.json"
  exit 2
fi

for mf in "${MANIFESTS[@]}"; do
  if LC_ALL=C grep -q $'\xEF\xBB\xBF' "$mf"; then
    echo "✗ BOM detected in $(relpath "$mf" "$ROOT")"
    exit 2
  fi
done

ajv_cmd=()
if command -v ajv >/dev/null 2>&1; then
  ajv_cmd=(ajv)
elif command -v npx >/dev/null 2>&1; then
  if npx --yes --no-install ajv-cli@5.0.0 --version >/dev/null 2>&1; then
    ajv_cmd=(npx --yes --no-install ajv-cli@5.0.0)
  fi
fi

rc=0
for mf in "${MANIFESTS[@]}"; do
  rel="$(relpath "$mf" "$ROOT")"
  echo "• validating $rel"
  if ! jq -e . "$mf" >/dev/null; then
    echo "  ✗ invalid JSON"
    rc=2
    continue
  fi
  if ((${#ajv_cmd[@]})); then
    if ! "${ajv_cmd[@]}" validate -s "$SCHEMA" -d "$mf"; then
      echo "  ✗ schema validation failed"
      rc=2
      continue
    fi
  else
    if ! jq -e 'has("name") and has("version") and has("entry") and (.capabilities|type=="array")' "$mf" >/dev/null; then
      echo "  ✗ missing required fields"
      rc=2
      continue
    fi
  fi
  echo "  ✓ ok"
done

exit "$rc"
