#!/usr/bin/env bash
set -euo pipefail

SCHEMA="plugins/manifest.schema.json"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$ROOT/$SCHEMA" ]]; then
  echo "Schema not found at $SCHEMA"
  exit 2
fi

shopt -s nullglob
MANIFESTS=("$ROOT"/plugins/*/manifest.json)

if (( ${#MANIFESTS[@]} == 0 )); then
  echo "No plugin manifests found under plugins/*/manifest.json"
  exit 2
fi

relpath() {
  python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' "$1" "$2"
}

ajv_available=0
if command -v npx >/dev/null 2>&1; then
  if npx -y ajv-cli@5.0.0 --version >/dev/null 2>&1; then
    ajv_available=1
  fi
fi

rc=0
for mf in "${MANIFESTS[@]}"; do
  rel=$(relpath "$mf" "$ROOT")
  echo "• validating $rel"
  if ! jq -e . "$mf" >/dev/null; then
    echo "  ✗ invalid JSON"
    rc=2
    continue
  fi
  if (( ajv_available )); then
    if ! npx -y ajv-cli@5.0.0 validate -s "$ROOT/$SCHEMA" -d "$mf"; then
      echo "  ✗ schema validation failed"
      rc=2
      continue
    fi
  else
    if ! jq -e 'has("name") and has("version") and has("entry") and (.capabilities|type=="array")' "$mf" >/dev/null; then
      echo "  ✗ missing required fields (name, version, entry, capabilities[])"
      rc=2
      continue
    fi
  fi
  echo "  ✓ ok"
done

exit "$rc"
