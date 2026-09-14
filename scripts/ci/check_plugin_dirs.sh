#!/usr/bin/env bash
# Every directory under plugins/ must either be a loadable plugin (i.e. contain
# a manifest.json) or be explicitly listed in plugins/EXCLUDED_DIRS as
# infrastructure/fixtures that are intentionally not plugins. This keeps the
# documented plugin count honest and stops half-finished plugin directories
# (manifest-less, unloadable) from silently accumulating.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLUGINS_DIR="$ROOT/plugins"
EXCLUDE_FILE="$PLUGINS_DIR/EXCLUDED_DIRS"

if [[ ! -f "$EXCLUDE_FILE" ]]; then
  echo "missing $EXCLUDE_FILE" >&2
  exit 2
fi

declare -A excluded
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo -n "$line" | xargs)"
  [[ -z "$line" ]] && continue
  excluded["$line"]=1
done < "$EXCLUDE_FILE"

rc=0
for dir in "$PLUGINS_DIR"/*/; do
  name="$(basename "$dir")"

  if [[ -f "$dir/manifest.json" ]]; then
    continue
  fi

  if [[ -n "${excluded[$name]:-}" ]]; then
    echo "• $name: no manifest.json (excluded: not a plugin)"
    continue
  fi

  echo "✗ $name: no manifest.json and not listed in plugins/EXCLUDED_DIRS" >&2
  rc=1
done

if [[ "$rc" -ne 0 ]]; then
  echo
  echo "Every directory under plugins/ must contain a manifest.json or be added to" >&2
  echo "plugins/EXCLUDED_DIRS with a comment explaining why it isn't a plugin." >&2
fi

exit "$rc"
