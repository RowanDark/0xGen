#!/usr/bin/env bash
set -euo pipefail

EVENT_NAME=${EVENT_NAME:-}
BASE_SHA=${BASE_SHA:-}
BEFORE_SHA=${BEFORE_SHA:-}

legacy_brand_prefix="Gl"
legacy_brand_suffix="yph"
legacy_brand="${legacy_brand_prefix}${legacy_brand_suffix}"
legacy_pattern="\\b${legacy_brand}\\b"

if [[ "$EVENT_NAME" == "pull_request" && -n "$BASE_SHA" ]]; then
  git fetch --no-tags --depth=1 origin "$BASE_SHA"
  diff_base="$BASE_SHA"
elif [[ -n "$BEFORE_SHA" && "$BEFORE_SHA" != "0000000000000000000000000000000000000000" ]]; then
  diff_base="$BEFORE_SHA"
else
  diff_base="$(git rev-parse HEAD^ 2>/dev/null || echo HEAD^)"
fi

mapfile -t changed_files < <(git diff --name-only "$diff_base" HEAD)
if (( ${#changed_files[@]} == 0 )); then
  echo "No files changed; skipping 0xgen guard."
  exit 0
fi

allowlist_file=".github/allowlists/glyph-allowlist.txt"
allow_patterns=()
if [[ -f "$allowlist_file" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    allow_patterns+=("$line")
  done < "$allowlist_file"
fi

shopt -s globstar nullglob
violations=0
for file in "${changed_files[@]}"; do
  [[ ! -f "$file" ]] && continue

  allowed=false
  for pattern in "${allow_patterns[@]}"; do
    if [[ "$file" == $pattern ]]; then
      allowed=true
      break
    fi
  done

  if [[ "$allowed" == true ]]; then
    continue
  fi

  if matches=$(rg -n --ignore-case "$legacy_pattern" --color=never "$file"); then
    if (( violations == 0 )); then
      echo "Forbidden legacy branding references detected:"
    fi
    violations=1
    echo "$matches"
  fi
done
shopt -u globstar nullglob

if (( violations )); then
  echo
  echo "Found forbidden legacy branding references. Update the naming or extend the allowlist intentionally."
  exit 1
fi

echo "0xgen guard passed."
