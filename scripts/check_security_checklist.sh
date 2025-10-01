#!/usr/bin/env bash
set -euo pipefail

EVENT_NAME="${GITHUB_EVENT_NAME:-}"
if [[ "$EVENT_NAME" != "pull_request" ]]; then
  echo "Security checklist check skipped: event '$EVENT_NAME' is not pull_request."
  exit 0
fi

BASE_REF="${GITHUB_BASE_REF:-main}"
if ! git rev-parse --verify "origin/$BASE_REF" >/dev/null 2>&1; then
  git fetch --quiet origin "$BASE_REF"
fi
BASE_SHA=$(git merge-base HEAD "origin/$BASE_REF")
CHANGED_FILES=$(git diff --name-only "$BASE_SHA"...HEAD)

if ! grep -Eq '^plugins/[^/]+/manifest.json$' <<<"$CHANGED_FILES"; then
  echo "No plugin manifest changes detected; security checklist not required."
  exit 0
fi

EVENT_PATH="${GITHUB_EVENT_PATH:-}"
if [[ -z "$EVENT_PATH" || ! -f "$EVENT_PATH" ]]; then
  echo "Unable to locate GitHub event payload for checklist verification." >&2
  exit 1
fi

BODY=$(jq -r '.pull_request.body // ""' "$EVENT_PATH")
if [[ -z "$BODY" ]]; then
  echo "Pull request body is empty; please fill out the security checklist." >&2
  exit 1
fi

checks=(
  "- [x] I reviewed the [security policy](../SECURITY.md) and [threat model](../THREAT_MODEL.md) for impacts."
  "- [x] (Plugins only) I followed the [plugin security guide](../PLUGIN_GUIDE.md) and documented any deviations."
)

failed=0
for check in "${checks[@]}"; do
  pattern=${check/- [x]/- \[x\]}
  if ! grep -Fiq "$pattern" <<<"$BODY"; then
    echo "Security checklist item missing or unchecked: ${check/- [x] /}" >&2
    failed=1
  fi
done

if (( failed )); then
  echo "Update the PR description to acknowledge the required security docs." >&2
  exit 1
fi

echo "Security checklist satisfied for plugin manifest changes."
