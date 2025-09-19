#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <target-domain> [additional amass args...]" >&2
  exit 1
fi

TARGET_DOMAIN="$1"
shift

if ! command -v glyphctl >/dev/null 2>&1; then
  echo "glyphctl binary not found in PATH" >&2
  exit 1
fi

mkdir -p out
glyphctl osint-well --domain "$TARGET_DOMAIN" --out ./out/assets.jsonl --args "$*"
echo "Normalized assets written to ./out/assets.jsonl"
