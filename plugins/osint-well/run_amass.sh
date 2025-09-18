#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <target-domain>" >&2
  exit 1
fi

TARGET_DOMAIN="$1"
mkdir -p out
amass enum -d "$TARGET_DOMAIN" -oA "./out/amass_${TARGET_DOMAIN}"
# TODO: normalize Amass outputs into Glyph-friendly findings.
