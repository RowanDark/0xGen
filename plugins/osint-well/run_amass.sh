#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<USAGE >&2
Usage: $0 [-o <assets.jsonl>] [-b <amass-binary>] -d <domain> [-- <extra passive amass args>]

Runs "amass enum --passive" for the requested domain and normalizes the
results to Glyph's assets.jsonl format.

Options:
  -d <domain>          Domain to enumerate (required)
  -o <path>            Output path for normalized JSONL (defaults to
                       "${GLYPH_OUT:-/out}/assets.jsonl")
  -b <binary>          Path to the amass binary (defaults to the first amass
                       on $PATH)
  -- <args>            Additional arguments forwarded to amass. Keep these
                       passive-only to avoid active probing.
USAGE
}

DOMAIN=""
OUTPUT_PATH="${GLYPH_OUT:-/out}/assets.jsonl"
AMASS_BIN="${AMASS_BIN:-amass}"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      if [[ $# -lt 2 ]]; then
        echo "error: -d|--domain requires a value" >&2
        usage
        exit 1
      fi
      DOMAIN="$2"
      shift 2
      ;;
    -o|--out)
      if [[ $# -lt 2 ]]; then
        echo "error: -o|--out requires a value" >&2
        usage
        exit 1
      fi
      OUTPUT_PATH="$2"
      shift 2
      ;;
    -b|--binary)
      if [[ $# -lt 2 ]]; then
        echo "error: -b|--binary requires a value" >&2
        usage
        exit 1
      fi
      AMASS_BIN="$2"
      shift 2
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$DOMAIN" ]]; then
        DOMAIN="$1"
      else
        EXTRA_ARGS+=("$1")
      fi
      shift
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "error: domain is required" >&2
  usage
  exit 1
fi

if ! command -v "$AMASS_BIN" >/dev/null 2>&1; then
  echo "error: amass binary '$AMASS_BIN' not found" >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "error: node is required to run the normalizer" >&2
  exit 1
fi

NORMALIZER="$(dirname "$0")/normalize.js"
if [[ ! -x "$NORMALIZER" && ! -f "$NORMALIZER" ]]; then
  echo "error: normalizer script not found at $NORMALIZER" >&2
  exit 1
fi

TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

AMASS_JSON="$TMPDIR/amass.json"

# Always enforce passive enumeration.
"$AMASS_BIN" enum --passive -d "$DOMAIN" -json "$AMASS_JSON" "${EXTRA_ARGS[@]}"

mkdir -p "$(dirname "$OUTPUT_PATH")"
node "$NORMALIZER" "$AMASS_JSON" "$OUTPUT_PATH"

echo "Normalized assets written to $OUTPUT_PATH"
