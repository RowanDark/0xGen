#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -ne 4 ]]; then
  cat >&2 <<'EOF'
Usage: build_windows_installer.sh <tag> <arch> <payload_dir> <output_dir>

Example: build_windows_installer.sh v1.2.3 amd64 dist/windows_amd64 dist
EOF
  exit 1
fi

tag=$1
arch=$2
payload_dir=$3
output_dir=$4

if [[ ! -d "$payload_dir" ]]; then
  echo "payload directory '$payload_dir' does not exist" >&2
  exit 1
fi

case "$arch" in
  amd64)
    wix_platform="x64"
    ;;
  arm64)
    wix_platform="arm64"
    ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

version=${tag#v}
if [[ -z "$version" || "$version" == "$tag" ]]; then
  echo "could not derive version from tag '$tag'" >&2
  exit 1
fi

msi_version=${version%%[-+]*}
if [[ -z "$msi_version" ]]; then
  echo "tag '$tag' does not contain a numeric version component" >&2
  exit 1
fi

if [[ ! "$msi_version" =~ ^[0-9]+(\.[0-9]+){0,3}$ ]]; then
  echo "tag '$tag' yields invalid MSI version '$msi_version'" >&2
  echo "expected a version in 'major.minor.build(.revision)' format" >&2
  exit 1
fi

if [[ ! -f "$payload_dir/0xgenctl.exe" ]]; then
  echo "0xgenctl.exe not found in payload directory '$payload_dir'" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$output_dir"

cp "$payload_dir/0xgenctl.exe" "$stage/0xgenctl.exe"
cp "$ROOT_DIR/README.md" "$stage/README.txt"
cp "$ROOT_DIR/LICENSE" "$stage/LICENSE.txt"

wixl \
  -DVersion="$msi_version" \
  -DWixPlatform="$wix_platform" \
  -DPayloadDir="$stage" \
  -o "$output_dir/0xgenctl_${tag}_windows_${arch}.msi" \
  packaging/windows/0xgenctl.wxs

echo "Built MSI: $output_dir/0xgenctl_${tag}_windows_${arch}.msi"
