#!/usr/bin/env bash

set -euo pipefail

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
if [[ -z "$version" ]]; then
  echo "could not derive version from tag '$tag'" >&2
  exit 1
fi

if [[ ! -f "$payload_dir/glyphctl.exe" ]]; then
  echo "glyphctl.exe not found in payload directory '$payload_dir'" >&2
  exit 1
fi

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

mkdir -p "$output_dir"

cp "$payload_dir/glyphctl.exe" "$stage/glyphctl.exe"
cp README.md "$stage/README.txt"
cp LICENSE "$stage/LICENSE.txt"

wixl \
  -DVersion="$version" \
  -DWixPlatform="$wix_platform" \
  -DPayloadDir="$stage" \
  -o "$output_dir/glyphctl_${tag}_windows_${arch}.msi" \
  packaging/windows/glyphctl.wxs

echo "Built MSI: $output_dir/glyphctl_${tag}_windows_${arch}.msi"
