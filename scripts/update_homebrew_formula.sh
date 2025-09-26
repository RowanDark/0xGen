#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <tag> <tap_dir>" >&2
        exit 1
fi

TAG="$1"
TAP_DIR="$2"
VERSION="${TAG#v}"

if [[ -z "$VERSION" ]]; then
        echo "Unable to determine version from tag: $TAG" >&2
        exit 1
fi

RELEASE_OWNER="RowanDark"
RELEASE_REPO="Glyph"

BASE_URL="https://github.com/${RELEASE_OWNER}/${RELEASE_REPO}/releases/download/${TAG}"
ARM_ARCHIVE="glyphctl_${VERSION}_darwin_arm64.tar.gz"
INTEL_ARCHIVE="glyphctl_${VERSION}_darwin_amd64.tar.gz"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -sSLf "${BASE_URL}/${ARM_ARCHIVE}" -o "${TMP_DIR}/${ARM_ARCHIVE}"
ARM_SHA="$(sha256sum "${TMP_DIR}/${ARM_ARCHIVE}" | awk '{print $1}')"

curl -sSLf "${BASE_URL}/${INTEL_ARCHIVE}" -o "${TMP_DIR}/${INTEL_ARCHIVE}"
INTEL_SHA="$(sha256sum "${TMP_DIR}/${INTEL_ARCHIVE}" | awk '{print $1}')"

FORMULA_DIR="${TAP_DIR}/Formula"
mkdir -p "$FORMULA_DIR"
FORMULA_PATH="${FORMULA_DIR}/glyph.rb"

cat >"$FORMULA_PATH" <<FORMULA
class Glyph < Formula
  desc "Automation toolkit for orchestrating red-team and detection workflows"
  homepage "https://github.com/${RELEASE_OWNER}/${RELEASE_REPO}"
  version "${VERSION}"

  on_macos do
    on_arm do
      url "${BASE_URL}/${ARM_ARCHIVE}"
      sha256 "${ARM_SHA}"
    end

    on_intel do
      url "${BASE_URL}/${INTEL_ARCHIVE}"
      sha256 "${INTEL_SHA}"
    end
  end

  def install
    arch = Hardware::CPU.arm? ? "arm64" : "amd64"
    target = "glyphctl_#{version}_darwin_#{arch}"
    bin.install "#{target}/glyphctl"
    prefix.install "#{target}/LICENSE"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/glyphctl version")
  end
end
FORMULA

# Normalize Ruby formatting
if command -v brew >/dev/null 2>&1; then
        brew style --fix "$FORMULA_PATH" || true
fi
