#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
        VERSION="$(git describe --tags --always)"
fi

if [[ -z "$VERSION" ]]; then
        echo "Unable to determine version for release" >&2
        exit 1
fi

DIST_DIR="$ROOT_DIR/dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

LDFLAGS="-s -w -X main.version=${VERSION}"

declare -a targets=(
        "linux amd64"
        "linux arm64"
        "darwin amd64"
        "darwin arm64"
)

for target in "${targets[@]}"; do
        read -r GOOS GOARCH <<<"$target"
        ARCHIVE_BASENAME="glyphctl_${VERSION}_${GOOS}_${GOARCH}"
        BUILD_DIR="$DIST_DIR/$ARCHIVE_BASENAME"
        mkdir -p "$BUILD_DIR"

        echo "Building glyphctl for $GOOS/$GOARCH"
        GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
                go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/glyphctl" ./cmd/glyphctl

        cp "$ROOT_DIR/LICENSE" "$BUILD_DIR/"
        cp "$ROOT_DIR/scripts/0xgenctl" "$BUILD_DIR/"
        chmod +x "$BUILD_DIR/0xgenctl"

        (cd "$DIST_DIR" && tar -czf "$ARCHIVE_BASENAME.tar.gz" "$ARCHIVE_BASENAME")
        rm -rf "$BUILD_DIR"

done

(
        cd "$DIST_DIR"
        sha256sum *.tar.gz > "glyphctl_${VERSION}_SHA256SUMS.txt"
)

printf '\nArtifacts written to %s\n' "$DIST_DIR"
