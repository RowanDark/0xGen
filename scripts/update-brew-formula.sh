#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ge 1 ]]; then
        TAG="$1"
elif [[ -n "${GITHUB_REF_NAME:-}" ]]; then
        TAG="${GITHUB_REF_NAME}"
else
        echo "Usage: $0 <tag>" >&2
        exit 1
fi

if [[ -z "${TAG}" ]]; then
        echo "Release tag is required" >&2
        exit 1
fi

if [[ ! "${TAG}" =~ ^v[0-9] ]]; then
        echo "Tag '${TAG}' does not look like a release tag (expected to start with 'v'). Skipping tap update." >&2
        exit 0
fi

VERSION="${TAG#v}"
if [[ -z "${VERSION}" ]]; then
        echo "Unable to determine version from tag: ${TAG}" >&2
        exit 1
fi

TAP_REPO="RowanDark/homebrew-glyph"
RELEASE_OWNER="RowanDark"
RELEASE_REPO="0xgen"

if ! command -v gh >/dev/null 2>&1; then
        echo "GitHub CLI (gh) is required" >&2
        exit 1
fi

if [[ -z "${GITHUB_TOKEN:-${GH_TOKEN:-}}" ]]; then
        echo "GITHUB_TOKEN or GH_TOKEN must be set for authentication" >&2
        exit 1
fi

# Ensure gh picks up the provided token.
export GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN}}"
gh auth setup-git >/dev/null

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

BASE_URL="https://github.com/${RELEASE_OWNER}/${RELEASE_REPO}/releases/download/${TAG}"
ARM_ARCHIVE="0xgenctl_${VERSION}_darwin_arm64.tar.gz"
INTEL_ARCHIVE="0xgenctl_${VERSION}_darwin_amd64.tar.gz"

for archive in "${ARM_ARCHIVE}" "${INTEL_ARCHIVE}"; do
        curl -sSLf "${BASE_URL}/${archive}" -o "${TMP_DIR}/${archive}"
done

ARM_SHA="$(sha256sum "${TMP_DIR}/${ARM_ARCHIVE}" | awk '{print $1}')"
INTEL_SHA="$(sha256sum "${TMP_DIR}/${INTEL_ARCHIVE}" | awk '{print $1}')"

TAP_CLONE_DIR="${TMP_DIR}/tap"

if ! gh repo view "${TAP_REPO}" >/dev/null 2>&1; then
        echo "Homebrew tap repository ${TAP_REPO} not found or inaccessible" >&2
        exit 1
fi

gh repo clone "${TAP_REPO}" "${TAP_CLONE_DIR}" >/dev/null 2>&1 || gh repo clone "${TAP_REPO}" "${TAP_CLONE_DIR}"

pushd "${TAP_CLONE_DIR}" >/dev/null

BRANCH="bump-0xgenctl-${TAG}"
DEFAULT_BRANCH="$(git symbolic-ref --short refs/remotes/origin/HEAD | cut -d/ -f2)"

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"

git checkout "${DEFAULT_BRANCH}"
git pull --ff-only origin "${DEFAULT_BRANCH}" >/dev/null
git checkout -B "${BRANCH}" "${DEFAULT_BRANCH}"

mkdir -p Formula Aliases
cat >Formula/oxgenctl.rb <<FORMULA
class Oxgenctl < Formula
  desc "Automation toolkit for orchestrating red-team and detection workflows"
  homepage "https://github.com/${RELEASE_OWNER}/${RELEASE_REPO}"
  version "${VERSION}"
  license "Apache-2.0"

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
    target = "0xgenctl_#{version}_darwin_#{arch}"
    bin.install "#{target}/0xgenctl"
    prefix.install "#{target}/LICENSE"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/0xgenctl --version")
  end
end
FORMULA

cat >Aliases/0xgenctl <<'ALIAS'
../Formula/oxgenctl.rb
ALIAS

cat >Aliases/0xgen <<'ALIAS'
../Formula/oxgenctl.rb
ALIAS

if git diff --quiet; then
        echo "Formula already up to date for ${TAG}."
        popd >/dev/null
        exit 0
fi

git add Formula/oxgenctl.rb Aliases/0xgenctl Aliases/0xgen
git commit -m "Update 0xgenctl to ${TAG}" >/dev/null

git push --set-upstream origin "${BRANCH}" --force-with-lease >/dev/null

if [[ -n "$(gh pr list --repo "${TAP_REPO}" --state open --head "${BRANCH}" --json number --jq '.[].number')" ]]; then
        echo "Pull request for ${TAG} already exists."
else
        gh pr create \
                --repo "${TAP_REPO}" \
                --title "Update 0xgenctl to ${TAG}" \
                --body "Automated update for ${TAG}." \
                --head "${BRANCH}" \
                --base "${DEFAULT_BRANCH}"
fi

popd >/dev/null
