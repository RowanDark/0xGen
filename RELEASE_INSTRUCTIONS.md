# Release Instructions for v2.0.0-alpha

## Status: Documentation Complete, Ready for Release

This document provides step-by-step instructions for the repository owner to publish the v2.0.0-alpha release after merging PR for Issue #8.

---

## What's Been Completed ✅

The following artifacts have been created and are ready in this PR:

1. **ALPHA_RELEASE_NOTES.md** - Comprehensive release notes with:
   - Production-ready features
   - Known limitations (transparently documented)
   - Installation instructions for all platforms
   - Quick start guide
   - Documentation links

2. **RELEASE_CHECKLIST.md** - Complete release process checklist with:
   - Pre-release verification steps
   - Build and publishing commands
   - SLSA provenance verification instructions
   - Post-release tasks
   - Rollback plan

3. **INSTALL.md** - Installation guide covering:
   - Homebrew (macOS/Linux)
   - Scoop (Windows)
   - DEB packages (Debian/Ubuntu)
   - RPM packages (Fedora/RHEL)
   - Binary downloads
   - Docker/OCI images
   - Build from source

4. **CHANGELOG.md** - Updated with v2.0.0-alpha entry documenting:
   - Major features by category
   - Verification reports
   - Known limitations
   - Breaking changes
   - Upgrade notes

5. **v2.0.0-alpha Git Tag** - Created locally (commit: `2c0e95d`)

---

## What Happens Next: Automated Release Process

The 0xGen repository has a fully automated release pipeline configured in `.github/workflows/release.yml`. When you push the `v2.0.0-alpha` tag, GitHub Actions will automatically:

### 1. Build Phase (Automated)
- Run all tests (`go test ./...`)
- Build 12 platform binaries via GoReleaser:
  - Linux: amd64, arm64
  - macOS: amd64, arm64
  - Windows: amd64, arm64
- Create archives (tar.gz, zip)
- Build DEB packages (Debian/Ubuntu)
- Build RPM packages (Fedora/RHEL)
- Build MSI installers (Windows)

### 2. Security Phase (Automated)
- Sign Windows binaries with Authenticode (if `WINDOWS_CODESIGN_PFX` secret is set)
- Generate consolidated SBOM in SPDX format (Syft)
- Generate SLSA Level 3 provenance (slsa-github-generator v2.1.0)
- Calculate SHA256 checksums for all artifacts

### 3. Publish Phase (Automated)
- Create GitHub Release with:
  - All binaries and installers
  - Checksums file (`0xgen_v2.0.0-alpha_checksums.txt`)
  - SBOM (`0xgen-v2.0.0-alpha-sbom.spdx.json`)
  - SLSA provenance (`0xgen-v2.0.0-alpha-provenance.intoto.jsonl`)
- Publish Docker images to `ghcr.io/rowandark/0xgenctl:v2.0.0-alpha` and `:latest`

### 4. Verification Phase (Automated)
- Run smoke tests on DEB packages (Debian)
- Run smoke tests on RPM packages (Rocky Linux)
- Update README.md version badge automatically

### 5. Distribution Phase (Manual - After CI Completes)
- Update Homebrew tap (see instructions below)
- Update Scoop bucket (see instructions below)

---

## Step-by-Step Release Instructions

### Prerequisites

1. Merge PR for Issue #8 into main branch
2. Ensure all CI checks pass on main
3. Pull latest main branch locally:
   ```bash
   git checkout main
   git pull origin main
   ```

### Step 1: Push the v2.0.0-alpha Tag

```bash
# Create the tag (or use existing local tag from PR branch)
git tag -a v2.0.0-alpha -m "Alpha Release: 100% Phase 2 Complete

This alpha release represents full completion of Phase 2 with comprehensive
audit verification (Issues #1-7). Production-ready core infrastructure with
89% feature parity vs Burp Suite Professional at $0 cost.

Major Features:
- HTTP/HTTPS Proxy Engine with full MITM interception
- AI-Powered Vulnerability Detection (Hydra plugin)
- 5-layer plugin security model
- Cross-platform desktop GUI (Tauri + React)
- SLSA Level 3 provenance and SBOM generation
- Comprehensive observability (Prometheus + OpenTelemetry)

See ALPHA_RELEASE_NOTES.md for complete details."

# Push the tag to trigger automated release
git push origin v2.0.0-alpha
```

### Step 2: Monitor Automated CI Pipeline

1. Go to: https://github.com/RowanDark/0xGen/actions
2. Watch the "0xgen Release" workflow execute
3. Workflow includes these jobs:
   - `goreleaser` - Build all binaries and packages
   - `linux-package-smoke` - Test DEB and RPM packages
   - `update-readme-badge` - Update version badge
   - `provenance` - Generate SLSA provenance

**Expected Duration**: 15-20 minutes

### Step 3: Verify GitHub Release

Once CI completes:

1. Go to: https://github.com/RowanDark/0xGen/releases/tag/v2.0.0-alpha
2. Verify all assets are present:
   - [ ] Binaries for all platforms (12 archives)
   - [ ] DEB packages (amd64, arm64)
   - [ ] RPM packages (amd64, arm64)
   - [ ] MSI installers (amd64, arm64)
   - [ ] Checksums file
   - [ ] SBOM (SPDX format)
   - [ ] SLSA provenance

3. Test download and checksum verification:
   ```bash
   # Download checksums
   curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen_v2.0.0-alpha_checksums.txt

   # Download binary for your platform (example: Linux amd64)
   curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgenctl_v2.0.0-alpha_linux_amd64.tar.gz

   # Verify checksum
   sha256sum -c 0xgen_v2.0.0-alpha_checksums.txt --ignore-missing
   ```

4. Verify SLSA provenance:
   ```bash
   # Install slsa-verifier
   go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

   # Download provenance
   curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgen-v2.0.0-alpha-provenance.intoto.jsonl

   # Verify an artifact
   slsa-verifier verify-artifact \
     --provenance-path 0xgen-v2.0.0-alpha-provenance.intoto.jsonl \
     --source-uri github.com/RowanDark/0xGen \
     --source-tag v2.0.0-alpha \
     0xgenctl_v2.0.0-alpha_linux_amd64.tar.gz
   ```

### Step 4: Update Homebrew Tap

**Repository**: https://github.com/RowanDark/homebrew-0xgen

The `.github/workflows/bump-homebrew.yml` workflow may handle this automatically. If manual update is needed:

1. Clone the Homebrew tap:
   ```bash
   git clone https://github.com/RowanDark/homebrew-0xgen.git
   cd homebrew-0xgen
   ```

2. Download the Linux amd64 archive and calculate SHA256:
   ```bash
   curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgenctl_v2.0.0-alpha_linux_amd64.tar.gz
   SHA256=$(sha256sum 0xgenctl_v2.0.0-alpha_linux_amd64.tar.gz | cut -d' ' -f1)
   echo "SHA256: $SHA256"
   ```

3. Update `Formula/0xgen.rb`:
   ```ruby
   class Oxgen < Formula
     desc "0xgen automation toolkit"
     homepage "https://github.com/RowanDark/0xgen"
     url "https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgenctl_v2.0.0-alpha_linux_amd64.tar.gz"
     sha256 "REPLACE_WITH_ACTUAL_SHA256"
     version "2.0.0-alpha"
     license "Apache-2.0"

     def install
       bin.install "0xgenctl"
     end

     test do
       assert_match "0xgenctl version 2.0.0-alpha", shell_output("#{bin}/0xgenctl --version")
     end
   end
   ```

4. Commit and push:
   ```bash
   git add Formula/0xgen.rb
   git commit -m "chore: bump formula to v2.0.0-alpha"
   git push origin main
   ```

5. Test the installation:
   ```bash
   brew update
   brew install rowandark/0xgen/0xgen
   0xgenctl --version
   ```

### Step 5: Update Scoop Bucket

**Repository**: https://github.com/RowanDark/scoop-0xgen

1. Clone the Scoop bucket:
   ```bash
   git clone https://github.com/RowanDark/scoop-0xgen.git
   cd scoop-0xgen
   ```

2. Download the Windows amd64 archive and calculate SHA256:
   ```bash
   curl -LO https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgenctl_v2.0.0-alpha_windows_amd64.zip
   SHA256=$(sha256sum 0xgenctl_v2.0.0-alpha_windows_amd64.zip | cut -d' ' -f1)
   echo "SHA256: $SHA256"
   ```

3. Update `bucket/0xgen.json`:
   ```json
   {
     "version": "2.0.0-alpha",
     "description": "0xgen automation toolkit",
     "homepage": "https://github.com/RowanDark/0xgen",
     "license": "Apache-2.0",
     "architecture": {
       "64bit": {
         "url": "https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgenctl_v2.0.0-alpha_windows_amd64.zip",
         "hash": "REPLACE_WITH_ACTUAL_SHA256"
       },
       "arm64": {
         "url": "https://github.com/RowanDark/0xGen/releases/download/v2.0.0-alpha/0xgenctl_v2.0.0-alpha_windows_arm64.zip",
         "hash": "REPLACE_WITH_ARM64_SHA256"
       }
     },
     "bin": "0xgenctl.exe",
     "checkver": {
       "github": "https://github.com/RowanDark/0xgen"
     },
     "autoupdate": {
       "architecture": {
         "64bit": {
           "url": "https://github.com/RowanDark/0xGen/releases/download/v$version/0xgenctl_v$version_windows_amd64.zip"
         },
         "arm64": {
           "url": "https://github.com/RowanDark/0xGen/releases/download/v$version/0xgenctl_v$version_windows_arm64.zip"
         }
       }
     }
   }
   ```

4. Commit and push:
   ```bash
   git add bucket/0xgen.json
   git commit -m "chore: bump manifest to v2.0.0-alpha"
   git push origin main
   ```

5. Test the installation (on Windows):
   ```powershell
   scoop update
   scoop install 0xgen
   0xgenctl --version
   ```

### Step 6: Verify Docker Images

The release workflow automatically publishes Docker images to GitHub Container Registry:

```bash
# Pull the image
docker pull ghcr.io/rowandark/0xgenctl:v2.0.0-alpha
docker pull ghcr.io/rowandark/0xgenctl:latest

# Verify version
docker run --rm ghcr.io/rowandark/0xgenctl:v2.0.0-alpha --version
```

### Step 7: Post-Release Announcements

After verifying all distribution channels work:

1. **GitHub Discussions**: Create announcement post
   - Link to ALPHA_RELEASE_NOTES.md
   - Highlight Phase 2 completion
   - Link to installation instructions

2. **Social Media** (if applicable):
   - Twitter/X
   - LinkedIn
   - Reddit (r/netsec, r/AskNetsec)
   - Hacker News

3. **Documentation Site**:
   - Verify docs are published at https://rowandark.github.io/0xgen/
   - Version selector should show v2.0.0-alpha

---

## Rollback Plan

If critical issues are discovered after release:

### Option 1: Hotfix Release (v2.0.0-alpha.1)

1. Create hotfix branch from v2.0.0-alpha tag
2. Apply minimal fix
3. Tag as v2.0.0-alpha.1
4. Push tag to trigger automated release
5. Update distribution channels

### Option 2: Unpublish Release

1. Delete GitHub Release (if within 24 hours)
2. Delete tag:
   ```bash
   git push --delete origin v2.0.0-alpha
   git tag -d v2.0.0-alpha
   ```
3. Revert Homebrew tap commit
4. Revert Scoop bucket commit
5. Post incident report in GitHub Discussions

---

## Verification Checklist

After completing all steps, verify:

- [ ] GitHub Release exists and is marked as "Alpha"
- [ ] All 12 binary archives are downloadable
- [ ] Checksums verify correctly
- [ ] SLSA provenance verifies correctly
- [ ] SBOM is valid SPDX JSON
- [ ] Homebrew installation works: `brew install rowandark/0xgen/0xgen`
- [ ] Scoop installation works: `scoop install 0xgen`
- [ ] Docker image works: `docker run ghcr.io/rowandark/0xgenctl:v2.0.0-alpha --version`
- [ ] DEB package installs on Ubuntu 22.04
- [ ] RPM package installs on Fedora 39
- [ ] MSI installer works on Windows 11
- [ ] Documentation site reflects v2.0.0-alpha
- [ ] README.md badge shows v2.0.0-alpha (automated)

---

## Success Metrics

Track these metrics post-release:

- **Downloads**: GitHub Release download counts
- **Stars**: Repository stars trend
- **Issues**: Bug reports and feature requests
- **Docker Pulls**: `ghcr.io/rowandark/0xgenctl` pull count
- **Documentation**: Page views on docs site

---

## Support

For questions or issues during the release process:

1. Check RELEASE_CHECKLIST.md for detailed troubleshooting
2. Review GitHub Actions logs: https://github.com/RowanDark/0xGen/actions
3. Open an issue if automated release fails: https://github.com/RowanDark/0xGen/issues

---

## Timeline Estimate

| Task | Duration | Owner |
|------|----------|-------|
| Merge PR #8 | 5 min | Maintainer |
| Push v2.0.0-alpha tag | 1 min | Maintainer |
| Automated CI build & publish | 15-20 min | GitHub Actions |
| Verify GitHub Release | 10 min | Maintainer |
| Update Homebrew tap | 10 min | Maintainer |
| Update Scoop bucket | 10 min | Maintainer |
| Verify Docker images | 5 min | Maintainer |
| Post-release announcements | 30 min | Maintainer |
| **Total** | **~90 minutes** | |

---

## Files Reference

All release documentation is now in the repository:

- `ALPHA_RELEASE_NOTES.md` - Complete release notes for users
- `RELEASE_CHECKLIST.md` - Detailed checklist for maintainers
- `INSTALL.md` - Installation instructions for all platforms
- `CHANGELOG.md` - Updated with v2.0.0-alpha entry
- `RELEASE_INSTRUCTIONS.md` - This file (handoff document)

---

**Status**: Ready for Release 🚀

Once the PR is merged and the tag is pushed, the automated release pipeline will handle the majority of the work. The total hands-on time required is approximately 90 minutes.
