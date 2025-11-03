# Supply-Chain Hardening

0xgen's CI pipelines enforce dependency hygiene, generate a software bill of
materials (SBOM), and sign every published artifact. This page documents the
controls and the steps operators can take to validate them independently.

## Dependency policy {#dependency-policy}

- The `Dependency Review` GitHub Action blocks pull requests that introduce new
  transitive risks with a severity of **high** or **critical**.
- JavaScript-based plugins must commit a `package-lock.json` file. The
  `JS Supply Chain` workflow runs `npm ci --omit=dev` and `npm audit` on every
  push and pull request to detect vulnerable packages.
- Go modules are pinned via `go.mod`/`go.sum` and are checked in the primary CI
  workflow (`ci.yml`).

If you maintain a plugin, run `npm audit --omit=dev --audit-level=high` locally
before submitting patches. CI fails if the audit reports a high or critical
vulnerability.

## SBOM generation {#sbom-generation}

Syft generates SPDX SBOMs for both the repository and the plugin tree on every
push and pull request. The artifacts are uploaded as `oxg-sboms` and contain:

- `oxg-repo.spdx.json` – the top-level Go module and ancillary tooling.
- `oxg-plugins.spdx.json` – dependencies bundled with the official plugins.

Download the SBOMs from the workflow run summary to integrate with your own
inventory or vulnerability scanners. Tagged releases also publish
`0xgen-${VERSION}-sbom.spdx.json` alongside the binaries so desktop users can
open the About dialog and jump straight to the release SBOM.

## Release signing & provenance {#release-signing-and-provenance}

Tagged releases trigger the `Release` workflow, which now performs the
following:

1. Build platform archives with GoReleaser.
2. Sign each archive and checksum file using [Sigstore Cosign] in keyless mode
   and publish the signatures as attached assets.
3. Generate a single SPDX SBOM (`0xgen-${VERSION}-sbom.spdx.json`) that matches
   the released binaries.
4. Emit an in-toto provenance statement via the reusable SLSA Level 3
   generator covering every uploaded artifact.

The complementary `slsa.yml` workflow runs on each release publication and
executes the `0xgenctl verify-build` command against the release bundles to
prove the provenance is valid.

To verify a release locally, download the archive you installed and run:

```bash
0xgenctl verify-build --tag v1.2.3 --artifact ~/Downloads/0xgenctl_v1.2.3_linux_amd64.tar.gz
```

The CLI queries the GitHub release, downloads the attestation, and invokes the
upstream `slsa-verifier` with the correct builder and source metadata. A
successful verification proves the archive was produced by the trusted release
workflow, signed with Sigstore, and covered by a SLSA Level 3 provenance
statement.

## Plugin signature verification {#plugin-signature-verification}

The `0xgenctl plugin run` command now validates detached signatures before a
plugin is compiled or executed. Each official plugin ships with:

- `<artifact>.sig` – a base64-encoded ECDSA signature generated via `cosign
  sign-blob`.
- `plugins/keys/oxg-plugin.pub` – the public key maintained by the 0xgen team.

Plugin manifests reference these files and CI ensures they stay in sync with the
recorded hashes. To verify manually:

```bash
cosign verify-blob \
  --key plugins/keys/oxg-plugin.pub \
  --signature plugins/excavator/plugin.js.sig \
  plugins/excavator/plugin.js
```

You can rotate the signing key by updating the public key, regenerating the
signatures, and adjusting the manifests. 0xgen refuses to run a plugin when the
signature is missing or invalid.

## Trust chain summary {#trust-chain-summary}

1. Dependency diffs and `npm audit` prevent risky packages from entering the
   tree.
2. Syft SBOMs document the exact dependency graph for reproducibility.
3. Cosign signatures and SLSA provenance cover release binaries and plugin
   artifacts.
4. The plugin loader enforces both hash allowlisting and cryptographic
   signatures before execution.

Combining these controls gives users a transparent path to validate the entire
supply chain from source to runtime.

[Sigstore Cosign]: https://docs.sigstore.dev/cosign/overview/
