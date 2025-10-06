# Security Policy

We take the security of Glyph deployments seriously. Responsible disclosure
helps the community remediate issues quickly and protect operators who rely on
the toolkit.

## Supported versions

We provide security fixes for:

* The latest stable release (N) and the previous minor release (N-1).
* The `main` branch, which backs nightly builds.

Older releases will not receive patched binaries once a successor ships. When
upgrading introduces breaking changes, we document mitigations or temporary
flags in the release notes.

## Reporting a vulnerability

* **Do not file public GitHub issues for security problems.**
* Submit a private report through the
  [GitHub Security Advisories portal](https://github.com/RowanDark/Glyph/security/advisories/new).
* If you cannot use the portal, email the maintainers at
  [security@rowandark.dev](mailto:security@rowandark.dev).

Please include the following details to help us triage your report:

* A description of the vulnerability and the affected Glyph components.
* Steps to reproduce the issue, including configuration snippets or sample
  inputs.
* Any suggested mitigations or potential impact.

We aim to acknowledge new reports within **two business days**. Once validated we
will coordinate a fix, publish release notes, and credit reporters who opt in to
disclosure.

## Disclosure timeline

* We target releasing fixes within **30 days** of confirming the vulnerability.
* If a complete fix is not possible in that window, we will share mitigations and
  a revised timeline with the reporter.
* Emergency fixes may ship on accelerated timelines when exploitation is
  observed.

## Deprecation policy

When deprecating APIs, plugin capabilities, or configuration flags, we provide at
least **one minor release** of overlap with clear migration guidance. Security
patches for deprecated features only continue while a supported version still
ships them.

## Scope

The policy covers the Glyph core (`glyphd`, `glyphctl`), bundled plugins, SDKs,
and example tooling. Third-party plugins or forks maintained outside this
repository are out of scope.

## Additional resources

* [Threat model](THREAT_MODEL.md) – plugin isolation, network posture, and
  artifact expectations.
* [Plugin security guide](PLUGIN_GUIDE.md) – recommended patterns for authoring
  safe integrations.
* [Build provenance verification](docs/en/security/provenance.md) – how to validate
  release signatures before installing.
* [Supply-chain hardening](docs/en/security/supply-chain.md) – dependency policy,
  SBOMs, and plugin signature verification.

## Coordinated disclosure

We ask reporters to keep issues private for at least **30 days** after
confirmation to give maintainers time to ship patches. We will provide status
updates throughout the process and share a final advisory once mitigations are
available.
