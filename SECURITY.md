# Security Policy

We take the security of Glyph deployments seriously. Responsible disclosure helps the
community remediate issues quickly and protect operators who rely on the toolkit.

## Reporting a Vulnerability

* **Do not file public GitHub issues for security problems.**
* Submit a private report through the [GitHub Security Advisories portal](https://github.com/RowanDark/Glyph/security/advisories/new).
* If you cannot use the portal, email the maintainers at [security@rowandark.dev](mailto:security@rowandark.dev).

Please include the following details to help us triage your report:

* A description of the vulnerability and the affected Glyph components.
* Steps to reproduce the issue, including configuration snippets or sample inputs.
* Any suggested mitigations.

We aim to acknowledge new reports within **two business days**. Once validated we will
coordinate a fix, publish release notes, and credit reporters who opt in to disclosure.

## Scope

The policy covers the Glyph core (`glyphd`, `glyphctl`), bundled plugins, SDKs, and
example tooling. Third-party plugins or forks maintained outside this repository are
out of scope.

## Coordinated Disclosure

We ask reporters to keep issues private for at least **30 days** after confirmation to
give maintainers time to ship patches. We will provide status updates throughout the
process and share a final advisory once mitigations are available.
