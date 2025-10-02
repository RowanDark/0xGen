# Glyph

[![Docs](https://img.shields.io/badge/docs-material-blue)](https://rowandark.github.io/Glyph/)

Glyph is an automation toolkit for orchestrating red-team and detection workflows.
It coordinates plugins such as Galdr (HTTP rewriting proxy), Excavator (Playwright
crawler), Seer (secret/PII detector), Ranker, and Scribe to turn raw telemetry into
ranked findings and human-readable reports.

## Installation

macOS users can install the prebuilt `glyphctl` binary via Homebrew using the
[RowanDark/homebrew-tap tap](https://github.com/RowanDark/homebrew-tap):

```bash
brew install rowandark/glyph/glyph
```

## Quickstart

Clone the repository and run the zero-touch demo pipeline:

```bash
glyphctl demo
```

The command spins up a local demo target, runs the Seer detector against it, ranks
the generated findings, and emits an interactive HTML report under `out/demo/`.
`make demo` remains available as a thin wrapper if you prefer a Make-based entry
point. See the [Quickstart walkthrough](https://rowandark.github.io/Glyph/quickstart/)
for a full tour and troubleshooting notes.

## Documentation

Browse the full documentation site at [rowandark.github.io/Glyph](https://rowandark.github.io/Glyph/).
Highlights include:

* [Quickstart demo](https://rowandark.github.io/Glyph/quickstart/)
* [Plugin author guide](https://rowandark.github.io/Glyph/plugins/)
* [CLI reference](https://rowandark.github.io/Glyph/cli/)
* [Developer guide](https://rowandark.github.io/Glyph/dev-guide/)
* [Security overview](https://rowandark.github.io/Glyph/security/)
* [Build provenance](https://rowandark.github.io/Glyph/security/provenance/)
* [Supply chain security](https://rowandark.github.io/Glyph/security/supply-chain/)
* [Threat model](THREAT_MODEL.md)
* [Plugin security guide](PLUGIN_GUIDE.md)

## Security

Please review our [security policy](SECURITY.md) for instructions on reporting
vulnerabilities, supported versions, and the disclosure timeline. The
[Glyph threat model](THREAT_MODEL.md) outlines major attack vectors and
assumptions, while the [plugin security guide](PLUGIN_GUIDE.md) captures safe
patterns for new integrations.
