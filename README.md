# Glyph

[![Docs](https://img.shields.io/badge/docs-material-blue)](https://rowandark.github.io/Glyph/)

Glyph is an automation toolkit for orchestrating red-team and detection workflows.
It coordinates plugins such as Galdr (HTTP rewriting proxy), Excavator (Playwright
crawler), Seer (secret/PII detector), Ranker, and Scribe to turn raw telemetry into
ranked findings and human-readable reports.

## Installation

macOS users can install the prebuilt `glyphctl` binary via Homebrew using the
[RowanDark/homebrew-glyph tap](https://github.com/RowanDark/homebrew-glyph):

```bash
brew install rowandark/glyph/glyph
```

## Quickstart

Clone the repository and run the end-to-end demo target:

```bash
make demo
```

The pipeline builds fresh binaries, starts Galdr and Seer locally, captures a crawl
with Excavator, ranks any emitted findings, and renders an HTML summary. The terminal
prints the absolute path to `report.html` once the run completes. See the
[Quickstart walkthrough](https://rowandark.github.io/Glyph/quickstart/) for a full
tour and troubleshooting notes.

## Documentation

Browse the full documentation site at [rowandark.github.io/Glyph](https://rowandark.github.io/Glyph/).
Highlights include:

* [Quickstart demo](https://rowandark.github.io/Glyph/quickstart/)
* [Plugin author guide](https://rowandark.github.io/Glyph/plugins/)
* [CLI reference](https://rowandark.github.io/Glyph/cli/)
* [Developer guide](https://rowandark.github.io/Glyph/dev-guide/)
* [Security overview](https://rowandark.github.io/Glyph/security/)

## Security

Please review our [security policy](SECURITY.md) for instructions on reporting
vulnerabilities and understanding the supported scope. For a deeper look at the
runtime isolation model and artifact expectations, see the
[threat model overview](https://rowandark.github.io/Glyph/security/threat-model/).
