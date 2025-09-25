# Glyph

Glyph is an automation toolkit for orchestrating red-team and detection workflows.
It coordinates plugins such as Galdr (HTTP rewriting proxy), Excavator (Playwright
crawler), Seer (secret/PII detector), Ranker, and Scribe to turn raw telemetry into
ranked findings and human-readable reports.

## Quickstart

Clone the repository and run the end-to-end demo target:

```bash
make demo
```

The pipeline builds fresh binaries, starts Galdr and Seer locally, captures a crawl
with Excavator, ranks any emitted findings, and renders an HTML summary. The terminal
prints the absolute path to `report.html` once the run completes. See
[`docs/quickstart.md`](docs/quickstart.md) for a full walkthrough and troubleshooting
notes.

## Documentation

* [Configuration reference](docs/configuration.md)
* [Plugin catalogue](docs/plugins.md)
* [Threat model](docs/security/threat-model.md)
* [Contributing guide](CONTRIBUTING.md)

## Security

Please review our [security policy](SECURITY.md) for instructions on reporting
vulnerabilities and understanding the supported scope.
