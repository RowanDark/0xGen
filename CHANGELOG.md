# Changelog

## Unreleased

- Removed all `GLYPH_*` environment-variable fallbacks across binaries, plugins, and tooling; only `0XGEN_*` configuration is now recognised.
- Replaced glyph-prefixed observability metrics and desktop shell aliases with `oxg_*` series.
- Dropped acceptance and emission of proxy headers branded for the legacy name in favour of the canonical `X-0xgen-*` family, updating E2E coverage accordingly.
- Rotated the plugin signing key and refreshed detached signatures for all bundled plugins to reflect the rebrand.

## v0.1.0-alpha

- Hardened the Excavator crawler with depth/host limits, URL normalisation, and golden coverage, plus a demo Make target.
- Delivered the Scribe reporting CLI and JSONL reader enhancements for stable Markdown summaries.
- Shipped Galdr proxy docs, example rules, and CLI flag updates to simplify CA trust configuration.
- Introduced the Seer detector library for high-signal secrets with redacted evidence and unit tests.
- Added the OSINT Well Amass wrapper (`0xgenctl osint-well`) to normalise assets into `/out/assets.jsonl`.
- Documented release processes and contribution guidelines.
- Automated the v0.1.0-alpha release packaging with embedded version metadata, cross-compiled binaries, and GitHub publishing.
