# Galdr Proxy

Galdr Proxy will act as the traffic gateway for Glyph, allowing other plugins to inspect and modify HTTP flows sourced from managed proxy nodes.

## Capabilities
- `CAP_HTTP_PASSIVE`
- `CAP_HTTP_ACTIVE`
- `CAP_EMIT_FINDINGS`

## Getting started
This skeleton wires up the standard plugin entrypoints and is ready for proxy experimentation. Populate `plugin.js` with proxy bootstrapping logic and extend the tests in `tests/sample_fixture.json` as behaviors are implemented.
