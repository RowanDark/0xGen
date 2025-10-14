---
title: Plugin Compatibility Matrix
description: Understand which plugin versions work with each Glyph core release.
---

# Plugin compatibility matrix

The table below maps every supported plugin release to the Glyph core versions it
supports. Compatibility testing runs as part of the release pipeline—plugins are
only published after their integration suite has passed against the targeted
core versions.

| Plugin | Latest version | Glyph v1.0 | Glyph v1.1 | Glyph v2.0 |
| ------ | -------------- | ---------- | ---------- | ---------- |
| Cartographer | `0.1.0` | ✅ 1.0.0+ | ✅ 1.1.0+ | ✅ 2.0.0+ |
| Cryptographer | `0.1.0` | ✅ 1.0.2+ | ✅ 1.1.0+ | ✅ 2.0.0+ |
| Excavator | `0.1.0` | ⚠️ Requires passive mode patch | ✅ 1.1.0+ | ✅ 2.0.0+ |
| Galdr Proxy | `0.1.0` | ❌ | ⚠️ HTTP-only support | ✅ 2.0.0+ |
| Grapher | `0.1.0` | ✅ 1.0.0+ | ✅ 1.1.0+ | ✅ 2.0.0+ |
| OSINT Well | `0.1.0` | ✅ 1.0.0+ | ✅ 1.1.0+ | ✅ 2.0.0+ |
| Raider | `0.1.0` | ❌ | ⚠️ Requires v1.1.5 hotfix | ✅ 2.0.0+ |
| Ranker | `0.1.0` | ✅ 1.0.0+ | ✅ 1.1.0+ | ✅ 2.0.0+ |
| Scribe | `0.1.0` | ✅ 1.0.3+ | ✅ 1.1.0+ | ✅ 2.0.0+ |
| Seer | `0.1.0` | ⚠️ Passive-only mode | ✅ 1.1.0+ | ✅ 2.0.0+ |

## Legend

- ✅ — Fully compatible with the specified Glyph release.
- ⚠️ — Supported with caveats documented in the plugin README.
- ❌ — Not compatible with that Glyph release.

## Version constraints

- **Glyph v1.0** introduced the initial plugin runtime. Plugins that rely on
  bidirectional communications (like Galdr Proxy and Raider) require the 1.1
  transport improvements.
- **Glyph v1.1** adds streaming responses and is the minimum version for
  real-time exploitation tooling.
- **Glyph v2.0** is the current stable release. All plugins target this version
  by default and are regression tested against it on every commit.

For deeper integration details, consult the release notes in
[`CHANGELOG.md`]({{ config.repo_url }}/blob/main/CHANGELOG.md) or reach out in
the [Glyph community forums](https://github.com/RowanDark/0xgen/discussions).
