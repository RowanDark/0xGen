---
title: Plugin Compatibility Matrix
description: Understand which plugin versions work with each Glyph core release.
---

# Plugin compatibility matrix

The matrix below reflects every plugin listed in the registry feed. Filter by
Glyph core version or compatibility status to plan safe upgrades—filters apply
instantly, and search works across plugin names, authors, and categories.

<div class="plugin-compatibility__toolbar">
  <label class="plugin-compatibility__filter">
    <span>Search</span>
    <input type="search" id="compatibility-search" placeholder="Search by plugin or capability" />
  </label>
  <label class="plugin-compatibility__filter">
    <span>Glyph version</span>
    <select id="compatibility-glyph">
      <option value="">All versions</option>
    </select>
  </label>
  <label class="plugin-compatibility__filter">
    <span>Status</span>
    <select id="compatibility-status">
      <option value="">All statuses</option>
      <option value="compatible">Compatible</option>
      <option value="limited">Limited</option>
      <option value="unsupported">Unsupported</option>
    </select>
  </label>
</div>

<div id="plugin-compatibility" class="plugin-compatibility__table-wrapper" data-mdx-component="plugin-compatibility"></div>

!!! note "Compatibility legend"
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
the [Glyph community forums](https://github.com/RowanDark/Glyph/discussions).
