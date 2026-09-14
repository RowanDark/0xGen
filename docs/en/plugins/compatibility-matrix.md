---
title: Plugin Compatibility Matrix
description: Understand which plugin versions work with each 0xgen core release.
---

# Plugin compatibility matrix

The matrix below reflects every plugin listed in the registry feed. Filter by
0xgen core version or compatibility status to plan safe upgrades—filters apply
instantly, and search works across plugin names, authors, and categories.

!!! warning "Eight plugins in this matrix are not yet implemented"
    Cartographer, Cryptographer, Excavator, Galdr Proxy, OSINT Well, Raider,
    Ranker, and Scribe all declare a `plugin.js` entry point that is an empty
    scaffold, and 0xgen's plugin launcher does not yet dispatch JavaScript
    plugins at all — none of them can be launched regardless of what this
    matrix reports for a given 0xgen version. See the
    [Plugin Roster](index.md#plugin-roster) for which plugins actually run
    today.

<div class="plugin-compatibility__toolbar">
  <label class="plugin-compatibility__filter">
    <span>Search</span>
    <input type="search" id="compatibility-search" placeholder="Search by plugin or capability" />
  </label>
  <label class="plugin-compatibility__filter">
    <span>0xgen version</span>
    <select id="compatibility-oxg">
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
    - ✅ — Fully compatible with the specified 0xgen release.
    - ⚠️ — Supported with caveats documented in the plugin README.
    - ❌ — Not compatible with that 0xgen release.

## Version constraints

- **0xgen v1.0** introduced the initial plugin runtime. Plugins that rely on
  bidirectional communications (like Galdr Proxy and Raider, once implemented)
  would require the 1.1 transport improvements.
- **0xgen v1.1** adds streaming responses and is the minimum version for
  real-time exploitation tooling.
- **0xgen v2.0** is the current stable release. All plugins target this version
  by default and are regression tested against it on every commit.

For deeper integration details, consult the release notes in
[`CHANGELOG.md`]({{ config.repo_url }}/blob/main/CHANGELOG.md) or reach out in
the [0xgen community forums](https://github.com/RowanDark/0xgen/discussions).
