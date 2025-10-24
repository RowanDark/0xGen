---
title: Plugin Marketplace
description: Discover 0xgen plugins, filter by capability, and explore their compatibility details.
---

# Plugin marketplace

0xgen ships with an extensible plugin runtime and a curated marketplace of
first-party extensions. Use the catalogue below to browse every maintained
plugin, inspect its capabilities, verify the detached signature, and jump
straight into the author guides.

<div class="plugin-catalog__toolbar">
  <label class="plugin-catalog__filter">
    <span>Search</span>
    <input type="search" id="plugin-search" placeholder="Search by name, summary, or capability" />
  </label>
  <label class="plugin-catalog__filter">
    <span>Language</span>
    <select id="plugin-language">
      <option value="">All languages</option>
    </select>
  </label>
  <label class="plugin-catalog__filter">
    <span>Category</span>
    <select id="plugin-category">
      <option value="">All categories</option>
    </select>
  </label>
  <label class="plugin-catalog__filter">
    <span>0xgen version</span>
    <select id="plugin-oxg">
      <option value="">All versions</option>
    </select>
  </label>
  <label class="plugin-catalog__filter">
    <span>Compatibility</span>
    <select id="plugin-compatibility-status">
      <option value="">All statuses</option>
    </select>
  </label>
</div>

<div id="plugin-catalog" class="plugin-catalog__grid" data-mdx-component="plugin-catalog"></div>

!!! tip "Filtering the catalogue"
    Filters can be combined. Start with a broad search term and then narrow the
    results with the language or category menus to quickly find the plugin you
    need for a workflow.

## Marketplace metadata feeds

The catalogue consumes the central registry feed stored at
[`docs/en/data/plugin-registry.json`](../data/plugin-registry.json). The JSON
payload combines the manifest metadata, SHA-256 signatures, categories, and
compatibility declarations for every vetted plugin.

Registry data is generated from the manifests under `plugins/<id>/manifest.json`
and the compatibility matrix declared in
[`plugins/compatibility.json`](../../plugins/compatibility.json). Regenerate the
feed after editing either source by running the publish workflow:

```bash
0xgenctl plugin registry publish --ref $(git rev-parse HEAD)
```

The command wraps `python scripts/update_plugin_catalog.py`, rebuilding:

- [`docs/en/data/plugin-catalog.json`](../data/plugin-catalog.json) for the
  marketplace cards.
- [`docs/en/data/plugin-registry.json`](../data/plugin-registry.json) consumed by
  the REST service and documentation UI.
- Reference documentation under [`docs/en/plugins/_catalog/`](./_catalog/).

Repository owners can extend the registry schema with additional properties—new
fields automatically appear in this catalogue without changes to the JavaScript
renderer.

!!! info "Self-hosting the registry API"
    Launch the lightweight registry server locally with
    `go run ./cmd/oxg-registry --data docs/en/data/plugin-registry.json`. The
    service exposes `/registry.json`, `/plugins`, and `/compatibility` endpoints
    for dashboards or automation workflows that want to consume the curated
    plugin feed directly.

## Discover more

- [Plugin author guide](./index.md)
- [Compatibility matrix](./compatibility-matrix.md)
- [SDK reference](../dev-guide/index.md#plugin-development-loop)
