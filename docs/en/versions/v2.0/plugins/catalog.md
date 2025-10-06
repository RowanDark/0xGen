---
title: Plugin Marketplace
description: Discover Glyph plugins, filter by capability, and explore their compatibility details.
---

# Plugin marketplace

Glyph ships with an extensible plugin runtime and a curated marketplace of
first-party extensions. Use the catalogue below to browse every maintained
plugin, inspect its capabilities, and jump straight into the author guides.

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
</div>

<div id="plugin-catalog" class="plugin-catalog__grid" data-mdx-component="plugin-catalog"></div>

!!! tip "Filtering the catalogue"
    Filters can be combined. Start with a broad search term and then narrow the
    results with the language or category menus to quickly find the plugin you
    need for a workflow.

## Marketplace metadata feeds

The data that powers the marketplace is stored in
[`docs/data/plugin-catalog.json`](../data/plugin-catalog.json). The file is
updated every time a plugin ships or gains a new capability. Repository owners
can extend the schema with custom fields—new properties automatically appear in
this table without changes to the JavaScript renderer.

If you are publishing a third-party plugin, open a pull request that updates the
catalogue entry with the plugin name, version, author, categories, and
capability list. The docs build picks up the change and republishes the
marketplace page without additional configuration.

## Discover more

- [Plugin author guide](./index.md)
- [Compatibility matrix](./compatibility-matrix.md)
- [SDK reference](../dev-guide/index.md#plugin-development-loop)
