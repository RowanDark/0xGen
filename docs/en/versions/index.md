# Documentation versions

0xgen ships the online documentation with per-release snapshots so you can keep
working against a stable API or CLI surface even after the latest release
moves forward.

## See what's changed

Head to the [comparison view](compare.md) to generate a diff between any two
published versions. The helper preloads GitHub's compare view and surfaces quick
links to the relevant release notes and changelog entries.

## Selecting a version

Use the **Version** drop-down in the site header to jump between the currently
published release and archived snapshots. Each entry links to the snapshot's
root so relative navigation stays on the selected version.

!!! tip "Linking to a specific version"
    Use links under `/versions/<id>/` when sharing documentation for a
    historical release. Those URLs will continue to resolve even after newer
    releases ship.

## Creating a new snapshot

When you cut a new release, capture the documentation into `docs/en/versions/`
by running:

```bash
python scripts/snapshot_docs.py vX.Y.Z --latest
```

The helper script:

- copies the English documentation into `docs/en/versions/vX.Y.Z/`,
- refreshes every `doc-versions.json` manifest so the drop-down stays
  up-to-date across the live site and each archived snapshot, and
- preserves older entries while stripping stale "(Latest)" suffixes.

If you need to regenerate an existing snapshot (for example to pick up a fix),
append `--force` to overwrite the destination directory.

!!! note "Localization"
    Archived documentation snapshots are currently published in English only.

## Available snapshots

- [Latest documentation](../)
- [v2.0](./v2.0/)
- [v1.0](./v1.0/)
