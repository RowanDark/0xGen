---
title: Compare documentation versions
---

# Compare documentation versions

Use the selector below to preload a GitHub diff between two releases. After the
compare view opens you can use GitHub's **Filter changed files** search box to
type `docs/` and focus on documentation updates. The helper also surfaces quick
links to release notes and the project changelog.

<div data-version-diff class="doc-version-diff">
  <noscript>
    <p><strong>JavaScript required:</strong> enable JavaScript to build the diff
    view. As a fallback you can open <a href="https://github.com/RowanDark/0xgen/blob/main/CHANGELOG.md" target="_blank" rel="noopener">the changelog</a>
    or use the GitHub compare tool manually:</p>
    <ol>
      <li>Navigate to <a href="https://github.com/RowanDark/0xgen/compare" target="_blank" rel="noopener">github.com/RowanDark/0xgen/compare</a>.</li>
      <li>Enter the base (older) version tag, then the newer target tag.</li>
      <li>Add <code>?diff=split</code> to the URL (or use the UI controls) and
        type <code>docs/</code> into the <strong>Filter changed files</strong> box
        to narrow the list to documentation changes.</li>
    </ol>
  </noscript>
</div>

## Tips for sharing diffs

- GitHub remembers the chosen versions and any file filter text in the URL, so
  you can share a link to a specific comparison.
- Release notes link to the corresponding GitHub tag so you can see binaries,
  issues, and merged pull requests for that version.
- Documentation snapshots remain available under `/versions/<id>/` if you need
  a stable permalink to an older page.
