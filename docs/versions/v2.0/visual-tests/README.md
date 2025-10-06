---
search: false
---

# Docs visual regression tests

This package captures Playwright screenshots for critical documentation pages and compares them against the version currently deployed to GitHub Pages. The suite will fail if the pixel drift exceeds the configured threshold, ensuring that unintended visual changes are caught before deployment.

## Prerequisites

* Python with MkDocs (`pip install -r docs/requirements.txt`)
* Node.js 18+
* Playwright browsers (`npx playwright install --with-deps chromium`)

## Usage

```bash
npm install --prefix docs/visual-tests
npm run --prefix docs/visual-tests test         # validate against the production baseline
npm run --prefix docs/visual-tests test:update  # refresh snapshots after intentional UI changes
```

By default the tests build the MkDocs site into `docs/visual-tests/.site` and serve it locally. They fetch the baseline from the published [documentation homepage](../index.md) (default `DOCS_BASELINE_URL=https://rowandark.github.io/Glyph/`) so the comparison always runs against the latest public documentation. Override the baseline with `DOCS_BASELINE_URL` when comparing against a staging environment.

```bash
DOCS_BASELINE_URL="https://docs-preview.example.com" \
  npm run --prefix docs/visual-tests test -- --update-snapshots
```
