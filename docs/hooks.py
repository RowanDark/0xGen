from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mkdocs.structure.pages import Page


def on_page_content(html: str, page: Page, config: dict[str, Any], files: Any) -> str:  # noqa: ARG001
    """Append a Last updated banner to each rendered page."""
    last_updated = page.meta.get("git_revision_date_localized") if page.meta else None
    if not last_updated:
        return html

    banner = (
        '\n<div class="doc-last-updated" data-md-component="last-updated">'
        f'<span class="doc-last-updated__label">Last updated:</span> {last_updated}'
        "</div>\n"
    )
    if "doc-last-updated" in html:
        return html
    return html + banner


def on_post_build(config: dict[str, Any]) -> None:
    """Emit badge metadata for Shields.io after building the documentation."""

    docs_dir = Path(config.get("docs_dir", "docs"))
    site_dir = Path(config.get("site_dir", "site"))

    badge_payload = _build_badge_payload(docs_dir)
    target = site_dir / "api" / "plugin-stats.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(badge_payload, indent=2) + "\n", encoding="utf-8")


def _build_badge_payload(docs_dir: Path) -> dict[str, Any]:
    catalog_path = docs_dir / "en" / "data" / "plugin-catalog.json"
    versions_path = docs_dir / "en" / "data" / "doc-versions.json"

    try:
        plugin_catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        plugin_catalog = []

    plugin_count = len([entry for entry in plugin_catalog if isinstance(entry, dict)])

    latest_version = "unreleased"
    try:
        versions_data = json.loads(versions_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        versions_data = {}

    default_version = versions_data.get("default")
    if isinstance(default_version, str):
        versions = versions_data.get("versions", [])
        display_name = next(
            (
                entry.get("name")
                for entry in versions
                if isinstance(entry, dict) and entry.get("id") == default_version
            ),
            None,
        )
        latest_version = display_name or default_version

    message = f"{latest_version} • {plugin_count} plugin{'s' if plugin_count != 1 else ''}"
    return {
        "schemaVersion": 1,
        "label": "Glyph",
        "message": message,
        "color": "1f6feb",
        "cacheSeconds": 3600,
    }
