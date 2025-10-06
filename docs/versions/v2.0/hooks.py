from __future__ import annotations

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
