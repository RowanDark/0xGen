from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import re
from typing import Any
import uuid
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile

from mkdocs.structure.files import File
from mkdocs.structure.pages import Page
from urllib.parse import urljoin


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
    _minify_static_assets(site_dir)
    _write_asset_metrics(site_dir)
    _build_epub_archive(site_dir, config)


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


def _minify_static_assets(site_dir: Path) -> None:
    """Minify custom CSS and JavaScript bundles copied into the site."""

    tasks: list[tuple[Path, str, Any]] = [
        (site_dir / "stylesheets", ".css", _minify_css),
        (site_dir / "javascripts", ".js", _minify_js),
    ]

    for directory, extension, reducer in tasks:
        if not directory.exists():
            continue
        for path in directory.rglob(f"*{extension}"):
            original = path.read_text(encoding="utf-8")
            optimised = reducer(original)
            if optimised and len(optimised) < len(original):
                path.write_text(optimised, encoding="utf-8")


def _write_asset_metrics(site_dir: Path) -> None:
    """Capture bundle sizes for JS and CSS assets."""

    assets_dir = site_dir / "assets"
    if not assets_dir.exists():
        return

    entries: list[dict[str, Any]] = []
    for path in assets_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in {".js", ".css"}:
            continue
        relative_path = path.relative_to(site_dir).as_posix()
        size = path.stat().st_size
        entries.append({"path": relative_path, "bytes": size})

    entries.sort(key=lambda item: item["bytes"], reverse=True)
    total_js = sum(item["bytes"] for item in entries if item["path"].endswith(".js"))
    total_css = sum(item["bytes"] for item in entries if item["path"].endswith(".css"))

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_js_bytes": total_js,
        "total_css_bytes": total_css,
        "top_assets": entries[:25],
    }

    target = site_dir / "api" / "asset-metrics.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _minify_css(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*([{};:,])\s*", r"\1", text)
    text = text.replace(";}", "}")
    return text.strip()


def _minify_js(text: str) -> str:
    result: list[str] = []
    length = len(text)
    i = 0
    in_string = False
    string_char = ""

    while i < length:
        char = text[i]
        if in_string:
            result.append(char)
            if char == "\\":
                if i + 1 < length:
                    result.append(text[i + 1])
                i += 2
                continue
            if char == string_char:
                in_string = False
            i += 1
            continue
        if char in {'"', "'", "`"}:
            in_string = True
            string_char = char
            result.append(char)
            i += 1
            continue
        if char == "/" and i + 1 < length:
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < length and text[i] not in "\r\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < length and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        result.append(char)
        i += 1

    minified = "".join(result)
    minified = "\n".join(line.rstrip() for line in minified.splitlines())
    minified = re.sub(r"\n{2,}", "\n", minified)
    return minified.strip()


def _build_epub_archive(site_dir: Path, config: dict[str, Any]) -> None:
    """Generate a lightweight EPUB snapshot of the rendered documentation."""

    extra = config.get("extra") or {}
    download_config = extra.get("pdf_download") or {}
    relative_output = download_config.get("path", "assets/offline/glyph-docs.epub")
    output_path = site_dir / relative_output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    html_files: list[Path] = []
    for path in site_dir.glob("**/*.html"):
        if not path.is_file():
            continue
        relative = path.relative_to(site_dir)
        # Skip assets, APIs, alternate languages, and the 404 page itself.
        if not relative.parts:
            continue
        if relative.parts[0] in {"assets", "api", "es"}:
            continue
        if relative.name == "404.html":
            continue
        html_files.append(path)

    if not html_files:
        return

    def sort_key(path: Path) -> tuple[Any, ...]:
        relative = path.relative_to(site_dir)
        priority = 1
        if relative.name == "index.html":
            priority = 0
        return (priority, str(relative))

    html_files.sort(key=sort_key)

    items: list[dict[str, Any]] = []
    for index, path in enumerate(html_files):
        html = path.read_text(encoding="utf-8")
        title_match = re.search(r"<title>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else path.stem
        article_match = re.search(
            r"<article[^>]*>(.*?)</article>", html, flags=re.IGNORECASE | re.DOTALL
        )
        if article_match:
            body = article_match.group(1).strip()
        else:
            body_match = re.search(r"<body[^>]*>(.*)</body>", html, flags=re.IGNORECASE | re.DOTALL)
            body = body_match.group(1).strip() if body_match else ""
        if not body:
            continue
        relative = path.relative_to(site_dir).with_suffix(".xhtml")
        href = (Path("text") / relative).as_posix()
        items.append(
            {
                "id": f"doc{index}",
                "title": title,
                "href": href,
                "content": body,
            }
        )

    if not items:
        return

    modified = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    identifier = f"urn:uuid:{uuid.uuid4()}"

    manifest_entries = "\n".join(
        f'    <item id="{escape(item["id"])}" href="{escape(item["href"])}" media-type="application/xhtml+xml"/>'
        for item in items
    )
    spine_entries = "\n".join(f'    <itemref idref="{escape(item["id"])}"/>' for item in items)
    nav_entries = "\n".join(
        f'        <li><a href="{escape(item["href"])}">{escape(item["title"])}</a></li>' for item in items
    )

    opf = (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<package version=\"3.0\" xmlns=\"http://www.idpf.org/2007/opf\" unique-identifier=\"bookid\">\n"
        "  <metadata xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\">\n"
        f"    <dc:identifier id=\"bookid\">{escape(identifier)}</dc:identifier>\n"
        "    <dc:title>Glyph Documentation</dc:title>\n"
        "    <dc:language>en</dc:language>\n"
        f"    <meta property=\"dcterms:modified\">{escape(modified)}</meta>\n"
        "  </metadata>\n"
        "  <manifest>\n"
        "    <item id=\"nav\" href=\"nav.xhtml\" media-type=\"application/xhtml+xml\" properties=\"nav\"/>\n"
        f"{manifest_entries}\n"
        "  </manifest>\n"
        "  <spine>\n"
        f"{spine_entries}\n"
        "  </spine>\n"
        "</package>\n"
    )

    nav = (
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<!DOCTYPE html>\n"
        "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\">\n"
        "  <head>\n"
        "    <meta charset=\"utf-8\"/>\n"
        "    <title>Glyph Documentation</title>\n"
        "  </head>\n"
        "  <body>\n"
        "    <nav epub:type=\"toc\">\n"
        "      <h1>Glyph Documentation</h1>\n"
        "      <ol>\n"
        f"{nav_entries}\n"
        "      </ol>\n"
        "    </nav>\n"
        "  </body>\n"
        "</html>\n"
    )

    def render_page(item: dict[str, Any]) -> str:
        return (
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<!DOCTYPE html>\n"
            "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\">\n"
            "  <head>\n"
            "    <meta charset=\"utf-8\"/>\n"
            f"    <title>{escape(item['title'])}</title>\n"
            "    <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:1.5rem;line-height:1.6;}" \
            "h1,h2,h3{color:#0f172a;} code{background:#f1f5f9;padding:0.1rem 0.3rem;border-radius:0.25rem;}</style>\n"
            "  </head>\n"
            "  <body>\n"
            f"{item['content']}\n"
            "  </body>\n"
            "</html>\n"
        )

    with ZipFile(output_path, "w") as archive:
        archive.writestr("mimetype", "application/epub+zip", compress_type=ZIP_STORED)
        archive.writestr(
            "META-INF/container.xml",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">\n"
            "  <rootfiles>\n"
            "    <rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\"/>\n"
            "  </rootfiles>\n"
            "</container>\n",
            compress_type=ZIP_DEFLATED,
        )
        archive.writestr("OEBPS/content.opf", opf, compress_type=ZIP_DEFLATED)
        archive.writestr("OEBPS/nav.xhtml", nav, compress_type=ZIP_DEFLATED)
        for item in items:
            archive.writestr(f"OEBPS/{item['href']}", render_page(item), compress_type=ZIP_DEFLATED)


def on_config(config: dict[str, Any]) -> dict[str, Any]:
    """Inject Glyph → 0xgen redirects for every published Markdown page."""

    plugins = config.get("plugins")
    if not plugins:
        return config

    redirects_plugin = plugins.get("redirects")
    if redirects_plugin is None:
        return config

    redirect_maps = redirects_plugin.config.get("redirect_maps")
    if not isinstance(redirect_maps, dict):
        return config

    docs_dir = Path(config.get("docs_dir", "docs"))
    if not docs_dir.exists():
        return config

    use_directory_urls = bool(config.get("use_directory_urls", True))
    site_url = (config.get("site_url") or "").rstrip("/")

    if site_url.endswith("/Glyph"):
        target_root = f"{site_url[:-len('/Glyph')]}/0xgen/"
    elif site_url:
        target_root = f"{site_url}/0xgen/"
    else:
        target_root = "/0xgen/"

    site_dir = config.get("site_dir", "site")

    for markdown_path in docs_dir.rglob("*.md"):
        relative_path = markdown_path.relative_to(docs_dir).as_posix()

        if relative_path.startswith("overrides/"):
            continue

        legacy_path = f"Glyph/{relative_path}"
        if legacy_path in redirect_maps:
            continue

        file = File(relative_path, docs_dir.as_posix(), site_dir, use_directory_urls)
        redirect_maps[legacy_path] = urljoin(target_root, file.url)

    return config

