#!/usr/bin/env python3
"""Validate internal and external links in a built MkDocs site."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import unquote, urlparse

import requests


@dataclass
class Link:
    url: str
    tag: str
    attribute: str
    line: int


@dataclass
class Document:
    ids: Set[str]
    links: List[Link]


class DocumentParser(HTMLParser):
    """Collect IDs and links from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: Set[str] = set()
        self.links: List[Link] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:  # noqa: D401
        self._process_tag(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:  # noqa: D401
        self._process_tag(tag, attrs)

    def _process_tag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attributes = {name: value for name, value in attrs if value}
        element_id = attributes.get("id")
        if element_id:
            self.ids.add(element_id)
        if tag == "a" and attributes.get("name"):
            self.ids.add(attributes["name"])

        attribute = None
        if tag in {"a", "area", "link"}:
            attribute = "href"
        elif tag in {"img", "script", "iframe", "audio", "video", "source", "track", "embed"}:
            attribute = "src"
        elif tag == "form":
            attribute = "action"

        if not attribute:
            return

        url = attributes.get(attribute)
        if not url:
            return

        line, _ = self.getpos()
        self.links.append(Link(url=url.strip(), tag=tag, attribute=attribute, line=line))


def parse_documents(root: Path) -> Dict[Path, Document]:
    documents: Dict[Path, Document] = {}
    for path in root.rglob("*.html"):
        parser = DocumentParser()
        parser.feed(path.read_text(encoding="utf-8"))
        parser.close()
        documents[path] = Document(ids=parser.ids, links=parser.links)
    return documents


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site_dir", type=Path, help="Path to the built MkDocs site directory")
    parser.add_argument(
        "--skip-external",
        action="store_true",
        help="Skip checking HTTP/HTTPS links and only validate internal links",
    )
    args = parser.parse_args()

    site_dir = args.site_dir.resolve()
    if not site_dir.is_dir():
        parser.error(f"Site directory '{site_dir}' does not exist or is not a directory")

    documents = parse_documents(site_dir)
    session = requests.Session()
    session.headers.update({"User-Agent": "0xgenDocsLinkChecker/1.0"})
    external_cache: Dict[str, str | None] = {}
    errors: List[Tuple[Path, Link, str]] = []
    total_links = 0

    for document_path, document in documents.items():
        for link in document.links:
            total_links += 1
            error = validate_link(
                document_path,
                link,
                site_dir,
                documents,
                session,
                external_cache,
                check_external_links=not args.skip_external,
            )
            if error:
                errors.append((document_path, link, error))

    if errors:
        for path, link, reason in errors:
            rel = path.relative_to(site_dir)
            print(f"{rel}:{link.line}: {link.url} -> {reason}")
        print(f"Found {len(errors)} broken links across {total_links} links.")
        raise SystemExit(1)

    print(f"Checked {total_links} links across {len(documents)} pages with no issues.")


def validate_link(
    document_path: Path,
    link: Link,
    site_dir: Path,
    documents: Dict[Path, Document],
    session: requests.Session,
    cache: Dict[str, str | None],
    *,
    check_external_links: bool,
) -> str | None:
    url = link.url
    if not url or url.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
        return None

    parsed = urlparse(url)
    if parsed.scheme in {"http", "https"} or parsed.netloc:
        if not check_external_links:
            return None
        return check_external(url, session, cache)

    if url.startswith("#"):
        fragment = unquote(parsed.fragment or url.lstrip("#"))
        if fragment and fragment not in documents[document_path].ids:
            return f"Missing anchor '#{fragment}'"
        return None

    target_path, fragment = resolve_internal_path(document_path, parsed, site_dir)
    if target_path is None:
        return "Link resolves outside the published documentation"

    if target_path.suffix and target_path.suffix.lower() != ".html":
        return None if target_path.exists() else "Target resource missing"

    if not target_path.exists():
        return "Target page missing"

    target_doc = documents.get(target_path)
    if target_doc is None:
        return None

    if fragment and fragment not in target_doc.ids:
        return f"Missing anchor '#{fragment}'"
    return None


def resolve_internal_path(document_path: Path, parsed, site_dir: Path) -> Tuple[Path | None, str | None]:
    raw_path = unquote(parsed.path or "")
    if raw_path.startswith("/"):
        candidate = (site_dir / raw_path.lstrip("/")).resolve()
    else:
        candidate = (document_path.parent / raw_path).resolve()

    try:
        candidate.relative_to(site_dir)
    except ValueError:
        return None, None

    if raw_path.endswith("/") or candidate.is_dir():
        candidate = candidate / "index.html"
    elif not candidate.suffix:
        candidate = candidate / "index.html"

    fragment = unquote(parsed.fragment) if parsed.fragment else None
    return candidate, fragment


def check_external(url: str, session: requests.Session, cache: Dict[str, str | None]) -> str | None:
    if url in cache:
        return cache[url]

    try:
        response = session.head(url, allow_redirects=True, timeout=10)
        status = response.status_code
        if status >= 400 or status == 405:
            response = session.get(url, allow_redirects=True, timeout=10)
            status = response.status_code
        if status >= 400:
            cache[url] = f"HTTP {status}"
        else:
            cache[url] = None
    except requests.RequestException as exc:  # pragma: no cover - network error path
        cache[url] = str(exc)

    return cache[url]


if __name__ == "__main__":
    main()
