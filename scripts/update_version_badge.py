#!/usr/bin/env python3
"""Update the release badge in the README with the provided tag."""

from __future__ import annotations

import re
import sys
from pathlib import Path

MARKER_START = "<!-- version-badge -->"
MARKER_END = "<!-- /version-badge -->"
BADGE_TEMPLATE = (
    "[![Release](https://img.shields.io/badge/release-{message}-blue)]"
    "(https://github.com/RowanDark/0xgen/releases/latest)"
)


def _shields_escape(tag: str) -> str:
    """Escape a version string for use in a static Shields badge."""

    escaped = tag
    escaped = escaped.replace("-", "--")
    escaped = escaped.replace("_", "__")
    escaped = escaped.replace(" ", "%20")
    escaped = escaped.replace("+", "%2B")
    return escaped


def update_badge(readme_path: Path, tag: str) -> bool:
    """Update the README badge and return True if a change was made."""

    original = readme_path.read_text(encoding="utf-8")
    escaped_tag = _shields_escape(tag)
    badge = f"{MARKER_START}{BADGE_TEMPLATE.format(message=escaped_tag)}{MARKER_END}"

    pattern = re.compile(
        re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END),
        flags=re.DOTALL,
    )

    if not pattern.search(original):
        raise SystemExit("Version badge markers not found in README.md")

    updated, count = pattern.subn(badge, original, count=1)
    if count == 0 or updated == original:
        return False

    readme_path.write_text(updated, encoding="utf-8")
    return True


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Usage: update_version_badge.py <tag>", file=sys.stderr)
        return 1

    tag = argv[1]
    repo_root = Path(__file__).resolve().parents[1]
    readme_path = repo_root / "README.md"

    changed = update_badge(readme_path, tag)
    return 0 if changed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
