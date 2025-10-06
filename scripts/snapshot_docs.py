#!/usr/bin/env python3
"""Snapshot the current documentation into a versioned directory."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
VERSIONS_DIR = DOCS_DIR / "versions"
DEFAULT_IGNORE = {"versions", "__pycache__", "site", ".mike", "node_modules"}
MANIFEST_NAME = "doc-versions.json"


def load_manifest() -> dict:
    manifest_path = DOCS_DIR / "data" / MANIFEST_NAME
    if manifest_path.exists():
        with manifest_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    return {"default": None, "versions": []}


def save_manifest(manifest: dict) -> None:
    data_dir = DOCS_DIR / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = data_dir / MANIFEST_NAME
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=False)
        handle.write("\n")


def snapshot(version: str, *, force: bool = False) -> Path:
    version_dir = VERSIONS_DIR / version
    if version_dir.exists():
        if not force:
            raise SystemExit(
                f"Version '{version}' already exists. Use --force to overwrite it."
            )
        shutil.rmtree(version_dir)
    ignored = shutil.ignore_patterns(*DEFAULT_IGNORE)
    shutil.copytree(DOCS_DIR, version_dir, ignore=ignored)
    return version_dir


def update_manifest(version: str, *, latest: bool) -> None:
    manifest = load_manifest()
    versions = []
    for entry in manifest.get("versions", []):
        if entry.get("id") == version:
            continue
        if entry.get("url") == "./":
            entry = {
                **entry,
                "url": f"versions/{entry['id']}/",
            }
        name = entry.get("name") or entry["id"]
        if name.endswith("(Latest)"):
            entry = {
                **entry,
                "name": name.replace(" (Latest)", ""),
            }
        versions.append(entry)
    name = f"{version} (Latest)" if latest else version
    entry = {
        "id": version,
        "name": name,
        "url": "./" if latest else f"versions/{version}/",
    }
    versions.append(entry)
    versions.sort(key=lambda item: item["name"], reverse=True)
    if latest:
        manifest["default"] = version
    elif manifest.get("default") is None:
        manifest["default"] = version
    manifest["versions"] = versions
    save_manifest(manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="Version label (for example v2.1.0)")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the destination directory if it already exists.",
    )
    parser.add_argument(
        "--latest",
        action="store_true",
        help="Mark this snapshot as the default version in the manifest.",
    )
    args = parser.parse_args()

    if not DOCS_DIR.exists():
        raise SystemExit(f"Docs directory not found: {DOCS_DIR}")

    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    version_dir = snapshot(args.version, force=args.force)
    update_manifest(args.version, latest=args.latest)
    print(f"Snapshot created at {version_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
