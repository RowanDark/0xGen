#!/usr/bin/env python3
"""Snapshot the current documentation into a versioned directory."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, Iterable, List


ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = ROOT / "docs"
DEFAULT_LANGUAGE = "en"
# Additional languages that should receive a drop-down manifest pointing back to
# the English snapshots.
TRANSLATED_LANGUAGES = ("es",)
LANG_DIR = DOCS_ROOT / DEFAULT_LANGUAGE
VERSIONS_DIR = LANG_DIR / "versions"
MANIFEST_PATH = Path("data") / "doc-versions.json"
DEFAULT_IGNORE = {"versions", "__pycache__", "site", ".mike", "node_modules"}


def _normalise_name(name: str) -> str:
    return name.replace(" (Latest)", "")


def _version_sort_key(entry: Dict[str, str]) -> tuple:
    identifier = entry.get("id", "")
    prefix = 1
    numbers: List[int] = []
    if identifier.startswith("v"):
        prefix = 0
        identifier = identifier[1:]
    for part in identifier.split('.'):
        try:
            numbers.append(int(part))
        except ValueError:
            prefix = 1
            break
    return (prefix, tuple(numbers), entry.get("id", ""))


def load_manifest(base_dir: Path) -> Dict[str, object]:
    manifest_path = base_dir / MANIFEST_PATH
    if manifest_path.exists():
        with manifest_path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    return {"default": None, "versions": []}


def save_manifest(base_dir: Path, manifest: Dict[str, object]) -> None:
    manifest_path = base_dir / MANIFEST_PATH
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=False)
        handle.write("\n")


def snapshot(version: str, *, force: bool = False) -> Path:
    version_dir = VERSIONS_DIR / version
    if version_dir.exists():
        if not force:
            raise SystemExit(
                f"Version '{version}' already exists. Use --force to overwrite it.",
            )
        shutil.rmtree(version_dir)
    ignored = shutil.ignore_patterns(*DEFAULT_IGNORE)
    shutil.copytree(LANG_DIR, version_dir, ignore=ignored)
    return version_dir


def _merge_entries(existing: Iterable[Dict[str, str]], version: str) -> List[Dict[str, str]]:
    merged: List[Dict[str, str]] = []
    seen = set()
    for entry in existing:
        identifier = entry.get("id")
        if not identifier or identifier in seen or identifier == version:
            continue
        name = _normalise_name(entry.get("name") or identifier)
        merged.append({"id": identifier, "name": name})
        seen.add(identifier)
    if version not in seen:
        merged.append({"id": version, "name": version})
    merged.sort(key=_version_sort_key, reverse=True)
    return merged


def _build_root_manifest(entries: List[Dict[str, str]], default_id: str) -> Dict[str, object]:
    manifest_entries = []
    for entry in entries:
        identifier = entry["id"]
        name = entry["name"]
        if identifier == default_id:
            manifest_entries.append({
                "id": identifier,
                "name": f"{name} (Latest)",
                "url": "./",
            })
        else:
            manifest_entries.append({
                "id": identifier,
                "name": name,
                "url": f"versions/{identifier}/",
            })
    return {"default": default_id, "versions": manifest_entries}


def _build_version_manifest(
    entries: List[Dict[str, str]],
    *,
    default_id: str,
    current_id: str,
) -> Dict[str, object]:
    manifest_entries = []
    for entry in entries:
        identifier = entry["id"]
        name = entry["name"]
        display_name = f"{name} (Latest)" if identifier == default_id else name
        if identifier == current_id:
            url = "./"
        elif identifier == default_id:
            url = "../../"
        else:
            url = f"../{identifier}/"
        manifest_entries.append({"id": identifier, "name": display_name, "url": url})
    return {"default": default_id, "versions": manifest_entries}


def update_manifests(version: str, *, latest: bool) -> None:
    manifest = load_manifest(LANG_DIR)
    entries = _merge_entries(manifest.get("versions", []), version)
    default_id = version if latest else manifest.get("default")
    if not default_id or all(entry["id"] != default_id for entry in entries):
        default_id = version
    entries.sort(key=_version_sort_key, reverse=True)
    save_manifest(LANG_DIR, _build_root_manifest(entries, default_id))

    for version_dir in VERSIONS_DIR.iterdir():
        if not version_dir.is_dir():
            continue
        current_id = version_dir.name
        save_manifest(
            version_dir,
            _build_version_manifest(entries, default_id=default_id, current_id=current_id),
        )

    for language in TRANSLATED_LANGUAGES:
        if language == DEFAULT_LANGUAGE:
            continue
        translated_dir = DOCS_ROOT / language
        if not translated_dir.exists():
            continue
        save_manifest(
            translated_dir,
            _build_translated_manifest(entries, default_id=default_id),
        )


def _build_translated_manifest(
    entries: List[Dict[str, str]], *, default_id: str
) -> Dict[str, object]:
    manifest_entries = []
    for entry in entries:
        identifier = entry["id"]
        name = entry["name"]
        display_name = f"{name} (Latest)" if identifier == default_id else name
        if identifier == default_id:
            url = "../"
        else:
            url = f"../versions/{identifier}/"
        manifest_entries.append({"id": identifier, "name": display_name, "url": url})
    return {"default": default_id, "versions": manifest_entries}


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

    if not LANG_DIR.exists():
        raise SystemExit(f"Docs directory not found: {LANG_DIR}")

    VERSIONS_DIR.mkdir(parents=True, exist_ok=True)
    version_dir = snapshot(args.version, force=args.force)
    update_manifests(args.version, latest=args.latest)
    print(f"Snapshot created at {version_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
