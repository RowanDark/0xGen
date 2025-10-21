"""Generate the plugin marketplace metadata used by the documentation site."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent.parent
PLUGINS_DIR = ROOT / "plugins"
DOCS_DIR = ROOT / "docs"
DEFAULT_LANGUAGE = "en"
CATALOG_DATA_PATH = DOCS_DIR / DEFAULT_LANGUAGE / "data" / "plugin-catalog.json"
REGISTRY_DATA_PATH = DOCS_DIR / DEFAULT_LANGUAGE / "data" / "plugin-registry.json"
CATALOG_DOCS_DIR = DOCS_DIR / DEFAULT_LANGUAGE / "plugins" / "_catalog"


LANGUAGE_MAP = {
    ".js": "TypeScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mjs": "TypeScript",
    ".cjs": "TypeScript",
    ".go": "Go",
    ".py": "Python",
    ".rb": "Ruby",
}

ALLOWED_COMPATIBILITY_STATUSES = {"compatible", "limited", "unsupported"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ref",
        default=_current_git_ref(),
        help="Git ref used for GitHub links (defaults to the current commit)",
    )
    parser.add_argument(
        "--repo-url",
        default=_detect_repo_url(),
        help="Repository URL used for documentation links",
    )
    args = parser.parse_args()

    repo_url = args.repo_url.rstrip("/")
    owner, repo = _extract_github_repo(repo_url)
    raw_base = f"https://raw.githubusercontent.com/{owner}/{repo}/{args.ref}/"
    tree_base = f"{repo_url}/tree/{args.ref}/"

    compatibility = _load_compatibility()
    _validate_compatibility(compatibility)

    compat_map = {
        item.get("id"): item
        for item in compatibility.get("plugins", [])
        if item.get("id")
    }
    versions_source = compatibility.get("oxg_versions") or compatibility.get("glyph_versions") or []
    oxg_versions = list(dict.fromkeys(versions_source))

    entries: list[dict[str, Any]] = []
    generated_docs: dict[str, Path] = {}

    for manifest_path in sorted(PLUGINS_DIR.glob("*/manifest.json")):
        plugin_dir = manifest_path.parent
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        plugin_id = manifest.get("name") or plugin_dir.name
        plugin_slug = _normalise_identifier(plugin_id)

        readme_path = plugin_dir / "README.md"
        metadata = _parse_readme(readme_path)
        display_name = metadata.name or _title_from_identifier(plugin_id)
        summary = metadata.summary or _default_summary(display_name)

        language = _detect_language(manifest, plugin_dir)
        author = manifest.get("author") or "0xgen Team"
        capabilities = sorted(set(manifest.get("capabilities") or []))

        artifact_path = _resolve_path(manifest.get("artifact"), base=plugin_dir)
        signature_rel = manifest.get("signature", {}).get("signature")
        signature_path = _resolve_path(signature_rel, base=plugin_dir)

        if artifact_path is None or signature_path is None:
            raise SystemExit(f"Manifest {manifest_path} is missing an artefact or signature path")

        manifest_rel = manifest_path.relative_to(ROOT).as_posix()
        artifact_rel = artifact_path.relative_to(ROOT).as_posix()
        signature_rel_path = signature_path.relative_to(ROOT).as_posix()

        signature_sha256 = _sha256(signature_path)
        last_updated = _git_last_updated(plugin_dir)

        install_anchor = metadata.anchors.get("installation") or metadata.anchors.get("getting-started")
        documentation_url = f"../plugins/_catalog/{plugin_slug}/"
        install_url = None
        if install_anchor:
            install_url = f"{tree_base}{plugin_dir.relative_to(ROOT).as_posix()}#" f"{install_anchor}"

        compat_entry = compat_map.get(plugin_slug)

        entry = {
            "id": plugin_slug,
            "name": display_name,
            "version": manifest.get("version", "0.0.0"),
            "author": author,
            "language": language,
            "summary": summary,
            "capabilities": capabilities,
            "last_updated": last_updated,
            "signature_sha256": signature_sha256,
            "links": {
                "documentation": documentation_url,
                "readme": f"{tree_base}{plugin_dir.relative_to(ROOT).as_posix()}#readme",
                "manifest": f"{raw_base}{manifest_rel}",
                "artifact": f"{raw_base}{artifact_rel}",
                "signature": f"{raw_base}{signature_rel_path}",
            },
        }
        if install_url:
            entry["links"]["installation"] = install_url

        if compat_entry:
            categories = sorted(set(compat_entry.get("categories") or []))
            if categories:
                entry["categories"] = categories
            compatibility_data = compat_entry.get("oxg_compat") or compat_entry.get("compatibility") or {}
            if compatibility_data:
                entry["oxg_compat"] = compatibility_data

        entries.append(entry)

        generated_docs[plugin_slug] = _write_plugin_doc(
            output_dir=CATALOG_DOCS_DIR,
            plugin_id=plugin_slug,
            name=display_name,
            summary=summary,
            version=entry["version"],
            language=language,
            author=author,
            capabilities=capabilities,
            last_updated=last_updated,
            signature_sha256=signature_sha256,
            links=entry["links"],
        )

    entries.sort(key=lambda item: item["name"].lower())
    CATALOG_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    CATALOG_DATA_PATH.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")

    registry_payload = {
        "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "oxg_versions": oxg_versions,
        "plugins": entries,
    }
    REGISTRY_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_DATA_PATH.write_text(json.dumps(registry_payload, indent=2) + "\n", encoding="utf-8")

    _prune_stale_docs(CATALOG_DOCS_DIR, set(generated_docs))


def _load_compatibility() -> dict[str, Any]:
    path = PLUGINS_DIR / "compatibility.json"
    if not path.exists():
        return {"oxg_versions": [], "plugins": []}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse compatibility file {path}: {exc}") from exc


def _validate_compatibility(data: dict[str, Any]) -> None:
    glyph_versions = data.get("glyph_versions")
    oxg_versions = data.get("oxg_versions")
    versions = None
    if oxg_versions is not None:
        versions = oxg_versions
    elif glyph_versions is not None:
        versions = glyph_versions
    if versions is not None:
        if not isinstance(versions, list) or not all(isinstance(item, str) for item in versions):
            raise SystemExit("compatibility oxg_versions/glyph_versions must be a list of strings")

    for plugin in data.get("plugins", []):
        plugin_id = plugin.get("id")
        if not plugin_id:
            raise SystemExit("compatibility plugin entries require an id")
        compat_map = plugin.get("oxg_compat") or plugin.get("compatibility") or {}
        if not isinstance(compat_map, dict):
            raise SystemExit(f"compatibility entry for {plugin_id} must be a mapping")
        for glyph_version, details in compat_map.items():
            if not isinstance(details, dict):
                raise SystemExit(
                    f"compatibility details for {plugin_id} {glyph_version} must be an object",
                )
            status = details.get("status")
            if status not in ALLOWED_COMPATIBILITY_STATUSES:
                allowed = ", ".join(sorted(ALLOWED_COMPATIBILITY_STATUSES))
                raise SystemExit(
                    f"compatibility status {status!r} for {plugin_id} must be one of: {allowed}",
                )


def _current_git_ref() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "main"


def _detect_repo_url() -> str:
    mkdocs_path = ROOT / "mkdocs.yml"
    if not mkdocs_path.exists():
        return "https://github.com/RowanDark/0xgen"
    for line in mkdocs_path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("repo_url:"):
            _, value = line.split(":", 1)
            return value.strip().strip("'\"")
    return "https://github.com/RowanDark/0xgen"


def _extract_github_repo(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise SystemExit(f"Unable to determine GitHub repository owner from URL: {url}")
    return parts[0], parts[1]


def _normalise_identifier(identifier: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", identifier.lower()).strip("-") or identifier


def _title_from_identifier(identifier: str) -> str:
    return identifier.replace("-", " ").title()


class ReadmeMetadata:
    def __init__(self, name: str | None, summary: str | None, anchors: dict[str, str]):
        self.name = name
        self.summary = summary
        self.anchors = anchors


def _parse_readme(path: Path) -> ReadmeMetadata:
    if not path.exists():
        return ReadmeMetadata(None, None, {})

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    name: str | None = None
    summary: str | None = None
    anchors: dict[str, str] = {}
    collecting_summary = False
    summary_lines: list[str] = []

    for line in lines:
        if line.startswith("# "):
            if name is None:
                name = line[2:].strip()
                collecting_summary = True
            else:
                collecting_summary = False
            continue
        if line.startswith("## "):
            heading = line[3:].strip()
            anchors[_slugify(heading)] = _slugify(heading)
            collecting_summary = False
            if summary_lines and summary is None:
                summary = " ".join(summary_lines).strip()
            continue
        if collecting_summary:
            stripped = line.strip()
            if not stripped:
                if summary_lines and summary is None:
                    summary = " ".join(summary_lines).strip()
                    summary_lines = []
                continue
            summary_lines.append(stripped)

    if summary is None and summary_lines:
        summary = " ".join(summary_lines).strip()

    return ReadmeMetadata(name, summary, anchors)


def _slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9\s-]", "", value)
    value = re.sub(r"\s+", "-", value)
    return value


def _default_summary(name: str) -> str:
    return f"{name} is a 0xgen plugin.".strip()


def _detect_language(manifest: dict[str, Any], base: Path) -> str:
    candidates = [manifest.get("entry"), manifest.get("artifact")]
    for candidate in candidates:
        resolved = _resolve_path(candidate, base=base)
        if resolved is None:
            continue
        suffix = resolved.suffix.lower()
        if suffix in LANGUAGE_MAP:
            return LANGUAGE_MAP[suffix]
    return "Unknown"


def _resolve_path(path: str | None, *, base: Path) -> Path | None:
    if not path:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    base_candidate = (base / candidate).resolve()
    if base_candidate.exists():
        return base_candidate
    root_candidate = (ROOT / candidate).resolve()
    if root_candidate.exists():
        return root_candidate
    return base_candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_last_updated(path: Path) -> str | None:
    try:
        output = subprocess.check_output(
            ["git", "log", "-1", "--format=%cI", str(path.relative_to(ROOT))],
            cwd=ROOT,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return output or None


def _write_plugin_doc(
    *,
    output_dir: Path,
    plugin_id: str,
    name: str,
    summary: str,
    version: str,
    language: str,
    author: str,
    capabilities: Iterable[str],
    last_updated: str | None,
    signature_sha256: str,
    links: dict[str, str],
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    doc_path = output_dir / f"{plugin_id}.md"

    manifest_link = links.get("manifest", "")
    artifact_link = links.get("artifact", "")
    signature_link = links.get("signature", "")
    readme_link = links.get("installation") or links.get("readme", "")

    metadata_rows = [
        ("Version", version),
        ("Author", author),
        ("Language", language),
    ]
    if last_updated:
        try:
            dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            formatted = dt.strftime("%b %d, %Y")
            metadata_rows.append(("Last updated", formatted))
        except ValueError:
            metadata_rows.append(("Last updated", last_updated))

    table = "\n".join(f"| {label} | {value} |" for label, value in metadata_rows)

    capability_lines = "\n".join(f"- `{cap}`" for cap in capabilities) or "- _None declared_"

    sections = [
        f"---\ntitle: \"{_escape_yaml(name)}\"\ndescription: \"{_escape_yaml(summary)}\"\n---",
        f"# {name}",
        summary,
        "## Metadata",
        "| Field | Value |",
        "| ----- | ----- |",
        table,
        "\n## Capabilities",
        capability_lines,
        "\n## Installation",
        "Download the signed artefact and verify its signature before running the plugin.",
    ]
    if readme_link:
        sections.append(f"Follow the [installation guide]({readme_link}) for detailed steps.")

    sections.extend(
        [
            "\n### Downloads",
            f"- [Manifest]({manifest_link})",
            f"- [Plugin artefact]({artifact_link})",
            f"- [Detached signature]({signature_link})",
            "\n### Signature",
            f"`{signature_sha256}`",
        ]
    )

    doc_path.write_text("\n\n".join(sections).strip() + "\n", encoding="utf-8")
    return doc_path


def _escape_yaml(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\"", "\\\"")


def _prune_stale_docs(directory: Path, valid_ids: set[str]) -> None:
    if not directory.exists():
        return
    for path in directory.glob("*.md"):
        if path.stem not in valid_ids:
            path.unlink()


if __name__ == "__main__":
    main()

