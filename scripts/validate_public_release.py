#!/usr/bin/env python3
"""Validate an explicit Orcastrata Max public repository stage."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable

PLUGIN_RELATIVE = PurePosixPath("plugins/codexmax-orchestrator")
MANIFEST_RELATIVE = PurePosixPath(".codex-plugin/release-manifest.json")
REPOSITORY_URL = "https://github.com/Vel-Labs/orcastrata-max"
ROOT_PUBLIC_FILES = (
    ".agents/plugins/marketplace.json",
    ".gitignore",
    "AGENTS.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "PRIVACY.md",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "package.json",
    "scripts/build_public_release.py",
    "scripts/validate_public_release.py",
)
FORBIDDEN_PARTS = frozenset({
    ".git", "__pycache__", "archives", "reports", "fixtures", "docs", "tests",
})
FORBIDDEN_SUFFIXES = (".pyc", ".pyo", ".p12", ".pfx", ".key", ".log")
TEXT_SUFFIXES = frozenset({
    "", ".css", ".html", ".ini", ".js", ".json", ".md", ".py", ".sh",
    ".toml", ".txt", ".yaml", ".yml",
})
PERSONAL_PATHS = (
    re.compile(rb"/Users/[A-Za-z0-9._-]+(?:/|\\b)"),
    re.compile(rb"[A-Za-z]:\\\\Users\\\\[A-Za-z0-9._-]+(?:\\\\|\\b)", re.IGNORECASE),
)
SECRET_MARKERS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(rb"sk-[A-Za-z0-9]{20,}"),
)
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


class PublicReleaseError(ValueError):
    """A deterministic public-stage validation failure."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PublicReleaseError(f"invalid_json:{path}") from exc
    if not isinstance(value, dict):
        raise PublicReleaseError(f"invalid_json_object:{path}")
    return value


def _safe_relative(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PublicReleaseError("unsafe_manifest_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PublicReleaseError(f"unsafe_manifest_path:{value}")
    if any(part in FORBIDDEN_PARTS for part in path.parts):
        raise PublicReleaseError(f"forbidden_manifest_path:{value}")
    if value.endswith(FORBIDDEN_SUFFIXES):
        raise PublicReleaseError(f"forbidden_manifest_suffix:{value}")
    return path


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def manifest_rows(plugin_root: Path) -> list[dict[str, Any]]:
    manifest_path = plugin_root / MANIFEST_RELATIVE
    value = _load_json(manifest_path)
    if set(value) != {
        "files", "package", "release_status", "schema_version",
        "t001_inventory_sha256",
    } or value["schema_version"] != 1:
        raise PublicReleaseError("release_manifest_shape_invalid")
    package = value.get("package")
    if not isinstance(package, dict) or package.get("name") != "codexmax-orchestrator":
        raise PublicReleaseError("release_manifest_package_invalid")
    rows = value.get("files")
    if not isinstance(rows, list) or not rows:
        raise PublicReleaseError("release_manifest_files_invalid")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            raise PublicReleaseError("release_manifest_row_invalid")
        relative = _safe_relative(row["path"])
        text = relative.as_posix()
        if text == MANIFEST_RELATIVE.as_posix() or text in seen:
            raise PublicReleaseError(f"release_manifest_duplicate:{text}")
        if (
            not isinstance(row["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
            or type(row["size"]) is not int
            or row["size"] < 0
        ):
            raise PublicReleaseError(f"release_manifest_row_invalid:{text}")
        seen.add(text)
        normalized.append(dict(row))
    if [row["path"] for row in normalized] != sorted(seen):
        raise PublicReleaseError("release_manifest_order_invalid")
    return normalized


def validate_manifest_source(plugin_root: Path) -> list[dict[str, Any]]:
    if not plugin_root.is_dir() or plugin_root.is_symlink():
        raise PublicReleaseError("plugin_root_invalid")
    rows = manifest_rows(plugin_root)
    listed = {row["path"] for row in rows}
    physical = {
        path.relative_to(plugin_root).as_posix()
        for path in plugin_root.rglob("*")
        if path.is_file() and path.relative_to(plugin_root).as_posix() != MANIFEST_RELATIVE.as_posix()
    }
    if not listed.issubset(physical):
        raise PublicReleaseError(
            f"release_manifest_stale:missing={sorted(listed-physical)!r}"
        )
    for row in rows:
        path = plugin_root / row["path"]
        if path.is_symlink():
            raise PublicReleaseError(f"symlink_forbidden:{row['path']}")
        raw = path.read_bytes()
        if len(raw) != row["size"] or _sha256(raw) != row["sha256"]:
            raise PublicReleaseError(f"release_manifest_stale:{row['path']}")
    return rows


def _iter_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PublicReleaseError(
                f"symlink_forbidden:{path.relative_to(root).as_posix()}"
            )
        if path.is_file():
            yield path


def _validate_links(root: Path, files: Iterable[Path]) -> None:
    for path in files:
        if path.suffix.lower() != ".md":
            continue
        text = path.read_text(encoding="utf-8")
        for target in MARKDOWN_LINK.findall(text):
            target = target.strip().split("#", 1)[0]
            if not target or target.startswith(("https://", "http://", "mailto:")):
                continue
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1]
            resolved = (path.parent / target).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError as exc:
                raise PublicReleaseError(
                    f"link_escapes_stage:{path.relative_to(root)}:{target}"
                ) from exc
            if not resolved.exists():
                raise PublicReleaseError(
                    f"broken_local_link:{path.relative_to(root)}:{target}"
                )


def _validate_metadata(root: Path) -> None:
    package = _load_json(root / "package.json")
    plugin_root = root / PLUGIN_RELATIVE
    plugin = _load_json(plugin_root / ".codex-plugin/plugin.json")
    release = _load_json(plugin_root / MANIFEST_RELATIVE)
    release_package = release.get("package")
    identities = (
        (package.get("name"), package.get("version")),
        (plugin.get("name"), plugin.get("version")),
        (
            release_package.get("name") if isinstance(release_package, dict) else None,
            release_package.get("version") if isinstance(release_package, dict) else None,
        ),
    )
    if (
        any(not isinstance(name, str) or not isinstance(version, str) or not version for name, version in identities)
        or len(set(identities)) != 1
    ):
        raise PublicReleaseError("package_identity_mismatch")
    if (
        package.get("name") != "codexmax-orchestrator"
        or package.get("private") is not True
        or package.get("license") != "Apache-2.0"
        or package.get("author") != "Vel Labs"
        or package.get("repository", {}).get("url") != REPOSITORY_URL + ".git"
        or package.get("bugs", {}).get("url") != REPOSITORY_URL + "/issues"
    ):
        raise PublicReleaseError("root_metadata_invalid")
    if (
        plugin.get("name") != "codexmax-orchestrator"
        or plugin.get("author", {}).get("name") != "Vel Labs"
        or plugin.get("interface", {}).get("displayName") != "Orcastrata Max"
    ):
        raise PublicReleaseError("plugin_metadata_invalid")
    marketplace = _load_json(root / ".agents/plugins/marketplace.json")
    plugins = marketplace.get("plugins")
    entry = plugins[0] if isinstance(plugins, list) and len(plugins) == 1 and isinstance(plugins[0], dict) else {}
    if (
        marketplace.get("interface", {}).get("displayName") != "Orcastrata Max"
        or entry.get("name") != "codexmax-orchestrator"
        or entry.get("source") != {"source": "local", "path": "./plugins/codexmax-orchestrator"}
        or entry.get("policy") != {"installation": "AVAILABLE", "authentication": "ON_USE"}
    ):
        raise PublicReleaseError("marketplace_metadata_invalid")


def validate_stage(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise PublicReleaseError("stage_root_invalid")
    expected_roots = set(ROOT_PUBLIC_FILES) | {
        (PLUGIN_RELATIVE / MANIFEST_RELATIVE).as_posix()
    }
    plugin_root = root / PLUGIN_RELATIVE
    rows = validate_manifest_source(plugin_root)
    expected = expected_roots | {
        (PLUGIN_RELATIVE / row["path"]).as_posix() for row in rows
    }
    files = list(_iter_files(root))
    actual = {path.relative_to(root).as_posix() for path in files}
    if actual != expected:
        raise PublicReleaseError(
            f"public_stage_inventory_invalid:missing={sorted(expected-actual)!r}:"
            f"extra={sorted(actual-expected)!r}"
        )
    for path in files:
        relative = path.relative_to(root).as_posix()
        if any(part in FORBIDDEN_PARTS for part in PurePosixPath(relative).parts):
            raise PublicReleaseError(f"forbidden_public_path:{relative}")
        if relative.endswith(FORBIDDEN_SUFFIXES):
            raise PublicReleaseError(f"forbidden_public_suffix:{relative}")
        raw = path.read_bytes()
        for marker in PERSONAL_PATHS:
            if marker.search(raw):
                raise PublicReleaseError(f"personal_path_detected:{relative}")
        for marker in SECRET_MARKERS:
            if marker.search(raw):
                raise PublicReleaseError(f"secret_marker_detected:{relative}")
        if path.suffix.lower() in TEXT_SUFFIXES:
            try:
                raw.decode("utf-8")
            except UnicodeError as exc:
                raise PublicReleaseError(f"invalid_utf8:{relative}") from exc
    _validate_links(root, files)
    _validate_metadata(root)
    return {
        "status": "valid",
        "file_count": len(files),
        "plugin_payload_rows": len(rows),
        "repository": REPOSITORY_URL,
        "publication_proved": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = validate_stage(args.stage)
    except PublicReleaseError as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
