#!/usr/bin/env python3
"""Resolve bounded Orcastrata project context without broad workspace scans."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

SCHEMA_VERSION = 1
PROJECT_MANIFEST = ".orcastrata/project.json"
WORKSPACE_MANIFEST = ".orcastrata/workspace.json"
MAX_CONTEXT_FILES = 20
MAX_CONTEXT_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_WORKSPACE_PROJECTS = 100
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SKILL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_DISPLAY_NAME = 160
PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class ProjectError(ValueError):
    """Stable fail-closed project-context error."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _root(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ProjectError("project_root_invalid")
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ProjectError("project_root_unavailable") from exc
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or resolved != path:
        raise ProjectError("project_root_alias_or_not_directory")
    return resolved


def _safe_relative(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ProjectError("manifest_invalid", field)
    candidate = Path(value)
    if candidate.is_absolute() or "\\" in value or ".." in candidate.parts or "." in candidate.parts:
        raise ProjectError("manifest_path_invalid", field)
    return candidate.as_posix()


def _safe_display_name(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_DISPLAY_NAME:
        raise ProjectError("manifest_invalid", "display_name")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ProjectError("manifest_invalid", "display_name")
    return value


def _installed_skill_ids() -> set[str]:
    skills_root = PLUGIN_ROOT / "skills"
    return {
        path.parent.name
        for path in skills_root.glob("*/SKILL.md")
        if path.is_file()
    }


def _read_manifest(path: Path, kind: str) -> dict[str, Any]:
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
        if (
            resolved != path
            or stat.S_ISLNK(named.st_mode)
            or not stat.S_ISREG(named.st_mode)
            or named.st_nlink != 1
            or named.st_size > MAX_MANIFEST_BYTES
        ):
            raise ProjectError("manifest_unsafe", kind)
        value = json.loads(path.read_text(encoding="utf-8"))
    except ProjectError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectError("manifest_unreadable", kind) from exc
    if not isinstance(value, dict):
        raise ProjectError("manifest_invalid", kind)
    return value


def _read_context_file(root: Path, relative: str) -> bytes:
    lexical = root / relative
    try:
        named = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise ProjectError("context_file_unreadable", relative) from exc
    if resolved != lexical or root not in resolved.parents:
        raise ProjectError("context_file_unsafe", relative)
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise ProjectError("context_file_unsafe", relative)
    try:
        raw = lexical.read_bytes()
    except OSError as exc:
        raise ProjectError("context_file_unreadable", relative) from exc
    return raw


def _validate_context(root: Path, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"files", "max_files", "max_bytes"}:
        raise ProjectError("manifest_invalid", "context")
    files = value.get("files", [])
    max_files = value.get("max_files", MAX_CONTEXT_FILES)
    max_bytes = value.get("max_bytes", MAX_CONTEXT_BYTES)
    if type(max_files) is not int or not 0 <= max_files <= MAX_CONTEXT_FILES:
        raise ProjectError("context_limit_invalid", "max_files")
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_CONTEXT_BYTES:
        raise ProjectError("context_limit_invalid", "max_bytes")
    if not isinstance(files, list) or len(files) > max_files:
        raise ProjectError("context_files_invalid", "count")
    result: list[dict[str, Any]] = []
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ProjectError("context_pointer_invalid", "fields")
        relative = _safe_relative(item["path"], "context.path")
        digest = item["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ProjectError("context_pointer_invalid", "sha256")
        if relative == PROJECT_MANIFEST or relative.startswith(".orcastrata/"):
            raise ProjectError("context_pointer_invalid", "orcastrata_path")
        raw = _read_context_file(root, relative)
        if len(raw) > max_bytes or total + len(raw) > max_bytes:
            raise ProjectError("context_limit_exceeded", relative)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
            raise ProjectError("context_hash_mismatch", relative)
        total += len(raw)
        result.append({"path": relative, "sha256": digest, "bytes": len(raw)})
    return {"files": result, "max_files": max_files, "max_bytes": max_bytes, "bytes": total}


def validate_project(root: str | Path, value: Any) -> dict[str, Any]:
    project_root = _root(root)
    if not isinstance(value, dict):
        raise ProjectError("manifest_invalid")
    required = {"schema_version", "manifest_type", "project_id", "display_name", "context", "skills", "scope", "usage"}
    if set(value) != required:
        raise ProjectError("manifest_invalid", "fields")
    if value["schema_version"] != SCHEMA_VERSION or value["manifest_type"] != "orcastrata_project_v1":
        raise ProjectError("manifest_invalid", "identity")
    if not isinstance(value["project_id"], str) or not ID_RE.fullmatch(value["project_id"]):
        raise ProjectError("manifest_invalid", "project_id")
    _safe_display_name(value["display_name"])
    skills = value["skills"]
    if not isinstance(skills, list) or any(not isinstance(item, str) or not SKILL_ID_RE.fullmatch(item) for item in skills):
        raise ProjectError("manifest_invalid", "skills")
    if any(item not in _installed_skill_ids() for item in skills):
        raise ProjectError("manifest_skill_unavailable")
    scope = value["scope"]
    if not isinstance(scope, dict) or set(scope) != {"root", "exclusions"} or scope.get("root") != "." or not isinstance(scope.get("exclusions"), list):
        raise ProjectError("manifest_invalid", "scope")
    if any((not isinstance(item, str) or item in {".", ""}) for item in scope["exclusions"]):
        raise ProjectError("manifest_invalid", "scope.exclusions")
    for item in scope["exclusions"]:
        _safe_relative(item, "scope.exclusions")
    usage = value["usage"]
    if not isinstance(usage, dict) or set(usage) != {"ledger", "privacy"} or usage.get("ledger") != ".orcastrata/usage/dispatch.jsonl" or usage.get("privacy") != "metadata_only":
        raise ProjectError("manifest_invalid", "usage")
    return {
        "project_root": project_root,
        "manifest": json.loads(json.dumps(value)),
        "context": _validate_context(project_root, value["context"]),
    }


def find_nearest(start: str | Path, *, boundary: str | Path | None = None) -> dict[str, Any] | None:
    current = _root(start)
    boundary_root = _root(boundary) if boundary is not None else None
    if boundary_root is not None and current != boundary_root and boundary_root not in current.parents:
        raise ProjectError("project_boundary_mismatch")
    candidates = (current, *current.parents)
    for candidate in candidates:
        if boundary_root is not None and candidate != boundary_root and boundary_root not in candidate.parents:
            break
        marker = candidate / PROJECT_MANIFEST
        if marker.is_file():
            value = _read_manifest(marker, "project")
            return validate_project(candidate, value)
    return None


def _validate_workspace(workspace_root: Path, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "manifest_type", "workspace_id", "projects"}:
        raise ProjectError("workspace_manifest_invalid", "fields")
    if value["schema_version"] != SCHEMA_VERSION or value["manifest_type"] != "orcastrata_workspace_v1":
        raise ProjectError("workspace_manifest_invalid", "identity")
    if not isinstance(value["workspace_id"], str) or not ID_RE.fullmatch(value["workspace_id"]):
        raise ProjectError("workspace_manifest_invalid", "workspace_id")
    projects = value["projects"]
    if not isinstance(projects, list) or len(projects) > MAX_WORKSPACE_PROJECTS:
        raise ProjectError("workspace_manifest_invalid", "projects")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in projects:
        if not isinstance(item, dict) or set(item) != {"project_id", "root"}:
            raise ProjectError("workspace_project_invalid", "fields")
        project_id = item["project_id"]
        relative = _safe_relative(item["root"], "projects.root")
        if not isinstance(project_id, str) or not ID_RE.fullmatch(project_id):
            raise ProjectError("workspace_project_invalid", "project_id")
        if project_id in seen:
            raise ProjectError("workspace_project_duplicate", project_id)
        seen.add(project_id)
        project_root = workspace_root / relative
        try:
            named = project_root.lstat()
            resolved = project_root.resolve(strict=True)
        except OSError as exc:
            raise ProjectError("workspace_project_unavailable", relative) from exc
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or resolved.parent != workspace_root and workspace_root not in resolved.parents:
            raise ProjectError("workspace_project_outside_root", relative)
        if resolved != project_root:
            raise ProjectError("workspace_project_symlink_alias", relative)
        project = find_nearest(resolved, boundary=workspace_root)
        if project is None or project["project_root"] != resolved or project["manifest"]["project_id"] != project_id:
            raise ProjectError("workspace_project_unconfigured", relative)
        result.append({"project_id": project_id, "root": relative, "context": project["context"]})
    return {"manifest": value, "projects": result}


def registered_projects(workspace_root: str | Path) -> dict[str, Any]:
    root = _root(workspace_root)
    value = _read_manifest(root / WORKSPACE_MANIFEST, "workspace")
    return _validate_workspace(root, value)


def _prepare_orcastrata_directory(root: Path) -> Path:
    directory = root / ".orcastrata"
    if directory.exists() or directory.is_symlink():
        try:
            named = directory.lstat()
            resolved = directory.resolve(strict=True)
        except OSError as exc:
            raise ProjectError("orcastrata_directory_unsafe") from exc
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or resolved != directory:
            raise ProjectError("orcastrata_directory_unsafe")
    else:
        directory.mkdir(mode=0o700)
    return directory


def init_workspace(workspace_root: str | Path, *, workspace_id: str, projects: list[dict[str, str]]) -> Path:
    root = _root(workspace_root)
    if not ID_RE.fullmatch(workspace_id):
        raise ProjectError("workspace_id_invalid")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "manifest_type": "orcastrata_workspace_v1",
        "workspace_id": workspace_id,
        "projects": projects,
    }
    marker = root / WORKSPACE_MANIFEST
    if marker.exists() or marker.is_symlink():
        raise ProjectError("workspace_already_initialized")
    _validate_workspace(root, manifest)
    _prepare_orcastrata_directory(root)
    with marker.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return marker


def descriptor(start: str | Path, *, workspace: bool = False) -> dict[str, Any]:
    project = find_nearest(start)
    result: dict[str, Any] = {
        "status": "configured" if project else "not_configured",
        "project": None,
        "workspace": None,
    }
    if project:
        result["project"] = {
            "project_id": project["manifest"]["project_id"],
            "display_name": project["manifest"]["display_name"],
            "context": project["context"],
            "installed_skill_ids": list(project["manifest"]["skills"]),
            "usage_ledger": ".orcastrata/usage/dispatch.jsonl",
        }
    if workspace:
        result["workspace"] = registered_projects(start)
    return result


def init_project(project_root: str | Path, *, project_id: str, display_name: str | None = None, context_files: list[str] | None = None, skills: list[str] | None = None) -> Path:
    root = _root(project_root)
    if not ID_RE.fullmatch(project_id):
        raise ProjectError("project_id_invalid")
    pointers: list[dict[str, str]] = []
    for relative in context_files or []:
        safe = _safe_relative(relative, "context_file")
        raw = _read_context_file(root, safe)
        pointers.append({"path": safe, "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()})
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "manifest_type": "orcastrata_project_v1",
        "project_id": project_id,
        "display_name": display_name or project_id,
        "context": {"files": pointers, "max_files": MAX_CONTEXT_FILES, "max_bytes": MAX_CONTEXT_BYTES},
        "skills": list(skills or []),
        "scope": {"root": ".", "exclusions": [".orcastrata", ".codexmax"]},
        "usage": {"ledger": ".orcastrata/usage/dispatch.jsonl", "privacy": "metadata_only"},
    }
    marker = root / PROJECT_MANIFEST
    if marker.exists() or marker.is_symlink():
        raise ProjectError("project_already_initialized")
    # Validate before creating the marker directory. Invalid input leaves no
    # project marker or runtime directory behind.
    validate_project(root, manifest)
    _prepare_orcastrata_directory(root)
    with marker.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return marker


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--project-root", required=True)
    init.add_argument("--project-id", required=True)
    init.add_argument("--display-name")
    init.add_argument("--context-file", action="append", default=[])
    init.add_argument("--skill-id", action="append", default=[])
    workspace_init = commands.add_parser("init-workspace")
    workspace_init.add_argument("--workspace-root", required=True)
    workspace_init.add_argument("--workspace-id", required=True)
    workspace_init.add_argument("--project", action="append", default=[], metavar="PROJECT_ID=RELATIVE_ROOT")
    describe = commands.add_parser("describe")
    describe.add_argument("--project-root", required=True)
    describe.add_argument("--workspace", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            result: Any = {"status": "created", "path": init_project(args.project_root, project_id=args.project_id, display_name=args.display_name, context_files=args.context_file, skills=args.skill_id).relative_to(Path(args.project_root).resolve()).as_posix()}
        elif args.command == "init-workspace":
            projects: list[dict[str, str]] = []
            for item in args.project:
                if "=" not in item:
                    raise ProjectError("workspace_project_invalid", "project must be PROJECT_ID=RELATIVE_ROOT")
                project_id, relative = item.split("=", 1)
                projects.append({"project_id": project_id, "root": relative})
            result = {"status": "created", "path": init_workspace(args.workspace_root, workspace_id=args.workspace_id, projects=projects).relative_to(Path(args.workspace_root).resolve()).as_posix()}
        else:
            result = descriptor(args.project_root, workspace=args.workspace)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except ProjectError as exc:
        print(json.dumps({"status": "failed", "code": exc.code}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
