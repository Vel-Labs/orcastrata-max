#!/usr/bin/env python3
"""Build a bounded, read-only repository opportunity map."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any

try:
    import orcastrata_project
except ImportError:  # pragma: no cover - direct source loading fallback
    import importlib.util
    _SPEC = importlib.util.spec_from_file_location(
        "orcastrata_project_discovery", Path(__file__).with_name("orcastrata_project.py")
    )
    assert _SPEC and _SPEC.loader
    orcastrata_project = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(orcastrata_project)

sys.dont_write_bytecode = True


SCHEMA_VERSION = 1
MAX_FILES_DEFAULT = 20_000
MAX_KEY_FILES = 200
MAX_SIGNAL_PATHS = 100
MAX_ROADMAP_FILES = 20
MAX_ROADMAP_ITEMS = 50
MAX_ROADMAP_BYTES = 256 * 1024
MAX_ITEM_CHARS = 240
EXCLUDED_DIRECTORIES = {
    ".git", ".goalbuddy-board", ".hg", ".svn", ".cache", ".codex", ".idea", ".tox",
    ".venv", "__pycache__", "build", "coverage", "dist", "node_modules",
    "raw", "reports", "target", "vendor", ".codexmax", ".orcastrata",
}
SECRET_FILENAMES = {
    ".env", ".npmrc", ".pypirc", "credentials", "credentials.json",
    "id_rsa", "id_ed25519", "secrets.json",
}
PROJECT_MANIFESTS = {
    "cargo.toml", "composer.json", "deno.json", "deno.jsonc", "gemfile",
    "go.mod", "package.json", "pom.xml", "pyproject.toml", "requirements.txt",
}
ROADMAP_NAMES = {
    "backlog.md", "milestones.md", "next-steps.md", "next_steps.md",
    "plan.md", "roadmap.md", "todo.md",
}
SOURCE_DIRECTORIES = {"app", "apps", "cmd", "crates", "lib", "packages", "src"}
TEST_DIRECTORIES = {"spec", "specs", "test", "tests"}
SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".mjs", ".php", ".py", ".rb", ".rs", ".scala",
    ".sh", ".swift", ".ts", ".tsx",
}
CHECKBOX_RE = re.compile(r"^\s*[-*]\s+\[\s\]\s+(.+?)\s*$")
HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*$")
SECRET_TEXT_RE = re.compile(
    r"(?i)(?:api[_ -]?key|access[_ -]?token|password|client[_ -]?secret|"
    r"private[_ -]?key)\s*[:=]\s*\S+|-----BEGIN [A-Z ]+PRIVATE KEY-----"
)


class DiscoveryError(ValueError):
    """Stable, non-sensitive repository discovery error."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical_json(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True,
    )


def _repository_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise DiscoveryError("repository_root_invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise DiscoveryError("repository_root_invalid")
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DiscoveryError("repository_root_unavailable") from error
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise DiscoveryError("repository_root_alias_or_not_directory")
    if resolved != Path(os.path.abspath(path)):
        raise DiscoveryError("repository_root_alias_or_not_directory")
    return resolved


def _relative(root: Path, path: Path) -> str:
    relative = path.relative_to(root).as_posix()
    parsed = PurePosixPath(relative)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in parsed.parts):
        raise DiscoveryError("repository_entry_invalid")
    return relative


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in SECRET_FILENAMES or lowered.endswith((".pem", ".key", ".p12"))


def _is_key_file(relative: str) -> bool:
    path = PurePosixPath(relative)
    name = path.name.lower()
    parts = {part.lower() for part in path.parts}
    return (
        name in PROJECT_MANIFESTS
        or name in ROADMAP_NAMES
        or name.startswith(("readme", "license", "changelog", "contributing", "security"))
        or name in {"agents.md", "dockerfile", "makefile", "justfile"}
        or name.endswith((".config.js", ".config.ts", ".config.mjs"))
        or ".github" in parts
        or "docs" in parts
        or ("goals" in parts and name in {"goal.md", "state.yaml", "state.yml"})
    )


def _is_roadmap(relative: str) -> bool:
    path = PurePosixPath(relative)
    name = path.name.lower()
    stem = path.stem.lower().replace("_", "-")
    return (
        path.suffix.lower() in {".md", ".markdown"}
        and len(path.parts) <= 6
        and not bool({part.lower() for part in path.parts} & TEST_DIRECTORIES)
        and (
            name in ROADMAP_NAMES
            or any(token in stem for token in ("roadmap", "backlog", "next-step"))
        )
    )


def _walk(root: Path, max_files: int) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    excluded_directories: set[str] = set()
    skipped = {"secret_name": 0, "special": 0, "symlink": 0}
    stack = [root]
    truncated = False
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise DiscoveryError("repository_tree_unavailable") from error
        child_directories: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                item = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise DiscoveryError("repository_tree_unavailable") from error
            relative = _relative(root, path)
            if stat.S_ISLNK(item.st_mode):
                skipped["symlink"] += 1
                continue
            if stat.S_ISDIR(item.st_mode):
                if entry.name.lower() in EXCLUDED_DIRECTORIES:
                    excluded_directories.add(relative)
                else:
                    child_directories.append(path)
                continue
            if not stat.S_ISREG(item.st_mode):
                skipped["special"] += 1
                continue
            if _is_secret_name(entry.name):
                skipped["secret_name"] += 1
                continue
            if len(files) >= max_files:
                truncated = True
                stack.clear()
                break
            files.append({
                "link_count": item.st_nlink,
                "path": relative,
                "size": item.st_size,
            })
        if truncated:
            break
        stack.extend(reversed(child_directories))
    files.sort(key=lambda row: row["path"])
    return {
        "excluded_directories": sorted(excluded_directories),
        "files": files,
        "skipped": skipped,
        "truncated": truncated,
    }


def _sanitize_item(text: str) -> tuple[str, bool]:
    normalized = " ".join(text.replace("\x00", " ").split())
    if SECRET_TEXT_RE.search(normalized):
        return "[redacted: secret-like roadmap text]", True
    if len(normalized) > MAX_ITEM_CHARS:
        return normalized[: MAX_ITEM_CHARS - 1].rstrip() + "…", False
    return normalized, False


def _roadmaps(root: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates = [row for row in rows if _is_roadmap(row["path"])]
    candidates = candidates[:MAX_ROADMAP_FILES]
    result: list[dict[str, Any]] = []
    total_items = 0
    for row in candidates:
        base = {"path": row["path"], "size": row["size"]}
        if row["link_count"] != 1:
            result.append({**base, "headings": [], "items": [], "status": "hardlink_rejected"})
            continue
        if row["size"] > MAX_ROADMAP_BYTES:
            result.append({**base, "headings": [], "items": [], "status": "oversize_rejected"})
            continue
        path = root / row["path"]
        try:
            raw = path.read_bytes()
        except OSError:
            result.append({**base, "headings": [], "items": [], "status": "unreadable"})
            continue
        if len(raw) != row["size"]:
            result.append({**base, "headings": [], "items": [], "status": "identity_changed"})
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            result.append({**base, "headings": [], "items": [], "status": "invalid_utf8"})
            continue
        items: list[dict[str, Any]] = []
        headings: list[dict[str, Any]] = []
        for number, line in enumerate(text.splitlines(), start=1):
            heading = HEADING_RE.fullmatch(line)
            if heading and len(headings) < 20:
                title, redacted = _sanitize_item(heading.group(1))
                headings.append({"line": number, "redacted": redacted, "title": title})
            match = CHECKBOX_RE.fullmatch(line)
            if match and total_items < MAX_ROADMAP_ITEMS:
                item, redacted = _sanitize_item(match.group(1))
                items.append({"line": number, "redacted": redacted, "text": item})
                total_items += 1
        result.append({
            **base,
            "headings": headings,
            "items": items,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "status": "read_local",
        })
    return {
        "file_limit": MAX_ROADMAP_FILES,
        "files": result,
        "item_limit": MAX_ROADMAP_ITEMS,
        "items_found": total_items,
        "truncated": len([row for row in rows if _is_roadmap(row["path"])]) > len(candidates)
        or total_items >= MAX_ROADMAP_ITEMS,
    }


def _signals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    paths = [row["path"] for row in rows]
    lowered = [path.lower() for path in paths]
    top_level = sorted({PurePosixPath(path).parts[0] for path in paths})
    extensions: dict[str, int] = {}
    for path in paths:
        suffix = PurePosixPath(path).suffix.lower() or "[no_extension]"
        extensions[suffix] = extensions.get(suffix, 0) + 1
    def matching(predicate) -> list[str]:
        return [path for path in paths if predicate(path, path.lower())]
    def in_test_tree(path: str) -> bool:
        return bool(set(PurePosixPath(path.lower()).parts) & TEST_DIRECTORIES)
    def is_test(path: str) -> bool:
        parsed = PurePosixPath(path.lower())
        return parsed.suffix in SOURCE_EXTENSIONS and (
            in_test_tree(path) or parsed.name.startswith("test_")
        )
    def is_source(path: str) -> bool:
        parsed = PurePosixPath(path.lower())
        if is_test(path) or bool(set(parsed.parts) & {"docs", ".github"}):
            return False
        return bool(set(parsed.parts) & SOURCE_DIRECTORIES) or parsed.suffix in SOURCE_EXTENSIONS
    matches = {
        "automation": matching(lambda path, lower: lower.startswith(".github/workflows/") or PurePosixPath(lower).name in {".gitlab-ci.yml", "jenkinsfile"}),
        "changelog": matching(lambda path, lower: not in_test_tree(path) and PurePosixPath(lower).name.startswith("changelog")),
        "contributing": matching(lambda path, lower: not in_test_tree(path) and PurePosixPath(lower).name.startswith("contributing")),
        "documentation": matching(lambda path, lower: lower.startswith("docs/")),
        "goal_states": matching(lambda path, lower: not in_test_tree(path) and "/goals/" in "/" + lower and PurePosixPath(lower).name in {"state.yaml", "state.yml"}),
        "licenses": matching(lambda path, lower: not in_test_tree(path) and PurePosixPath(lower).name.startswith(("license", "copying"))),
        "manifests": matching(lambda path, lower: not in_test_tree(path) and PurePosixPath(lower).name in PROJECT_MANIFESTS),
        "readmes": matching(lambda path, lower: not in_test_tree(path) and PurePosixPath(lower).name.startswith("readme")),
        "security": matching(lambda path, lower: not in_test_tree(path) and PurePosixPath(lower).name.startswith("security")),
        "source_files": matching(lambda path, lower: is_source(path)),
        "test_files": matching(lambda path, lower: is_test(path)),
    }
    return {
        **{key: values[:MAX_SIGNAL_PATHS] for key, values in matches.items()},
        "counts": {key: len(values) for key, values in matches.items()},
        "extensions": dict(sorted(extensions.items(), key=lambda item: (-item[1], item[0]))[:20]),
        "path_limit_per_signal": MAX_SIGNAL_PATHS,
        "top_level": top_level[:MAX_SIGNAL_PATHS],
        "top_level_count": len(top_level),
    }


def _prompt(outcome: str, evidence: list[str]) -> str:
    basis = ", ".join(evidence[:3]) if evidence else "the repository opportunity map"
    return (
        "Use $codexmax-orchestrator:codexmax-orchestrate to " + outcome
        + ". Begin from " + basis
        + ". Verify current board and repository rules first, propose a bounded "
        "execution preview, and preserve existing work."
    )


def _opportunities(
    signals: dict[str, Any], roadmaps: dict[str, Any], *, truncated: bool
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    def add(identifier: str, category: str, score: int, horizon: str, title: str,
            rationale: str, evidence: list[str], outcome: str, confidence: str = "high") -> None:
        rows.append({
            "basis": {"inferred": rationale, "observed": evidence, "proposed": outcome},
            "category": category,
            "confidence": confidence,
            "horizon": horizon,
            "id": identifier,
            "orchestrate_prompt": _prompt(outcome, evidence),
            "score": score,
            "title": title,
        })

    roadmap_paths = [row["path"] for row in roadmaps["files"]]
    roadmap_items = [
        {"path": row["path"], **item}
        for row in roadmaps["files"] if row["status"] == "read_local"
        for item in row["items"]
    ]
    if roadmap_items:
        first = roadmap_items[0]
        add(
            "roadmap-next", "roadmap", 100, "next",
            "Turn existing roadmap work into an execution tranche",
            f"Found {len(roadmap_items)} unchecked roadmap items; board truth still requires verification.",
            roadmap_paths,
            "review the current roadmap and GoalBuddy state, prioritize the highest-value unchecked item, and execute one verified tranche",
        )
    elif roadmap_paths:
        add(
            "roadmap-refresh", "roadmap", 82, "next",
            "Reconcile the roadmap with current repository truth",
            "Planning files exist but no bounded unchecked checklist items were observed.",
            roadmap_paths,
            "reconcile the existing roadmap with current code, tests, and GoalBuddy state and propose the next three evidence-backed tranches",
        )
    if signals["goal_states"]:
        add(
            "goal-next-ready", "governance", 96, "next",
            "Inspect canonical goals and resume the best next-ready work",
            "Goal state files are present and may already own priority and dependency truth.",
            signals["goal_states"],
            "inspect canonical GoalBuddy boards, explain active and blocked work, and recommend the highest-value next-ready checkpoint without rewriting board truth",
        )
    if signals["source_files"] and not signals["test_files"] and not truncated:
        add(
            "quality-baseline", "quality", 90, "quick_win",
            "Establish a practical automated quality baseline",
            "Source files were observed but no conventional test files were indexed.",
            signals["source_files"][:3],
            "identify the highest-risk behavior and add a minimal repository-native test and validation baseline",
        )
    if signals["test_files"] and not signals["automation"] and not truncated:
        add(
            "automation-baseline", "automation", 80, "quick_win",
            "Turn existing tests into a repeatable automation gate",
            "Tests were observed without a conventional CI workflow.",
            signals["test_files"][:3],
            "map the existing test commands and add the smallest reliable automation gate appropriate for this repository",
        )
    if not signals["readmes"] and not truncated:
        add(
            "onboarding", "documentation", 78, "quick_win",
            "Create a source-backed operator and contributor entry point",
            "No conventional README was indexed.", [],
            "derive a concise repository README from current manifests, source layout, validation commands, and planning artifacts",
        )
    if signals["manifests"]:
        add(
            "dependency-health", "maintenance", 68, "quick_win",
            "Audit dependency and developer-command health",
            "Project manifests provide a concrete starting point for dependency, script, and runtime review.",
            signals["manifests"],
            "audit project manifests for stale dependencies, missing scripts, reproducibility gaps, and low-risk developer-experience improvements",
        )
    if signals["counts"]["source_files"] >= 200:
        add(
            "architecture-map", "architecture", 76, "strategic",
            "Build an architecture and ownership map before the next large change",
            "The indexed source surface is large enough that navigation and ownership clarity may provide leverage.",
            signals["source_files"][:3],
            "produce a verified architecture, dependency, and ownership map and identify the three highest-leverage simplification opportunities",
            "medium",
        )
    if signals["manifests"] and not signals["licenses"] and not truncated:
        add(
            "release-boundary", "release", 45, "strategic",
            "Clarify local-use versus distribution readiness",
            "Project manifests exist but no conventional license file was indexed.",
            signals["manifests"],
            "assess packaging and publication gaps without selecting a license or making a release claim",
        )
    add(
        "repository-map", "orientation", 60, "quick_win",
        "Create a navigable project map and focused improvement shortlist",
        "A bounded structural index is available even when no single roadmap item dominates.",
        (signals["readmes"] + signals["manifests"] + signals["documentation"])[:3],
        "turn the repository index into a concise architecture map, validation map, risk register, and ranked 30-minute, one-day, and one-week improvements",
        "medium",
    )
    return sorted(rows, key=lambda row: (-row["score"], row["id"]))[:8]


def discover(repo_root: object, *, max_files: int = MAX_FILES_DEFAULT) -> dict[str, Any]:
    if type(max_files) is not int or max_files < 1 or max_files > MAX_FILES_DEFAULT:
        raise DiscoveryError("max_files_invalid")
    root = _repository_root(repo_root)
    walked = _walk(root, max_files)
    try:
        project = orcastrata_project.find_nearest(root, boundary=root)
        project_context = {
            "status": "configured" if project else "not_configured",
            "project_id": project["manifest"]["project_id"] if project else None,
            "display_name": project["manifest"]["display_name"] if project else None,
            "context": project["context"] if project else None,
            "installed_skill_ids": list(project["manifest"]["skills"]) if project else [],
            "authority": "installed_skill_ids_are_references_only",
        }
    except orcastrata_project.ProjectError as error:
        project_context = {
            "status": "invalid",
            "code": error.code,
            "authority": "installed_skill_ids_are_references_only",
        }
    signals = _signals(walked["files"])
    roadmaps = _roadmaps(root, walked["files"])
    key_files = sorted(
        row["path"] for row in walked["files"] if _is_key_file(row["path"])
    )[:MAX_KEY_FILES]
    return {
        "index": {
            "excluded_directories": walked["excluded_directories"],
            "file_count": len(walked["files"]),
            "file_limit": max_files,
            "key_file_limit": MAX_KEY_FILES,
            "key_files": key_files,
            "skipped": walked["skipped"],
            "truncated": walked["truncated"],
        },
        "limitations": [
            "read-only structural discovery; recommendations are proposals, not accepted board truth",
            "general file contents are not read; only bounded roadmap Markdown headings and unchecked items are projected",
            "excluded, secret-named, symlinked, special, oversized, hard-linked, or out-of-bound content cannot support a recommendation",
            ".orcastrata and .codexmax contents are excluded; only the bounded project-context descriptor is exposed",
            "each signal projects at most 100 relative paths while preserving its total observed count",
            "absence-based opportunities are suppressed when the file index is truncated",
        ],
        "operation": "discover_repository",
        "opportunities": _opportunities(
            signals, roadmaps, truncated=walked["truncated"]
        ),
        "proof_boundary": "local_read_only",
        "project_context": project_context,
        "roadmaps": roadmaps,
        "schema_version": SCHEMA_VERSION,
        "signals": signals,
        "status": "ok",
    }


def discover_workspace(workspace_root: object, *, max_files: int = MAX_FILES_DEFAULT) -> dict[str, Any]:
    """Discover only projects named by one explicit workspace registry."""
    if type(max_files) is not int or max_files < 1 or max_files > MAX_FILES_DEFAULT:
        raise DiscoveryError("max_files_invalid")
    root = _repository_root(workspace_root)
    try:
        registry = orcastrata_project.registered_projects(root)
    except orcastrata_project.ProjectError as error:
        raise DiscoveryError("workspace_context_invalid") from error
    projects = []
    for registered in registry["projects"]:
        projects.append({
            "project_id": registered["project_id"],
            "root": registered["root"],
            "discovery": discover(root / registered["root"], max_files=max_files),
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "ok",
        "operation": "discover_workspace",
        "workspace_id": registry["manifest"]["workspace_id"],
        "registered_projects": projects,
        "registered_project_count": len(projects),
        "proof_boundary": "registered_projects_only_local_read_only",
        "limitations": [
            "only explicit workspace registrations are read",
            "unregistered sibling directories are not scanned",
            "project context and skills are evidence references, not authority",
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a bounded, read-only Codexmax repository opportunity map."
    )
    roots = parser.add_mutually_exclusive_group(required=True)
    roots.add_argument("--repo-root")
    roots.add_argument("--workspace-root")
    parser.add_argument("--max-files", type=int, default=MAX_FILES_DEFAULT)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = (
            discover(args.repo_root, max_files=args.max_files)
            if args.repo_root is not None
            else discover_workspace(args.workspace_root, max_files=args.max_files)
        )
    except DiscoveryError as error:
        result = {
            "error": error.code,
            "operation": "discover_repository",
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
        }
        print(canonical_json(result))
        return 1
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
