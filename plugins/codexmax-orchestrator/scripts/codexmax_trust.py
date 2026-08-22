#!/usr/bin/env python3
"""Audit local Codexmax trust controls and measure the deterministic audit."""

from __future__ import annotations

import argparse
import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
from typing import Any


PROTOCOL = "codexmax_trust"
SCHEMA_VERSION = 1
PLUGIN = Path("plugins/codexmax-orchestrator")
DEFAULT_SOURCE_MAP = PLUGIN / "assets/templates/trust-source-map.json"
NOTICE = PLUGIN / "THIRD_PARTY_NOTICES.md"
PACKAGE = Path("package.json")
ACCEPTED_T001_INVENTORY = Path(
    "tests/fixtures/archive-derived/reports/"
    "codexmax-product-surface-release-20260717T132709Z/"
    "t001/release-inventory.json"
)
ACCEPTED_T001_INVENTORY_SHA256 = (
    "c4134153b8ab9868ac9104cce5b8f975bd18c954f75523bb5ecc4cd6a45c973d"
)
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{2,63}$")
DEPENDENCY_SECTIONS = (
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"
)
EXTERNAL_RUNTIME_MODULES = frozenset({"codexmax_package_host"})
REQUIRED_CATEGORIES = {
    "accessibility", "billing", "filesystem", "integrity", "migration",
    "privacy", "recovery", "status", "support",
}
HOST_DEFAULT_PROMPT_LABELS = ("Orchestrate", "Discover", "Audit")
PUBLIC_README_HEADINGS = (
    "## Start In 60 Seconds",
    "## Use An Exact Tool And Model",
    "## Authority Is Task-Local",
    "## Main Skills",
    "## Support Matrix",
)
THREAT_SURFACES = [
    {
        "surface": "explicit_local_files",
        "threats": ["alias", "hardlink", "race", "traversal"],
        "boundary": "canonical bounded single-link descriptor reads",
    },
    {
        "surface": "durable_state",
        "threats": ["corruption", "duplicate", "interruption", "stale_hash"],
        "boundary": "stable errors and no inferred resume",
    },
    {
        "surface": "migration",
        "threats": ["downgrade", "history_loss", "partial_write"],
        "boundary": "forward-only byte-preserving journaled migration",
    },
    {
        "surface": "configuration_and_routes",
        "threats": ["credential_leak", "silent_metered_fallback"],
        "boundary": "allowlisted projection and explicit route authority",
    },
    {
        "surface": "diagnostics_and_support",
        "threats": ["raw_exception", "raw_path", "secret_export"],
        "boundary": "redacted explicit local export with operator retention",
    },
    {
        "surface": "plugin_interface",
        "threats": ["ambiguous_label", "terminal_control", "unreadable_output"],
        "boundary": "named prompts, structured JSON, and no ANSI output",
    },
]


class TrustError(ValueError):
    """Stable trust-report error without raw input detail."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class DuplicateKeyError(TrustError):
    pass


class Artifact:
    def __init__(self, path: Path, raw: bytes, status: os.stat_result):
        self.path = path
        self.raw = raw
        self.status = status
        self.sha256 = hashlib.sha256(raw).hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True,
    )


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("trust_json_duplicate_key")
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise TrustError("trust_json_non_finite")


def _canonical_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise TrustError("trust_root_invalid")
    path = Path(value)
    if not str(path) or not path.is_absolute() or ".." in path.parts:
        raise TrustError("trust_root_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
        named = path.lstat()
    except OSError as error:
        raise TrustError("trust_root_unavailable") from error
    if (
        resolved != lexical
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
    ):
        raise TrustError("trust_root_alias_forbidden")
    return lexical


def _lexical_path(value: object, root: Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise TrustError("trust_path_invalid")
    path = Path(value)
    if not str(path) or not path.is_absolute() or "\x00" in str(path) or ".." in path.parts:
        raise TrustError("trust_path_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        lexical.relative_to(root)
    except ValueError as error:
        raise TrustError("trust_path_outside_repository") from error
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise TrustError("trust_path_missing") from error
    except OSError as error:
        raise TrustError("trust_path_unavailable") from error
    if resolved != lexical:
        raise TrustError("trust_path_alias_forbidden")
    return lexical


def _assert_identity(path: Path, descriptor: int) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise TrustError("trust_path_identity_changed") from error
    if (
        resolved != path
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or named.st_nlink != 1
        or opened.st_nlink != 1
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise TrustError("trust_path_identity_changed")
    return opened


def _read_bound(value: object, root: Path) -> Artifact:
    path = _lexical_path(value, root)
    try:
        named = path.lstat()
    except OSError as error:
        raise TrustError("trust_path_unavailable") from error
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
        raise TrustError("trust_path_alias_forbidden")
    if named.st_nlink != 1:
        raise TrustError("trust_path_hardlink_forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ELOOP}:
            raise TrustError("trust_path_identity_changed") from error
        raise TrustError("trust_path_unavailable") from error
    try:
        before = _assert_identity(path, descriptor)
        raw = bytearray()
        while len(raw) <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = _assert_identity(path, descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev, after.st_ino, after.st_size
        ):
            raise TrustError("trust_path_identity_changed")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_FILE_BYTES:
        raise TrustError("trust_file_oversize")
    return Artifact(path, bytes(raw), after)


def _load_json(artifact: Artifact) -> dict[str, Any]:
    try:
        text = artifact.raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TrustError("trust_json_utf8_invalid") from error
    try:
        value = json.loads(
            text, object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except DuplicateKeyError:
        raise
    except json.JSONDecodeError as error:
        raise TrustError("trust_json_invalid") from error
    if not isinstance(value, dict):
        raise TrustError("trust_json_shape_invalid")
    return value


def _locator(path: Path, root: Path) -> str:
    return "<repository>/" + path.relative_to(root).as_posix()


def _inventory(root: Path) -> tuple[list[dict[str, Any]], list[Artifact]]:
    product = root / PLUGIN
    try:
        named = product.lstat()
        resolved = product.resolve(strict=True)
    except OSError as error:
        raise TrustError("trust_product_missing") from error
    if resolved != product or stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise TrustError("trust_product_alias_forbidden")
    rows: list[dict[str, Any]] = []
    artifacts: list[Artifact] = []
    for path in sorted(product.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        try:
            status = path.lstat()
        except OSError as error:
            raise TrustError("trust_inventory_unavailable") from error
        if stat.S_ISLNK(status.st_mode):
            raise TrustError("trust_inventory_alias_forbidden")
        if stat.S_ISDIR(status.st_mode):
            if path.resolve(strict=True) != path:
                raise TrustError("trust_inventory_alias_forbidden")
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise TrustError("trust_inventory_alias_forbidden")
        artifact = _read_bound(path, root)
        artifacts.append(artifact)
        rows.append({"path": relative, "sha256": artifact.sha256, "size": len(artifact.raw)})
    if not rows:
        raise TrustError("trust_inventory_empty")
    return rows, artifacts


def _parse_imports(artifacts: list[Artifact], root: Path) -> dict[str, Any]:
    scripts = [item for item in artifacts if item.path.suffix == ".py" and "/scripts/" in item.path.as_posix()]
    repository_modules = {item.path.stem for item in scripts if item.path.name != "__init__.py"}
    repository_modules.update(
        item.path.parent.name
        for item in artifacts
        if item.path.name == "__init__.py" and item.path.parent.name.isidentifier()
    )
    modules: set[str] = set()
    syntax_failures: list[str] = []
    for artifact in scripts:
        try:
            tree = ast.parse(artifact.raw.decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            syntax_failures.append(_locator(artifact.path, root))
            continue
        statements: list[ast.stmt] = list(reversed(tree.body))
        while statements:
            node = statements.pop()
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
            children: list[ast.stmt] = []
            handled_fields: set[str] = set()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                children.extend(node.body)
                handled_fields.add("body")
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                children.extend(node.body)
                children.extend(node.orelse)
                handled_fields.update(("body", "orelse"))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                children.extend(node.body)
                handled_fields.add("body")
            elif isinstance(node, (ast.Try, ast.TryStar)):
                children.extend(node.body)
                for handler in node.handlers:
                    children.extend(handler.body)
                children.extend(node.orelse)
                children.extend(node.finalbody)
                handled_fields.update(("body", "handlers", "orelse", "finalbody"))
            elif isinstance(node, ast.Match):
                for case in node.cases:
                    children.extend(case.body)
                handled_fields.add("cases")
            for field, value in ast.iter_fields(node):
                if field in handled_fields:
                    continue
                owns_statement = isinstance(value, ast.stmt) or (
                    isinstance(value, list)
                    and any(isinstance(item, ast.stmt) for item in value)
                )
                if owns_statement:
                    raise TrustError("trust_ast_statement_container_unsupported")
            statements.extend(reversed(children))
    stdlib = sorted(module for module in modules if module in sys.stdlib_module_names)
    repository_local = sorted(
        module for module in modules
        if module not in sys.stdlib_module_names and module in repository_modules
    )
    external_runtime = sorted(
        module for module in modules
        if module not in sys.stdlib_module_names and module in EXTERNAL_RUNTIME_MODULES
    )
    unaccounted = sorted(
        module for module in modules
        if module not in sys.stdlib_module_names
        and module not in repository_modules
        and module not in EXTERNAL_RUNTIME_MODULES
    )
    return {
        "python_script_count": len(scripts),
        "external_runtime_modules": external_runtime,
        "repository_local_modules": repository_local,
        "stdlib_modules": stdlib,
        "syntax_failures": sorted(syntax_failures),
        "unaccounted_modules": unaccounted,
    }


def _package_dependencies(root: Path) -> tuple[list[dict[str, str]], Artifact]:
    artifact = _read_bound(root / PACKAGE, root)
    value = _load_json(artifact)
    rows: list[dict[str, str]] = []
    for section in DEPENDENCY_SECTIONS:
        dependencies = value.get(section, {})
        if not isinstance(dependencies, dict):
            raise TrustError("trust_package_dependency_shape_invalid")
        for name, version in sorted(dependencies.items()):
            if not isinstance(name, str) or not isinstance(version, str):
                raise TrustError("trust_package_dependency_shape_invalid")
            rows.append({"name": name, "section": section, "version": version})
    return rows, artifact


def _accepted_inventory_drift(
    root: Path, inventory: list[dict[str, Any]]
) -> dict[str, Any]:
    artifact = _read_bound(root / ACCEPTED_T001_INVENTORY, root)
    if artifact.sha256 != ACCEPTED_T001_INVENTORY_SHA256:
        raise TrustError("trust_accepted_inventory_stale")
    accepted = _load_json(artifact)
    rows = accepted.get("candidate_manifest")
    if not isinstance(rows, list):
        raise TrustError("trust_accepted_inventory_invalid")
    accepted_by_path: dict[str, str] = {}
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or SHA256_RE.fullmatch(str(row.get("sha256"))) is None
            or row["path"] in accepted_by_path
        ):
            raise TrustError("trust_accepted_inventory_invalid")
        accepted_by_path[row["path"]] = row["sha256"]
    current_by_path = {row["path"]: row["sha256"] for row in inventory}
    added = sorted(set(current_by_path) - set(accepted_by_path))
    missing = sorted(set(accepted_by_path) - set(current_by_path))
    changed = sorted(
        path for path in set(current_by_path) & set(accepted_by_path)
        if current_by_path[path] != accepted_by_path[path]
    )
    return {
        "accepted_file_count": len(accepted_by_path),
        "accepted_inventory_locator": _locator(artifact.path, root),
        "accepted_inventory_sha256": artifact.sha256,
        "added_paths": added,
        "changed_paths": changed,
        "current_file_count": len(current_by_path),
        "missing_paths": missing,
        "status": "stale" if added or changed or missing else "current",
    }


def _validated_rows(
    value: object, required: set[str], identity_key: str, label: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise TrustError(f"trust_{label}_invalid")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in value:
        if not isinstance(row, dict) or set(row) != required:
            raise TrustError(f"trust_{label}_invalid")
        identity = row.get(identity_key)
        if not isinstance(identity, str) or not identity or identity in seen:
            raise TrustError(f"trust_{label}_duplicate")
        if any(not isinstance(item, (str, bool)) for item in row.values()):
            raise TrustError(f"trust_{label}_invalid")
        seen.add(identity)
        rows.append({key: row[key] for key in sorted(row)})
    return sorted(rows, key=lambda row: str(row[identity_key]))


def _source_map(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) != {
        "schema_version", "controls", "performance_budgets", "privacy_matrix",
        "support_matrix", "third_party_boundaries",
    } or value.get("schema_version") != 1:
        raise TrustError("trust_source_map_shape_invalid")
    controls = value["controls"]
    if not isinstance(controls, list) or not controls:
        raise TrustError("trust_controls_invalid")
    seen: set[str] = set()
    parsed_controls: list[dict[str, Any]] = []
    required = {
        "control_id", "category", "severity", "source", "source_markers",
        "test", "test_markers",
    }
    for row in controls:
        if not isinstance(row, dict) or set(row) != required:
            raise TrustError("trust_controls_invalid")
        control_id = row["control_id"]
        if not isinstance(control_id, str) or ID_RE.fullmatch(control_id) is None:
            raise TrustError("trust_control_id_invalid")
        if control_id in seen:
            raise TrustError("trust_control_duplicate")
        if row["category"] not in REQUIRED_CATEGORIES or row["severity"] != "high":
            raise TrustError("trust_control_class_invalid")
        for key in ("source", "test"):
            path = row[key]
            if not isinstance(path, str) or Path(path).is_absolute() or ".." in Path(path).parts:
                raise TrustError("trust_control_path_invalid")
        for key in ("source_markers", "test_markers"):
            markers = row[key]
            if (
                not isinstance(markers, list) or not markers
                or any(not isinstance(marker, str) or not marker for marker in markers)
            ):
                raise TrustError("trust_control_markers_invalid")
        seen.add(control_id)
        parsed_controls.append(row)
    if {row["category"] for row in parsed_controls} != REQUIRED_CATEGORIES:
        raise TrustError("trust_control_category_incomplete")
    budgets = value["performance_budgets"]
    if not isinstance(budgets, dict) or set(budgets) != {
        "audit_max_bytes", "audit_max_wall_ms", "measurement_samples",
        "measurement_warmups", "operation_max_wall_ms",
    }:
        raise TrustError("trust_performance_budget_invalid")
    scalar_budgets = {key: value for key, value in budgets.items() if key != "operation_max_wall_ms"}
    operation_budgets = budgets["operation_max_wall_ms"]
    if (
        any(type(item) is not int or item <= 0 or item > MAX_SAFE_INTEGER for item in scalar_budgets.values())
        or not isinstance(operation_budgets, dict)
        or set(operation_budgets) != {
            "status", "config_validation", "workgraph_inspect",
            "migration_inspect", "interrupted_recovery_snapshot",
        }
        or any(type(item) is not int or item <= 0 or item > MAX_SAFE_INTEGER for item in operation_budgets.values())
    ):
        raise TrustError("trust_performance_budget_invalid")
    privacy = _validated_rows(
        value["privacy_matrix"],
        {"data_class", "collection", "redaction", "retention", "opt_in", "failure"},
        "data_class",
        "privacy_matrix",
    )
    support = _validated_rows(
        value["support_matrix"],
        {"surface", "support_level", "owner", "retention"},
        "surface",
        "support_matrix",
    )
    third_party = _validated_rows(
        value["third_party_boundaries"],
        {"boundary_id", "relationship", "bundled", "license_evidence", "source"},
        "boundary_id",
        "third_party_boundaries",
    )
    return {
        "controls": sorted(parsed_controls, key=lambda row: row["control_id"]),
        "performance_budgets": dict(sorted(budgets.items())),
        "privacy_matrix": privacy,
        "support_matrix": support,
        "third_party_boundaries": third_party,
    }


def _evaluate_controls(
    controls: list[dict[str, Any]], root: Path
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    for row in controls:
        control_id = row["control_id"]
        try:
            source = _read_bound(root / row["source"], root)
            test = _read_bound(root / row["test"], root)
            source_text = source.raw.decode("utf-8")
            test_text = test.raw.decode("utf-8")
            missing_source = any(marker not in source_text for marker in row["source_markers"])
            missing_test = any(marker not in test_text for marker in row["test_markers"])
        except (TrustError, UnicodeDecodeError):
            findings.append({
                "code": "control_evidence_unreadable", "control_id": control_id,
                "severity": "high",
            })
            continue
        if missing_source or missing_test:
            findings.append({
                "code": "control_marker_missing", "control_id": control_id,
                "severity": "high",
            })
        evidence.append({
            "category": row["category"],
            "control_id": control_id,
            "severity": row["severity"],
            "source": _locator(source.path, root),
            "source_sha256": source.sha256,
            "test": _locator(test.path, root),
            "test_sha256": test.sha256,
        })
    return evidence, findings


def _accessibility(root: Path, artifacts: list[Artifact]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    manifest_artifact = _read_bound(root / PLUGIN / ".codex-plugin/plugin.json", root)
    manifest = _load_json(manifest_artifact)
    interface = manifest.get("interface")
    findings: list[dict[str, str]] = []
    prompt_labels: list[str] = []
    valid = isinstance(interface, dict)
    if valid:
        for key in ("displayName", "shortDescription", "longDescription"):
            valid = valid and isinstance(interface.get(key), str) and bool(interface[key].strip())
        prompts = interface.get("defaultPrompt")
        valid = valid and isinstance(prompts, list) and len(prompts) == len(
            HOST_DEFAULT_PROMPT_LABELS
        )
        if isinstance(prompts, list):
            for prompt in prompts:
                if isinstance(prompt, str) and " — " in prompt:
                    prompt_labels.append(prompt.split(" — ", 1)[0])
        valid = valid and tuple(prompt_labels) == HOST_DEFAULT_PROMPT_LABELS
    readme = _read_bound(root / PLUGIN / "README.md", root).raw.decode("utf-8")
    valid = valid and all(heading in readme for heading in PUBLIC_README_HEADINGS)
    ansi_files = sorted(
        _locator(item.path, root) for item in artifacts if b"\x1b" in item.raw
    )
    skill_files = sorted(
        (
            item for item in artifacts
            if item.path.name == "SKILL.md" and "skills" in item.path.parts
        ),
        key=lambda item: item.path.as_posix(),
    )
    skill_headings_valid = bool(skill_files) and all(
        b"# " in item.raw and b"description:" in item.raw for item in skill_files
    )
    valid = valid and skill_headings_valid
    if not valid:
        findings.append({"code": "plugin_interface_accessibility_invalid", "severity": "high"})
    if ansi_files:
        findings.append({"code": "plugin_ansi_control_bytes_present", "severity": "high"})
    return {
        "ansi_control_bytes": False if not ansi_files else "present",
        "goalbuddy_ui": "external_not_evaluated",
        "machine_readable_cli": "canonical_json",
        "prompt_labels": prompt_labels,
        "scope": "plugin_manifest_skills_docs_cli_and_status_output",
        "skill_document_count": len(skill_files),
        "structured_headings": valid,
        "terminal_color_dependency": False,
        "wcag_conformance_claim": "not_made",
    }, findings


def build_report(
    repository_root: object,
    *,
    source_map_path: object | None = None,
    expected_source_map_sha256: str | None = None,
) -> tuple[dict[str, Any], int]:
    root = _canonical_root(repository_root)
    map_path = source_map_path or root / DEFAULT_SOURCE_MAP
    map_artifact = _read_bound(map_path, root)
    if expected_source_map_sha256 is not None:
        if SHA256_RE.fullmatch(expected_source_map_sha256) is None:
            raise TrustError("trust_expected_hash_invalid")
        if map_artifact.sha256 != expected_source_map_sha256:
            raise TrustError("trust_source_map_stale")
    parsed = _source_map(_load_json(map_artifact))
    inventory, artifacts = _inventory(root)
    accepted_inventory = _accepted_inventory_drift(root, inventory)
    imports = _parse_imports(artifacts, root)
    declared_dependencies, package_artifact = _package_dependencies(root)
    package_value = _load_json(package_artifact)
    notice = _read_bound(root / NOTICE, root)
    controls, findings = _evaluate_controls(parsed["controls"], root)
    accessibility, accessibility_findings = _accessibility(root, artifacts)
    findings.extend(accessibility_findings)
    if imports["syntax_failures"]:
        findings.append({"code": "python_source_syntax_failure", "severity": "high"})
    if imports["unaccounted_modules"]:
        findings.append({"code": "python_dependency_unaccounted", "severity": "high"})
    if declared_dependencies:
        findings.append({"code": "package_dependency_unaccounted", "severity": "high"})
    notice_text = " ".join(notice.raw.decode("utf-8").split())
    if "not legal advice" not in notice_text or "not a legal or compliance conclusion" not in notice_text:
        findings.append({"code": "third_party_notice_boundary_missing", "severity": "high"})
    rows_digest = hashlib.sha256(canonical_json(inventory).encode("utf-8")).hexdigest()
    severity_counts = {
        severity: sum(1 for finding in findings if finding["severity"] == severity)
        for severity in ("critical", "high", "medium", "low")
    }
    report = {
        "accessibility": accessibility,
        "authority": {
            "acceptance": False,
            "board_mutation": False,
            "goalbuddy_write": False,
            "install_or_cache_edit": False,
            "network_or_provider": False,
            "publication": False,
        },
        "candidate_decision": "fail" if severity_counts["high"] else "candidate_complete",
        "controls": controls,
        "dependencies": {
            "declared_package_dependencies": declared_dependencies,
            "package_locator": _locator(package_artifact.path, root),
            "package_sha256": package_artifact.sha256,
            **imports,
        },
        "findings": sorted(findings, key=lambda row: (row["severity"], row["code"])),
        "license_and_third_party": {
            "legal_or_compliance_conclusion": "not_made",
            "package_license_declaration": package_value.get("license", "absent"),
            "repository_license_file": "absent",
            "redistribution_conclusion": "not_made_missing_license_declaration",
            "notice_locator": _locator(notice.path, root),
            "notice_sha256": notice.sha256,
            "runtime_boundaries": parsed["third_party_boundaries"],
        },
        "operation": "audit",
        "performance_budgets": parsed["performance_budgets"],
        "privacy_matrix": parsed["privacy_matrix"],
        "product_inventory": {
            "accepted_t001_drift": accepted_inventory,
            "digest": rows_digest,
            "file_count": len(inventory),
            "rows": inventory,
        },
        "proof_boundary": (
            "repository-local source, tests, declarations, and documentation only; "
            "no installed, host, external UI, legal, compliance, or publication proof"
        ),
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "severity_counts": severity_counts,
        "source_map": {
            "binding": "expected_hash" if expected_source_map_sha256 else "self_observed",
            "locator": _locator(map_artifact.path, root),
            "sha256": map_artifact.sha256,
        },
        "status": "failed" if severity_counts["high"] else "pass",
        "support_matrix": parsed["support_matrix"],
        "threat_model": THREAT_SURFACES,
        "telemetry": {
            "billing": "unknown", "collection": "disabled", "cost": "unknown",
            "quota": "unknown", "tokens": "unknown",
        },
    }
    report["performance_budgets"]["observed_audit_bytes"] = 0
    for _ in range(4):
        payload_size = len((canonical_json(report) + "\n").encode("utf-8"))
        report["performance_budgets"]["observed_audit_bytes"] = payload_size
    payload_size = len((canonical_json(report) + "\n").encode("utf-8"))
    if payload_size > parsed["performance_budgets"]["audit_max_bytes"]:
        report["findings"].append({"code": "audit_output_budget_exceeded", "severity": "high"})
        report["severity_counts"]["high"] += 1
        report["candidate_decision"] = "fail"
        report["status"] = "failed"
    return report, 2 if report["status"] == "failed" else 0


def measure_report(
    repository_root: object,
    *,
    source_map_path: object | None = None,
    expected_source_map_sha256: str | None = None,
    mode: str = "calibration",
) -> tuple[dict[str, Any], int]:
    initial, initial_code = build_report(
        repository_root,
        source_map_path=source_map_path,
        expected_source_map_sha256=expected_source_map_sha256,
    )
    sample_count = initial["performance_budgets"]["measurement_samples"]
    warmup_count = initial["performance_budgets"]["measurement_warmups"]
    for _ in range(warmup_count):
        build_report(
            repository_root,
            source_map_path=source_map_path,
            expected_source_map_sha256=expected_source_map_sha256,
        )
    samples: list[float] = []
    digests: set[str] = set()
    sizes: set[int] = set()
    for _ in range(sample_count):
        started = time.perf_counter_ns()
        report, code = build_report(
            repository_root,
            source_map_path=source_map_path,
            expected_source_map_sha256=expected_source_map_sha256,
        )
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        payload = (canonical_json(report) + "\n").encode("utf-8")
        samples.append(round(elapsed_ms, 3))
        digests.add(hashlib.sha256(payload).hexdigest())
        sizes.add(len(payload))
        if code != initial_code:
            raise TrustError("trust_measurement_result_changed")
    ordered = sorted(samples)
    max_ms = max(samples)
    budget_ms = initial["performance_budgets"]["audit_max_wall_ms"]
    budget_passed = (
        initial_code == 0 and len(digests) == 1 and len(sizes) == 1
        and max_ms <= budget_ms
    )
    passed = initial_code == 0 and (mode == "calibration" or budget_passed)
    result = {
        "audit_report_sha256": next(iter(digests)),
        "budget": {
            "audit_max_wall_ms": budget_ms,
            "budget_passed": budget_passed,
            "measurement_samples": sample_count,
            "warmup_samples": warmup_count,
        },
        "command": (
            "python3 plugins/codexmax-orchestrator/scripts/codexmax_trust.py "
            f"measure --mode {mode} --repository-root <repository>"
        ),
        "environment": {
            "machine": platform.machine() or "unknown",
            "operating_system": platform.system() or "unknown",
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
        },
        "measurement": {
            "deterministic_report_digests": len(digests),
            "deterministic_report_sizes": len(sizes),
            "max_ms": max_ms,
            "median_ms": ordered[len(ordered) // 2],
            "min_ms": min(samples),
            "p95_ms": ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)],
            "samples_ms": samples,
        },
        "operation": "measure",
        "outcome": "calibration_only" if mode == "calibration" and passed else (
            "pass" if passed else "fail"
        ),
        "proof_boundary": "local process wall-clock samples; no CPU, memory, network, token, or cost inference",
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "telemetry": {"billing": "unknown", "cost": "unknown", "quota": "unknown", "tokens": "unknown"},
    }
    return result, 0 if passed else 2


def failure_receipt(operation: str, code: str) -> dict[str, Any]:
    return {
        "authority": {"acceptance": False, "board_mutation": False},
        "candidate_decision": "fail",
        "failure": code,
        "operation": operation,
        "outcome": "fail_closed",
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("audit", "measure"):
        child = subparsers.add_parser(operation)
        child.add_argument("--repository-root", required=True)
        child.add_argument("--source-map")
        child.add_argument("--expected-source-map-sha256")
        if operation == "measure":
            child.add_argument(
                "--mode", choices=("calibration", "acceptance"),
                default="calibration",
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        builder = measure_report if args.operation == "measure" else build_report
        result, exit_code = builder(
            args.repository_root,
            source_map_path=args.source_map,
            expected_source_map_sha256=args.expected_source_map_sha256,
            **({"mode": args.mode} if args.operation == "measure" else {}),
        )
        print(canonical_json(result))
        return exit_code
    except TrustError as error:
        print(canonical_json(failure_receipt(args.operation, error.code)))
        return 2
    except Exception:
        print(canonical_json(failure_receipt(args.operation, "trust_internal_error")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
