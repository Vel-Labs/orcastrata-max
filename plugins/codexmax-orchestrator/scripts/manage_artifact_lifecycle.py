#!/usr/bin/env python3
"""Manage provider-neutral, bounded worker-attempt artifacts.

The runtime tree is deliberately separate from repository source:
`.codexmax/runs/<goal>/<task>/<attempt>/`. Cleanup planning is always dry-run;
execution is a distinct command with an exact confirmation gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any, Iterable


SCHEMA_VERSION = 1
HANDOFF_MAX_BYTES = 16 * 1024
DEFAULT_MAX_FILES = 256
DEFAULT_MAX_DIRECTORIES = 256
DEFAULT_MAX_ENTRIES = 1024
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
MANIFEST_NAME = "artifact-lifecycle-manifest.json"
HANDOFF_NAME = "compact-worker-handoff.json"
ACCEPTANCE_NAME = "parent-acceptance.json"
PLAN_NAME = "cleanup-plan.json"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RELATIVE_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
COST_USD = re.compile(r"^(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{0,5}[1-9])?$")
STATES = (
    "staged",
    "provider_complete",
    "quality_checked",
    "integrated",
    "parent_accepted",
    "cleanup_planned",
    "reaped",
)


class LifecycleError(ValueError):
    """Fail-closed lifecycle error with a stable machine-readable code."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _output(value: object) -> None:
    print(canonical_json(value))


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LifecycleError("json_duplicate_key", key)
        result[key] = value
    return result


def _validate_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise LifecycleError(
            "identifier_invalid",
            f"{field} must be one canonical relative identifier",
        )
    return value


def _validate_metadata(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise LifecycleError("metadata_invalid", field)
    return value


def _canonical_root(value: object) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or "\x00" in str(value):
        raise LifecycleError("root_invalid", "root is required")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise LifecycleError("root_invalid", "root must be an absolute canonical path")
    lexical = Path(os.path.abspath(path))
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise LifecycleError("root_invalid", str(exc)) from exc
    macos_var_alias = str(lexical).startswith("/var/") and str(resolved) == "/private" + str(lexical)
    if (resolved != lexical and not macos_var_alias) or stat.S_ISLNK(named.st_mode):
        raise LifecycleError("root_alias_forbidden", str(path))
    if not stat.S_ISDIR(named.st_mode):
        raise LifecycleError("root_invalid", "root must be a directory")
    return resolved


def _ensure_real_directories(root: Path, target: Path, *, create: bool) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise LifecycleError("path_escape", str(target)) from exc
    current = root
    for part in relative.parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise LifecycleError("path_missing", str(current))
            try:
                os.mkdir(current, 0o700)
            except OSError as exc:
                raise LifecycleError("path_create_failed", str(current)) from exc
            info = os.lstat(current)
        except OSError as exc:
            raise LifecycleError("path_unsafe", str(current)) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise LifecycleError("path_unsafe", f"non-directory or link component: {current}")


def _attempt_path(
    root_value: object,
    goal: object,
    task: object,
    attempt: object,
    *,
    create_parents: bool = False,
) -> tuple[Path, str, str, str]:
    root = _canonical_root(root_value)
    goal_id = _validate_identifier(goal, "goal")
    task_id = _validate_identifier(task, "task")
    attempt_id = _validate_identifier(attempt, "attempt")
    runs = root / ".codexmax" / "runs"
    if create_parents:
        _ensure_real_directories(root, runs / goal_id / task_id, create=True)
    else:
        _ensure_real_directories(root, runs / goal_id / task_id, create=False)
    return runs / goal_id / task_id / attempt_id, goal_id, task_id, attempt_id


def _relative(value: object, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise LifecycleError("relative_path_invalid", field)
    path = PurePosixPath(value)
    if path.is_absolute() or any(
        part in {"", ".", ".."} or not RELATIVE_PART.fullmatch(part) for part in path.parts
    ):
        raise LifecycleError("relative_path_invalid", field)
    return path


def _path_in_attempt(attempt: Path, relative: PurePosixPath, field: str) -> Path:
    candidate = attempt.joinpath(*relative.parts)
    try:
        candidate.relative_to(attempt)
    except ValueError as exc:
        raise LifecycleError("path_escape", field) from exc
    current = attempt
    for part in relative.parts[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError as exc:
            raise LifecycleError("path_unsafe", field) from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise LifecycleError("path_unsafe", field)
    return candidate


def _descriptor(path: Path, attempt: Path, field: str) -> dict[str, Any]:
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise LifecycleError("file_unavailable", field) from exc
    if stat.S_ISLNK(named.st_mode):
        raise LifecycleError("symlink_forbidden", field)
    if not stat.S_ISREG(named.st_mode):
        raise LifecycleError("special_file_forbidden", field)
    if named.st_nlink != 1:
        raise LifecycleError("hardlink_forbidden", field)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LifecycleError("file_unavailable", field) from exc
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_nlink,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_nlink,
    )
    if identity_before != identity_after or named.st_dev != before.st_dev or named.st_ino != before.st_ino:
        raise LifecycleError("descriptor_drift", field)
    return {
        "path": path.relative_to(attempt).as_posix(),
        "sha256": "sha256:" + digest.hexdigest(),
        "size": before.st_size,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mtime_ns": before.st_mtime_ns,
        "links": before.st_nlink,
    }


def _read_json(path: Path, attempt: Path, field: str, *, max_bytes: int) -> dict[str, Any]:
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise LifecycleError("file_unavailable", field) from exc
    if stat.S_ISLNK(named.st_mode):
        raise LifecycleError("symlink_forbidden", field)
    if not stat.S_ISREG(named.st_mode):
        raise LifecycleError("special_file_forbidden", field)
    if named.st_nlink != 1:
        raise LifecycleError("hardlink_forbidden", field)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        opened = os.open(path, flags)
    except OSError as exc:
        raise LifecycleError("file_unavailable", field) from exc
    try:
        before = os.fstat(opened)
        if before.st_size > max_bytes:
            raise LifecycleError("file_too_large", field)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(opened, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(opened)
    finally:
        os.close(opened)
    if len(data) > max_bytes:
        raise LifecycleError("file_too_large", field)
    identity_before = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink
    )
    identity_after = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink
    )
    if (
        identity_before != identity_after
        or named.st_dev != before.st_dev
        or named.st_ino != before.st_ino
    ):
        raise LifecycleError("descriptor_drift", field)
    try:
        value = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except LifecycleError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("json_invalid", field) from exc
    if not isinstance(value, dict):
        raise LifecycleError("json_invalid", f"{field} must be an object")
    return value


def _cap_value(caps: dict[str, Any], field: str) -> int:
    value = caps.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LifecycleError("manifest_invalid", f"caps.{field}")
    return value


def _scan_tree(root: Path, attempt: Path, caps: dict[str, Any]) -> dict[str, Any]:
    """Stream one bounded tree without materializing an uncapped directory."""
    max_files = _cap_value(caps, "max_files")
    max_directories = _cap_value(caps, "max_directories")
    max_entries = _cap_value(caps, "max_entries")
    max_bytes = _cap_value(caps, "max_bytes")
    pending_directories = [root]
    directories: list[Path] = []
    files: list[tuple[Path, dict[str, Any]]] = []
    entry_count = 0
    total_bytes = 0
    while pending_directories:
        current = pending_directories.pop()
        try:
            iterator = os.scandir(current)
        except OSError as exc:
            raise LifecycleError("path_unsafe", str(current)) from exc
        with iterator:
            for entry in iterator:
                entry_count += 1
                if entry_count > max_entries:
                    raise LifecycleError("entry_cap_exceeded", f"{entry_count} > {max_entries}")
                path = current / entry.name
                relative = path.relative_to(attempt).as_posix()
                _relative(relative, "tree entry")
                try:
                    info = os.lstat(path)
                except OSError as exc:
                    raise LifecycleError("path_unsafe", relative) from exc
                if stat.S_ISLNK(info.st_mode):
                    raise LifecycleError("symlink_forbidden", relative)
                if stat.S_ISDIR(info.st_mode):
                    directories.append(path)
                    if len(directories) > max_directories:
                        raise LifecycleError(
                            "directory_cap_exceeded",
                            f"{len(directories)} > {max_directories}",
                        )
                    pending_directories.append(path)
                    continue
                if total_bytes + info.st_size > max_bytes:
                    raise LifecycleError(
                        "byte_cap_exceeded", f"{total_bytes + info.st_size} > {max_bytes}"
                    )
                descriptor = _descriptor(path, attempt, relative)
                files.append((path, descriptor))
                if len(files) > max_files:
                    raise LifecycleError("file_cap_exceeded", f"{len(files)} > {max_files}")
                total_bytes += descriptor["size"]
                if total_bytes > max_bytes:
                    raise LifecycleError("byte_cap_exceeded", f"{total_bytes} > {max_bytes}")
    files.sort(key=lambda item: item[1]["path"])
    directories.sort(key=lambda item: item.relative_to(attempt).as_posix())
    return {
        "files": files,
        "directories": directories,
        "entry_count": entry_count,
        "total_bytes": total_bytes,
    }


def _enforce_caps(attempt: Path, manifest: dict[str, Any], *, pending: tuple[Path, bytes] | None = None) -> None:
    caps = manifest.get("caps")
    if not isinstance(caps, dict):
        raise LifecycleError("manifest_invalid", "caps")
    max_files = _cap_value(caps, "max_files")
    max_entries = _cap_value(caps, "max_entries")
    max_bytes = _cap_value(caps, "max_bytes")
    scan = _scan_tree(attempt, attempt, caps)
    sizes = {path: descriptor["size"] for path, descriptor in scan["files"]}
    if pending is not None:
        path, data = pending
        is_new = path not in sizes
        sizes[path] = len(data)
        if is_new and scan["entry_count"] + 1 > max_entries:
            raise LifecycleError(
                "entry_cap_exceeded", f"{scan['entry_count'] + 1} > {max_entries}"
            )
    if len(sizes) > max_files:
        raise LifecycleError("file_cap_exceeded", f"{len(sizes)} > {max_files}")
    total = sum(sizes.values())
    if total > max_bytes:
        raise LifecycleError("byte_cap_exceeded", f"{total} > {max_bytes}")


def _atomic_write(path: Path, data: bytes) -> None:
    temp = path.with_name("." + path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(temp, flags, 0o600)
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short write")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temp, path)
    except OSError as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        raise LifecycleError("write_failed", path.name) from exc


def _write_json(path: Path, value: dict[str, Any], attempt: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    data = (canonical_json(value) + "\n").encode("utf-8")
    _enforce_caps(attempt, manifest, pending=(path, data))
    _atomic_write(path, data)
    return _descriptor(path, attempt, path.name)


def _load_manifest(attempt: Path, goal: str, task: str, attempt_id: str) -> dict[str, Any]:
    _ensure_real_directories(attempt.parent.parent.parent.parent, attempt, create=False)
    path = attempt / MANIFEST_NAME
    value = _read_json(path, attempt, MANIFEST_NAME, max_bytes=1024 * 1024)
    if value.get("schema_version") != SCHEMA_VERSION:
        raise LifecycleError("manifest_invalid", "schema_version")
    expected = {"goal": goal, "task": task, "attempt": attempt_id}
    if value.get("identity") != expected:
        raise LifecycleError("manifest_identity_mismatch", canonical_json(expected))
    if value.get("state") not in STATES:
        raise LifecycleError("manifest_invalid", "state")
    return value


def _save_manifest(attempt: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("state") != "staged":
        _validate_bound_evidence(attempt, manifest)
    _write_json(attempt / MANIFEST_NAME, manifest, attempt, manifest)


def _require_state(manifest: dict[str, Any], expected: str) -> None:
    if manifest.get("state") != expected:
        raise LifecycleError("transition_invalid", f"expected {expected}, got {manifest.get('state')}")


def _unknown_usage() -> dict[str, dict[str, Any]]:
    return {
        field: {"status": "unknown", "value": None, "unknown_reason": "telemetry_not_reported"}
        for field in ("input_tokens", "output_tokens", "total_tokens", "cost_usd")
    }


def _usage_value(value: str | None, field: str) -> dict[str, Any]:
    if value is None:
        return {"status": "unknown", "value": None, "unknown_reason": "telemetry_not_reported"}
    if field == "cost_usd":
        if not COST_USD.fullmatch(value):
            raise LifecycleError("usage_invalid", field)
        parsed: int | float = float(value) if "." in value else int(value)
        return {"status": "reported", "value": parsed, "unknown_reason": None}
    try:
        parsed = int(value)
    except ValueError as exc:
        raise LifecycleError("usage_invalid", field) from exc
    if parsed < 0 or str(parsed) != value:
        raise LifecycleError("usage_invalid", field)
    return {"status": "reported", "value": parsed, "unknown_reason": None}


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    attempt, goal, task, attempt_id = _attempt_path(
        args.root, args.goal, args.task, args.attempt, create_parents=True
    )
    if attempt.exists() or attempt.is_symlink():
        raise LifecycleError("attempt_exists", attempt.as_posix())
    if (
        args.max_files < 4
        or args.max_directories < 2
        or args.max_entries < 3
        or args.max_bytes < 1024
    ):
        raise LifecycleError("cap_invalid", "caps must preserve lifecycle metadata")
    os.mkdir(attempt, 0o700)
    os.mkdir(attempt / "raw", 0o700)
    os.mkdir(attempt / "accepted", 0o700)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "identity": {"goal": goal, "task": task, "attempt": attempt_id},
        "state": "staged",
        "worker": {
            field: _validate_metadata(getattr(args, field), field)
            for field in ("provider", "model", "route", "role", "runtime")
        },
        "usage": _unknown_usage(),
        "caps": {
            "max_files": args.max_files,
            "max_directories": args.max_directories,
            "max_entries": args.max_entries,
            "max_bytes": args.max_bytes,
            "handoff_max_bytes": HANDOFF_MAX_BYTES,
        },
        "evidence": {},
        "raw_snapshot": None,
        "cleanup": {"plan": None, "executed": False},
    }
    _save_manifest(attempt, manifest)
    return {"status": "prepared", "state": "staged", "attempt_root": str(attempt)}


def _existing(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    attempt, goal, task, attempt_id = _attempt_path(args.root, args.goal, args.task, args.attempt)
    return attempt, _load_manifest(attempt, goal, task, attempt_id)


def record_result(args: argparse.Namespace) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _require_state(manifest, "staged")
    relative = _relative(args.result, "result")
    if not relative.parts or relative.parts[0] != "raw":
        raise LifecycleError("result_location_invalid", "result must be under raw/")
    path = _path_in_attempt(attempt, relative, "result")
    _enforce_caps(attempt, manifest)
    snapshot = _raw_snapshot(attempt, manifest)
    result = next(
        (row for row in snapshot["files"] if row["path"] == path.relative_to(attempt).as_posix()),
        None,
    )
    if result is None:
        raise LifecycleError("result_unavailable", relative.as_posix())
    usage = {
        field: _usage_value(getattr(args, field), field)
        for field in ("input_tokens", "output_tokens", "total_tokens", "cost_usd")
    }
    manifest["evidence"]["provider_result"] = result
    manifest["raw_snapshot"] = snapshot
    manifest["usage"] = usage
    manifest["state"] = "provider_complete"
    _enforce_caps(attempt, manifest)
    _save_manifest(attempt, manifest)
    return {"status": "recorded", "state": manifest["state"], "result": result, "usage": usage}


def _record_accepted_receipt(args: argparse.Namespace, expected: str, next_state: str, key: str) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _require_state(manifest, expected)
    _validate_bound_evidence(attempt, manifest)
    relative = _relative(args.receipt, "receipt")
    if not relative.parts or relative.parts[0] != "accepted":
        raise LifecycleError("receipt_location_invalid", "receipt must be under accepted/")
    receipt = _descriptor(_path_in_attempt(attempt, relative, "receipt"), attempt, "receipt")
    manifest["evidence"][key] = receipt
    manifest["state"] = next_state
    _enforce_caps(attempt, manifest)
    _save_manifest(attempt, manifest)
    return {"status": "recorded", "state": next_state, "receipt": receipt}


def quality_check(args: argparse.Namespace) -> dict[str, Any]:
    return _record_accepted_receipt(args, "provider_complete", "quality_checked", "quality_check")


def integrate(args: argparse.Namespace) -> dict[str, Any]:
    return _record_accepted_receipt(args, "quality_checked", "integrated", "integration")


def handoff(args: argparse.Namespace) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _require_state(manifest, "integrated")
    _validate_bound_evidence(attempt, manifest)
    if "compact_handoff" in manifest["evidence"] or (attempt / HANDOFF_NAME).exists():
        raise LifecycleError("handoff_already_bound", HANDOFF_NAME)
    summary = args.summary or "Worker attempt is ready for Parent review."
    claims = args.claim or []
    changed_files = args.changed_file or []
    value = {
        "schema_version": SCHEMA_VERSION,
        "identity": manifest["identity"],
        "state": manifest["state"],
        "worker": manifest["worker"],
        "usage": manifest["usage"],
        "summary": summary,
        "claims": claims,
        "changed_files": changed_files,
        "evidence": manifest["evidence"],
        "raw_snapshot_binding": {
            key: manifest["raw_snapshot"][key]
            for key in ("tree_sha256", "file_count", "directory_count", "total_bytes")
        },
        "raw_evidence_policy": "retrieve_only_for_named_disputed_claim",
        "acceptance_authority": "parent_sol_only",
    }
    data = (canonical_json(value) + "\n").encode("utf-8")
    if len(data) > HANDOFF_MAX_BYTES:
        raise LifecycleError("handoff_too_large", f"{len(data)} > {HANDOFF_MAX_BYTES}")
    _enforce_caps(attempt, manifest, pending=(attempt / HANDOFF_NAME, data))
    _atomic_write(attempt / HANDOFF_NAME, data)
    descriptor = _descriptor(attempt / HANDOFF_NAME, attempt, HANDOFF_NAME)
    manifest["evidence"]["compact_handoff"] = descriptor
    _save_manifest(attempt, manifest)
    return {"status": "ready_for_parent", "state": manifest["state"], "handoff": descriptor}


def accept(args: argparse.Namespace) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _require_state(manifest, "integrated")
    _validate_bound_evidence(attempt, manifest)
    if args.authority != "parent_sol":
        raise LifecycleError("acceptance_authority_invalid", "--authority parent_sol is required")
    handoff_descriptor = _descriptor(attempt / HANDOFF_NAME, attempt, HANDOFF_NAME)
    if manifest["evidence"].get("compact_handoff") != handoff_descriptor:
        raise LifecycleError("descriptor_drift", HANDOFF_NAME)
    value = {
        "schema_version": SCHEMA_VERSION,
        "decision": "accepted",
        "authority": "parent_sol",
        "acceptance_id": _validate_identifier(args.acceptance_id, "acceptance_id"),
        "handoff": handoff_descriptor,
    }
    acceptance = _write_json(attempt / ACCEPTANCE_NAME, value, attempt, manifest)
    manifest["evidence"]["parent_acceptance"] = acceptance
    manifest["state"] = "parent_accepted"
    _save_manifest(attempt, manifest)
    return {"status": "accepted", "state": manifest["state"], "acceptance": acceptance}


def _raw_scan(attempt: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    raw = attempt / "raw"
    _ensure_real_directories(attempt, raw, create=False)
    caps = manifest.get("caps")
    if not isinstance(caps, dict):
        raise LifecycleError("manifest_invalid", "caps")
    return _scan_tree(raw, attempt, caps)


def _raw_candidates(attempt: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [descriptor for _path, descriptor in _raw_scan(attempt, manifest)["files"]]


def _raw_snapshot(attempt: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    scan = _raw_scan(attempt, manifest)
    files = [descriptor for _path, descriptor in scan["files"]]
    directories = [
        path.relative_to(attempt).as_posix() for path in scan["directories"]
    ]
    binding = {"directories": directories, "files": files}
    return {
        "schema_version": SCHEMA_VERSION,
        **binding,
        "file_count": len(files),
        "directory_count": len(directories),
        "entry_count": scan["entry_count"],
        "total_bytes": scan["total_bytes"],
        "tree_sha256": _sha256(canonical_json(binding).encode("utf-8")),
    }


def _validate_bound_descriptor(attempt: Path, value: object, field: str) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("path"), str):
        raise LifecycleError("manifest_invalid", field)
    relative = _relative(value["path"], field)
    path = _path_in_attempt(attempt, relative, field)
    actual = _descriptor(path, attempt, field)
    if actual != value:
        raise LifecycleError("descriptor_drift", field)


def _validate_bound_evidence(attempt: Path, manifest: dict[str, Any]) -> None:
    """Revalidate the complete immutable evidence binding before transition."""
    expected_snapshot = manifest.get("raw_snapshot")
    if not isinstance(expected_snapshot, dict):
        raise LifecycleError("manifest_invalid", "raw_snapshot")
    current_snapshot = _raw_snapshot(attempt, manifest)
    if current_snapshot != expected_snapshot:
        raise LifecycleError("descriptor_drift", "raw_snapshot")
    evidence = manifest.get("evidence")
    if not isinstance(evidence, dict) or "provider_result" not in evidence:
        raise LifecycleError("manifest_invalid", "evidence")
    for key in sorted(evidence):
        _validate_bound_descriptor(attempt, evidence[key], f"evidence.{key}")
    cleanup = manifest.get("cleanup")
    if not isinstance(cleanup, dict):
        raise LifecycleError("manifest_invalid", "cleanup")
    if cleanup.get("plan") is not None:
        _validate_bound_descriptor(attempt, cleanup["plan"], "cleanup.plan")


def plan_cleanup(args: argparse.Namespace) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _require_state(manifest, "parent_accepted")
    _validate_bound_evidence(attempt, manifest)
    _enforce_caps(attempt, manifest)
    acceptance = _descriptor(attempt / ACCEPTANCE_NAME, attempt, ACCEPTANCE_NAME)
    if manifest["evidence"].get("parent_acceptance") != acceptance:
        raise LifecycleError("descriptor_drift", ACCEPTANCE_NAME)
    gate = "reap:{goal}/{task}/{attempt}".format(**manifest["identity"])
    value = {
        "schema_version": SCHEMA_VERSION,
        "mode": "dry_run",
        "identity": manifest["identity"],
        "acceptance": acceptance,
        "candidates": _raw_candidates(attempt, manifest),
        "protected": [
            MANIFEST_NAME,
            HANDOFF_NAME,
            ACCEPTANCE_NAME,
            PLAN_NAME,
            "accepted/",
        ],
        "execution_gate": gate,
    }
    plan = _write_json(attempt / PLAN_NAME, value, attempt, manifest)
    manifest["cleanup"] = {"plan": plan, "executed": False}
    manifest["state"] = "cleanup_planned"
    _save_manifest(attempt, manifest)
    return {
        "status": "planned",
        "mode": "dry_run",
        "state": manifest["state"],
        "candidate_count": len(value["candidates"]),
        "execution_gate": gate,
        "mutated_candidates": False,
    }


def _descriptor_matches(actual: dict[str, Any], planned: object) -> bool:
    return isinstance(planned, dict) and all(actual.get(key) == planned.get(key) for key in (
        "path", "sha256", "size", "device", "inode", "mtime_ns", "links"
    ))


def execute_cleanup(args: argparse.Namespace) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _require_state(manifest, "cleanup_planned")
    _validate_bound_evidence(attempt, manifest)
    cleanup = manifest.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("executed") is not False:
        raise LifecycleError("cleanup_manifest_invalid", "execution state")
    planned_descriptor = cleanup.get("plan")
    actual_plan_descriptor = _descriptor(attempt / PLAN_NAME, attempt, PLAN_NAME)
    if planned_descriptor != actual_plan_descriptor:
        raise LifecycleError("descriptor_drift", PLAN_NAME)
    plan = _read_json(attempt / PLAN_NAME, attempt, PLAN_NAME, max_bytes=1024 * 1024)
    expected_gate = plan.get("execution_gate")
    if not isinstance(expected_gate, str) or args.authorization != expected_gate:
        raise LifecycleError("cleanup_authorization_required", str(expected_gate))
    if plan.get("mode") != "dry_run" or plan.get("identity") != manifest.get("identity"):
        raise LifecycleError("cleanup_plan_invalid", "identity or mode")
    candidates = plan.get("candidates")
    if not isinstance(candidates, list):
        raise LifecycleError("cleanup_plan_invalid", "candidates")
    raw_scan = _raw_scan(attempt, manifest)
    current_candidates = [descriptor for _path, descriptor in raw_scan["files"]]
    if current_candidates != candidates:
        raise LifecycleError("descriptor_drift", "raw candidate set")
    checked: list[tuple[Path, dict[str, Any]]] = []
    for planned in candidates:
        if not isinstance(planned, dict):
            raise LifecycleError("cleanup_plan_invalid", "candidate")
        relative = _relative(planned.get("path"), "candidate.path")
        if not relative.parts or relative.parts[0] != "raw":
            raise LifecycleError("cleanup_scope_invalid", relative.as_posix())
        path = _path_in_attempt(attempt, relative, "candidate.path")
        actual = _descriptor(path, attempt, relative.as_posix())
        if not _descriptor_matches(actual, planned):
            raise LifecycleError("descriptor_drift", relative.as_posix())
        checked.append((path, actual))
    final_manifest = json.loads(canonical_json(manifest))
    final_manifest["cleanup"]["executed"] = True
    final_manifest["cleanup"]["deleted_count"] = len(checked)
    final_manifest["state"] = "reaped"
    final_data = (canonical_json(final_manifest) + "\n").encode("utf-8")
    _enforce_caps(attempt, final_manifest, pending=(attempt / MANIFEST_NAME, final_data))
    # Validation of the complete candidate set and final receipt occurs before
    # the first unlink. Each candidate is then revalidated immediately before
    # its own unlink.
    for path, planned in checked:
        if not _descriptor_matches(_descriptor(path, attempt, planned["path"]), planned):
            raise LifecycleError("descriptor_drift", planned["path"])
        os.unlink(path)
    for directory in sorted(
        raw_scan["directories"], key=lambda item: len(item.parts), reverse=True
    ):
        try:
            directory.rmdir()
        except OSError:
            pass
    _atomic_write(attempt / MANIFEST_NAME, final_data)
    return {"status": "reaped", "state": "reaped", "deleted_count": len(checked)}


def status(args: argparse.Namespace) -> dict[str, Any]:
    attempt, manifest = _existing(args)
    _enforce_caps(attempt, manifest)
    if manifest.get("state") not in {"staged", "reaped"}:
        _validate_bound_evidence(attempt, manifest)
    return {"status": "ok", "attempt_root": str(attempt), "manifest": manifest}


def _common(subparser: argparse.ArgumentParser) -> None:
    subparser.add_argument("--root", required=True, help="Absolute repository/workspace root")
    subparser.add_argument("--goal", required=True, help="Canonical goal identifier")
    subparser.add_argument("--task", required=True, help="Canonical task identifier")
    subparser.add_argument("--attempt", required=True, help="Canonical attempt identifier")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare", help="Create one isolated staged attempt")
    _common(prepare_parser)
    for field in ("provider", "model", "route", "role", "runtime"):
        prepare_parser.add_argument(f"--{field}", default="unknown")
    prepare_parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    prepare_parser.add_argument(
        "--max-directories", type=int, default=DEFAULT_MAX_DIRECTORIES
    )
    prepare_parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    prepare_parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    prepare_parser.set_defaults(handler=prepare)

    record_parser = subparsers.add_parser("record-result", help="Bind the immutable provider result")
    _common(record_parser)
    record_parser.add_argument("--result", default="raw/result.json")
    for field in ("input_tokens", "output_tokens", "total_tokens", "cost_usd"):
        record_parser.add_argument(f"--{field.replace('_', '-')}", dest=field)
    record_parser.set_defaults(handler=record_result)

    quality_parser = subparsers.add_parser("quality-check", help="Bind an accepted quality receipt")
    _common(quality_parser)
    quality_parser.add_argument("--receipt", default="accepted/quality-check.json")
    quality_parser.set_defaults(handler=quality_check)

    integrate_parser = subparsers.add_parser("integrate", help="Bind an integration receipt")
    _common(integrate_parser)
    integrate_parser.add_argument("--receipt", default="accepted/integration.json")
    integrate_parser.set_defaults(handler=integrate)

    handoff_parser = subparsers.add_parser("handoff", help="Render the bounded Parent-first handoff")
    _common(handoff_parser)
    handoff_parser.add_argument("--summary")
    handoff_parser.add_argument("--claim", action="append")
    handoff_parser.add_argument("--changed-file", action="append")
    handoff_parser.set_defaults(handler=handoff)

    accept_parser = subparsers.add_parser("accept", help="Record Parent Sol acceptance")
    _common(accept_parser)
    accept_parser.add_argument("--authority", required=True)
    accept_parser.add_argument("--acceptance-id", required=True)
    accept_parser.set_defaults(handler=accept)

    plan_parser = subparsers.add_parser("plan-cleanup", help="Write a non-destructive cleanup plan")
    _common(plan_parser)
    plan_parser.set_defaults(handler=plan_cleanup)

    execute_parser = subparsers.add_parser("execute-cleanup", help="Execute an accepted, bound plan")
    _common(execute_parser)
    execute_parser.add_argument("--authorization", required=True)
    execute_parser.set_defaults(handler=execute_cleanup)

    status_parser = subparsers.add_parser("status", help="Inspect and validate one attempt")
    _common(status_parser)
    status_parser.set_defaults(handler=status)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    try:
        _output(args.handler(args))
        return 0
    except LifecycleError as exc:
        _output({"status": "error", "code": exc.code, "detail": exc.detail})
        return 2


if __name__ == "__main__":
    sys.exit(main())
