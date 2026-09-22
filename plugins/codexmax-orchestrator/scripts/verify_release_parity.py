#!/usr/bin/env python3
"""Build or verify an immutable Codexmax release manifest without mutation."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
from typing import Any


SCHEMA_VERSION = 1
PACKAGE_NAME = "codexmax-orchestrator"
CANDIDATE_VERSION = "1.4.1"
T001_INVENTORY_SHA256 = "c4134153b8ab9868ac9104cce5b8f975bd18c954f75523bb5ecc4cd6a45c973d"
RELEASE_STATUS = {
    "installed": False,
    "executed": False,
    "service_started": False,
    "live_admission_proved": False,
    "provider_execution_proved": False,
    "production_ready": False,
    "release": False,
}
MANIFEST_RELATIVE = PurePosixPath(".codex-plugin/release-manifest.json")
PLUGIN_RELATIVE = PurePosixPath(".codex-plugin/plugin.json")
MAX_FILE_BYTES = 8 * 1024 * 1024
SHA256_HEX = set("0123456789abcdef")


class ParityError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def canonical_json(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"),
        sort_keys=True,
    )


def _same_canonical_path(lexical: Path, resolved: Path) -> bool:
    return resolved == lexical or (
        str(lexical).startswith("/var/")
        and str(resolved) == "/private" + str(lexical)
    )


def _root(value: object, *, missing_code: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise ParityError("path_invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ParityError("path_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ParityError(missing_code) from error
    except OSError as error:
        raise ParityError("path_unavailable") from error
    if (
        not _same_canonical_path(lexical, resolved)
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
    ):
        raise ParityError("path_alias_forbidden")
    return lexical


def _relative(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ParityError("manifest_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ParityError("manifest_path_invalid")
    return path


def _read_regular(path: Path, root: Path) -> bytes:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ParityError("path_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        lexical.relative_to(root)
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except ValueError as error:
        raise ParityError("path_outside_root") from error
    except FileNotFoundError as error:
        raise ParityError("file_missing") from error
    except OSError as error:
        raise ParityError("file_unavailable") from error
    if (
        not _same_canonical_path(lexical, resolved)
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISREG(named.st_mode)
    ):
        raise ParityError("file_nonregular_or_alias")
    if named.st_nlink != 1:
        raise ParityError("file_hardlink_forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ELOOP}:
            raise ParityError("file_identity_changed") from error
        raise ParityError("file_unavailable") from error
    try:
        before = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ParityError("file_identity_changed")
        raw = bytearray()
        while len(raw) <= MAX_FILE_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_FILE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ParityError("file_identity_changed")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_FILE_BYTES:
        raise ParityError("file_oversize")
    return bytes(raw)


def _identity(path: Path, root: Path, *, kind: str, value: os.stat_result) -> dict[str, Any]:
    relative = "." if path == root else path.relative_to(root).as_posix()
    return {
        "ctime_ns": value.st_ctime_ns,
        "device": value.st_dev,
        "inode": value.st_ino,
        "kind": kind,
        "link_count": value.st_nlink,
        "mode": stat.S_IMODE(value.st_mode),
        "mtime_ns": value.st_mtime_ns,
        "path": relative,
        "size": value.st_size,
    }


def _inventory(
    root: Path, *, exclude_source_generated: bool = False,
    exclude_cache_bytecode: bool = False,
) -> tuple[list[dict[str, Any]], list[Path]]:
    identities: list[dict[str, Any]] = []
    files: list[Path] = []

    def visit(directory: Path, *, record: bool = True, in_python_cache: bool = False) -> None:
        try:
            directory_stat = directory.lstat()
        except OSError as error:
            raise ParityError("tree_unavailable") from error
        if not stat.S_ISDIR(directory_stat.st_mode) or stat.S_ISLNK(directory_stat.st_mode):
            raise ParityError("tree_alias_forbidden")
        if record:
            identities.append(_identity(directory, root, kind="directory", value=directory_stat))
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise ParityError("tree_unavailable") from error
        for entry in entries:
            path = Path(entry.path)
            relative = PurePosixPath(path.relative_to(root).as_posix())
            if exclude_source_generated and (
                entry.name == "__pycache__" or entry.name.endswith((".pyc", ".pyo"))
            ):
                continue
            try:
                named = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ParityError("tree_unavailable") from error
            if stat.S_ISLNK(named.st_mode):
                raise ParityError("tree_alias_forbidden")
            if stat.S_ISDIR(named.st_mode):
                lexical = Path(os.path.abspath(path))
                try:
                    resolved = path.resolve(strict=True)
                except OSError as error:
                    raise ParityError("tree_unavailable") from error
                if not _same_canonical_path(lexical, resolved):
                    raise ParityError("tree_alias_forbidden")
                if exclude_cache_bytecode and entry.name == "__pycache__":
                    visit(path, record=False, in_python_cache=True)
                else:
                    visit(path)
                continue
            if not stat.S_ISREG(named.st_mode):
                raise ParityError("tree_nonregular_forbidden")
            if named.st_nlink != 1:
                raise ParityError("tree_hardlink_forbidden")
            if exclude_cache_bytecode and in_python_cache and entry.name.endswith((".pyc", ".pyo")):
                continue
            identities.append(_identity(path, root, kind="file", value=named))
            files.append(path)

    visit(root)
    identities.sort(key=lambda row: (row["path"], row["kind"]))
    files.sort(key=lambda path: path.relative_to(root).as_posix())
    return identities, files


def _snapshot(
    root: Path, *, source_projection: bool = False, cache_projection: bool = False
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    before, files = _inventory(
        root,
        exclude_source_generated=source_projection,
        exclude_cache_bytecode=cache_projection,
    )
    payloads: dict[str, bytes] = {}
    rows: list[dict[str, Any]] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        raw = _read_regular(path, root)
        payloads[relative] = raw
        if PurePosixPath(relative) != MANIFEST_RELATIVE:
            rows.append({
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            })
    after, final_files = _inventory(
        root,
        exclude_source_generated=source_projection,
        exclude_cache_bytecode=cache_projection,
    )
    if before != after or files != final_files:
        raise ParityError("tree_changed_during_snapshot")
    rows.sort(key=lambda row: row["path"])
    if not rows:
        raise ParityError("tree_empty")
    return rows, payloads


def _tree(root: Path) -> list[dict[str, Any]]:
    rows, _ = _snapshot(root)
    return rows


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ParityError("json_duplicate_key")
        value[key] = item
    return value


def _constant(_: str) -> object:
    raise ParityError("json_non_finite")


def _json(raw: bytes, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except ParityError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ParityError(code) from error
    if not isinstance(value, dict):
        raise ParityError(code)
    return value


def build_manifest(source_root: object) -> dict[str, Any]:
    source = _root(source_root, missing_code="source_missing")
    rows, payloads = _snapshot(source, source_projection=True)
    plugin = _json(payloads[PLUGIN_RELATIVE.as_posix()], code="plugin_json_invalid")
    if plugin.get("name") != PACKAGE_NAME or plugin.get("version") != CANDIDATE_VERSION:
        raise ParityError("plugin_name_or_version_mismatch")
    return {
        "files": rows,
        "package": {"name": PACKAGE_NAME, "version": CANDIDATE_VERSION},
        "release_status": RELEASE_STATUS,
        "schema_version": SCHEMA_VERSION,
        "t001_inventory_sha256": T001_INVENTORY_SHA256,
    }


def write_manifest(source_root: object) -> dict[str, Any]:
    """Atomically replace the source manifest with the current candidate inventory."""
    source = _root(source_root, missing_code="source_missing")
    value = build_manifest(source)
    target = source / Path(MANIFEST_RELATIVE)
    raw = (canonical_json(value) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".release-manifest.", suffix=".tmp", dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ParityError("manifest_write_failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
        raise
    return value


def _sha(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= SHA256_HEX


def _manifest(raw: bytes) -> dict[str, Any]:
    value = _json(raw, code="release_manifest_invalid")
    if raw != (canonical_json(value) + "\n").encode("utf-8"):
        raise ParityError("release_manifest_noncanonical")
    if set(value) != {"files", "package", "release_status", "schema_version", "t001_inventory_sha256"}:
        raise ParityError("release_manifest_shape_invalid")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ParityError("release_manifest_version_unsupported")
    package = value["package"]
    if not isinstance(package, dict) or set(package) != {"name", "version"}:
        raise ParityError("release_manifest_shape_invalid")
    if value["release_status"] != RELEASE_STATUS:
        raise ParityError("release_manifest_status_not_fail_closed")
    if package != {"name": PACKAGE_NAME, "version": CANDIDATE_VERSION}:
        raise ParityError("release_manifest_name_or_version_mismatch")
    if value["t001_inventory_sha256"] != T001_INVENTORY_SHA256:
        raise ParityError("release_manifest_t001_mismatch")
    files = value["files"]
    if not isinstance(files, list) or not files:
        raise ParityError("release_manifest_files_invalid")
    seen: set[str] = set()
    prior = ""
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            raise ParityError("release_manifest_files_invalid")
        path = _relative(row["path"])
        if path == MANIFEST_RELATIVE:
            raise ParityError("release_manifest_self_reference")
        if row["path"] in seen:
            raise ParityError("release_manifest_duplicate_entry")
        if row["path"] <= prior:
            raise ParityError("release_manifest_unsorted")
        if not _sha(row["sha256"]) or type(row["size"]) is not int or row["size"] < 0:
            raise ParityError("release_manifest_files_invalid")
        prior = row["path"]
        seen.add(row["path"])
    return value


def _mismatch(
    expected: list[dict[str, Any]],
    observed: list[dict[str, Any]],
    *,
    cache: bool,
    stage_leaf: bool = False,
) -> None:
    expected_by_path = {row["path"]: row for row in expected}
    observed_by_path = {row["path"]: row for row in observed}
    if stage_leaf:
        missing_code = "stage_leaf_file_missing"
        extra_code = "stage_leaf_file_extra"
        drift_code = "stage_leaf_content_drift"
    elif cache:
        missing_code = "cache_file_missing"
        extra_code = "cache_file_extra"
        drift_code = "same_version_cache_drift"
    else:
        missing_code = "source_file_missing"
        extra_code = "source_file_extra"
        drift_code = "source_manifest_mismatch"
    if set(expected_by_path) - set(observed_by_path):
        raise ParityError(missing_code)
    if set(observed_by_path) - set(expected_by_path):
        raise ParityError(extra_code)
    if expected_by_path != observed_by_path:
        raise ParityError(drift_code)


def _tree_sha256(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_json(rows).encode("utf-8")).hexdigest()


def _candidate_receipt(
    source: Path, manifest_sha256: str, rows: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "authority": "source_release_manifest",
        "file_count": len(rows),
        "package_name": PACKAGE_NAME,
        "receipt_type": "candidate_manifest",
        "release_manifest_sha256": manifest_sha256,
        "schema_version": SCHEMA_VERSION,
        "source_root": str(source),
        "source_tree_sha256": _tree_sha256(rows),
        "status": "pass",
        "version": CANDIDATE_VERSION,
    }


def _receipt(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    receipt_root = _root(path.parent, missing_code="release_receipt_missing")
    raw = _read_regular(path, receipt_root)
    value = _json(raw, code="release_receipt_invalid")
    if raw != (canonical_json(value) + "\n").encode("utf-8"):
        raise ParityError("release_receipt_noncanonical")
    if set(value) != set(expected):
        raise ParityError("release_receipt_shape_invalid")
    if value != expected:
        raise ParityError("release_receipt_stale_or_mismatched")
    return value


def verify(
    source_root: object,
    *,
    cache_root: object | None = None,
    stage_leaf: object | None = None,
    receipt_path: object | None = None,
) -> dict[str, Any]:
    source = _root(source_root, missing_code="source_missing")
    source_rows, source_payloads = _snapshot(source, source_projection=True)
    try:
        manifest_raw = source_payloads[MANIFEST_RELATIVE.as_posix()]
        plugin_raw = source_payloads[PLUGIN_RELATIVE.as_posix()]
    except KeyError as error:
        raise ParityError("source_file_missing") from error
    manifest = _manifest(manifest_raw)
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    plugin = _json(plugin_raw, code="plugin_json_invalid")
    if plugin.get("name") != PACKAGE_NAME or plugin.get("version") != CANDIDATE_VERSION:
        raise ParityError("plugin_name_or_version_mismatch")
    _mismatch(manifest["files"], source_rows, cache=False)
    candidate_receipt = _candidate_receipt(source, manifest_sha256, source_rows)
    receipt = None
    if receipt_path is not None:
        receipt = _receipt(Path(receipt_path), candidate_receipt)
    cache: dict[str, Any] = {"status": "not_requested"}
    if cache_root is not None:
        cache_path = _root(cache_root, missing_code="cache_missing")
        if cache_path.name != CANDIDATE_VERSION or cache_path.parent.name != PACKAGE_NAME:
            raise ParityError("cache_name_or_version_mismatch")
        cache_rows, cache_payloads = _snapshot(cache_path, cache_projection=True)
        try:
            cache_manifest = cache_payloads[MANIFEST_RELATIVE.as_posix()]
            cache_plugin_raw = cache_payloads[PLUGIN_RELATIVE.as_posix()]
        except KeyError as error:
            raise ParityError("cache_file_missing") from error
        if cache_manifest != manifest_raw:
            raise ParityError("cache_manifest_mismatch")
        cache_plugin = _json(
            cache_plugin_raw,
            code="cache_plugin_json_invalid",
        )
        if cache_plugin.get("name") != PACKAGE_NAME or cache_plugin.get("version") != CANDIDATE_VERSION:
            raise ParityError("cache_name_or_version_mismatch")
        try:
            _mismatch(manifest["files"], cache_rows, cache=True)
        except ParityError as error:
            if error.code in {"cache_file_missing", "cache_file_extra"}:
                raise
            raise ParityError("same_version_cache_drift") from error
        cache = {
            "file_count": len(cache_rows),
            "root": str(cache_path),
            "status": "parity",
            "tree_sha256": _tree_sha256(cache_rows),
        }
    staged: dict[str, Any] = {"status": "not_requested"}
    if stage_leaf is not None:
        stage_path = _root(stage_leaf, missing_code="stage_leaf_missing")
        if (
            stage_path.name != manifest_sha256
            or stage_path.parent.name != CANDIDATE_VERSION
            or stage_path.parent.parent.name != PACKAGE_NAME
        ):
            raise ParityError("stage_leaf_identity_mismatch")
        stage_rows, stage_payloads = _snapshot(stage_path)
        _verify_stage_modes(stage_path)
        try:
            stage_manifest_raw = stage_payloads[MANIFEST_RELATIVE.as_posix()]
            stage_plugin_raw = stage_payloads[PLUGIN_RELATIVE.as_posix()]
        except KeyError as error:
            raise ParityError("stage_leaf_file_missing") from error
        if stage_manifest_raw != manifest_raw:
            raise ParityError("stage_leaf_manifest_mismatch")
        stage_plugin = _json(stage_plugin_raw, code="stage_leaf_plugin_json_invalid")
        if (
            stage_plugin.get("name") != PACKAGE_NAME
            or stage_plugin.get("version") != CANDIDATE_VERSION
        ):
            raise ParityError("stage_leaf_name_or_version_mismatch")
        _mismatch(manifest["files"], stage_rows, cache=False, stage_leaf=True)
        staged = {
            "file_count": len(stage_rows),
            "root": str(stage_path),
            "status": "parity",
            "tree_sha256": _tree_sha256(stage_rows),
        }
    return {
        "authority": "source_release_manifest",
        "cache": cache,
        "package_name": PACKAGE_NAME,
        "release_manifest_sha256": manifest_sha256,
        "release_receipt": receipt or {"status": "not_requested"},
        "schema_version": SCHEMA_VERSION,
        "stage_leaf": staged,
        "source": {
            "file_count": len(source_rows),
            "root": str(source),
            "status": "parity",
            "tree_sha256": _tree_sha256(source_rows),
        },
        "status": "pass",
        "version": CANDIDATE_VERSION,
    }


def _stage_parent(parent: Path, name: str) -> Path:
    path = parent / name
    try:
        path.mkdir(exist_ok=True)
    except OSError as error:
        raise ParityError("stage_parent_unavailable") from error
    return _root(path, missing_code="stage_parent_unavailable")


def _write_payloads(root: Path, payloads: dict[str, bytes]) -> None:
    for relative, raw in sorted(payloads.items()):
        path = root / Path(PurePosixPath(relative))
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o444,
            )
        except OSError as error:
            raise ParityError("stage_write_failed") from error
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ParityError("stage_write_failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _harden_stage_tree(root: Path) -> None:
    """Make every staged file and directory read-only before publication."""
    identities, files = _inventory(root)
    directories = [
        root if row["path"] == "." else root / Path(PurePosixPath(row["path"]))
        for row in identities
        if row["kind"] == "directory"
    ]
    try:
        for path in files:
            os.chmod(path, 0o444, follow_symlinks=False)
        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            os.chmod(path, 0o555, follow_symlinks=False)
    except OSError as error:
        raise ParityError("stage_hardening_failed") from error


def _verify_stage_modes(root: Path) -> None:
    identities, _ = _inventory(root)
    for row in identities:
        expected = 0o555 if row["kind"] == "directory" else 0o444
        if row["mode"] != expected:
            raise ParityError("stage_leaf_mode_drift")


def stage(source_root: object, staging_parent: object) -> dict[str, Any]:
    source = _root(source_root, missing_code="source_missing")
    parent = _root(staging_parent, missing_code="stage_parent_missing")
    rows, payloads = _snapshot(source, source_projection=True)
    try:
        manifest_raw = payloads[MANIFEST_RELATIVE.as_posix()]
        plugin_raw = payloads[PLUGIN_RELATIVE.as_posix()]
    except KeyError as error:
        raise ParityError("source_file_missing") from error
    manifest = _manifest(manifest_raw)
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    plugin = _json(plugin_raw, code="plugin_json_invalid")
    if plugin.get("name") != PACKAGE_NAME or plugin.get("version") != CANDIDATE_VERSION:
        raise ParityError("plugin_name_or_version_mismatch")
    _mismatch(manifest["files"], rows, cache=False)

    package_parent = _stage_parent(parent, PACKAGE_NAME)
    version_parent = _stage_parent(package_parent, CANDIDATE_VERSION)
    target = version_parent / manifest_sha256
    if target.exists() or target.is_symlink():
        raise ParityError("stage_target_exists")
    temporary = Path(tempfile.mkdtemp(prefix=f".{manifest_sha256}.tmp-", dir=version_parent))
    try:
        _write_payloads(temporary, payloads)
        staged_rows, staged_payloads = _snapshot(temporary)
        if staged_rows != rows or staged_payloads.get(MANIFEST_RELATIVE.as_posix()) != manifest_raw:
            raise ParityError("stage_content_mismatch")
        _harden_stage_tree(temporary)
        _verify_stage_modes(temporary)
        try:
            os.rename(temporary, target)
        except OSError as error:
            raise ParityError("stage_publish_failed") from error
        try:
            os.chmod(version_parent, 0o555, follow_symlinks=False)
        except OSError as error:
            raise ParityError("stage_hardening_failed") from error
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    artifact = _root(target, missing_code="stage_publish_failed")
    candidate = _candidate_receipt(artifact, manifest_sha256, staged_rows)
    return {
        "artifact": {
            "file_count": len(staged_rows),
            "immutable_modes": True,
            "root": str(artifact),
            "status": "staged",
            "tree_sha256": _tree_sha256(staged_rows),
        },
        "authority": "source_release_manifest",
        "candidate_receipt": candidate,
        "origin": {
            "file_count": len(rows),
            "root": str(source),
            "status": "stable_snapshot",
            "tree_sha256": _tree_sha256(rows),
        },
        "package_name": PACKAGE_NAME,
        "release_manifest_sha256": manifest_sha256,
        "schema_version": SCHEMA_VERSION,
        "status": "pass",
        "version": CANDIDATE_VERSION,
    }


def _failure(operation: str, error: ParityError) -> dict[str, Any]:
    return {
        "authority": "source_release_manifest",
        "failure": error.code,
        "operation": operation,
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    build = sub.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--write-manifest", action="store_true")
    staging = sub.add_parser("stage")
    staging.add_argument("--source-root", type=Path, required=True)
    staging.add_argument("--staging-parent", type=Path, required=True)
    check = sub.add_parser("verify")
    check.add_argument("--source-root", type=Path, required=True)
    check.add_argument("--cache-root", type=Path)
    check.add_argument("--stage-leaf", type=Path)
    check.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == "build":
            result = (
                write_manifest(args.source_root)
                if args.write_manifest else build_manifest(args.source_root)
            )
        elif args.operation == "stage":
            result = stage(args.source_root, args.staging_parent)
        else:
            result = verify(
                args.source_root, cache_root=args.cache_root,
                stage_leaf=args.stage_leaf,
                receipt_path=args.receipt,
            )
    except ParityError as error:
        print(canonical_json(_failure(args.operation, error)))
        return 2
    except Exception:
        print(canonical_json({
            "authority": "source_release_manifest",
            "failure": "release_parity_internal_error",
            "operation": args.operation,
            "schema_version": SCHEMA_VERSION,
            "status": "failed",
        }))
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
