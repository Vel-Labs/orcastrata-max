#!/usr/bin/env python3
"""Forward-only, byte-preserving GoalBuddy WorkGraph migration runtime."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Any, Callable, Sequence


PROTOCOL = "workgraph_migration"
RECEIPT_VERSION = 1
CURRENT_VERSION = 2
NEXT_VERSION = 3
JOURNAL_NAME = "migration-journal.json"
LOCK_NAME = ".workgraph-migration.lock"
BACKUP_DIR = "migration-backups"
INTERNAL_PREFIX = ".workgraph-migration-"
VERSION_LINE = re.compile(
    r"^(version:[ \t]*)([^#\r\n]+?)([ \t]*(?:#.*)?)(\r?\n?)$"
)
JOURNAL_KEYS = {
    "schema_version", "source_version", "target_version", "source_board_sha256",
    "result_board_sha256", "result_board_base64", "history", "history_digest",
    "backup_path", "backup_manifest_sha256", "phase",
}
PHASES = {"backup_ready", "state_prepared", "state_replaced", "complete"}


class MigrationError(Exception):
    """Stable migration failure."""

    def __init__(self, code: str, details: object | None = None):
        super().__init__(code)
        self.code = code
        self.details = details


class ReceiptArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise MigrationError("migration_arguments_invalid", message)


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_root(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise MigrationError("migration_root_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
        status = path.lstat()
    except OSError as error:
        raise MigrationError("migration_root_unavailable") from error
    if resolved != lexical or stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise MigrationError("migration_root_alias_forbidden")
    return lexical


def _regular(path: Path, *, required: bool = True) -> os.stat_result | None:
    try:
        status = path.lstat()
    except FileNotFoundError:
        if required:
            raise MigrationError("migration_file_missing", str(path))
        return None
    except OSError as error:
        raise MigrationError("migration_file_unavailable", str(path)) from error
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise MigrationError("migration_file_unavailable", str(path)) from error
    if (
        resolved != Path(os.path.abspath(path))
        or stat.S_ISLNK(status.st_mode)
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
    ):
        raise MigrationError("migration_file_alias_forbidden", str(path))
    return status


def _read_regular(path: Path) -> bytes:
    before = _regular(path)
    assert before is not None
    try:
        raw = path.read_bytes()
        after = _regular(path)
    except OSError as error:
        raise MigrationError("migration_file_unavailable", str(path)) from error
    assert after is not None
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise MigrationError("migration_file_identity_changed", str(path))
    return raw


def _version_and_result(raw: bytes) -> tuple[int, bytes]:
    try:
        lines = raw.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise MigrationError("migration_state_utf8_invalid") from error
    matches: list[tuple[int, re.Match[str]]] = []
    for index, line in enumerate(lines):
        if line.startswith("version:"):
            match = VERSION_LINE.fullmatch(line)
            if match is None:
                raise MigrationError("migration_version_invalid")
            matches.append((index, match))
    if len(matches) != 1:
        raise MigrationError("migration_version_ambiguous" if matches else "migration_version_missing")
    index, match = matches[0]
    token = match.group(2).strip()
    if not re.fullmatch(r"[0-9]+", token) or token in {"0", "1"}:
        raise MigrationError("migration_version_invalid")
    version = int(token)
    lines[index] = f"{match.group(1)}{NEXT_VERSION}{match.group(3)}{match.group(4)}"
    return version, "".join(lines).encode("utf-8")


def _sidecar(root: Path, *, create: bool) -> Path:
    path = root / ".goalbuddy-board"
    if not path.exists():
        if not create:
            return path
        path.mkdir(mode=0o700)
        _fsync_directory(root)
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise MigrationError("migration_sidecar_unavailable") from error
    if resolved != Path(os.path.abspath(path)) or stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise MigrationError("migration_sidecar_alias_forbidden")
    return path


def _directory(path: Path, code: str) -> None:
    try:
        status = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise MigrationError(code) from error
    if resolved != Path(os.path.abspath(path)) or stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise MigrationError(code)


@contextmanager
def _locked(sidecar: Path):
    path = sidecar / LOCK_NAME
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        named = path.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise MigrationError("migration_lock_alias_forbidden") from error
    if (
        not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
        or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        raise MigrationError("migration_lock_alias_forbidden")
    with os.fdopen(descriptor, "a+b", closefd=True) as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield stream


def _excluded(relative: Path) -> bool:
    if not relative.parts:
        return False
    first = relative.parts[0]
    return first in {BACKUP_DIR, JOURNAL_NAME, LOCK_NAME}


def _inventory(sidecar: Path) -> list[dict[str, object]]:
    if not sidecar.exists():
        return []
    rows: list[dict[str, object]] = []
    for path in sorted(sidecar.rglob("*"), key=lambda item: item.relative_to(sidecar).as_posix()):
        relative = path.relative_to(sidecar)
        if _excluded(relative):
            continue
        try:
            status = path.lstat()
        except OSError as error:
            raise MigrationError("migration_history_unavailable", relative.as_posix()) from error
        if stat.S_ISLNK(status.st_mode):
            raise MigrationError("migration_history_alias_forbidden", relative.as_posix())
        if stat.S_ISDIR(status.st_mode):
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise MigrationError("migration_history_alias_forbidden", relative.as_posix())
        raw = _read_regular(path)
        rows.append({
            "device": status.st_dev,
            "inode": status.st_ino,
            "path": relative.as_posix(),
            "size": len(raw),
            "sha256": _digest(raw),
        })
    return rows


def _inventory_digest(rows: list[dict[str, object]]) -> str:
    return _digest(canonical_json(rows).encode("utf-8"))


def _validate_history_rows(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise MigrationError("migration_journal_corrupt")
    rows: list[dict[str, object]] = []
    previous = ""
    for row in value:
        if not isinstance(row, dict) or set(row) != {"device", "inode", "path", "size", "sha256"}:
            raise MigrationError("migration_journal_corrupt")
        path = row["path"]
        size = row["size"]
        device = row["device"]
        inode = row["inode"]
        digest = row["sha256"]
        relative = Path(path) if isinstance(path, str) and "\x00" not in path else None
        if (
            relative is None or not path or relative.is_absolute()
            or relative.as_posix() != path or path in {".", ".."} or ".." in relative.parts
            or _excluded(relative) or path <= previous
            or not isinstance(size, int) or isinstance(size, bool) or size < 0
            or not isinstance(device, int) or isinstance(device, bool) or device < 0
            or not isinstance(inode, int) or isinstance(inode, bool) or inode < 1
            or not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
        ):
            raise MigrationError("migration_journal_corrupt")
        previous = path
        rows.append(row)
    return rows


def _atomic_bytes(path: Path, raw: bytes, mode: int = 0o600) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=INTERNAL_PREFIX, dir=path.parent)
    temp_path = Path(temporary)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            if stream.write(raw) != len(raw):
                raise MigrationError("migration_write_incomplete")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temp_path.unlink(missing_ok=True)
        raise


def _atomic_json(path: Path, value: object) -> None:
    _atomic_bytes(path, (canonical_json(value) + "\n").encode("utf-8"))


def _manifest_value(board_raw: bytes, history: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "source_version": CURRENT_VERSION,
        "target_version": NEXT_VERSION,
        "source_board_sha256": _digest(board_raw),
        "history": history,
        "history_digest": _inventory_digest(history),
    }


def _backup_path(sidecar: Path, board_raw: bytes) -> Path:
    source_hex = _digest(board_raw).split(":", 1)[1]
    return sidecar / BACKUP_DIR / f"v2-to-v3-{source_hex}"


def _verify_backup_tree(final: Path, history: list[dict[str, object]]) -> None:
    expected_files = {Path("manifest.json"), Path("state.yaml")}
    expected_files.update(Path(".goalbuddy-board") / str(row["path"]) for row in history)
    expected_directories: set[Path] = set()
    for relative in expected_files:
        parent = relative.parent
        while parent != Path("."):
            expected_directories.add(parent)
            parent = parent.parent
    actual_files: set[Path] = set()
    actual_directories: set[Path] = set()
    try:
        for current, directories, files in os.walk(final, topdown=True, followlinks=False):
            current_path = Path(current)
            for name in directories:
                path = current_path / name
                status = path.lstat()
                relative = path.relative_to(final)
                if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                    raise MigrationError("migration_backup_conflict", relative.as_posix())
                actual_directories.add(relative)
            for name in files:
                path = current_path / name
                status = path.lstat()
                relative = path.relative_to(final)
                if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise MigrationError("migration_backup_conflict", relative.as_posix())
                actual_files.add(relative)
    except OSError as error:
        raise MigrationError("migration_backup_conflict", str(final)) from error
    if actual_files != expected_files or actual_directories != expected_directories:
        raise MigrationError("migration_backup_conflict", str(final))


def _existing_backup(sidecar: Path, board_raw: bytes,
                     history: list[dict[str, object]], *, missing_code: str) -> tuple[Path, str]:
    parent = sidecar / BACKUP_DIR
    final = _backup_path(sidecar, board_raw)
    if not parent.exists() or not final.exists():
        raise MigrationError(missing_code)
    _directory(parent, "migration_backup_alias_forbidden")
    _directory(final, "migration_backup_alias_forbidden")
    _verify_backup_tree(final, history)
    expected_manifest_raw = (canonical_json(_manifest_value(board_raw, history)) + "\n").encode("utf-8")
    manifest_raw = _read_regular(final / "manifest.json")
    if manifest_raw != expected_manifest_raw or _read_regular(final / "state.yaml") != board_raw:
        raise MigrationError("migration_backup_conflict", str(final))
    for row in history:
        relative = Path(str(row["path"]))
        copied = _read_regular(final / ".goalbuddy-board" / relative)
        if len(copied) != row["size"] or _digest(copied) != row["sha256"]:
            raise MigrationError("migration_backup_conflict", relative.as_posix())
    _verify_backup_tree(final, history)
    return final, _digest(manifest_raw)


def _backup(root: Path, sidecar: Path, board_raw: bytes, history: list[dict[str, object]]) -> tuple[Path, str]:
    parent = sidecar / BACKUP_DIR
    parent.mkdir(mode=0o700, exist_ok=True)
    _directory(parent, "migration_backup_alias_forbidden")
    _fsync_directory(sidecar)
    final = _backup_path(sidecar, board_raw)
    if final.exists() or final.is_symlink():
        return _existing_backup(sidecar, board_raw, history, missing_code="migration_backup_unavailable")
    temporary = Path(tempfile.mkdtemp(prefix=INTERNAL_PREFIX, dir=parent))
    try:
        state_copy = temporary / "state.yaml"
        state_copy.write_bytes(board_raw)
        with state_copy.open("rb") as stream:
            os.fsync(stream.fileno())
        for row in history:
            relative = Path(str(row["path"]))
            source = sidecar / relative
            destination = temporary / ".goalbuddy-board" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            source_raw = _read_regular(source)
            if len(source_raw) != row["size"] or _digest(source_raw) != row["sha256"]:
                raise MigrationError("migration_history_changed", relative.as_posix())
            destination.write_bytes(source_raw)
            os.chmod(destination, 0o600)
            with destination.open("rb") as stream:
                os.fsync(stream.fileno())
        manifest = _manifest_value(board_raw, history)
        manifest_raw = (canonical_json(manifest) + "\n").encode("utf-8")
        (temporary / "manifest.json").write_bytes(manifest_raw)
        with (temporary / "manifest.json").open("rb") as stream:
            os.fsync(stream.fileno())
        for directory in sorted({path.parent for path in temporary.rglob("*")}, key=lambda item: len(item.parts), reverse=True):
            _fsync_directory(directory)
        _fsync_directory(temporary)
        os.replace(temporary, final)
        _fsync_directory(parent)
        return final, _digest(manifest_raw)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _journal(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_read_regular(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("migration_journal_corrupt") from error
    if not isinstance(value, dict) or set(value) != JOURNAL_KEYS or value.get("schema_version") != 1 or value.get("phase") not in PHASES:
        raise MigrationError("migration_journal_corrupt")
    if value.get("source_version") != CURRENT_VERSION or value.get("target_version") != NEXT_VERSION:
        raise MigrationError("migration_journal_corrupt")
    for key in ("source_board_sha256", "result_board_sha256", "history_digest", "backup_manifest_sha256"):
        if not isinstance(value.get(key), str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) is None:
            raise MigrationError("migration_journal_corrupt")
    backup_value = value.get("backup_path")
    if (
        not isinstance(backup_value, str) or not backup_value or "\x00" in backup_value
        or not Path(backup_value).is_absolute() or ".." in Path(backup_value).parts
    ):
        raise MigrationError("migration_backup_invalid")
    history = _validate_history_rows(value.get("history"))
    if value.get("history_digest") != _inventory_digest(history):
        raise MigrationError("migration_journal_corrupt")
    try:
        result = base64.b64decode(value["result_board_base64"], validate=True)
    except Exception as error:
        raise MigrationError("migration_journal_corrupt") from error
    if _digest(result) != value.get("result_board_sha256"):
        raise MigrationError("migration_journal_corrupt")
    return value


def _verify_backup(journal: dict[str, Any], sidecar: Path) -> None:
    backup_value = journal["backup_path"]
    if not isinstance(backup_value, str):
        raise MigrationError("migration_backup_invalid")
    backup = Path(backup_value)
    expected_parent = sidecar / BACKUP_DIR
    source_hash = str(journal["source_board_sha256"])
    expected_backup = expected_parent / f"v2-to-v3-{source_hash.split(':', 1)[1]}"
    if Path(os.path.abspath(backup)) != expected_backup:
        raise MigrationError("migration_backup_invalid")
    _directory(expected_parent, "migration_backup_unavailable")
    _directory(backup, "migration_backup_unavailable")
    try:
        if backup.parent.resolve(strict=True) != expected_parent.resolve(strict=True):
            raise MigrationError("migration_backup_invalid")
    except OSError as error:
        raise MigrationError("migration_backup_unavailable") from error
    manifest_path = backup / "manifest.json"
    manifest_raw = _read_regular(manifest_path)
    if _digest(manifest_raw) != journal["backup_manifest_sha256"]:
        raise MigrationError("migration_backup_manifest_mismatch")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("migration_backup_manifest_invalid") from error
    expected_manifest = {
        "schema_version": 1,
        "source_version": CURRENT_VERSION,
        "target_version": NEXT_VERSION,
        "source_board_sha256": journal["source_board_sha256"],
        "history": journal["history"],
        "history_digest": journal["history_digest"],
    }
    if manifest != expected_manifest:
        raise MigrationError("migration_backup_manifest_invalid")
    backup_state = _read_regular(backup / "state.yaml")
    if _digest(backup_state) != journal["source_board_sha256"]:
        raise MigrationError("migration_backup_state_mismatch")
    backup_version, derived_result = _version_and_result(backup_state)
    try:
        journal_result = base64.b64decode(str(journal["result_board_base64"]), validate=True)
    except Exception as error:
        raise MigrationError("migration_journal_corrupt") from error
    if (
        backup_version != CURRENT_VERSION
        or journal_result != derived_result
        or _digest(derived_result) != journal["result_board_sha256"]
    ):
        raise MigrationError("migration_journal_result_mismatch")
    for row in journal["history"]:
        relative = Path(str(row["path"]))
        raw = _read_regular(backup / ".goalbuddy-board" / relative)
        if len(raw) != row["size"] or _digest(raw) != row["sha256"]:
            raise MigrationError("migration_backup_history_mismatch", relative.as_posix())


def _receipt(operation: str, *, source_version: int, source_hash: str, result_hash: str,
             history: list[dict[str, object]], backup: str | None, phase: str,
             outcome: str) -> dict[str, object]:
    return {
        "acceptance_effect": "none", "authority_effect": "none",
        "backup_path": backup, "history": history,
        "history_digest": _inventory_digest(history), "journal_phase": phase,
        "operation": operation, "outcome": outcome, "protocol": PROTOCOL,
        "result_board_sha256": result_hash, "schema_version": RECEIPT_VERSION,
        "source_board_sha256": source_hash, "source_version": source_version,
        "status": "ok", "target_version": NEXT_VERSION,
    }


def inspect(root_value: str | Path) -> dict[str, object]:
    root = _canonical_root(root_value)
    raw = _read_regular(root / "state.yaml")
    version, result = _version_and_result(raw)
    if version not in {CURRENT_VERSION, NEXT_VERSION}:
        raise MigrationError("migration_version_unsupported", version)
    sidecar = _sidecar(root, create=False)
    history = _inventory(sidecar)
    return {
        "acceptance_effect": "none", "authority_effect": "none",
        "capabilities": {
            "downgrade": False, "forward_migration": version == CURRENT_VERSION,
            "pinned_current_version": CURRENT_VERSION, "recognized_next_version": NEXT_VERSION,
        },
        "history": history, "history_digest": _inventory_digest(history),
        "operation": "inspect", "protocol": PROTOCOL,
        "result_board_sha256": _digest(result if version == CURRENT_VERSION else raw),
        "schema_version": RECEIPT_VERSION, "source_board_sha256": _digest(raw),
        "source_version": version, "status": "ok", "target_version": NEXT_VERSION,
    }


def migrate(root_value: str | Path, *, to_version: int = NEXT_VERSION,
            interrupt_after: str | None = None,
            before_replace: Callable[[], None] | None = None) -> dict[str, object]:
    root = _canonical_root(root_value)
    state = root / "state.yaml"
    initial_raw = _read_regular(state)
    initial_version, _ = _version_and_result(initial_raw)
    if to_version != NEXT_VERSION:
        if to_version < initial_version:
            raise MigrationError("migration_downgrade_refused")
        raise MigrationError("migration_target_unsupported", to_version)
    if initial_version == NEXT_VERSION:
        raise MigrationError("migration_already_current_next")
    if initial_version != CURRENT_VERSION:
        raise MigrationError("migration_version_unsupported", initial_version)
    sidecar = _sidecar(root, create=True)
    with _locked(sidecar):
        raw = _read_regular(state)
        version, result_raw = _version_and_result(raw)
        if raw != initial_raw or version != initial_version:
            raise MigrationError("migration_board_changed_before_lock")
        state_status = _regular(state)
        assert state_status is not None
        state_mode = stat.S_IMODE(state_status.st_mode)
        journal_path = sidecar / JOURNAL_NAME
        if journal_path.exists():
            raise MigrationError("migration_recovery_required")
        history = _inventory(sidecar)
        backup, manifest_hash = _backup(root, sidecar, raw, history)
        journal: dict[str, object] = {
            "schema_version": 1, "source_version": version, "target_version": to_version,
            "source_board_sha256": _digest(raw), "result_board_sha256": _digest(result_raw),
            "result_board_base64": base64.b64encode(result_raw).decode("ascii"),
            "history": history, "history_digest": _inventory_digest(history),
            "backup_path": str(backup), "backup_manifest_sha256": manifest_hash,
            "phase": "backup_ready",
        }
        _atomic_json(journal_path, journal)
        if interrupt_after == "backup_ready":
            raise MigrationError("migration_interrupted", "backup_ready")
        journal["phase"] = "state_prepared"
        _atomic_json(journal_path, journal)
        if interrupt_after == "state_prepared":
            raise MigrationError("migration_interrupted", "state_prepared")
        if before_replace is not None:
            before_replace()
        if _read_regular(state) != raw:
            raise MigrationError("migration_board_changed_before_replace")
        if _inventory(sidecar) != history:
            raise MigrationError("migration_history_changed")
        _atomic_bytes(state, result_raw, mode=state_mode)
        journal["phase"] = "state_replaced"
        _atomic_json(journal_path, journal)
        if interrupt_after == "state_replaced":
            raise MigrationError("migration_interrupted", "state_replaced")
        after_history = _inventory(sidecar)
        if after_history != history:
            raise MigrationError("migration_history_changed")
        journal["phase"] = "complete"
        _atomic_json(journal_path, journal)
        return _receipt(
            "migrate", source_version=version, source_hash=_digest(raw),
            result_hash=_digest(result_raw), history=history, backup=str(backup),
            phase="complete", outcome="migrated",
        )


def recover(root_value: str | Path, *, before_replace: Callable[[], None] | None = None) -> dict[str, object]:
    root = _canonical_root(root_value)
    sidecar = _sidecar(root, create=False)
    if not sidecar.exists():
        raise MigrationError("migration_journal_missing")
    with _locked(sidecar):
        journal_path = sidecar / JOURNAL_NAME
        if not journal_path.exists():
            state = root / "state.yaml"
            orphan_raw = _read_regular(state)
            orphan_version, orphan_result = _version_and_result(orphan_raw)
            if orphan_version != CURRENT_VERSION:
                raise MigrationError("migration_journal_missing")
            orphan_history = _inventory(sidecar)
            backup, manifest_hash = _existing_backup(
                sidecar, orphan_raw, orphan_history, missing_code="migration_journal_missing"
            )
            orphan_journal: dict[str, object] = {
                "schema_version": 1, "source_version": CURRENT_VERSION,
                "target_version": NEXT_VERSION, "source_board_sha256": _digest(orphan_raw),
                "result_board_sha256": _digest(orphan_result),
                "result_board_base64": base64.b64encode(orphan_result).decode("ascii"),
                "history": orphan_history, "history_digest": _inventory_digest(orphan_history),
                "backup_path": str(backup), "backup_manifest_sha256": manifest_hash,
                "phase": "backup_ready",
            }
            _atomic_json(journal_path, orphan_journal)
        journal = _journal(journal_path)
        _verify_backup(journal, sidecar)
        state = root / "state.yaml"
        raw = _read_regular(state)
        current_hash = _digest(raw)
        source_hash = str(journal["source_board_sha256"])
        result_hash = str(journal["result_board_sha256"])
        history = journal["history"]
        assert isinstance(history, list)
        if _inventory(sidecar) != history:
            raise MigrationError("migration_history_divergent")
        result_raw = base64.b64decode(str(journal["result_board_base64"]), validate=True)
        if journal["phase"] == "complete":
            if current_hash != result_hash:
                raise MigrationError("migration_board_divergent")
            outcome = "already_complete"
        elif current_hash == source_hash:
            state_status = _regular(state)
            assert state_status is not None
            if before_replace is not None:
                before_replace()
            if _read_regular(state) != raw:
                raise MigrationError("migration_board_changed_before_recovery_replace")
            if _inventory(sidecar) != history:
                raise MigrationError("migration_history_changed")
            _atomic_bytes(state, result_raw, mode=stat.S_IMODE(state_status.st_mode))
            journal["phase"] = "state_replaced"
            _atomic_json(journal_path, journal)
            outcome = "recovered_forward"
        elif current_hash == result_hash:
            outcome = "finalized_forward"
        else:
            raise MigrationError("migration_board_divergent")
        if _inventory(sidecar) != history:
            raise MigrationError("migration_history_changed")
        journal["phase"] = "complete"
        _atomic_json(journal_path, journal)
        return _receipt(
            "recover", source_version=CURRENT_VERSION, source_hash=source_hash,
            result_hash=result_hash, history=history, backup=str(journal["backup_path"]),
            phase="complete", outcome=outcome,
        )


def _error(operation: str, error: MigrationError) -> dict[str, object]:
    result: dict[str, object] = {
        "acceptance_effect": "none", "authority_effect": "none", "error": error.code,
        "operation": operation, "protocol": PROTOCOL, "schema_version": RECEIPT_VERSION,
        "status": "error",
    }
    if error.details is not None:
        result["details"] = error.details
    return result


def _target_version(value: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise MigrationError("migration_target_invalid", value)
    return int(value)


def main(argv: Sequence[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    operation = raw_args[0] if raw_args and re.fullmatch(r"[a-z-]+", raw_args[0]) else "unknown"
    try:
        parser = ReceiptArgumentParser(description=__doc__)
        subparsers = parser.add_subparsers(dest="operation", required=True, parser_class=ReceiptArgumentParser)
        for name in ("inspect", "recover"):
            command = subparsers.add_parser(name)
            command.add_argument("goal_root")
        command = subparsers.add_parser("migrate")
        command.add_argument("goal_root")
        command.add_argument("--to-version", required=True)
        args = parser.parse_args(raw_args)
        operation = args.operation
        if args.operation == "inspect":
            receipt = inspect(args.goal_root)
        elif args.operation == "migrate":
            receipt = migrate(args.goal_root, to_version=_target_version(args.to_version))
        else:
            receipt = recover(args.goal_root)
    except MigrationError as error:
        print(canonical_json(_error(operation, error)))
        return 2
    except OSError as error:
        print(canonical_json(_error(operation, MigrationError("migration_storage_error", error.errno))))
        return 2
    print(canonical_json(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
