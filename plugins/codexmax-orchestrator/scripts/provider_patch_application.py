#!/usr/bin/env python3
"""Validate and apply bounded unified diffs to existing regular files."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence


HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$")
MAX_PATCH_BYTES = 1024 * 1024
MAX_FILES = 32


class PatchError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\\" in value:
        raise PatchError("patch_path_invalid", str(value))
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PatchError("patch_path_invalid", value)
    return path.as_posix()


def _parent_fd(root: Path, relative: str) -> tuple[int, str]:
    parts = Path(relative).parts
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except Exception:
        os.close(descriptor)
        raise


def read_existing(root: Path, relative: str) -> bytes:
    relative = relative_path(relative)
    descriptor, name = _parent_fd(root, relative)
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PatchError("authorized_file_unsafe", relative)
            return os.read(fd, info.st_size + 1)
        finally:
            os.close(fd)
    except FileNotFoundError as exc:
        raise PatchError("authorized_file_missing", relative) from exc
    finally:
        os.close(descriptor)


def overwrite_existing(root: Path, relative: str, data: bytes, expected_sha256: str) -> None:
    relative = relative_path(relative)
    descriptor, name = _parent_fd(root, relative)
    try:
        fd = os.open(name, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), dir_fd=descriptor)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PatchError("authorized_file_unsafe", relative)
            current = os.read(fd, info.st_size + 1)
            if sha256(current) != expected_sha256:
                raise PatchError("authorized_file_drift", relative)
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(descriptor)


def validate_authorized_files(root: Path, values: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_FILES:
        raise PatchError("authorized_files_invalid")
    result: dict[str, dict[str, Any]] = {}
    for row in values:
        if not isinstance(row, Mapping) or set(row) != {"path", "before_sha256", "max_bytes"}:
            raise PatchError("authorized_file_shape_invalid")
        path = relative_path(row["path"])
        if path in result:
            raise PatchError("authorized_file_duplicate", path)
        max_bytes = row["max_bytes"]
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 4 * 1024 * 1024:
            raise PatchError("authorized_file_max_bytes_invalid", path)
        before = read_existing(root, path)
        if len(before) > max_bytes:
            raise PatchError("authorized_file_too_large", path)
        if sha256(before) != row["before_sha256"]:
            raise PatchError("authorized_file_before_mismatch", path)
        try:
            before.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PatchError("authorized_file_not_utf8", path) from exc
        result[path] = {"before": before, "max_bytes": max_bytes}
    return result


def _header_path(line: str, prefix: str) -> str:
    if not line.startswith(prefix):
        raise PatchError("patch_header_invalid", line)
    value = line[len(prefix):].split("\t", 1)[0]
    if value == "/dev/null":
        raise PatchError("patch_create_delete_forbidden", value)
    if value.startswith(("a/", "b/")):
        value = value[2:]
    return relative_path(value)


def _apply_hunks(path: str, original: str, lines: list[str], start: int) -> tuple[str, int]:
    source = original.splitlines(keepends=True)
    output: list[str] = []
    source_index = 0
    index = start
    changed = False
    while index < len(lines) and not lines[index].startswith("--- "):
        match = HUNK.fullmatch(lines[index].rstrip("\n"))
        if match is None:
            raise PatchError("patch_hunk_header_invalid", lines[index].rstrip())
        old_start = int(match.group(1))
        expected_index = old_start - 1
        if expected_index < source_index or expected_index > len(source):
            raise PatchError("patch_hunk_position_invalid", path)
        output.extend(source[source_index:expected_index])
        source_index = expected_index
        old_count = 0
        new_count = 0
        index += 1
        while index < len(lines) and not lines[index].startswith(("@@ ", "--- ")):
            line = lines[index]
            if line.startswith("\\ No newline at end of file"):
                raise PatchError("patch_no_newline_marker_unsupported", path)
            if not line or line[0] not in " +-":
                raise PatchError("patch_line_invalid", path)
            marker, content = line[0], line[1:]
            if marker in " -":
                if source_index >= len(source) or source[source_index] != content:
                    raise PatchError("patch_context_mismatch", path)
                if marker == " ":
                    output.append(content)
                    new_count += 1
                else:
                    changed = True
                source_index += 1
                old_count += 1
            else:
                output.append(content)
                new_count += 1
                changed = True
            index += 1
        declared_old = int(match.group(2) or "1")
        declared_new = int(match.group(4) or "1")
        if old_count != declared_old or new_count != declared_new:
            raise PatchError("patch_hunk_count_mismatch", path)
    if not changed:
        raise PatchError("patch_file_no_change", path)
    output.extend(source[source_index:])
    return "".join(output), index


def apply_patch(
    *, root: Path, patch_text: str, authorized_files: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    if not isinstance(patch_text, str) or not patch_text or len(patch_text.encode("utf-8")) > MAX_PATCH_BYTES:
        raise PatchError("patch_text_invalid")
    if "GIT binary patch" in patch_text or "Binary files " in patch_text:
        raise PatchError("patch_binary_forbidden")
    authorized = validate_authorized_files(root, authorized_files)
    lines = patch_text.splitlines(keepends=True)
    if not lines or not lines[0].startswith("--- "):
        raise PatchError("patch_header_invalid")
    proposed: dict[str, bytes] = {}
    index = 0
    while index < len(lines):
        old_path = _header_path(lines[index].rstrip("\n"), "--- ")
        index += 1
        if index >= len(lines):
            raise PatchError("patch_header_incomplete", old_path)
        new_path = _header_path(lines[index].rstrip("\n"), "+++ ")
        index += 1
        if old_path != new_path:
            raise PatchError("patch_rename_forbidden", f"{old_path}->{new_path}")
        if old_path not in authorized:
            raise PatchError("patch_path_not_authorized", old_path)
        if old_path in proposed:
            raise PatchError("patch_path_duplicate", old_path)
        result, index = _apply_hunks(
            old_path, authorized[old_path]["before"].decode("utf-8"), lines, index,
        )
        encoded = result.encode("utf-8")
        if len(encoded) > authorized[old_path]["max_bytes"]:
            raise PatchError("patch_result_too_large", old_path)
        proposed[old_path] = encoded
    if not proposed:
        raise PatchError("patch_no_changes")

    applied: list[str] = []
    try:
        for path in sorted(proposed):
            before = authorized[path]["before"]
            overwrite_existing(root, path, proposed[path], sha256(before))
            applied.append(path)
    except Exception:
        for path in reversed(applied):
            before = authorized[path]["before"]
            overwrite_existing(root, path, before, sha256(proposed[path]))
        raise
    return {
        "changed_paths": sorted(proposed),
        "files": [
            {
                "path": path,
                "before_sha256": sha256(authorized[path]["before"]),
                "after_sha256": sha256(proposed[path]),
                "before_bytes": len(authorized[path]["before"]),
                "after_bytes": len(proposed[path]),
            }
            for path in sorted(proposed)
        ],
        "before_bytes": {path: authorized[path]["before"] for path in proposed},
    }


def rollback(*, root: Path, receipt: Mapping[str, Any], before_bytes: Mapping[str, bytes]) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    files = receipt.get("files")
    if not isinstance(files, list) or not files:
        raise PatchError("rollback_receipt_invalid")
    prepared: list[tuple[str, bytes, bytes, str]] = []
    for row in files:
        path = relative_path(row.get("path"))
        before = before_bytes.get(path)
        if not isinstance(before, bytes) or sha256(before) != row.get("before_sha256"):
            raise PatchError("rollback_before_invalid", path)
        after = read_existing(root, path)
        after_digest = str(row.get("after_sha256"))
        if sha256(after) != after_digest:
            raise PatchError("authorized_file_drift", path)
        prepared.append((path, before, after, after_digest))
    restored: list[str] = []
    try:
        for path, before, _after, after_digest in reversed(prepared):
            overwrite_existing(root, path, before, after_digest)
            restored.append(path)
    except Exception:
        for path, before, after, _after_digest in prepared:
            if path in restored:
                overwrite_existing(root, path, after, sha256(before))
        raise
    return {"performed": True, "restored_paths": sorted(restored)}


__all__ = [
    "PatchError", "apply_patch", "read_existing", "relative_path", "rollback",
    "sha256", "validate_authorized_files",
]
