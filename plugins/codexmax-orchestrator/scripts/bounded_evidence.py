#!/usr/bin/env python3
"""Search receipt trees and summarize preserved logs without context floods."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Sequence


MAX_OUTPUT_CHARS = 16 * 1024
MIN_OUTPUT_CHARS = 512
EXCLUDED_GLOBS = ("!**/raw/**", "!**/*-raw.*", "!**/*.jsonl")
MAX_SERVICE_LOG_BYTES = 1024 * 1024
SERVICE_LOG_SUFFIXES = frozenset({".log", ".out", ".txt"})
FORBIDDEN_NAME_TOKEN = re.compile(
    r"(?:^|[^a-z0-9])(?:raw|transcripts?|credentials?|secrets?|tokens?|api[-_]?keys?)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)


class BoundedEvidenceError(ValueError):
    """Raised when bounded evidence access cannot fail closed safely."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _excerpt(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    marker = "\n... bounded excerpt ...\n"
    if limit <= len(marker):
        return value[:limit]
    remaining = limit - len(marker)
    head = remaining // 2
    tail = remaining - head
    return value[:head] + marker + value[-tail:]


def render_bounded(
    payload: dict[str, Any], text_field: str, text: str, max_chars: int
) -> str:
    if not isinstance(max_chars, int) or isinstance(max_chars, bool):
        raise BoundedEvidenceError("max_output_chars_invalid")
    if not MIN_OUTPUT_CHARS <= max_chars <= MAX_OUTPUT_CHARS:
        raise BoundedEvidenceError(
            f"max_output_chars_out_of_range:{max_chars}:{MIN_OUTPUT_CHARS}:{MAX_OUTPUT_CHARS}"
        )
    budget = max_chars - 1  # Reserve the CLI newline.
    candidate = dict(payload)
    candidate[text_field] = text
    candidate["truncated"] = False

    def encode(value: dict[str, Any]) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    encoded = encode(candidate)
    if len(encoded) <= budget:
        return encoded

    candidate["truncated"] = True
    low, high = 0, len(text)
    best: str | None = None
    while low <= high:
        middle = (low + high) // 2
        candidate[text_field] = _excerpt(text, middle)
        encoded = encode(candidate)
        if len(encoded) <= budget:
            best = encoded
            low = middle + 1
        else:
            high = middle - 1
    if best is None:
        raise BoundedEvidenceError("bounded_metadata_exceeds_output_limit")
    return best


def _validate_search_root(root: Path) -> Path:
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise BoundedEvidenceError("search_root_invalid") from error
    if not resolved.is_dir():
        raise BoundedEvidenceError("search_root_invalid")
    if "raw" in {part.lower() for part in resolved.parts}:
        raise BoundedEvidenceError("explicit_raw_root_forbidden")
    return resolved


def _excluded_result_path(path: Path) -> bool:
    lowered_parts = tuple(part.lower() for part in path.parts)
    name = path.name.lower()
    return (
        "raw" in lowered_parts[:-1]
        or "-raw." in name
        or name.endswith(".jsonl")
    )


def _search_locator(path_text: str, roots: Sequence[Path]) -> str:
    lexical = Path(os.path.abspath(path_text)).resolve(strict=False)
    for index, root in enumerate(roots, start=1):
        try:
            relative = lexical.relative_to(root)
        except ValueError:
            continue
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise BoundedEvidenceError("rg_match_locator_invalid_no_fallback")
        return f"root-{index:02d}/{relative.as_posix()}"
    raise BoundedEvidenceError("rg_match_outside_roots_no_fallback")


def _post_filter_rg_json(output: str, roots: Sequence[Path]) -> str:
    rendered: list[str] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise BoundedEvidenceError("rg_json_invalid_no_fallback") from error
        if not isinstance(event, dict) or event.get("type") != "match":
            continue
        data = event.get("data")
        path_value = data.get("path") if isinstance(data, dict) else None
        lines_value = data.get("lines") if isinstance(data, dict) else None
        path_text = path_value.get("text") if isinstance(path_value, dict) else None
        matched_text = lines_value.get("text") if isinstance(lines_value, dict) else None
        line_number = data.get("line_number") if isinstance(data, dict) else None
        if (
            not isinstance(path_text, str)
            or not isinstance(matched_text, str)
            or not isinstance(line_number, int)
        ):
            raise BoundedEvidenceError("rg_match_identity_invalid_no_fallback")
        if _excluded_result_path(Path(path_text)):
            continue
        locator = _search_locator(path_text, roots)
        rendered.append(f"{locator}:{line_number}:{matched_text}")
    return "".join(rendered)


def search(
    pattern: str, roots: Sequence[Path], *, max_chars: int = MAX_OUTPUT_CHARS
) -> str:
    if not pattern:
        raise BoundedEvidenceError("search_pattern_empty")
    resolved_roots = [_validate_search_root(root) for root in roots]
    if not resolved_roots:
        raise BoundedEvidenceError("search_roots_empty")
    rg = shutil.which("rg")
    if rg is None:
        raise BoundedEvidenceError("rg_missing_no_fallback")
    command = [rg, "--json", "--color", "never"]
    for glob in EXCLUDED_GLOBS:
        command.extend(("--iglob", glob))
    command.extend(("--", pattern, *(str(root) for root in resolved_roots)))
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise BoundedEvidenceError("rg_timeout_no_fallback") from error
    if completed.returncode not in (0, 1):
        raise BoundedEvidenceError("rg_failed_no_detail")
    capture = _post_filter_rg_json(completed.stdout, resolved_roots)
    status = "ok" if capture else "no_matches"
    payload = {
        "schema_version": 1,
        "status": status,
        "operation": "search",
        "roots": [{"label": f"root-{index:02d}"} for index in range(1, len(resolved_roots) + 1)],
        "excluded_globs": list(EXCLUDED_GLOBS),
        "sha256": _sha256_bytes(capture.encode("utf-8")),
        "total_chars": len(capture),
        "match_lines": len(capture.splitlines()),
    }
    return render_bounded(payload, "results", capture, max_chars)


def _service_relative(value: object) -> PurePosixPath:
    if not isinstance(value, (str, Path)):
        raise BoundedEvidenceError("service_log_path_invalid")
    text = str(value)
    if not text or "\x00" in text or "\\" in text:
        raise BoundedEvidenceError("service_log_path_invalid")
    relative = PurePosixPath(text)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise BoundedEvidenceError("service_log_path_invalid")
    lowered = tuple(part.lower() for part in relative.parts)
    if "raw" in lowered[:-1] or FORBIDDEN_NAME_TOKEN.search(relative.as_posix()):
        raise BoundedEvidenceError("service_log_sensitive_path_forbidden")
    if relative.suffix.lower() == ".jsonl":
        raise BoundedEvidenceError("service_log_jsonl_forbidden")
    if relative.suffix.lower() not in SERVICE_LOG_SUFFIXES:
        raise BoundedEvidenceError("service_log_suffix_unsupported")
    return relative


def _open_service_root(value: object) -> tuple[Path, int]:
    if not isinstance(value, (str, Path)):
        raise BoundedEvidenceError("service_log_root_required")
    root = Path(value)
    if not str(root) or "\x00" in str(root) or ".." in root.parts:
        raise BoundedEvidenceError("service_log_root_invalid")
    lexical = Path(os.path.abspath(root))
    try:
        named = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise BoundedEvidenceError("service_log_root_unavailable") from error
    if (
        resolved != lexical
        and not (str(lexical).startswith("/var/") and str(resolved) == "/private" + str(lexical))
    ) or stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise BoundedEvidenceError("service_log_root_alias_forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lexical, flags)
    except OSError as error:
        raise BoundedEvidenceError("service_log_root_unavailable") from error
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        os.close(descriptor)
        raise BoundedEvidenceError("service_log_root_identity_changed")
    return lexical, descriptor


def _open_service_file(root_descriptor: int, relative: PurePosixPath) -> tuple[int, os.stat_result]:
    directory = os.dup(root_descriptor)
    try:
        for part in relative.parts[:-1]:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                child = os.open(part, flags, dir_fd=directory)
            except OSError as error:
                code = "service_log_alias_forbidden" if error.errno in {errno.ELOOP, errno.ENOTDIR} else "service_log_path_unavailable"
                raise BoundedEvidenceError(code) from error
            os.close(directory)
            directory = child
        try:
            named = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
        except OSError as error:
            raise BoundedEvidenceError("service_log_path_unavailable") from error
        if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
            raise BoundedEvidenceError("service_log_nonregular_or_alias")
        if named.st_nlink != 1:
            raise BoundedEvidenceError("service_log_hardlink_forbidden")
        if not named.st_mode & (stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH):
            raise BoundedEvidenceError("service_log_unreadable")
        if named.st_size > MAX_SERVICE_LOG_BYTES:
            raise BoundedEvidenceError("service_log_oversize")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(relative.name, flags, dir_fd=directory)
        except OSError as error:
            code = "service_log_identity_changed" if error.errno in {errno.ENOENT, errno.ELOOP} else "service_log_unreadable"
            raise BoundedEvidenceError(code) from error
        opened = os.fstat(descriptor)
        current = os.stat(relative.name, dir_fd=directory, follow_symlinks=False)
        if not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(current.st_mode):
            os.close(descriptor)
            raise BoundedEvidenceError("service_log_nonregular_or_alias")
        if opened.st_nlink != 1 or current.st_nlink != 1:
            os.close(descriptor)
            raise BoundedEvidenceError("service_log_hardlink_forbidden")
        if opened.st_size > MAX_SERVICE_LOG_BYTES or current.st_size > MAX_SERVICE_LOG_BYTES:
            os.close(descriptor)
            raise BoundedEvidenceError("service_log_oversize")
        if (
            (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            or (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            os.close(descriptor)
            raise BoundedEvidenceError("service_log_identity_changed")
        return descriptor, opened
    finally:
        os.close(directory)


def service_log(
    path: Path, *, root: Path | None = None, max_chars: int = MAX_OUTPUT_CHARS
) -> str:
    if root is None:
        raise BoundedEvidenceError("service_log_root_required")
    if not isinstance(max_chars, int) or isinstance(max_chars, bool):
        raise BoundedEvidenceError("max_output_chars_invalid")
    if not MIN_OUTPUT_CHARS <= max_chars <= MAX_OUTPUT_CHARS:
        raise BoundedEvidenceError(
            f"max_output_chars_out_of_range:{max_chars}:{MIN_OUTPUT_CHARS}:{MAX_OUTPUT_CHARS}"
        )
    relative = _service_relative(path)
    _, root_descriptor = _open_service_root(root)
    try:
        descriptor, metadata = _open_service_file(root_descriptor, relative)
        try:
            final = os.fstat(descriptor)
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns):
                raise BoundedEvidenceError("service_log_identity_changed")
        finally:
            os.close(descriptor)
        verification_descriptor, current = _open_service_file(root_descriptor, relative)
        try:
            if (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            ) != (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
            ):
                raise BoundedEvidenceError("service_log_identity_changed")
        finally:
            os.close(verification_descriptor)
    finally:
        os.close(root_descriptor)
    opaque = _sha256_bytes(
        f"bounded-evidence-service-log-v1\0{metadata.st_dev}\0{metadata.st_ino}\0"
        f"{metadata.st_size}\0{metadata.st_mtime_ns}\0{metadata.st_ctime_ns}".encode("ascii")
    )
    payload = {
        "identity": opaque,
        "locator": f"authorized-root/{relative.as_posix()}",
        "operation": "service_log",
        "schema_version": 1,
        "size_bytes": metadata.st_size,
        "status": "metadata_only",
        "truncated": False,
    }
    rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(rendered) + 1 > max_chars:
        raise BoundedEvidenceError("bounded_metadata_exceeds_output_limit")
    return rendered


def _option_count(argv: Sequence[str], option: str) -> int:
    count = 0
    for token in argv:
        if token == "--":
            break
        if token == option or token.startswith(option + "="):
            count += 1
    return count


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["service-log"] and _option_count(arguments[1:], "--root") > 1:
        print(json.dumps(
            {"status": "error", "error": "service_log_root_duplicate"},
            separators=(",", ":"), sort_keys=True,
        ))
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    search_parser = subparsers.add_parser("search")
    search_parser.add_argument("pattern")
    search_parser.add_argument("roots", nargs="+", type=Path)
    search_parser.add_argument("--max-output-chars", type=int, default=MAX_OUTPUT_CHARS)
    log_parser = subparsers.add_parser("service-log")
    log_parser.add_argument("path", type=Path)
    log_parser.add_argument("--root", required=True, type=Path)
    log_parser.add_argument("--max-output-chars", type=int, default=MAX_OUTPUT_CHARS)
    args = parser.parse_args(arguments)
    try:
        if args.operation == "search":
            rendered = search(args.pattern, args.roots, max_chars=args.max_output_chars)
        else:
            rendered = service_log(args.path, root=args.root, max_chars=args.max_output_chars)
    except BoundedEvidenceError as error:
        print(json.dumps({"status": "error", "error": str(error)}, separators=(",", ":")))
        return 2
    except OSError:
        print(json.dumps(
            {"status": "error", "error": "bounded_evidence_unavailable"},
            separators=(",", ":"), sort_keys=True,
        ))
        return 2
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
