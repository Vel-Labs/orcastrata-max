#!/usr/bin/env python3
"""Deterministic, standard-library LoopRegistry v1 inspection engine.

This module validates and matches policy only. It never resolves argv or runs an
action profile.
"""

from __future__ import annotations

import copy
import datetime as dt
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any


MAX_ERRORS = 64
MAX_YAML_BYTES = 262_144
MAX_JSON_BYTES = 65_536
MAX_DEPTH = 16
MAX_NODES = 4_096
MAX_COLLECTION = 256
MAX_SCALAR_BYTES = 4_096
EVENT_KEYS = {
    "schema_version", "artifact_type", "event_id", "event_type", "occurred_at",
    "observed_at", "source", "origin", "workspace_root", "subject",
    "requested_scope", "authority", "dedupe_key",
}
EVENT_TYPES = {
    "manual.requested", "session.start", "prompt.submitted", "file.changed",
    "run.completed", "run.failed", "goal.state_changed", "schedule.tick",
    "git.pre_commit", "git.post_commit",
}
REGISTRY_KEYS = {
    "schema_version", "registry_id", "workspace_root", "mode", "logical_root_ids",
    "contract_refs", "action_profile_contract", "loops",
}
LOOP_KEYS = {
    "loop_schema_version", "loop_id", "definition_version", "owner_path",
    "lifecycle", "loop_type", "contract_refs", "trigger", "scope", "graph",
    "action_profile_ids", "budget", "proof", "notification", "stop_conditions",
}
RECEIPT_KEYS = {
    "schema_version", "artifact_type", "receipt_id", "recorded_at", "event",
    "registry", "admission", "action", "execution", "validation", "budget",
    "artifacts", "notification_intents", "proof_boundary", "acceptance",
}
FORBIDDEN_KEYS = {
    "command", "commands", "argv", "executable", "shell", "script", "cwd",
    "environment",
}
COMMAND_TOKENS = ("`", "$(", "&&", "||", "\x00")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
KEBAB_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
FIXED_PROFILE_IDS = {
    "ops-config-fast", "goalbuddy-board-fast", "skill-contract-fast",
    "codexmax-loop-focused", "codexmax-repository-full", "git-diff-sanity",
    "receipt-completeness",
}
LIFECYCLE_STATES = {"proposed", "dry_run", "pilot", "active", "paused", "failed", "retired"}
LIFECYCLE_TRANSITIONS = {
    ("proposed", "dry_run"),
    ("dry_run", "pilot"),
    ("pilot", "active"),
    ("dry_run", "paused"), ("pilot", "paused"), ("active", "paused"),
    ("dry_run", "failed"), ("pilot", "failed"), ("active", "failed"),
    ("dry_run", "retired"), ("pilot", "retired"), ("active", "retired"),
    ("paused", "dry_run"), ("paused", "pilot"), ("paused", "active"),
    ("paused", "retired"),
    ("failed", "dry_run"),
}
STABLE_REJECTION_CODES = {
    "schema_invalid", "schema_version_unsupported", "unknown_field",
    "duplicate_key", "duplicate_loop_id", "input_too_large",
    "structure_too_deep", "node_limit_exceeded", "collection_limit_exceeded",
    "scalar_too_large", "yaml_feature_forbidden", "reference_missing",
    "reference_stale", "reference_symlink", "reference_hardlink",
    "path_invalid", "path_escape", "action_profile_unknown",
    "action_profile_unbound", "command_input_forbidden", "authority_missing",
    "authority_ambiguous", "authority_stale", "scope_widening",
    "capability_unknown", "event_stale", "event_duplicate", "recursive_event",
    "origin_invalid", "event_unauthorized", "generic_stdin_dry_run_only",
    "ambiguous_match", "static_cycle", "budget_invalid", "budget_unknown",
    "proof_unknown",
}
MUTATION_MODES = {"advisory_report_only", "automatic_read_only"}
MANDATORY_FORBIDDEN = {
    "arbitrary_command", "network", "credentials", "install", "delete", "move",
    "rename", "publish", "push", "scheduler_activation", "hook_installation",
    "goalbuddy_mutation", "authority_widening",
}
STOP_CONDITIONS = {
    "operator_stop", "scope_widening", "authority_missing", "source_unavailable",
    "stale_event", "duplicate_event", "recursive_event", "budget_exhausted",
    "no_improvement", "action_unavailable", "validation_failed", "unsafe_input",
}


class LoopContractError(Exception):
    def __init__(self, *codes: str):
        self.codes = sorted(set(codes or ("schema_invalid",)))[:MAX_ERRORS]
        super().__init__(",".join(self.codes))


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LoopContractError("duplicate_key")
        result[key] = value
    return result


def _limits(value: object, *, depth: int = 0, max_nodes: int = MAX_NODES) -> tuple[int, int]:
    if depth > MAX_DEPTH:
        raise LoopContractError("structure_too_deep")
    nodes = 1
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION:
            raise LoopContractError("collection_limit_exceeded")
        for key, child in value.items():
            if len(str(key).encode()) > MAX_SCALAR_BYTES:
                raise LoopContractError("scalar_too_large")
            child_nodes, _ = _limits(child, depth=depth + 1, max_nodes=max_nodes)
            nodes += child_nodes
    elif isinstance(value, list):
        if len(value) > MAX_COLLECTION:
            raise LoopContractError("collection_limit_exceeded")
        for child in value:
            child_nodes, _ = _limits(child, depth=depth + 1, max_nodes=max_nodes)
            nodes += child_nodes
    elif isinstance(value, str) and len(value.encode()) > MAX_SCALAR_BYTES:
        raise LoopContractError("scalar_too_large")
    if nodes > max_nodes:
        raise LoopContractError("node_limit_exceeded")
    return nodes, depth


def load_json_bytes(raw: bytes, *, receipt: bool = False) -> object:
    limit = 262_144 if receipt else MAX_JSON_BYTES
    if len(raw) > limit:
        raise LoopContractError("input_too_large")
    try:
        text = raw.decode("utf-8")
        if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
            raise LoopContractError("schema_invalid")
        value = json.loads(text, object_pairs_hook=_duplicates, parse_constant=lambda _: (_ for _ in ()).throw(LoopContractError("schema_invalid")))
    except LoopContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LoopContractError("schema_invalid")
    _limits(value, max_nodes=MAX_NODES if receipt else 2_048)
    return value


def load_json(path: Path, *, receipt: bool = False) -> object:
    return load_json_bytes(_read_input(path, 262_144 if receipt else MAX_JSON_BYTES), receipt=receipt)


def _strip_comment(line: str) -> str:
    quoted = False
    escaped = False
    for index, char in enumerate(line):
        if char == '"' and not escaped:
            quoted = not quoted
        if char == "#" and not quoted and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
        escaped = char == "\\" and not escaped
        if char != "\\":
            escaped = False
    return line.rstrip()


def _yaml_scalar(text: str) -> object:
    text = text.strip()
    if text in {"[]", "{}"}:
        return [] if text == "[]" else {}
    if text in {"null", "~"}:
        return None
    if text in {"true", "false"}:
        return text == "true"
    if re.fullmatch(r"-?(0|[1-9][0-9]*)", text):
        return int(text)
    if text.startswith('"'):
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            raise LoopContractError("schema_invalid") from error
        if not isinstance(value, str):
            raise LoopContractError("schema_invalid")
        return value
    if not text or text.startswith(("'", "|", ">", "!", "&", "*", "[", "{")):
        raise LoopContractError("yaml_feature_forbidden")
    if any(token in text for token in ("<<:", "\t", "\x00")):
        raise LoopContractError("yaml_feature_forbidden")
    return text


def load_yaml_bytes(raw: bytes) -> object:
    if len(raw) > MAX_YAML_BYTES:
        raise LoopContractError("input_too_large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LoopContractError("schema_invalid") from error
    if "\t" in text or any((ord(char) < 32 and char not in "\n\r") or 127 <= ord(char) <= 159 for char in text):
        raise LoopContractError("yaml_feature_forbidden")
    raw_lines: list[tuple[int, str]] = []
    for original in text.splitlines():
        line = _strip_comment(original)
        if not line.strip():
            continue
        stripped = line.lstrip(" ")
        if stripped.startswith(("%", "---", "...")) or re.search(r"(^|\s)[&*!][A-Za-z0-9_-]+", stripped) or "<<:" in stripped:
            raise LoopContractError("yaml_feature_forbidden")
        indent = len(line) - len(stripped)
        if indent % 2:
            raise LoopContractError("schema_invalid")
        raw_lines.append((indent, stripped))

    def split_pair(text_value: str) -> tuple[str, str]:
        quoted = False
        escaped = False
        for index, char in enumerate(text_value):
            if char == '"' and not escaped:
                quoted = not quoted
            if char == ":" and not quoted:
                key, rest = text_value[:index].strip(), text_value[index + 1 :].strip()
                if not key or key.startswith("'"):
                    raise LoopContractError("yaml_feature_forbidden")
                return key, rest
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
        raise LoopContractError("schema_invalid")

    def parse_block(index: int, indent: int) -> tuple[object, int]:
        if index >= len(raw_lines) or raw_lines[index][0] != indent:
            raise LoopContractError("schema_invalid")
        is_list = raw_lines[index][1].startswith("- ")
        container: object = [] if is_list else {}
        while index < len(raw_lines) and raw_lines[index][0] == indent:
            content = raw_lines[index][1]
            if is_list:
                if not content.startswith("- "):
                    raise LoopContractError("schema_invalid")
                item = content[2:].strip()
                if not item:
                    raise LoopContractError("schema_invalid")
                if ":" in item:
                    key, rest = split_pair(item)
                    mapping: dict[str, Any] = {}
                    mapping[key] = _yaml_scalar(rest) if rest else None
                    index += 1
                    if index < len(raw_lines) and raw_lines[index][0] > indent:
                        nested, index = parse_block(index, indent + 2)
                        if rest:
                            if not isinstance(nested, dict):
                                raise LoopContractError("schema_invalid")
                            for nested_key, value in nested.items():
                                if nested_key in mapping:
                                    raise LoopContractError("duplicate_key")
                                mapping[nested_key] = value
                        else:
                            mapping[key] = nested
                    cast_list = container
                    assert isinstance(cast_list, list)
                    cast_list.append(mapping)
                    continue
                cast_list = container
                assert isinstance(cast_list, list)
                cast_list.append(_yaml_scalar(item))
            else:
                if content.startswith("- "):
                    raise LoopContractError("schema_invalid")
                key, rest = split_pair(content)
                cast_dict = container
                assert isinstance(cast_dict, dict)
                if key in cast_dict:
                    raise LoopContractError("duplicate_key")
                if rest:
                    cast_dict[key] = _yaml_scalar(rest)
                else:
                    if index + 1 >= len(raw_lines) or raw_lines[index + 1][0] <= indent:
                        raise LoopContractError("schema_invalid")
                    value, next_index = parse_block(index + 1, indent + 2)
                    cast_dict[key] = value
                    index = next_index
                    continue
            index += 1
        if index < len(raw_lines) and raw_lines[index][0] > indent:
            raise LoopContractError("schema_invalid")
        return container, index

    if not raw_lines:
        raise LoopContractError("schema_invalid")
    value, final = parse_block(0, raw_lines[0][0])
    if raw_lines[0][0] != 0 or final != len(raw_lines):
        raise LoopContractError("schema_invalid")
    _limits(value)
    return value


def load_yaml(path: Path) -> object:
    return load_yaml_bytes(_read_input(path, MAX_YAML_BYTES))


def _read_input(path: Path, limit: int) -> bytes:
    """Read one exact unique regular file without following aliases."""
    supplied = Path(path)
    if "\x00" in str(supplied) or ".." in supplied.parts:
        raise LoopContractError("path_invalid")
    lexical = Path(os.path.abspath(supplied))
    try:
        resolved = supplied.resolve(strict=True)
        named = supplied.lstat()
    except FileNotFoundError as error:
        raise LoopContractError("input_unavailable") from error
    except OSError as error:
        raise LoopContractError("path_invalid") from error
    if resolved != lexical or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
        raise LoopContractError("path_invalid")
    if named.st_nlink != 1:
        raise LoopContractError("reference_hardlink")
    if named.st_size > limit:
        raise LoopContractError("input_too_large")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(supplied, flags)
    except OSError as error:
        raise LoopContractError("path_invalid") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise LoopContractError("path_invalid")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            raw = stream.read(limit + 1)
            final = os.fstat(stream.fileno())
            if (final.st_dev, final.st_ino, final.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise LoopContractError("path_invalid")
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    if len(raw) > limit:
        raise LoopContractError("input_too_large")
    return raw


def package_root() -> Path:
    """Return only the package that owns this module."""
    root = Path(__file__).resolve().parent.parent
    if root.name != "codexmax-orchestrator" or not (root / "scripts").is_dir():
        raise LoopContractError("path_invalid")
    return root


def default_roots(*, workspace_root: Path | None = None) -> dict[str, Path]:
    """Build roots without inferring a workspace from package ancestors."""
    roots = {"codexmax_repo": package_root()}
    if workspace_root is None:
        return roots
    supplied = Path(workspace_root)
    if not supplied.is_absolute():
        raise LoopContractError("path_invalid")
    try:
        resolved = supplied.resolve(strict=True)
        info = supplied.lstat()
    except OSError as error:
        raise LoopContractError("path_invalid") from error
    if resolved != supplied or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise LoopContractError("path_invalid")
    roots["workspace"] = resolved
    return roots


def _root_candidate(root_id: str, root: Path, relative: str) -> Path:
    """Map the frozen source prefix only when the root is this package."""
    prefix = "plugins/codexmax-orchestrator/"
    try:
        owns_module = root.resolve(strict=True) == package_root()
    except OSError:
        owns_module = False
    if (
        root_id == "codexmax_repo"
        and owns_module
        and relative.startswith(prefix)
    ):
        relative = relative[len(prefix):]
    return root / relative


def _errors() -> list[str]:
    return []


def _add(errors: list[str], code: str) -> None:
    if code not in errors and len(errors) < MAX_ERRORS:
        errors.append(code)


def _closed(value: object, allowed: set[str], errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _add(errors, "schema_invalid")
        return None
    if set(value) - allowed:
        _add(errors, "unknown_field")
    return value


def _exact(value: object, keys: set[str], errors: list[str]) -> dict[str, Any] | None:
    obj = _closed(value, keys, errors)
    if obj is None or not keys.issubset(obj):
        _add(errors, "schema_invalid")
    return obj


def _unique_strings(value: object, errors: list[str], *, nonempty: bool = False, allowed: set[str] | None = None) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value) or not all(isinstance(item, str) and item for item in value):
        _add(errors, "schema_invalid")
        return []
    if len(value) != len(set(value)) or (allowed is not None and set(value) - allowed):
        _add(errors, "schema_invalid")
    return value


def _unique_objects(value: object, errors: list[str], *, nonempty: bool = False) -> list[object]:
    if not isinstance(value, list) or (nonempty and not value):
        _add(errors, "schema_invalid")
        return []
    identities = [canonical_json(item) for item in value]
    if len(identities) != len(set(identities)):
        _add(errors, "schema_invalid")
    return value


def _bounded_int(value: object, low: int, high: int, errors: list[str], *, code: str = "budget_invalid") -> bool:
    valid = isinstance(value, int) and not isinstance(value, bool) and low <= value <= high
    if not valid:
        _add(errors, code)
    return valid


def _digest_or_unknown(value: object) -> bool:
    return value == "unknown" or isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None


def _nonnegative_number_or_unknown(value: object) -> bool:
    return value == "unknown" or isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def _validate_locator(locator: object, roots: dict[str, Path], errors: list[str], *, require_digest: bool, resolve_references: bool) -> None:
    if not isinstance(locator, dict):
        _add(errors, "path_invalid")
        return
    if resolve_references:
        _resolve(locator, roots, errors, require_digest=require_digest)
        return
    parsed = _logical_path(locator, errors, digest=True)
    if parsed is not None and require_digest and locator.get("sha256") == "unknown":
        _add(errors, "reference_stale")


def _command_scan(value: object, errors: list[str]) -> None:
    if isinstance(value, dict):
        if FORBIDDEN_KEYS & set(value):
            _add(errors, "command_input_forbidden")
        for child in value.values():
            _command_scan(child, errors)
    elif isinstance(value, list):
        for child in value:
            _command_scan(child, errors)
    elif isinstance(value, str):
        if any(token in value for token in COMMAND_TOKENS) or re.search(r"\$(?:\{|[A-Za-z_])", value):
            _add(errors, "command_input_forbidden")


def _safe_relative_text(value: object) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return False
    if re.match(r"^[A-Za-z]:", value) or value.startswith("//") or "//" in value:
        return False
    pure = PurePosixPath(value)
    return not pure.is_absolute() and "." not in pure.parts and ".." not in pure.parts and all(part for part in value.split("/"))


def _logical_path(value: object, errors: list[str], *, digest: bool = False, pattern: bool = False) -> tuple[str, str] | None:
    expected = {"root_id", "path" if not pattern else "pattern"} | ({"sha256"} if digest else set())
    obj = _closed(value, expected, errors)
    if obj is None or set(obj) != expected:
        _add(errors, "path_invalid")
        return None
    root_id = obj.get("root_id")
    path_value = obj.get("pattern" if pattern else "path")
    if root_id not in {"workspace", "codexmax_repo"} or not isinstance(path_value, str):
        _add(errors, "path_invalid")
        return None
    pure = PurePosixPath(path_value)
    if not _safe_relative_text(path_value):
        _add(errors, "path_escape" if ".." in pure.parts else "path_invalid")
        return None
    if pattern and any(token in path_value for token in (";", "`", "$(", "&&", "||", "<", ">", "{", "}")):
        _add(errors, "command_input_forbidden")
        _add(errors, "path_invalid")
    if digest:
        sha = obj.get("sha256")
        if sha != "unknown" and (not isinstance(sha, str) or not DIGEST_RE.fullmatch(sha)):
            _add(errors, "reference_stale")
    return str(root_id), path_value


def _resolve(locator: dict[str, Any], roots: dict[str, Path], errors: list[str], *, require_digest: bool = False) -> Path | None:
    parsed = _logical_path(locator, errors, digest=True)
    if parsed is None:
        return None
    root_id, relative = parsed
    root = roots.get(root_id)
    if root is None:
        _add(errors, "path_invalid")
        return None
    candidate = _root_candidate(root_id, root, relative)
    try:
        root_resolved = root.resolve(strict=True)
        lexical = root_resolved / candidate.relative_to(root)
        resolved = candidate.resolve(strict=True)
        info = candidate.lstat()
    except OSError:
        _add(errors, "reference_missing")
        return None
    if not lexical.is_relative_to(root_resolved) or not resolved.is_relative_to(root_resolved):
        _add(errors, "path_escape")
        return None
    if resolved != lexical or stat.S_ISLNK(info.st_mode):
        _add(errors, "reference_symlink")
        return None
    if not stat.S_ISREG(info.st_mode):
        _add(errors, "path_invalid")
        return None
    if info.st_nlink != 1:
        _add(errors, "reference_hardlink")
        return None
    expected = locator.get("sha256")
    if require_digest and expected == "unknown":
        _add(errors, "reference_stale")
    elif expected != "unknown":
        try:
            raw = _read_input(candidate, MAX_YAML_BYTES)
        except LoopContractError as error:
            for code in error.codes:
                _add(errors, code)
            return None
        if expected != "sha256:" + hashlib.sha256(raw).hexdigest():
            _add(errors, "reference_stale")
    return candidate


def _timestamp(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def validate_registry(value: object, *, roots: dict[str, Path] | None = None, resolve_references: bool = True) -> list[str]:
    errors = _errors()
    obj = _closed(value, REGISTRY_KEYS, errors)
    if obj is None:
        return sorted(errors)
    _command_scan(obj, errors)
    if set(obj) != REGISTRY_KEYS or obj.get("schema_version") != 1 or obj.get("workspace_root") != "." or obj.get("mode") != "advisory_report_only" or obj.get("logical_root_ids") != ["workspace", "codexmax_repo"]:
        _add(errors, "schema_invalid")
    if not isinstance(obj.get("registry_id"), str) or not KEBAB_RE.fullmatch(obj["registry_id"]):
        _add(errors, "schema_invalid")
    refs = _closed(obj.get("contract_refs"), {"registry", "events"}, errors)
    if refs is None or set(refs) != {"registry", "events"}:
        _add(errors, "schema_invalid")
    else:
        for locator in refs.values():
            _validate_locator(locator, roots or default_roots(), errors, require_digest=True, resolve_references=resolve_references)
    profiles = _closed(obj.get("action_profile_contract"), {"schema_version", "resolution", "allowed_profile_ids"}, errors)
    allowed_profiles: set[str] = set()
    if profiles is None or set(profiles) != {"schema_version", "resolution", "allowed_profile_ids"} or profiles.get("schema_version") != 1 or profiles.get("resolution") != "version_bound_codexmax_source":
        _add(errors, "schema_invalid")
    else:
        ids = profiles.get("allowed_profile_ids")
        if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)) or not all(isinstance(item, str) and KEBAB_RE.fullmatch(item) for item in ids):
            _add(errors, "schema_invalid")
        else:
            allowed_profiles = set(ids)
            if allowed_profiles - FIXED_PROFILE_IDS:
                _add(errors, "action_profile_unknown")
    loops = obj.get("loops")
    if not isinstance(loops, list) or len(loops) > MAX_COLLECTION:
        _add(errors, "schema_invalid")
        return sorted(errors)
    seen: set[str] = set()
    for loop in loops:
        loop_obj = _closed(loop, LOOP_KEYS, errors)
        if loop_obj is None or set(loop_obj) != LOOP_KEYS:
            _add(errors, "schema_invalid")
            continue
        loop_id = loop_obj.get("loop_id")
        if not isinstance(loop_id, str) or not KEBAB_RE.fullmatch(loop_id):
            _add(errors, "schema_invalid")
        elif loop_id in seen:
            _add(errors, "duplicate_loop_id")
        else:
            seen.add(loop_id)
        actions = _unique_strings(loop_obj.get("action_profile_ids"), errors, nonempty=True)
        for action in actions:
            if action not in allowed_profiles or action not in FIXED_PROFILE_IDS:
                _add(errors, "action_profile_unknown")
        nested_shapes = (
            (loop_obj.get("lifecycle"), {"state", "prior_state", "changed_at", "promotion_evidence"}),
            (loop_obj.get("contract_refs"), {"source_paths", "authority_board", "authority_receipt"}),
            (loop_obj.get("trigger"), {"event_types", "source_adapters", "path_match", "debounce_seconds", "dedupe_window_seconds", "freshness_seconds", "max_recursion_depth"}),
            (loop_obj.get("scope"), {"allowed_reads", "allowed_writes", "mutation_mode", "forbidden_actions"}),
            (loop_obj.get("graph"), {"workgraph", "goalbuddy_board"}),
            (loop_obj.get("budget"), {"max_attempts", "no_improvement_window", "timeout_seconds", "max_output_bytes", "max_concurrency", "token_forecast", "explicit_token_cap", "external_cash_authorized"}),
            (loop_obj.get("proof"), {"required_freshness_seconds", "receipt_sink_id", "report_root", "required_artifact_ids"}),
            (loop_obj.get("notification"), {"mode", "intent_path"}),
        )
        for nested, keys in nested_shapes:
            _exact(nested, keys, errors)
        if loop_obj.get("loop_schema_version") != 1 or not isinstance(loop_obj.get("definition_version"), int) or isinstance(loop_obj.get("definition_version"), bool) or loop_obj.get("definition_version", 0) < 1 or loop_obj.get("loop_type") not in {"manual", "goal", "time", "event"}:
            _add(errors, "schema_invalid")
        owner_path = loop_obj.get("owner_path")
        if not _safe_relative_text(owner_path):
            _add(errors, "path_invalid")
        lifecycle = loop_obj.get("lifecycle")
        if isinstance(lifecycle, dict):
            state, prior, changed = lifecycle.get("state"), lifecycle.get("prior_state"), lifecycle.get("changed_at")
            evidence = lifecycle.get("promotion_evidence")
            if state not in LIFECYCLE_STATES or not isinstance(evidence, list):
                _add(errors, "schema_invalid")
            elif state == "proposed":
                if prior is not None or changed is not None or evidence:
                    _add(errors, "schema_invalid")
            elif prior not in LIFECYCLE_STATES or _timestamp(changed) is None or not evidence:
                _add(errors, "schema_invalid")
            elif (prior, state) not in LIFECYCLE_TRANSITIONS:
                _add(errors, "schema_invalid")
            if isinstance(evidence, list):
                for locator in evidence:
                    if isinstance(locator, dict):
                        _validate_locator(locator, roots or default_roots(), errors, require_digest=True, resolve_references=resolve_references)
                    else:
                        _add(errors, "schema_invalid")
        trigger = loop_obj.get("trigger")
        if isinstance(trigger, dict):
            _unique_strings(trigger.get("event_types"), errors, nonempty=True, allowed=EVENT_TYPES)
            adapters = _unique_strings(trigger.get("source_adapters"), errors, nonempty=True)
            if any(not KEBAB_RE.fullmatch(item) for item in adapters):
                _add(errors, "schema_invalid")
            _bounded_int(trigger.get("debounce_seconds"), 0, 3_600, errors, code="schema_invalid")
            _bounded_int(trigger.get("dedupe_window_seconds"), 1, 86_400, errors, code="schema_invalid")
            _bounded_int(trigger.get("freshness_seconds"), 1, 86_400, errors, code="schema_invalid")
            _bounded_int(trigger.get("max_recursion_depth"), 0, 8, errors, code="schema_invalid")
            path_match = trigger.get("path_match")
            if isinstance(path_match, dict):
                if set(path_match) != {"include", "exclude"}:
                    if set(path_match) - {"include", "exclude"}:
                        _add(errors, "unknown_field")
                    _add(errors, "schema_invalid")
                for key in ("include", "exclude"):
                    entries = path_match.get(key)
                    if not isinstance(entries, list):
                        _add(errors, "schema_invalid")
                        continue
                    for entry in entries:
                        _logical_path(entry, errors, pattern=True)
        scope = loop_obj.get("scope")
        if isinstance(scope, dict):
            if scope.get("mutation_mode") not in MUTATION_MODES:
                _add(errors, "schema_invalid")
            forbidden = _unique_strings(scope.get("forbidden_actions"), errors, nonempty=True)
            if not MANDATORY_FORBIDDEN.issubset(forbidden):
                _add(errors, "schema_invalid")
            for key in ("allowed_reads", "allowed_writes"):
                entries = scope.get(key)
                for entry in _unique_objects(entries, errors):
                    _logical_path(entry, errors, pattern=True)
        budget = loop_obj.get("budget")
        if isinstance(budget, dict):
            max_attempts_ok = _bounded_int(budget.get("max_attempts"), 1, 10, errors)
            no_improvement_ok = _bounded_int(budget.get("no_improvement_window"), 1, 10, errors)
            if max_attempts_ok and no_improvement_ok and budget["no_improvement_window"] > budget["max_attempts"]:
                _add(errors, "budget_invalid")
            _bounded_int(budget.get("timeout_seconds"), 1, 3_600, errors)
            _bounded_int(budget.get("max_output_bytes"), 1_024, 1_048_576, errors)
            _bounded_int(budget.get("max_concurrency"), 1, 4, errors)
            for key in ("token_forecast", "explicit_token_cap"):
                if budget.get(key) is not None and (not isinstance(budget[key], int) or isinstance(budget[key], bool) or budget[key] < 1):
                    _add(errors, "budget_invalid")
            if budget.get("external_cash_authorized") is not False:
                _add(errors, "budget_invalid")
        proof = loop_obj.get("proof")
        if not isinstance(proof, dict) or proof.get("receipt_sink_id") != "local_loop_receipts_v1":
            _add(errors, "proof_unknown")
        elif isinstance(proof, dict):
            _bounded_int(proof.get("required_freshness_seconds"), 1, 86_400, errors, code="proof_unknown")
            _logical_path(proof.get("report_root"), errors)
            _unique_strings(proof.get("required_artifact_ids"), errors, nonempty=True)
        notification = loop_obj.get("notification")
        if isinstance(notification, dict):
            if notification.get("mode") != "dashboard_only":
                _add(errors, "schema_invalid")
            if notification.get("intent_path") is not None:
                _logical_path(notification.get("intent_path"), errors)
        _unique_strings(loop_obj.get("stop_conditions"), errors, nonempty=True, allowed=STOP_CONDITIONS)
        contract_refs = loop_obj.get("contract_refs")
        if isinstance(contract_refs, dict):
            sources = _unique_objects(contract_refs.get("source_paths"), errors, nonempty=True)
            for locator in sources:
                if isinstance(locator, dict):
                    _validate_locator(locator, roots or default_roots(), errors, require_digest=loop_obj.get("lifecycle", {}).get("state") != "proposed", resolve_references=resolve_references)
                else:
                    _add(errors, "schema_invalid")
            for key in ("authority_board", "authority_receipt"):
                locator = contract_refs.get(key)
                if isinstance(locator, dict):
                    _validate_locator(locator, roots or default_roots(), errors, require_digest=True, resolve_references=resolve_references)
                elif locator is not None and not isinstance(locator, dict):
                    _add(errors, "schema_invalid")
        graph = loop_obj.get("graph")
        if isinstance(graph, dict):
            for key in ("workgraph", "goalbuddy_board"):
                locator = graph.get(key)
                if isinstance(locator, dict):
                    _validate_locator(locator, roots or default_roots(), errors, require_digest=True, resolve_references=resolve_references)
                elif locator is not None and not isinstance(locator, dict):
                    _add(errors, "schema_invalid")
    return sorted(errors)[:MAX_ERRORS]


def validate_event(value: object, *, evaluation_time: str, roots: dict[str, Path] | None = None, check_identity: bool = True) -> list[str]:
    errors = _errors()
    obj = _closed(value, EVENT_KEYS, errors)
    if obj is None:
        return sorted(errors)
    _command_scan(obj, errors)
    if not EVENT_KEYS.issubset(obj) or obj.get("schema_version") != 1 or obj.get("artifact_type") != "LoopEvent" or obj.get("workspace_root") != ".":
        _add(errors, "schema_invalid")
    if obj.get("event_type") not in EVENT_TYPES or not isinstance(obj.get("event_id"), str) or not ID_RE.fullmatch(obj["event_id"]) or not isinstance(obj.get("dedupe_key"), str) or not ID_RE.fullmatch(obj["dedupe_key"]):
        _add(errors, "schema_invalid")
    occurred, observed, evaluated = _timestamp(obj.get("occurred_at")), _timestamp(obj.get("observed_at")), _timestamp(evaluation_time)
    if not all((occurred, observed, evaluated)) or not (occurred <= observed <= evaluated + dt.timedelta(seconds=5)) or observed - occurred > dt.timedelta(seconds=300):
        _add(errors, "event_stale")
    source = _exact(obj.get("source"), {"adapter_id", "source_event_id", "trust"}, errors)
    if source is None or source.get("trust") not in {"local_adapter", "fixture", "generic_stdin"} or not isinstance(source.get("adapter_id"), str) or not KEBAB_RE.fullmatch(source["adapter_id"]) or not isinstance(source.get("source_event_id"), str) or not ID_RE.fullmatch(source["source_event_id"]):
        _add(errors, "schema_invalid")
    origin = _exact(obj.get("origin"), {"run_id", "loop_id", "depth", "ancestry"}, errors)
    if origin is None:
        _add(errors, "origin_invalid")
    else:
        ancestry = origin.get("ancestry")
        depth = origin.get("depth")
        loop_id = origin.get("loop_id")
        run_id = origin.get("run_id")
        root_origin = depth == 0
        if not isinstance(ancestry, list) or not all(isinstance(item, str) and KEBAB_RE.fullmatch(item) for item in ancestry) or not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 8 or depth != len(ancestry) or len(ancestry) != len(set(ancestry)) or (loop_id is None) != root_origin or (run_id is None) != root_origin or (loop_id is not None and (not isinstance(loop_id, str) or not KEBAB_RE.fullmatch(loop_id) or not ancestry or ancestry[-1] != loop_id)) or (run_id is not None and (not isinstance(run_id, str) or not ID_RE.fullmatch(run_id))):
            _add(errors, "origin_invalid")
    subject = _exact(obj.get("subject"), {"paths", "goalbuddy_board", "workgraph"}, errors)
    if subject is None:
        _add(errors, "schema_invalid")
    else:
        paths = subject.get("paths")
        if not isinstance(paths, list):
            _add(errors, "schema_invalid")
        elif len(paths) != len({canonical_json(path) for path in paths}):
            _add(errors, "schema_invalid")
        for locator in paths if isinstance(paths, list) else []:
            parsed = _logical_path(locator, errors)
            if check_identity and parsed:
                root_id, relative = parsed
                root = (roots or default_roots()).get(root_id)
                if root:
                    candidate = _root_candidate(root_id, root, relative)
                    try:
                        root_resolved = root.resolve(strict=True)
                        lexical = root_resolved / candidate.relative_to(root)
                        resolved = candidate.resolve(strict=True)
                        info = candidate.lstat()
                        if resolved != lexical or stat.S_ISLNK(info.st_mode):
                            _add(errors, "reference_symlink")
                        elif not stat.S_ISREG(info.st_mode):
                            _add(errors, "path_invalid")
                        elif info.st_nlink != 1:
                            _add(errors, "reference_hardlink")
                    except OSError:
                        _add(errors, "reference_missing")
        for key in ("goalbuddy_board", "workgraph"):
            locator = subject.get(key)
            if isinstance(locator, dict):
                _resolve(locator, roots or default_roots(), errors, require_digest=True)
            elif locator is not None:
                _add(errors, "schema_invalid")
    requested = _exact(obj.get("requested_scope"), {"read", "write"}, errors)
    if requested is None:
        _add(errors, "schema_invalid")
    else:
        for key in ("read", "write"):
            entries = requested.get(key)
            if not isinstance(entries, list):
                _add(errors, "schema_invalid")
            for locator in entries if isinstance(entries, list) else []:
                _logical_path(locator, errors)
    authority = _exact(obj.get("authority"), {"board", "receipt", "mutation_mode"}, errors)
    if authority is None:
        _add(errors, "schema_invalid")
    else:
        if authority.get("mutation_mode") not in MUTATION_MODES:
            _add(errors, "schema_invalid")
        if authority.get("board") is not None and authority.get("receipt") is not None:
            _add(errors, "authority_ambiguous")
        for key in () if "authority_ambiguous" in errors else ("board", "receipt"):
            locator = authority.get(key)
            if isinstance(locator, dict):
                _resolve(locator, roots or default_roots(), errors, require_digest=True)
            elif locator is not None:
                _add(errors, "schema_invalid")
    return sorted(errors)[:MAX_ERRORS]


def _path_matches(locator: dict[str, Any], pattern: dict[str, Any]) -> bool:
    return locator.get("root_id") == pattern.get("root_id") and fnmatch.fnmatchcase(str(locator.get("path")), str(pattern.get("pattern")))


def match_event(registry: dict[str, Any], event: dict[str, Any], *, evaluation_time: str, roots: dict[str, Path] | None = None, ledger: dict[str, Any] | None = None, dry_run: bool = True) -> dict[str, Any]:
    errors = validate_registry(registry, roots=roots)
    errors.extend(validate_event(event, evaluation_time=evaluation_time, roots=roots))
    if errors:
        return {
            "schema_version": 1, "operation": "match", "valid": False,
            "errors": sorted(set(errors))[:MAX_ERRORS], "matched_loop_ids": [],
            "action_profile_ids": [], "admission": "rejected",
            "preflight_status": "not_run", "execution_status": "not_run",
            "validation_result": "not_run", "proof_state": "not_run",
            "executed": False,
        }
    ledger = ledger or {}
    evaluated = _timestamp(evaluation_time)
    for row in ledger.get("event_ids", []):
        if row == event.get("event_id"):
            _add(errors, "event_duplicate")
        elif isinstance(row, dict) and row.get("id") == event.get("event_id"):
            observed = _timestamp(row.get("observed_at"))
            if evaluated and observed and dt.timedelta(0) <= evaluated - observed <= dt.timedelta(seconds=86_400):
                _add(errors, "event_duplicate")
    max_dedupe = max((loop.get("trigger", {}).get("dedupe_window_seconds", 0) for loop in registry.get("loops", [])), default=0)
    for row in ledger.get("dedupe_keys", []):
        if row.get("key") != event.get("dedupe_key"):
            continue
        admitted = _timestamp(row.get("admitted_at"))
        if evaluated and admitted and dt.timedelta(0) <= evaluated - admitted <= dt.timedelta(seconds=max_dedupe):
            _add(errors, "event_duplicate")
    if event.get("source", {}).get("trust") == "generic_stdin" and not dry_run:
        _add(errors, "generic_stdin_dry_run_only")
    matches: list[dict[str, Any]] = []
    for loop in sorted(registry.get("loops", []), key=lambda row: row.get("loop_id", "")):
        trigger = loop.get("trigger", {})
        if event.get("event_type") not in trigger.get("event_types", []) or event.get("source", {}).get("adapter_id") not in trigger.get("source_adapters", []):
            continue
        paths = event.get("subject", {}).get("paths", [])
        included = trigger.get("path_match", {}).get("include", [])
        excluded = trigger.get("path_match", {}).get("exclude", [])
        if included and not any(_path_matches(path, pattern) for path in paths for pattern in included):
            continue
        if any(_path_matches(path, pattern) for path in paths for pattern in excluded):
            continue
        if loop.get("loop_id") in event.get("origin", {}).get("ancestry", []):
            _add(errors, "recursive_event")
            continue
        if event.get("origin", {}).get("depth", 0) > trigger.get("max_recursion_depth", 0):
            _add(errors, "recursive_event")
            continue
        allowed_reads = loop.get("scope", {}).get("allowed_reads", [])
        allowed_writes = loop.get("scope", {}).get("allowed_writes", [])
        reads = event.get("requested_scope", {}).get("read", [])
        writes = event.get("requested_scope", {}).get("write", [])
        if any(not any(_path_matches(path, pattern) for pattern in allowed_reads) for path in reads) or any(not any(_path_matches(path, pattern) for pattern in allowed_writes) for path in writes):
            _add(errors, "scope_widening")
            continue
        occurred = _timestamp(event.get("occurred_at"))
        evaluated = _timestamp(evaluation_time)
        freshness = trigger.get("freshness_seconds")
        if occurred and evaluated and isinstance(freshness, int) and evaluated - occurred > dt.timedelta(seconds=freshness):
            _add(errors, "event_stale")
            continue
        matches.append(loop)
    if len(matches) > 1:
        _add(errors, "ambiguous_match")
        matches = []
    return {
        "schema_version": 1,
        "operation": "match",
        "valid": not errors,
        "errors": sorted(set(errors))[:MAX_ERRORS],
        "matched_loop_ids": [row["loop_id"] for row in matches],
        "action_profile_ids": matches[0]["action_profile_ids"] if len(matches) == 1 else [],
        "admission": "matched" if len(matches) == 1 and not errors else "rejected" if errors else "not_matched",
        "preflight_status": "not_run",
        "execution_status": "not_run",
        "validation_result": "not_run",
        "proof_state": "not_run",
        "executed": False,
    }


def verify_receipt(value: object, *, roots: dict[str, Path] | None = None) -> list[str]:
    errors = _errors()
    obj = _closed(value, RECEIPT_KEYS, errors)
    if obj is None:
        return sorted(errors)
    _command_scan(obj, errors)
    if set(obj) != RECEIPT_KEYS or obj.get("schema_version") != 1 or obj.get("artifact_type") != "LoopRunReceipt":
        _add(errors, "schema_invalid")
    if not isinstance(obj.get("receipt_id"), str) or not ID_RE.fullmatch(obj["receipt_id"]) or _timestamp(obj.get("recorded_at")) is None:
        _add(errors, "schema_invalid")
    event = _exact(obj.get("event"), {"event_id", "event_type", "dedupe_key", "event_sha256"}, errors) or {}
    if event.get("event_type") not in EVENT_TYPES or not all(isinstance(event.get(key), str) and ID_RE.fullmatch(event[key]) for key in ("event_id", "dedupe_key")) or not _digest_or_unknown(event.get("event_sha256")):
        _add(errors, "schema_invalid")
    registry = _exact(obj.get("registry"), {"registry_id", "registry_sha256", "loop_id", "definition_version", "lifecycle"}, errors) or {}
    if not isinstance(registry.get("registry_id"), str) or not KEBAB_RE.fullmatch(registry["registry_id"]) or not _digest_or_unknown(registry.get("registry_sha256")):
        _add(errors, "schema_invalid")
    if registry.get("loop_id") is not None and (not isinstance(registry["loop_id"], str) or not KEBAB_RE.fullmatch(registry["loop_id"])):
        _add(errors, "schema_invalid")
    definition_version = registry.get("definition_version")
    if definition_version is not None and (not isinstance(definition_version, int) or isinstance(definition_version, bool) or definition_version < 1):
        _add(errors, "schema_invalid")
    if registry.get("lifecycle") is not None and registry.get("lifecycle") not in LIFECYCLE_STATES:
        _add(errors, "schema_invalid")
    if (registry.get("loop_id") is None) != (definition_version is None) or (registry.get("loop_id") is None) != (registry.get("lifecycle") is None):
        _add(errors, "schema_invalid")
    admission = _exact(obj.get("admission"), {"decision", "preflight_status", "rejection_codes", "authority_receipt", "authority_sha256", "scope_decision"}, errors) or {}
    execution = _exact(obj.get("execution"), {"status", "result", "attempt", "started_at", "finished_at", "duration_ms", "output", "failure_code"}, errors) or {}
    proof = _exact(obj.get("proof_boundary"), {"state", "local_source", "installed", "live_hook", "scheduler_active", "external_connector", "published", "summary"}, errors) or {}
    validations = obj.get("validation", [])
    validation_rows = [row for row in validations if isinstance(row, dict)] if isinstance(validations, list) else []
    validation_count = len(validations) if isinstance(validations, list) else -1
    decision = admission.get("decision") if isinstance(admission, dict) else None
    preflight = admission.get("preflight_status") if isinstance(admission, dict) else None
    if decision not in {"matched", "admitted", "rejected"} or preflight not in {"not_run", "passed", "rejected"} or admission.get("scope_decision") not in {"contained", "widened", "unknown"}:
        _add(errors, "schema_invalid")
    rejection_codes = _unique_strings(admission.get("rejection_codes"), errors, allowed=STABLE_REJECTION_CODES)
    if rejection_codes != sorted(rejection_codes) or (decision == "rejected") != bool(rejection_codes):
        _add(errors, "schema_invalid")
    authority_locator = admission.get("authority_receipt")
    if isinstance(authority_locator, dict):
        _resolve(authority_locator, roots or default_roots(), errors, require_digest=True)
    elif authority_locator is not None:
        _add(errors, "schema_invalid")
    authority_sha = admission.get("authority_sha256")
    if not _digest_or_unknown(authority_sha):
        _add(errors, "schema_invalid")
    if isinstance(authority_locator, dict) and authority_sha != authority_locator.get("sha256"):
        _add(errors, "reference_stale")
    if decision == "matched" and preflight != "not_run":
        _add(errors, "schema_invalid")
    if decision == "admitted" and preflight != "passed":
        _add(errors, "schema_invalid")
    if decision == "matched" and admission.get("scope_decision") != "contained":
        _add(errors, "schema_invalid")
    if decision == "admitted" and (admission.get("scope_decision") != "contained" or authority_locator is None or authority_sha == "unknown"):
        _add(errors, "schema_invalid")
    if decision == "rejected" and preflight == "passed":
        _add(errors, "schema_invalid")
    if decision == "rejected" and execution.get("result") == "pass":
        _add(errors, "schema_invalid")
    status, result = execution.get("status"), execution.get("result")
    if status not in {"completed", "failed", "not_run"} or result not in {"pass", "fail", "rejected", "not_run", "unknown"}:
        _add(errors, "schema_invalid")
    if status == "failed" and result != "fail":
        _add(errors, "schema_invalid")
    if status == "not_run" and result not in {"not_run", "rejected"}:
        _add(errors, "schema_invalid")
    if status == "completed" and result not in {"pass", "fail"}:
        _add(errors, "schema_invalid")
    if decision == "matched" and (status != "not_run" or result != "not_run"):
        _add(errors, "schema_invalid")
    if result == "rejected" and decision != "rejected":
        _add(errors, "schema_invalid")
    if result in {"pass", "fail"} and decision != "admitted":
        _add(errors, "schema_invalid")
    attempt = execution.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or not 0 <= attempt <= 10 or (status == "not_run") != (attempt == 0):
        _add(errors, "schema_invalid")
    output = _exact(execution.get("output"), {"captured_chars", "truncated", "sha256", "artifact_path"}, errors) or {}
    if not isinstance(output.get("captured_chars"), int) or isinstance(output.get("captured_chars"), bool) or output.get("captured_chars", -1) < 0 or not isinstance(output.get("truncated"), bool):
        _add(errors, "schema_invalid")
    if not _digest_or_unknown(output.get("sha256")):
        _add(errors, "schema_invalid")
    output_path = output.get("artifact_path")
    if isinstance(output_path, dict):
        _logical_path(output_path, errors)
    elif output_path is not None:
        _add(errors, "schema_invalid")
    started, finished = execution.get("started_at"), execution.get("finished_at")
    duration = execution.get("duration_ms")
    if status == "not_run":
        if started is not None or finished is not None or duration != "unknown":
            _add(errors, "schema_invalid")
        if output.get("captured_chars") != 0 or output.get("truncated") is not False or output.get("sha256") != "unknown" or output_path is not None:
            _add(errors, "schema_invalid")
    else:
        start_time, finish_time = _timestamp(started), _timestamp(finished)
        if start_time is None or finish_time is None or finish_time < start_time or not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
            _add(errors, "schema_invalid")
        if output.get("sha256") == "unknown":
            _add(errors, "schema_invalid")
    failure_code = execution.get("failure_code")
    if status == "failed" and (not isinstance(failure_code, str) or not ID_RE.fullmatch(failure_code)):
        _add(errors, "schema_invalid")
    if status != "failed" and failure_code is not None:
        _add(errors, "schema_invalid")
    pairs = {("completed", "pass"), ("completed", "fail"), ("failed", "fail"), ("not_run", "not_run"), ("not_applicable", "not_applicable")}
    if not isinstance(validations, list) or not validations:
        _add(errors, "schema_invalid")
    validation_ids: list[str] = []
    for row in validations if isinstance(validations, list) else []:
        checked = _exact(row, {"validation_id", "execution_status", "result", "evidence_path", "evidence_sha256"}, errors)
        if checked is None or (checked.get("execution_status"), checked.get("result")) not in pairs or not isinstance(checked.get("validation_id"), str) or not ID_RE.fullmatch(checked["validation_id"]):
            _add(errors, "schema_invalid")
            continue
        validation_ids.append(checked["validation_id"])
        evidence_status = checked.get("execution_status")
        evidence_path, evidence_sha = checked.get("evidence_path"), checked.get("evidence_sha256")
        if evidence_status in {"not_run", "not_applicable"}:
            if evidence_path is not None or evidence_sha != "unknown":
                _add(errors, "schema_invalid")
        elif evidence_status in {"completed", "failed"}:
            if evidence_path is None or not isinstance(evidence_sha, str) or not DIGEST_RE.fullmatch(evidence_sha):
                _add(errors, "schema_invalid")
            elif isinstance(evidence_path, dict):
                _logical_path(evidence_path, errors)
            else:
                _add(errors, "schema_invalid")
    if len(validation_ids) != len(set(validation_ids)):
        _add(errors, "schema_invalid")
    if proof.get("state") == "proved" and (len(validation_rows) != validation_count or any(row.get("execution_status") != "completed" or row.get("result") != "pass" for row in validation_rows)):
        _add(errors, "proof_unknown")
    if proof.get("state") not in {"unknown", "not_run", "rejected", "failed", "candidate", "proved"} or not all(isinstance(proof.get(key), bool) for key in ("local_source", "installed", "live_hook", "scheduler_active", "external_connector", "published")) or not isinstance(proof.get("summary"), str):
        _add(errors, "schema_invalid")
    if any(proof.get(key) is not False for key in ("installed", "live_hook", "scheduler_active", "external_connector", "published")):
        _add(errors, "schema_invalid")
    if proof.get("state") == "proved" and (decision != "admitted" or preflight != "passed" or status != "completed" or result != "pass"):
        _add(errors, "proof_unknown")
    action = _exact(obj.get("action"), {"action_profile_id", "profile_schema_version", "profile_sha256", "command_identity", "capability_decision"}, errors) or {}
    action_id = action.get("action_profile_id")
    unknown_rejected_action = decision == "rejected" and action_id is None
    if (not unknown_rejected_action and action_id not in FIXED_PROFILE_IDS) or action.get("capability_decision") not in {"compatible", "incompatible", "unknown"}:
        _add(errors, "schema_invalid")
    profile_version = action.get("profile_schema_version")
    if profile_version is not None and (not isinstance(profile_version, int) or isinstance(profile_version, bool) or profile_version < 1):
        _add(errors, "schema_invalid")
    profile_sha = action.get("profile_sha256")
    if not _digest_or_unknown(profile_sha):
        _add(errors, "schema_invalid")
    if unknown_rejected_action and any((profile_version is not None, profile_sha != "unknown", action.get("command_identity") is not None, action.get("capability_decision") != "unknown")):
        _add(errors, "schema_invalid")
    if decision == "matched" and preflight == "not_run" and isinstance(action, dict):
        if any((action.get("profile_schema_version") is not None, action.get("profile_sha256") != "unknown", action.get("command_identity") is not None, action.get("capability_decision") != "unknown")):
            _add(errors, "schema_invalid")
    if decision == "admitted" and isinstance(action, dict):
        if action.get("profile_schema_version") is None or action.get("profile_sha256") == "unknown" or action.get("command_identity") is None or action.get("capability_decision") != "compatible":
            _add(errors, "schema_invalid")
    command_identity = action.get("command_identity")
    if command_identity is not None and (not isinstance(command_identity, str) or not ID_RE.fullmatch(command_identity)):
        _add(errors, "schema_invalid")
    budget = _exact(obj.get("budget"), {"max_attempts", "timeout_seconds", "max_output_bytes", "explicit_token_cap", "external_cash_authorized", "observed_tokens", "observed_external_cash_usd", "evidence_status"}, errors) or {}
    _bounded_int(budget.get("max_attempts"), 1, 10, errors)
    _bounded_int(budget.get("timeout_seconds"), 1, 3_600, errors)
    _bounded_int(budget.get("max_output_bytes"), 1_024, 1_048_576, errors)
    if budget.get("external_cash_authorized") is not False or budget.get("evidence_status") not in {"known", "partial", "unknown"}:
        _add(errors, "budget_invalid")
    explicit_cap = budget.get("explicit_token_cap")
    if explicit_cap is not None and (not isinstance(explicit_cap, int) or isinstance(explicit_cap, bool) or explicit_cap < 1):
        _add(errors, "budget_invalid")
    observed_tokens = budget.get("observed_tokens")
    observed_cash = budget.get("observed_external_cash_usd")
    if not _nonnegative_number_or_unknown(observed_tokens) or not _nonnegative_number_or_unknown(observed_cash):
        _add(errors, "budget_invalid")
    evidence_status = budget.get("evidence_status")
    unknown_observations = sum(value == "unknown" for value in (observed_tokens, observed_cash))
    if (evidence_status == "known" and unknown_observations) or (evidence_status == "unknown" and unknown_observations != 2) or (evidence_status == "partial" and unknown_observations != 1):
        _add(errors, "budget_invalid")
    if isinstance(output.get("captured_chars"), int) and not isinstance(output.get("captured_chars"), bool) and isinstance(budget.get("max_output_bytes"), int) and output["captured_chars"] > budget["max_output_bytes"]:
        _add(errors, "budget_invalid")
    if isinstance(attempt, int) and not isinstance(attempt, bool) and isinstance(budget.get("max_attempts"), int) and attempt > budget["max_attempts"]:
        _add(errors, "budget_invalid")
    if isinstance(duration, int) and not isinstance(duration, bool) and isinstance(budget.get("timeout_seconds"), int) and duration > budget["timeout_seconds"] * 1_000:
        _add(errors, "budget_invalid")
    if isinstance(explicit_cap, int) and not isinstance(explicit_cap, bool) and isinstance(observed_tokens, (int, float)) and not isinstance(observed_tokens, bool) and observed_tokens > explicit_cap:
        _add(errors, "budget_invalid")
    if isinstance(observed_cash, (int, float)) and not isinstance(observed_cash, bool) and observed_cash > 0:
        _add(errors, "budget_invalid")
    for collection in ("artifacts", "notification_intents"):
        rows = obj.get(collection)
        if not isinstance(rows, list):
            _add(errors, "schema_invalid")
            continue
        artifact_ids: list[str] = []
        for row in rows:
            checked = _exact(row, {"artifact_id", "path", "sha256", "state"}, errors)
            if checked is None or checked.get("state") not in {"expected", "written", "validated", "not_written", "rejected"} or not isinstance(checked.get("artifact_id"), str) or not ID_RE.fullmatch(checked["artifact_id"]):
                _add(errors, "schema_invalid")
                continue
            artifact_ids.append(checked["artifact_id"])
            if not _digest_or_unknown(checked.get("sha256")):
                _add(errors, "schema_invalid")
            if checked.get("state") in {"expected", "not_written", "rejected"} and (checked.get("path") is not None or checked.get("sha256") != "unknown"):
                _add(errors, "schema_invalid")
            if checked.get("state") in {"written", "validated"}:
                _logical_path(checked.get("path"), errors)
            elif checked.get("path") is not None:
                _add(errors, "schema_invalid")
            if checked.get("state") == "validated" and (not isinstance(checked.get("sha256"), str) or not DIGEST_RE.fullmatch(checked["sha256"])):
                _add(errors, "schema_invalid")
        if len(artifact_ids) != len(set(artifact_ids)):
            _add(errors, "schema_invalid")
    acceptance = _exact(obj.get("acceptance"), {"state", "authority"}, errors) or {}
    if acceptance.get("state") not in {"not_requested", "candidate", "accepted", "rejected"} or acceptance.get("authority") not in {"Parent", "operator", "none"}:
        _add(errors, "schema_invalid")
    if acceptance.get("state") == "accepted" and proof.get("state") != "proved":
        _add(errors, "proof_unknown")
    if acceptance.get("state") != "not_requested" or acceptance.get("authority") != "none":
        _add(errors, "schema_invalid")
    if decision == "matched" and preflight == "not_run":
        if proof.get("state") != "not_run" or len(validation_rows) != validation_count or any(row.get("execution_status") != "not_run" or row.get("result") != "not_run" for row in validation_rows):
            _add(errors, "proof_unknown")
    if decision == "rejected" and (status != "not_run" or result != "rejected" or proof.get("state") != "rejected" or len(validation_rows) != validation_count or any(row.get("execution_status") != "not_run" or row.get("result") != "not_run" for row in validation_rows)):
        _add(errors, "schema_invalid")
    if decision == "admitted" and result == "pass" and (proof.get("state") != "proved" or len(validation_rows) != validation_count or any(row.get("execution_status") != "completed" or row.get("result") != "pass" for row in validation_rows)):
        _add(errors, "proof_unknown")
    if decision == "admitted" and result == "fail" and proof.get("state") not in {"failed", "rejected"}:
        _add(errors, "proof_unknown")
    if proof.get("state") == "proved" and (event.get("event_sha256") == "unknown" or registry.get("registry_sha256") == "unknown" or budget.get("evidence_status") != "known"):
        _add(errors, "proof_unknown")
    return sorted(errors)[:MAX_ERRORS]


def load_registry(path: Path, *, roots: dict[str, Path] | None = None) -> dict[str, Any]:
    value = load_yaml(path)
    errors = validate_registry(value, roots=roots)
    if errors:
        raise LoopContractError(*errors)
    assert isinstance(value, dict)
    return value


def validate_definition_projection(registry: object, definition: object, *, roots: dict[str, Path] | None = None) -> list[str]:
    """Validate a standalone definition and bind it byte-semantically to registry."""
    if not isinstance(registry, dict) or not isinstance(definition, dict):
        return ["schema_invalid"]
    projected = copy.deepcopy(registry)
    projected["loops"] = [copy.deepcopy(definition)]
    errors = validate_registry(projected, roots=roots)
    matching = [row for row in registry.get("loops", []) if isinstance(row, dict) and row.get("loop_id") == definition.get("loop_id")]
    if len(matching) != 1 or matching[0] != definition:
        _add(errors, "reference_stale")
    return sorted(set(errors))[:MAX_ERRORS]


def apply_set(value: object, changes: dict[str, object]) -> object:
    result = copy.deepcopy(value)
    for dotted, replacement in changes.items():
        cursor: Any = result
        parts = dotted.split(".")
        for part in parts[:-1]:
            cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
        last = parts[-1]
        if isinstance(cursor, list):
            cursor[int(last)] = replacement
        else:
            cursor[last] = replacement
    return result
