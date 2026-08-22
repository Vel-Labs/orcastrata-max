#!/usr/bin/env python3
"""Plan or run one bounded Codexmax headless provider dispatch."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import importlib.util
import json
import math
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
RETURN_MANIFEST_VERSION = 1
MAX_ASSIGNMENT_BYTES = 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_STDOUT_LIMIT = 1024 * 1024
DEFAULT_STDERR_LIMIT = 256 * 1024
DEADLINE_GUARD_SECONDS = 1.0
EXIT_OK = 0
EXIT_FAILED = 2
SCRIPT_PATH = Path(__file__).resolve()
PLUGIN_ROOT = SCRIPT_PATH.parents[1]
SEMANTIC_TO_RESOLVER_ROLE = {
    "planner": "worker",
    "architect": "worker",
    "worker": "worker",
    "tester": "tester",
    "documenter": "worker",
    "auditor": "auditor",
}
FIXTURE_MANIFEST_RELATIVE = "tests/fixtures/headless-dispatch/test-adapters.json"
FIXTURE_EXECUTABLE_RELATIVE = "tests/fixtures/headless-dispatch/fake_provider.py"
FIXTURE_MANIFEST_SHA256 = "sha256:a5d8921fcf4eac09e42182b7f77e851e660000f98ff2e8ce777df20769a4e3eb"
FIXTURE_EXECUTABLE_SHA256 = "sha256:9fa20c109370d656ade27327dd70f375cab9fe54e37fe8b8c9b64fc359c62849"
RESPONSE_IDENTITY_FIELDS = {
    "declared_route", "actual_provider", "actual_model", "fallback_used", "retry_count",
}
SUPPORTED_SCHEMA_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
SUPPORTED_SCHEMA_KEYS = {
    "$id", "$schema", "type", "properties", "required", "additionalProperties",
    "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength",
    "pattern", "minimum", "maximum", "const", "enum",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_config = _load_module(
    "codexmax_config_for_headless_dispatch", PLUGIN_ROOT / "scripts" / "resolve_codexmax_config.py"
)
_route = _load_module(
    "codexmax_route_for_headless_dispatch", PLUGIN_ROOT / "scripts" / "resolve_worker_route.py"
)
_protected_receiver = _load_module(
    "codexmax_protected_receiver_for_headless_dispatch",
    PLUGIN_ROOT / "scripts" / "supported_host_protected_receiver_v1.py",
)
_provider_work = _load_module(
    "codexmax_provider_work_for_headless_dispatch",
    PLUGIN_ROOT / "scripts" / "provider_work_authority.py",
)
_execution_policy = _load_module(
    "codexmax_provider_execution_policy_for_headless_dispatch",
    PLUGIN_ROOT / "scripts" / "provider_execution_policy.py",
)
_execution_backend = _load_module(
    "codexmax_provider_execution_backend_for_headless_dispatch",
    PLUGIN_ROOT / "scripts" / "provider_execution_backend.py",
)


class DispatchError(ValueError):
    """Fail-closed dispatch input or runtime error."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class MiniMaxObservationPending(DispatchError):
    def __init__(self, *, result: dict[str, Any], observation: dict[str, Any]) -> None:
        self.result = result
        self.observation = observation
        super().__init__("execution_unknown", "observation_pending; no retry")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _same_canonical_path(lexical: Path, resolved: Path) -> bool:
    return resolved == lexical or (
        str(lexical).startswith("/var/") and str(resolved) == "/private" + str(lexical)
    )


def _canonical_repo_root(path: Path) -> Path:
    if not path.is_absolute():
        raise DispatchError("unsafe_repo_root", "repo root must be absolute")
    lexical = Path(os.path.abspath(path))
    try:
        resolved = lexical.resolve(strict=True)
        info = os.lstat(lexical)
    except OSError as exc:
        raise DispatchError("unsafe_repo_root", str(exc)) from exc
    if not _same_canonical_path(lexical, resolved) or not stat.S_ISDIR(info.st_mode):
        raise DispatchError("unsafe_repo_root", "repo root must be a canonical directory")
    return resolved


def _ensure_inside(path: Path, root: Path, field: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise DispatchError("unsafe_path", f"{field} escapes repo root") from exc


def _regular_single_link(path: Path, root: Path, field: str, *, max_bytes: int | None = None) -> Path:
    if not path.is_absolute():
        raise DispatchError("unsafe_path", f"{field} must be absolute")
    lexical = Path(os.path.abspath(path))
    _ensure_inside(lexical, root, field)
    try:
        resolved = lexical.resolve(strict=True)
        before = os.lstat(lexical)
    except OSError as exc:
        raise DispatchError("unsafe_path", f"{field}: {exc}") from exc
    if not _same_canonical_path(lexical, resolved):
        raise DispatchError("unsafe_path", f"{field} must be canonical and cannot be a symlink")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise DispatchError("unsafe_path", f"{field} must be a regular single-link file")
    if max_bytes is not None and before.st_size > max_bytes:
        raise DispatchError("input_too_large", field)
    return resolved


def _relative_path(value: Any, root: Path, field: str, *, must_exist: bool = False) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DispatchError("invalid_assignment", f"{field} must be a non-empty repo-relative path")
    raw = Path(value)
    if value == "." and must_exist:
        return root
    if raw.is_absolute() or value in {".", ".."} or any(part in {"", ".", ".."} for part in raw.parts):
        raise DispatchError("unsafe_path", f"{field} must be canonical and repo-relative")
    candidate = root.joinpath(*raw.parts)
    current = root
    for part in raw.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            try:
                info = os.lstat(current)
            except OSError as exc:
                raise DispatchError("unsafe_path", f"{field}: {exc}") from exc
            if stat.S_ISLNK(info.st_mode):
                raise DispatchError("unsafe_path", f"{field} contains a symlink")
            if current == candidate and must_exist and not stat.S_ISDIR(info.st_mode):
                raise DispatchError("unsafe_path", f"{field} must be a directory")
            if current == candidate and not must_exist and not stat.S_ISREG(info.st_mode):
                raise DispatchError("unsafe_path", f"{field} must be a regular file when present")
            if current == candidate and not must_exist and info.st_nlink != 1:
                raise DispatchError("unsafe_path", f"{field} must be single-link when present")
        elif must_exist:
            raise DispatchError("unsafe_path", f"{field} does not exist")
    _ensure_inside(candidate, root, field)
    return candidate


def _output_path(
    value: Any, root: Path, field: str, *, reserved_parent: Path | None = None,
) -> Path:
    path = _relative_path(value, root, field)
    parent = path.parent
    if parent.is_dir():
        return path
    if reserved_parent is None or parent != reserved_parent:
        raise DispatchError("unsafe_path", f"{field} parent does not exist")
    # The only permitted absent parent is the exact single-use evidence
    # directory validated from this same assignment.  run/run-one atomically
    # claims it before publishing the artifact; unrelated missing parents are
    # never inferred from broad output scope.
    if parent.exists() or parent.is_symlink():
        raise DispatchError("evidence_collision", "reserved evidence directory must be absent")
    return path


def _scope_allows(relative: str, scopes: Any) -> bool:
    if not isinstance(scopes, list):
        return False
    for scope in scopes:
        if not isinstance(scope, str):
            continue
        if scope.endswith("/**") and (relative == scope[:-3] or relative.startswith(scope[:-2])):
            return True
        if fnmatch.fnmatchcase(relative, scope):
            return True
    return False


def _require_write_scope(path: Path, root: Path, scopes: Any, field: str) -> None:
    relative = path.relative_to(root).as_posix()
    if not _scope_allows(relative, scopes):
        raise DispatchError("scope_violation", f"{field} is outside dispatch_output_scope")


def _evidence_directory(value: Any, root: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise DispatchError("invalid_assignment", "evidence_directory must be a path")
    raw = Path(value)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise DispatchError("unsafe_path", "evidence_directory must be canonical and repo-relative")
    target = root.joinpath(*raw.parts)
    current = root
    for part in raw.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise DispatchError("unsafe_path", "evidence_directory components must be real directories")
            if current == target:
                raise DispatchError(
                    "evidence_collision",
                    "evidence_directory is single-use and must not already exist",
                )
        else:
            os.mkdir(current, 0o700)
    return target


def _validate_evidence_target(value: Any, root: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise DispatchError("invalid_assignment", "evidence_directory must be a path")
    raw = Path(value)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise DispatchError("unsafe_path", "evidence_directory must be canonical and repo-relative")
    target = root.joinpath(*raw.parts)
    current = root
    for part in raw.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise DispatchError("unsafe_path", "evidence_directory components must be real directories")
    return target


def _read_json_file(path: Path, root: Path, field: str, *, max_bytes: int = MAX_ASSIGNMENT_BYTES) -> dict[str, Any]:
    safe = _regular_single_link(path, root, field, max_bytes=max_bytes)
    descriptor = os.open(safe, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= max_bytes:
            chunk = os.read(descriptor, min(65536, max_bytes + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(data) > max_bytes:
        raise DispatchError("input_too_large", field)
    if (before.st_dev, before.st_ino, before.st_size, before.st_nlink) != (
        after.st_dev, after.st_ino, after.st_size, after.st_nlink
    ):
        raise DispatchError("input_changed", field)
    try:
        value = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DispatchError("invalid_json", field) from exc
    if not isinstance(value, dict):
        raise DispatchError("invalid_json", f"{field} must contain an object")
    return value


def _schema_error(path: str, detail: str) -> DispatchError:
    return DispatchError("invalid_response_schema", f"{path}:{detail}")


def _validate_schema_definition(schema: Any, path: str = "response_schema") -> None:
    if not isinstance(schema, dict):
        raise _schema_error(path, "must_be_object")
    unknown = sorted(set(schema) - SUPPORTED_SCHEMA_KEYS)
    if unknown:
        raise _schema_error(path, f"unsupported_keyword:{unknown[0]}")
    raw_type = schema.get("type")
    types = raw_type if isinstance(raw_type, list) else ([] if raw_type is None else [raw_type])
    if not types and "const" not in schema and "enum" not in schema:
        raise _schema_error(path, "type_const_or_enum_required")
    if any(item not in SUPPORTED_SCHEMA_TYPES for item in types):
        raise _schema_error(path, "invalid_type")
    if len(types) != len(set(types)):
        raise _schema_error(path, "duplicate_type")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise _schema_error(path, "enum_must_be_nonempty_array")
    if "object" in types:
        properties = schema.get("properties")
        required = schema.get("required")
        if not isinstance(properties, dict) or any(not isinstance(key, str) or not key for key in properties):
            raise _schema_error(path, "properties_must_be_object")
        if (
            not isinstance(required, list)
            or any(not isinstance(item, str) or not item for item in required)
            or len(required) != len(set(required))
            or not set(required).issubset(properties)
        ):
            raise _schema_error(path, "required_must_be_unique_property_names")
        if schema.get("additionalProperties") is not False:
            raise _schema_error(path, "additional_properties_must_be_false")
        for name, child in properties.items():
            _validate_schema_definition(child, f"{path}.properties.{name}")
    elif any(key in schema for key in ("properties", "required", "additionalProperties")):
        raise _schema_error(path, "object_keywords_without_object_type")
    if "array" in types:
        if "items" not in schema and schema.get("maxItems") != 0:
            raise _schema_error(path, "items_required")
        if "items" in schema:
            _validate_schema_definition(schema["items"], f"{path}.items")
        for field in ("minItems", "maxItems"):
            if field in schema and (
                not isinstance(schema[field], int) or isinstance(schema[field], bool) or schema[field] < 0
            ):
                raise _schema_error(path, f"invalid_{field}")
        if "uniqueItems" in schema and type(schema["uniqueItems"]) is not bool:
            raise _schema_error(path, "uniqueItems_must_be_boolean")
    elif any(key in schema for key in ("items", "minItems", "maxItems", "uniqueItems")):
        raise _schema_error(path, "array_keywords_without_array_type")
    if "string" in types:
        for field in ("minLength", "maxLength"):
            if field in schema and (
                not isinstance(schema[field], int) or isinstance(schema[field], bool) or schema[field] < 0
            ):
                raise _schema_error(path, f"invalid_{field}")
        if "pattern" in schema:
            if not isinstance(schema["pattern"], str):
                raise _schema_error(path, "pattern_must_be_string")
            try:
                re.compile(schema["pattern"])
            except re.error as exc:
                raise _schema_error(path, "pattern_invalid") from exc
    elif any(key in schema for key in ("minLength", "maxLength", "pattern")):
        raise _schema_error(path, "string_keywords_without_string_type")
    if any(item in types for item in ("integer", "number")):
        for field in ("minimum", "maximum"):
            if field in schema and (
                not isinstance(schema[field], (int, float)) or isinstance(schema[field], bool)
            ):
                raise _schema_error(path, f"invalid_{field}")
    elif any(key in schema for key in ("minimum", "maximum")):
        raise _schema_error(path, "number_keywords_without_number_type")


def _validate_response_schema(schema: Any) -> dict[str, Any]:
    _validate_schema_definition(schema)
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise _schema_error("response_schema", "root_must_be_strict_object")
    if "route_identity" not in schema["required"]:
        raise _schema_error("response_schema", "route_identity_must_be_required")
    identity = schema["properties"].get("route_identity")
    if not isinstance(identity, dict) or identity.get("type") != "object":
        raise _schema_error("response_schema.properties.route_identity", "must_be_object")
    if set(identity.get("properties", {})) != RESPONSE_IDENTITY_FIELDS:
        raise _schema_error("response_schema.properties.route_identity", "fields_must_match_contract")
    if set(identity.get("required", [])) != RESPONSE_IDENTITY_FIELDS:
        raise _schema_error("response_schema.properties.route_identity", "all_fields_must_be_required")
    return copy.deepcopy(schema)


def _require_assignment(value: dict[str, Any], root: Path) -> dict[str, Any]:
    required = {
        "schema_version", "dispatch_id", "supervisor_assignment_id", "supervisor_lane_id",
        "semantic_role", "prompt", "working_directory", "expected_artifact",
        "evidence_directory", "dispatch_output_scope", "proof_mode", "authority", "route_packet",
        "response_schema",
    }
    if set(value) != required:
        raise DispatchError("invalid_assignment", "assignment fields must match schema exactly")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise DispatchError("unsupported_schema", str(value.get("schema_version")))
    for field in ("dispatch_id", "supervisor_assignment_id", "supervisor_lane_id", "prompt"):
        if not isinstance(value.get(field), str) or not value[field]:
            raise DispatchError("invalid_assignment", f"{field} must be a non-empty string")
    if value.get("proof_mode") not in {"simulated", "live", "task_scoped_live"}:
        raise DispatchError(
            "invalid_assignment",
            "proof_mode must be simulated, live, or task_scoped_live",
        )
    authority = value.get("authority")
    authority_fields = {
        "provider_call_authorized", "network_authorized", "billing_authorized",
        "credential_mechanism_authorized", "scope_authorized", "retention_authorized",
    }
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        raise DispatchError("invalid_assignment", "authority must declare every authority fact exactly once")
    if any(type(authority[field]) is not bool for field in authority_fields):
        raise DispatchError("invalid_assignment", "authority facts must be booleans")
    if not isinstance(value.get("route_packet"), dict):
        raise DispatchError("invalid_assignment", "route_packet must be an object")
    semantic_role = value.get("semantic_role")
    if semantic_role not in SEMANTIC_TO_RESOLVER_ROLE:
        raise DispatchError("invalid_assignment", "semantic_role is unsupported")
    resolver_role = value["route_packet"].get("role")
    if resolver_role != SEMANTIC_TO_RESOLVER_ROLE[semantic_role]:
        raise DispatchError(
            "role_mismatch",
            f"semantic_role {semantic_role} requires resolver role {SEMANTIC_TO_RESOLVER_ROLE[semantic_role]}",
        )
    working = _relative_path(value["working_directory"], root, "working_directory", must_exist=True)
    evidence_candidate = _validate_evidence_target(value["evidence_directory"], root)
    expected = _output_path(
        value["expected_artifact"], root, "expected_artifact",
        reserved_parent=evidence_candidate,
    )
    scopes = value.get("dispatch_output_scope")
    if (
        not isinstance(scopes, list) or not scopes
        or any(not isinstance(scope, str) or not scope for scope in scopes)
    ):
        raise DispatchError("invalid_assignment", "dispatch_output_scope must be nonempty string paths")
    _require_write_scope(expected, root, scopes, "expected_artifact")
    _require_write_scope(evidence_candidate, root, scopes, "evidence_directory")
    response_schema = _validate_response_schema(value["response_schema"])
    return {
        **copy.deepcopy(value), "response_schema": response_schema,
        "_working": working, "_expected": expected,
    }


def _effective_config(root: Path, workspace_config: Path | None) -> dict[str, Any]:
    args = SimpleNamespace(
        repo_root=root,
        workspace_config=workspace_config,
        goal_override=None,
        goal_id=None,
        active_goal_id=None,
        checkpoint_override=None,
        checkpoint_id=None,
        active_checkpoint_id=None,
        operator_override=None,
    )
    return _config.resolve(_config.build_layers(args))["effective_config"]


def _prepare_packet(
    assignment: dict[str, Any], effective: dict[str, Any], *, scheduler_mode: bool = False,
    scheduler_route: str | None = None,
) -> dict[str, Any]:
    packet = copy.deepcopy(assignment["route_packet"])
    semantic_role = assignment["semantic_role"]
    try:
        if scheduler_mode:
            registry, profile = _config.registry_for_scheduler_role(
                effective, semantic_role, selected_route=scheduler_route
            )
        else:
            registry = _config.registry_for_role(effective, semantic_role)
            profile = effective["headless_dispatch"]["role_priorities"][semantic_role]["task_profile"]
    except _config.UnsafeOverrideError as exc:
        if scheduler_mode and scheduler_route is not None:
            raise DispatchError("profile_incompatible", str(exc)) from exc
        raise DispatchError("role_priority_rejected", str(exc)) from exc
    except (KeyError, TypeError, _config.ConfigError) as exc:
        raise DispatchError("role_priority_rejected", str(exc)) from exc
    packet["registry"] = registry
    packet["profile"] = profile
    return packet


def _resolve_pre_dispatch(packet: dict[str, Any]) -> dict[str, Any]:
    compatible = copy.deepcopy(packet)
    compatible["resolution_phase"] = "pre_dispatch"
    try:
        receipt = _route.resolve_worker_route(compatible)
    except _route.ResolutionError as exc:
        if exc.code == "profile_requirement_weakened":
            raise DispatchError("profile_incompatible", exc.detail) from exc
        raise
    if receipt.get("status") == "no_eligible_route":
        profile_reasons = (
            "required_capability_missing:", "provider_input:", "source_access_compatibility",
        )
        if any(
            any(str(reason).startswith(profile_reasons) for reason in row.get("reasons", []))
            for row in receipt.get("considerations", [])
        ):
            receipt["status"] = "profile_incompatible"
            receipt["stop_reason"] = "profile_incompatible"
    return receipt


def _adapter_id(route_name: str, identity: dict[str, Any]) -> str:
    provider = str(identity.get("provider", "")).lower()
    runtime = str(identity.get("runtime", "")).lower()
    if route_name in {"worker_claude_sonnet_5", "worker_claude_code_sonnet_5"} or "anthropic" in provider or "claude" in runtime:
        return "claude_cli"
    if route_name.startswith("worker_deepseek") or "command" in provider:
        return "commandcode"
    if route_name in _execution_policy.OPENCODE_BACKEND_BINDINGS:
        try:
            _execution_policy.validate_opencode_backend_binding(route_name, identity)
        except _execution_policy.ExecutionPolicyError as exc:
            raise DispatchError(exc.code, exc.path) from exc
        return "opencode_tool_loop"
    if route_name == "worker_minimax_m3_tool_loop":
        if (
            identity.get("provider") != "MiniMax"
            or identity.get("model") != "MiniMax-M3"
            or identity.get("route") != "minimax-subscription-m3-tool-loop"
            or identity.get("runtime") != "mmx 1.0.16"
            or identity.get("billing") != "subscription"
        ):
            raise DispatchError("minimax_tool_loop_identity_mismatch", route_name)
        return "minimax_mmx_tool_loop"
    if route_name == "worker_minimax_m3" or "minimax" in provider:
        return "minimax_mmx"
    if route_name in {"worker_grok_4_5", "worker_grok_4_6"} or "grok" in provider:
        return "grok_cli"
    if route_name in {
        "worker_sol_high", "worker_sol_medium", "worker_terra_high",
        "worker_terra_medium", "worker_luna_xhigh", "worker_codex_spark",
    }:
        return "native_codex"
    raise DispatchError("unsupported_identity", route_name)


def _validate_explicit_execution_selection(
    packet: dict[str, Any], *, route_name: str, identity: dict[str, Any],
    adapter_id: str, task_envelope: dict[str, Any] | None,
) -> dict[str, Any] | None:
    raw = packet.get("explicit_selection")
    if raw is None:
        return None
    try:
        selection = _route._explicit_tool_model.validate_selection(raw)
    except _route._explicit_tool_model.ExplicitSelectionError as exc:
        raise DispatchError(exc.code, exc.detail) from exc
    if packet.get("task_id") != selection["task_id"]:
        raise DispatchError("explicit_selection_task_mismatch", "task_id")
    if packet.get("task_grant_sha256") != selection["task_grant_sha256"]:
        raise DispatchError("explicit_selection_grant_mismatch", "task_grant_sha256")
    expected = {
        "route_name": route_name, "requested_model": identity.get("model"),
        "route_id": identity.get("route"), "provider": identity.get("provider"),
        "runtime": identity.get("runtime"), "billing_basis": identity.get("billing"),
        "adapter_type": adapter_id, "adapter_sha256": identity.get("adapter_sha256"),
    }
    for field, value in expected.items():
        if selection.get(field) != value:
            raise DispatchError("explicit_selection_execution_mismatch", field)
    expected_tool_adapter = {
        "OpenCode": {"opencode_tool_loop", "opencode_qwopus"},
        "Command Code": {"commandcode"},
    }
    if adapter_id not in expected_tool_adapter.get(selection.get("tool"), set()):
        raise DispatchError("explicit_selection_tool_mismatch", adapter_id)
    if isinstance(task_envelope, dict):
        authority_sha256 = task_envelope.get("bindings", {}).get("authority_sha256")
        if not isinstance(authority_sha256, str):
            raise DispatchError("explicit_selection_grant_mismatch", "task_envelope")
        normalized = authority_sha256 if authority_sha256.startswith("sha256:") else "sha256:" + authority_sha256
        if normalized != selection["task_grant_sha256"]:
            raise DispatchError("explicit_selection_grant_mismatch", "task_envelope")
    return selection


def _validate_explicit_argv(selection: dict[str, Any] | None, argv: list[str]) -> None:
    if selection is None:
        return
    try:
        model_index = argv.index("--model") + 1
        argv_model = argv[model_index]
    except (ValueError, IndexError) as exc:
        raise DispatchError("explicit_selection_argv_model_missing", "--model") from exc
    expected_model = (
        selection["session_probe"]["observed_model_token"]
        if selection["tool"] == "OpenCode" else selection["requested_model"]
    )
    if argv_model != expected_model:
        raise DispatchError("explicit_selection_argv_model_mismatch", argv_model)


def _runtime_controls(
    execution_profile: dict[str, Any] | None,
    *,
    default_turns: int | None = None,
) -> dict[str, Any]:
    try:
        controls = _execution_policy.argv_controls(execution_profile)
    except _execution_policy.ExecutionPolicyError as exc:
        raise DispatchError(exc.code, exc.path) from exc
    if execution_profile is None and default_turns is not None:
        controls = {**controls, "max_turns": default_turns}
    return controls


def _require_write_flag_match(scoped_write: bool, execution_profile: dict[str, Any] | None) -> None:
    if execution_profile is None:
        return
    expected = execution_profile.get("mutation_mode") == "scoped_write"
    if scoped_write is not expected:
        raise DispatchError("argv_mutation_mode_mismatch", "scoped_write")


def _argv_claude(
    exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False,
    execution_profile: dict[str, Any] | None = None,
    claude_guard: dict[str, Any] | None = None,
) -> list[str]:
    controls = _runtime_controls(execution_profile, default_turns=20)
    _require_write_flag_match(scoped_write, execution_profile)
    binding = _execution_policy.CLAUDE_ROUTE_BINDINGS["worker_claude_code_sonnet_5"]
    identity_fields = {"model": "model", "route": "route_id", "runtime": "runtime", "billing": "billing_basis"}
    if any(
        identity.get(key) != binding[field]
        for key, field in identity_fields.items()
        if key != "billing"
    ) or identity.get("billing") not in ({binding["billing_basis"]} if scoped_write else {"subscription"}):
        raise DispatchError("claude_route_binding_invalid", "identity")
    if controls["max_turns"] > 20:
        raise DispatchError("claude_guard_turn_limit_invalid", "max_turns")
    if scoped_write:
        try:
            guarded = _execution_policy.validate_claude_scoped_write_grant(
                claude_guard, route_name="worker_claude_code_sonnet_5",
                model=binding["model"],
            )
        except _execution_policy.ExecutionPolicyError as exc:
            raise DispatchError(exc.code, exc.path) from exc
    else:
        if claude_guard is not None:
            raise DispatchError("claude_read_only_guard_forbidden", "claude_guard")
        guarded = None
    argv = [
        exe, "-p", prompt,
        "--model", binding["model"],
        "--permission-mode", "acceptEdits" if scoped_write else "dontAsk",
        "--max-turns", str(controls["max_turns"]),
        "--output-format", "stream-json", "--verbose", "--include-hook-events",
        "--no-session-persistence",
        "--no-chrome",
        "--disable-slash-commands",
        "--setting-sources", "",
        "--strict-mcp-config", "--mcp-config", ".claude/empty-mcp.json",
    ]
    if scoped_write:
        argv.extend(["--settings", ".claude/settings.json", "--tools", ",".join(guarded["allowed_tools"])])
    else:
        argv.extend(["--safe-mode", "--tools", "Read"])
    return argv


def _argv_commandcode(
    exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False,
    execution_profile: dict[str, Any] | None = None,
    commandcode_guard: dict[str, Any] | None = None,
) -> list[str]:
    # Command Code defaults to 100 turns. Preserve that ceiling for read-only
    # DeepSeek work because startup and repository orientation can consume many
    # turns. Guarded mutation remains separately capped at 20 turns.
    controls = _runtime_controls(
        execution_profile, default_turns=20 if scoped_write else 100,
    )
    _require_write_flag_match(scoped_write, execution_profile)
    argv = [
        exe, "-p", prompt,
        "--model", str(identity.get("model", "unknown")),
        "--max-turns", str(controls["max_turns"]),
    ]
    if scoped_write:
        try:
            policy = _execution_policy.validate_commandcode_scoped_write_grant(
                commandcode_guard,
                route_name=(execution_profile or {}).get("route_name"),
                model=str(identity.get("model", "")),
            )
        except _execution_policy.ExecutionPolicyError as exc:
            raise DispatchError(exc.code, exc.path) from exc
        if controls["max_turns"] > 20:
            raise DispatchError("commandcode_guard_turn_limit_invalid", "max_turns")
        argv.extend(["--yolo", "--tools-enable", ",".join(policy["allowed_tools"])])
    else:
        argv.extend(["--permission-mode", "plan"])
    argv.extend([
        "--no-session",
        "--no-skills",
        "--skip-onboarding",
        "--no-auto-update",
    ])
    if "--tools-all" in argv:
        raise DispatchError("commandcode_tools_all_forbidden", "argv")
    return argv


def _argv_minimax(exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False, execution_profile: dict[str, Any] | None = None) -> list[str]:
    _runtime_controls(execution_profile, default_turns=1)
    _require_write_flag_match(scoped_write, execution_profile)
    if scoped_write:
        if (
            execution_profile is None
            or execution_profile.get("mutation_mode") != "scoped_write"
            or execution_profile.get("tool_loop") != "agentic"
            or execution_profile.get("write_transport") in {"none", "qualification_required"}
        ):
            raise DispatchError("provider_scoped_write_unsupported", "exact harness write transport is not qualified")
    return [exe, "text", "chat", "--model", str(identity.get("model", "unknown")), "--message", prompt, "--output", "json"]


MINIMAX_FILE_TOOL_FIELDS = {
    "read_file": {"tool", "path"},
    "write_file": {"tool", "path", "content"},
}


def _argv_minimax_tool_loop(
    exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False,
    execution_profile: dict[str, Any] | None = None,
) -> list[str]:
    controls = _runtime_controls(execution_profile, default_turns=20)
    _require_write_flag_match(scoped_write, execution_profile)
    if execution_profile is None or execution_profile.get("adapter_type") != "minimax_mmx_tool_loop":
        raise DispatchError("minimax_tool_loop_profile_required", "execution_profile")
    if execution_profile.get("command_transport") != "none":
        raise DispatchError("minimax_tool_loop_commands_forbidden", "command_transport")
    argv = [
        exe, "text", "chat", "--model", str(identity.get("model", "unknown")),
        "--messages-file", "-", "--max-tokens",
        str(execution_profile.get("max_output_tokens") or 4096), "--output", "json",
    ]
    enabled_tools = execution_profile.get("enabled_tools")
    if not isinstance(enabled_tools, list) or any(
        tool not in MINIMAX_FILE_TOOL_FIELDS for tool in enabled_tools
    ):
        raise DispatchError("minimax_tool_allowlist_invalid", "enabled_tools")
    if "write_file" in enabled_tools and not scoped_write:
        raise DispatchError("minimax_tool_write_forbidden", "read-only profile")
    return argv


def _argv_grok(
    exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False,
    execution_profile: dict[str, Any] | None = None,
    grok_guard: dict[str, Any] | None = None,
) -> list[str]:
    controls = _runtime_controls(execution_profile, default_turns=20)
    _require_write_flag_match(scoped_write, execution_profile)
    binding = _execution_policy.GROK_ROUTE_BINDINGS["worker_grok_4_6"]
    is_grok_46 = (
        (execution_profile or {}).get("route_name") == "worker_grok_4_6"
        or (
            identity.get("model") == binding["model"]
            and identity.get("route") == binding["route_id"]
            and identity.get("runtime") == binding["runtime"]
        )
    )
    if is_grok_46:
        identity_fields = {"model": "model", "route": "route_id", "runtime": "runtime", "billing": "billing_basis"}
        if any(
            identity.get(key) != binding[field]
            for key, field in identity_fields.items()
            if key != "billing"
        ) or identity.get("billing") not in ({binding["billing_basis"]} if scoped_write else {"subscription"}):
            raise DispatchError("grok_route_binding_invalid", "identity")
        if controls["max_turns"] > 20:
            raise DispatchError("grok_guard_turn_limit_invalid", "max_turns")
        if scoped_write:
            try:
                guard = _execution_policy.validate_grok_scoped_write_grant(
                    grok_guard, route_name="worker_grok_4_6", model=binding["model"],
                )
            except _execution_policy.ExecutionPolicyError as exc:
                raise DispatchError(exc.code, exc.path) from exc
            session_id = guard["session_id"]
            tools = guard["allowed_tools"]
        else:
            if grok_guard is not None:
                raise DispatchError("grok_read_only_guard_forbidden", "grok_guard")
            session_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                json.dumps(identity, sort_keys=True, separators=(",", ":")),
            ))
            tools = ["read_file"]
        argv = [
            exe, "--single", prompt, "--model", binding["model"],
            "--max-turns", str(controls["max_turns"]), "--disable-web-search",
            "--no-memory", "--no-subagents", "--no-plan",
            "--tools", ",".join(tools),
            "--disallowed-tools", "shell,web_search,web_fetch,mcp",
            "--session-id", session_id,
            "--output-format", "streaming-json",
        ]
        if scoped_write:
            argv.extend(["--sandbox", "strict"])
        return argv
    argv = [
        exe, "--single", prompt, "--model", str(identity.get("model", "unknown")),
        "--output-format", "json", "--permission-mode", "acceptEdits" if scoped_write else "plan",
        "--max-turns", str(controls["max_turns"]),
    ]
    enabled_tools = execution_profile.get("enabled_tools", []) if execution_profile is not None else []
    if execution_profile is None or not execution_profile.get("web_search_enabled", False):
        argv.append("--disable-web-search")
    if "memory" not in enabled_tools:
        argv.append("--no-memory")
    if "subagents" not in enabled_tools:
        argv.append("--no-subagents")
    return argv


def _argv_opencode(exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False, execution_profile: dict[str, Any] | None = None) -> list[str]:
    _require_write_flag_match(scoped_write, execution_profile)
    if execution_profile is None:
        raise DispatchError("opencode_backend_binding_required", "execution_profile")
    try:
        backend = _execution_policy.validate_opencode_backend_binding(
            str(execution_profile.get("route_name", "")), identity
        )
    except _execution_policy.ExecutionPolicyError as exc:
        raise DispatchError(exc.code, exc.path) from exc
    if scoped_write and (
        execution_profile is None
        or execution_profile.get("tool_loop") != "agentic"
        or execution_profile.get("write_transport") in {"none", "qualification_required"}
        or execution_profile.get("command_transport") != "native_tools"
    ):
        raise DispatchError(
            "provider_scoped_write_unsupported",
            "exact OpenCode tool-loop harness is not qualified",
        )
    selector = backend.get("model_selector")
    if not isinstance(selector, str) or "/" not in selector or selector == identity.get("model"):
        raise DispatchError("opencode_model_selector_invalid", "backend.model_selector")
    return [
        exe, "run", "--pure", "--model", selector,
        "--format", "json", "--", prompt,
    ]


def _argv_codex(exe: str, prompt: str, identity: dict[str, Any], *, scoped_write: bool = False, execution_profile: dict[str, Any] | None = None) -> list[str]:
    controls = _runtime_controls(execution_profile)
    _require_write_flag_match(scoped_write, execution_profile)
    reasoning = str(controls["reasoning_depth"] if execution_profile is not None else identity.get("reasoning", "unknown"))
    return [
        exe, "exec", "--model", str(identity.get("model", "unknown")),
        "--config", f'model_reasoning_effort="{reasoning}"',
        "--sandbox", "workspace-write" if scoped_write else "read-only", "--json", "--", prompt,
    ]


ADAPTERS: dict[str, tuple[str, Callable[[str, str, dict[str, Any]], list[str]]]] = {
    "claude_cli": ("claude", _argv_claude),
    "commandcode": ("commandcode", _argv_commandcode),
    "minimax_mmx": ("mmx", _argv_minimax),
    "minimax_mmx_tool_loop": ("mmx", _argv_minimax_tool_loop),
    "opencode_tool_loop": ("opencode", _argv_opencode),
    "grok_cli": ("grok", _argv_grok),
    # Retain the frozen simulated-fixture identifier. Route resolution never
    # selects this legacy name for a live OpenCode backend.
    "opencode_qwopus": ("opencode", _argv_opencode),
    "native_codex": ("codex", _argv_codex),
}


def _resolved_execution_profile(
    *, task_envelope: dict[str, Any] | None, route_name: str,
    identity: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Resolve optional v2 behavior controls without creating authority."""
    if not isinstance(task_envelope, dict):
        return None
    provider_work = task_envelope.get("provider_work")
    if not isinstance(provider_work, dict):
        return None
    try:
        card = _provider_work.validate_capability_card(provider_work.get("capability_card"))
        grant = _provider_work.validate_task_grant(provider_work.get("task_grant"))
        if card["schema_version"] == 1 and grant["schema_version"] == 1:
            if provider_work.get("legacy_schema_v1") is not True:
                raise _execution_policy.ExecutionPolicyError(
                    "legacy_v1_migration_required", "provider_work.legacy_schema_v1"
                )
            return None
        if card["schema_version"] != 2 or grant["schema_version"] != 2:
            raise _execution_policy.ExecutionPolicyError("provider_work_schema_mixed", "provider_work")
        if card["route_name"] != route_name or grant["route_name"] != route_name:
            raise _execution_policy.ExecutionPolicyError(
                "selected_route_binding_mismatch", "provider_work.route_name"
            )
        if not isinstance(identity, dict):
            raise _execution_policy.ExecutionPolicyError(
                "selected_identity_required", "selected_identity"
            )
        identity_bindings = {
            "provider": "provider", "exact_model": "model", "route_id": "route",
            "runtime": "runtime", "billing_basis": "billing",
        }
        for card_field, identity_field in identity_bindings.items():
            if card.get(card_field) != identity.get(identity_field):
                raise _execution_policy.ExecutionPolicyError(
                    "selected_identity_binding_mismatch", f"capability_card.{card_field}"
                )
        if "task_intent" not in provider_work:
            raise _execution_policy.ExecutionPolicyError("task_intent_required", "provider_work.task_intent")
        if "harness_card" not in provider_work:
            raise _execution_policy.ExecutionPolicyError("harness_card_required", "provider_work.harness_card")
        harness = _execution_policy.validate_harness_card(provider_work["harness_card"])
        profile = _execution_policy.resolve_execution_profile(
            intent_value=provider_work["task_intent"], harness_value=harness,
            capability_card=card, task_grant=grant,
            runtime_constraints=provider_work.get("runtime_constraints"),
        )
        if profile["adapter_type"] == "opencode_tool_loop":
            _execution_policy.validate_opencode_backend_binding(route_name, identity)
        if profile["mutation_mode"] != task_envelope.get("mutation_mode"):
            raise _execution_policy.ExecutionPolicyError(
                "envelope_mutation_mode_mismatch", "task_envelope.mutation_mode"
            )
        if profile["mutation_mode"] == "scoped_write":
            requested_write = task_envelope.get("scope", {}).get("requested_write")
            if requested_write != grant.get("write_scope"):
                raise _execution_policy.ExecutionPolicyError(
                    "envelope_write_scope_mismatch", "task_envelope.scope.requested_write"
                )
        return profile
    except (_provider_work.ProviderWorkError, _execution_policy.ExecutionPolicyError) as exc:
        raise DispatchError(exc.code, exc.path) from exc


def _behavior_bound_prompt(prompt: str, profile: dict[str, Any] | None) -> str:
    if profile is None:
        return prompt
    controls = _runtime_controls(profile)
    return (
        prompt
        + "\n\nRuntime behavior policy: reasoning_depth="
        + str(controls["reasoning_depth"])
        + "; answer_verbosity=" + str(controls["answer_verbosity"])
        + ". These behavior settings do not grant tools, commands, network access, or writes."
    )


def _test_executables(path: Path | None, root: Path, proof_mode: str) -> dict[str, str]:
    if path is None:
        return {}
    if proof_mode != "simulated":
        raise DispatchError("test_adapter_forbidden", "test adapter manifests are simulated-only")
    expected_manifest = root / FIXTURE_MANIFEST_RELATIVE
    safe_manifest = _regular_single_link(path, root, "test_adapter_manifest")
    if safe_manifest != expected_manifest or _sha256(safe_manifest.read_bytes()) != FIXTURE_MANIFEST_SHA256:
        raise DispatchError("test_adapter_forbidden", "only the frozen repository fixture manifest is allowed")
    manifest = _read_json_file(path, root, "test_adapter_manifest")
    if set(manifest) != {"schema_version", "adapters"} or manifest["schema_version"] != 1:
        raise DispatchError("invalid_test_adapter", "unsupported manifest schema")
    adapters = manifest["adapters"]
    if not isinstance(adapters, dict):
        raise DispatchError("invalid_test_adapter", "adapters must be an object")
    result: dict[str, str] = {}
    for adapter_id, relative in adapters.items():
        if adapter_id not in ADAPTERS or not isinstance(relative, str):
            raise DispatchError("invalid_test_adapter", str(adapter_id))
        executable = _relative_path(relative, root, f"test_adapter:{adapter_id}")
        safe = _regular_single_link(executable, root, f"test_adapter:{adapter_id}")
        if (
            safe != root / FIXTURE_EXECUTABLE_RELATIVE
            or _sha256(safe.read_bytes()) != FIXTURE_EXECUTABLE_SHA256
        ):
            raise DispatchError("test_adapter_forbidden", f"{adapter_id} is not the frozen fake fixture")
        if not os.access(safe, os.X_OK):
            raise DispatchError("invalid_test_adapter", f"{adapter_id} is not executable")
        result[adapter_id] = str(safe)
    return result


def _minimal_environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired as exc:
            raise DispatchError("process_reap_failed", str(process.pid)) from exc


def _capture(
    argv: list[str], cwd: Path, deadline_monotonic: float,
    stdout_limit: int, stderr_limit: int,
) -> dict[str, Any]:
    started = time.monotonic()
    if deadline_monotonic <= started:
        raise DispatchError("execution_deadline_expired", "absolute monotonic deadline")
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=_minimal_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_limit))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr_limit))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded: str | None = None
    timed_out = False
    deadline = deadline_monotonic
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(process)
                break
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in list(selector.get_map().values())]
            for key, _ in events:
                name, limit = key.data
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max(0, limit - len(buffers[name]))
                buffers[name].extend(chunk[:room])
                if len(chunk) > room:
                    exceeded = name
                    _terminate(process)
                    break
            if exceeded:
                break
        if process.poll() is None:
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate(process)
    finally:
        selector.close()
        if process.poll() is None:
            _terminate(process)
        process.stdout.close()
        process.stderr.close()
    return {
        "returncode": process.returncode,
        "stdout": bytes(buffers["stdout"]),
        "stderr": bytes(buffers["stderr"]),
        "timed_out": timed_out,
        "output_limit_stream": exceeded,
        "elapsed_time_ms": max(0, int((time.monotonic() - started) * 1000)),
    }


def _unknown(reason: str) -> dict[str, str]:
    return {"value": "unknown", "reason": reason}


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _strict_json_object(data: bytes) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "response_invalid_utf8"
    if not text.strip():
        return None, "response_empty"

    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except _DuplicateJsonKey as exc:
        return None, f"response_duplicate_key:{exc}"
    except json.JSONDecodeError:
        return None, "response_not_one_json_object"
    if not isinstance(value, dict):
        return None, "response_root_not_object"
    return value, None


def _embedded_json_object(data: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """Extract one terminal JSON object after bounded provider preface text."""
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None, "response_invalid_utf8"
    start = text.find("{")
    if start < 0 or start > 512:
        return None, "response_not_one_json_object"
    candidate = text[start:]
    try:
        value, consumed = json.JSONDecoder(
            object_pairs_hook=_reject_duplicate_pairs
        ).raw_decode(candidate)
    except _DuplicateJsonKey as exc:
        return None, f"response_duplicate_key:{exc}"
    except json.JSONDecodeError:
        return None, "response_not_one_json_object"
    if candidate[consumed:].strip() or not isinstance(value, dict):
        return None, "response_not_one_json_object"
    return value, None


MINIMAX_MESSAGE_FIELDS = {
    "id", "type", "role", "model", "content", "usage", "stop_reason", "base_resp",
}
MINIMAX_USAGE_FIELDS = {
    "input_tokens", "output_tokens", "cache_creation_input_tokens",
    "cache_read_input_tokens", "service_tier",
}
MINIMAX_MESSAGES_PROTOCOL = "mmx-1.0.16:codexmax-json-text-tool-v1"


def _minimax_protocol_prompt(prompt: str, enabled_tools: list[str]) -> str:
    shapes = []
    if "read_file" in enabled_tools:
        shapes.append('{"tool":"read_file","path":"<relative-path>"}')
    if "write_file" in enabled_tools:
        shapes.append('{"tool":"write_file","path":"<relative-path>","content":"<exact-utf8>"}')
    tool_text = " or ".join(shapes) if shapes else "no tool request"
    return (
        "You are in a bounded Codexmax adapter tool loop. Return exactly one JSON object "
        "and no markdown. You may return " + tool_text + ". Return at most one tool request. "
        "Do not request commands, URLs, absolute paths, or parent traversal. After a TOOL_RESULT "
        "message, continue from that exact result. When finished, return only the final JSON "
        "artifact required below.\n\n" + prompt
    )


def _parse_minimax_turn(data: bytes) -> tuple[str, dict[str, Any], bytes | None]:
    """Parse one exact mmx wrapper containing one closed JSON text object."""
    value, failure = _strict_json_object(data)
    if failure is not None or value is None:
        raise DispatchError("minimax_tool_response_invalid", failure or "empty")
    if set(value) != MINIMAX_MESSAGE_FIELDS:
        raise DispatchError("minimax_tool_response_invalid", "message fields")
    if value["type"] != "message" or value["role"] != "assistant" or value["model"] != "MiniMax-M3":
        raise DispatchError("minimax_tool_identity_mismatch", "message identity")
    if not isinstance(value["id"], str) or not value["id"]:
        raise DispatchError("minimax_message_id_invalid", "id")
    base = value["base_resp"]
    if not isinstance(base, dict) or set(base) != {"status_code", "status_msg"} or base["status_code"] != 0 or base["status_msg"] != "":
        raise DispatchError("minimax_tool_response_invalid", "base_resp")
    usage = value["usage"]
    if not isinstance(usage, dict) or set(usage) != MINIMAX_USAGE_FIELDS:
        raise DispatchError("minimax_tool_response_invalid", "usage fields")
    if any(type(usage[field]) is not int or usage[field] < 0 for field in MINIMAX_USAGE_FIELDS - {"service_tier"}):
        raise DispatchError("minimax_tool_response_invalid", "usage counters")
    if not isinstance(usage["service_tier"], str) or not usage["service_tier"]:
        raise DispatchError("minimax_tool_response_invalid", "usage service_tier")
    content = value["content"]
    if not isinstance(content, list) or len(content) != 1:
        raise DispatchError("minimax_content_count_invalid", "one content block per turn")
    block = content[0]
    if value["stop_reason"] != "end_turn":
        raise DispatchError("minimax_stop_reason_invalid", str(value["stop_reason"]))
    if not isinstance(block, dict) or set(block) != {"type", "text"} or block["type"] != "text":
        raise DispatchError("minimax_text_result_invalid", "content[0]")
    if not isinstance(block["text"], str):
        raise DispatchError("minimax_text_result_invalid", "text")
    text_bytes = block["text"].encode("utf-8")
    result, result_failure = _strict_json_object(text_bytes)
    if result_failure is not None or result is None:
        raise DispatchError("minimax_text_json_invalid", result_failure or "empty")
    if "tool" not in result:
        return "final", value, text_bytes
    name = result.get("tool")
    if name not in MINIMAX_FILE_TOOL_FIELDS:
        raise DispatchError("minimax_tool_call_invalid", "tool")
    if set(result) != MINIMAX_FILE_TOOL_FIELDS[name]:
        raise DispatchError("minimax_tool_arguments_invalid", str(name))
    if not isinstance(result["path"], str) or not result["path"]:
        raise DispatchError("minimax_tool_arguments_invalid", "path")
    if name == "write_file" and not isinstance(result["content"], str):
        raise DispatchError("minimax_tool_arguments_invalid", "content")
    value["parsed_tool_request"] = result
    return "tool_use", value, None


def _parse_minimax_tool_turn(data: bytes) -> dict[str, Any]:
    """Compatibility wrapper for callers that require a tool-use turn."""
    kind, value, _ = _parse_minimax_turn(data)
    if kind != "tool_use":
        raise DispatchError("minimax_tool_turn_required", kind)
    return value


def _minimax_relative_parts(value: str) -> tuple[str, ...]:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise DispatchError("minimax_tool_path_invalid", value)
    return path.parts


def _minimax_parent_fd(workspace: Path, value: str) -> tuple[int, str]:
    parts = _minimax_relative_parts(value)
    descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except Exception:
        os.close(descriptor)
        raise


def _apply_minimax_file_tool(
    workspace: Path, call: dict[str, Any], *, root: Path,
    read_scope: list[str], write_scope: list[str], enabled_tools: list[str],
    scope_base: str | None = None,
    result_byte_cap: int = 1_048_576,
) -> str:
    name = call["tool"]
    args = call
    if name not in enabled_tools:
        raise DispatchError("minimax_tool_not_granted", name)
    logical_parts = _minimax_relative_parts(args["path"])
    base = scope_base if scope_base is not None else workspace.relative_to(root).as_posix()
    relative = base.rstrip("/") + "/" + "/".join(logical_parts)
    scope = read_scope if name == "read_file" else write_scope
    if not _provider_work.path_allowed(relative, scope):
        raise DispatchError("minimax_tool_scope_denied", relative)
    parent_fd, leaf = _minimax_parent_fd(workspace, args["path"])
    try:
        if name == "read_file":
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > result_byte_cap:
                    raise DispatchError("minimax_tool_file_invalid", args["path"])
                data = os.read(fd, info.st_size + 1)
            finally:
                os.close(fd)
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DispatchError("minimax_tool_file_not_utf8", args["path"]) from exc
        if name != "write_file":
            raise DispatchError("minimax_tool_write_forbidden", args["path"])
        data = args["content"].encode("utf-8")
        if len(data) > result_byte_cap:
            raise DispatchError("minimax_tool_content_too_large", args["path"])
        try:
            info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DispatchError("minimax_tool_file_invalid", args["path"])
        except FileNotFoundError:
            pass
        temp_name = f".{leaf}.minimax-{os.getpid()}-{time.monotonic_ns()}"
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        try:
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            os.replace(temp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
        except Exception:
            try: os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError: pass
            raise
        return json.dumps({"bytes_written": len(data), "path": args["path"]}, sort_keys=True)
    finally:
        os.close(parent_fd)


def _minimax_tool_continuation(messages: list[dict[str, Any]], turn: dict[str, Any], result: str) -> list[dict[str, Any]]:
    call = turn["parsed_tool_request"]
    call_text = json.dumps(call, sort_keys=True, separators=(",", ":"))
    result_text = "TOOL_RESULT " + json.dumps({
        "path": call["path"], "result": result, "tool": call["tool"],
    }, sort_keys=True, separators=(",", ":"))
    assistant = {"role": "assistant", "content": call_text}
    tool_result = {"role": "user", "content": result_text}
    return [*messages, assistant, tool_result]


def _minimax_request_wire_bytes(
    messages: list[dict[str, Any]], identity: dict[str, Any],
    execution_profile: dict[str, Any],
) -> bytes:
    """Return a conservative canonical representation of the full request."""
    request = {
        "model": identity.get("model"),
        "messages": messages,
        "enabled_json_text_tools": execution_profile.get("enabled_tools", []),
        "max_tokens": execution_profile.get("max_output_tokens") or 4096,
        "output_format": "json",
        "messages_transport": "messages-file",
        "messages_protocol": MINIMAX_MESSAGES_PROTOCOL,
        "runtime": identity.get("runtime"),
        "route": identity.get("route"),
        "provider": identity.get("provider"),
    }
    return (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write_new_durable(path: Path, data: bytes) -> dict[str, Any]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
    except Exception:
        try: path.unlink()
        except FileNotFoundError: pass
        raise
    return {"name": path.name, "bytes": len(data), "sha256": _sha256(data)}


def _append_minimax_observation(path: Path, event: str, call_index: int, payload: dict[str, Any]) -> None:
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DispatchError("minimax_observation_journal_invalid", str(path))
        os.lseek(fd, 0, os.SEEK_SET)
        existing = bytearray()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk: break
            existing.extend(chunk)
            if len(existing) > 4_194_304:
                raise DispatchError("minimax_observation_journal_invalid", "oversized")
        try:
            rows = [json.loads(line) for line in bytes(existing).decode("utf-8").splitlines()]
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DispatchError("minimax_observation_journal_invalid", str(path)) from exc
        previous = None
        for index, prior in enumerate(rows, 1):
            supplied = prior.get("event_sha256") if isinstance(prior, dict) else None
            core = {key: value for key, value in prior.items() if key != "event_sha256"} if isinstance(prior, dict) else {}
            if prior.get("sequence") != index or prior.get("previous_sha256") != previous or supplied != _canonical_digest(core):
                raise DispatchError("minimax_observation_journal_invalid", str(path))
            previous = supplied
        row = {
            "schema_version": 1, "sequence": len(rows) + 1,
            "event": event, "call_index": call_index,
            "previous_sha256": previous, "payload": payload,
        }
        row["event_sha256"] = _canonical_digest(row)
        raw = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, raw); os.fsync(fd)
    finally:
        os.close(fd)


def _run_minimax_tool_loop(
    *, executable: str, prompt: str, identity: dict[str, Any],
    execution_profile: dict[str, Any], workspace: Path,
    root: Path, read_scope: list[str], write_scope: list[str],
    scope_base: str,
    observation_directory: Path,
    deadline_monotonic: float, stdout_limit: int, stderr_limit: int,
) -> dict[str, Any]:
    """Run the closed mmx file-tool protocol. Final success remains pending."""
    controls = _runtime_controls(execution_profile)
    enabled_tools = execution_profile.get("enabled_tools", [])
    messages: list[dict[str, Any]] = [{
        "role": "user", "content": _minimax_protocol_prompt(prompt, enabled_tools),
    }]
    max_input_tokens = execution_profile.get("max_input_tokens")
    if type(max_input_tokens) is not int or max_input_tokens < 1:
        raise DispatchError("minimax_input_budget_invalid", "max_input_tokens")
    # Treat the token ceiling as a stricter byte ceiling. This makes no
    # tokenizer assumption. The full canonical request must fit before spawn.
    request_wire_byte_cap = min(max_input_tokens, 1_048_576)
    result_byte_cap = min(
        262_144,
        max(1, request_wire_byte_cap // max(2, controls["max_turns"] * 2)),
    )
    mutated = False
    raw_observations: list[dict[str, Any]] = []
    observation_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    observation_journal = observation_directory / "provider-calls.jsonl"
    for _turn_index in range(controls["max_turns"]):
        call_index = _turn_index + 1
        argv = _argv_minimax_tool_loop(
            executable, prompt, identity,
            scoped_write=execution_profile.get("mutation_mode") == "scoped_write",
            execution_profile=execution_profile,
        )
        message_bytes = (json.dumps(messages, sort_keys=True, separators=(",", ":")) + "\n").encode()
        request_bytes = _minimax_request_wire_bytes(messages, identity, execution_profile)
        if len(request_bytes) > request_wire_byte_cap:
            raise DispatchError(
                "execution_unknown" if mutated else "minimax_message_budget_exceeded",
                "no next provider call",
            )
        _append_minimax_observation(
            observation_journal, "process_spawn_intent", call_index,
            {"request_sha256": _sha256(request_bytes), "request_bytes": len(request_bytes)},
        )
        descriptor, path_value = tempfile.mkstemp(prefix=".minimax-messages-", suffix=".json", dir=workspace)
        message_path = Path(path_value)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(message_bytes)
                stream.flush(); os.fsync(stream.fileno())
            info = os.lstat(message_path)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DispatchError("minimax_messages_file_invalid", str(message_path))
            argv[argv.index("-")] = str(message_path)
            capture = _capture(argv, workspace, deadline_monotonic, stdout_limit, stderr_limit)
        finally:
            try: message_path.unlink()
            except FileNotFoundError: pass
        stdout_descriptor = _write_new_durable(
            observation_directory / f"call-{call_index:03d}.stdout.bin", capture["stdout"]
        )
        stderr_descriptor = _write_new_durable(
            observation_directory / f"call-{call_index:03d}.stderr.bin", capture["stderr"]
        )
        _append_minimax_observation(
            observation_journal, "capture_completed", call_index,
            {"stdout": stdout_descriptor, "stderr": stderr_descriptor,
             "returncode": capture["returncode"], "timed_out": capture["timed_out"],
             "output_limit_stream": capture["output_limit_stream"],
             "process_spawned": True, "capture_completed": True,
             "provider_call_performed": "unknown", "network_performed": "unknown"},
        )
        raw_observations.append({"call_index": call_index, "stdout": stdout_descriptor, "stderr": stderr_descriptor})
        pending_observation = {
            "process_count": call_index, "capture_count": call_index,
            "provider_call_performed": "unknown", "network_performed": "unknown",
            "raw_observations": copy.deepcopy(raw_observations),
            "journal": observation_journal.relative_to(root).as_posix(),
            "retry_allowed": False, "terminal_state": "execution_unknown",
        }
        def raise_pending(reason: str) -> None:
            final_reason = reason
            try:
                _append_minimax_observation(
                    observation_journal, "observation_pending", call_index,
                    {"reason": reason, "retry_allowed": False,
                     "terminal_state": "execution_unknown",
                     "process_count": call_index, "capture_count": call_index,
                     "provider_call_performed": "unknown", "network_performed": "unknown"},
                )
            except Exception as exc:
                final_reason = "observation_terminal_append_failed:" + type(exc).__name__
            raise MiniMaxObservationPending(
                result=capture, observation={**pending_observation, "reason": final_reason},
            )
        if capture["timed_out"]:
            raise_pending("timeout")
        if capture["output_limit_stream"] is not None or capture["returncode"] != 0:
            raise_pending("nonzero_or_output_limit")
        try:
            turn_kind, turn, final_bytes = _parse_minimax_turn(capture["stdout"])
        except DispatchError as exc:
            raise_pending(exc.code)
        if turn_kind == "final":
            assert final_bytes is not None
            pending_observation = {
                "process_count": call_index, "capture_count": call_index,
                "provider_call_performed": "unknown", "network_performed": "unknown",
                "raw_observations": copy.deepcopy(raw_observations),
                "journal": observation_journal.relative_to(root).as_posix(),
                "retry_allowed": False,
                "terminal_state": "wrapper_valid_pending_response_validation",
            }
            return {
                **capture, "stdout": final_bytes,
                "minimax_final_pending": {
                    "call_index": call_index,
                    "journal_path": observation_journal,
                    "observation": pending_observation,
                },
            }
        call = turn["parsed_tool_request"]
        result = _apply_minimax_file_tool(
            workspace, call, root=root, read_scope=read_scope,
            write_scope=write_scope,
            enabled_tools=execution_profile.get("enabled_tools", []),
            scope_base=scope_base,
            result_byte_cap=result_byte_cap,
        )
        mutated = mutated or call["tool"] == "write_file"
        messages = _minimax_tool_continuation(messages, turn, result)
        if len(_minimax_request_wire_bytes(messages, identity, execution_profile)) > request_wire_byte_cap:
            raise DispatchError(
                "execution_unknown" if mutated else "minimax_message_budget_exceeded",
                "no next provider call",
            )
    raise DispatchError(
        "execution_unknown" if mutated else "minimax_tool_turn_limit",
        "no retry",
    )


def _value_matches_type(value: Any, schema_type: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": type(value) is bool,
        "null": value is None,
    }[schema_type]


def _schema_finding(value: Any, schema: dict[str, Any], path: str = "response") -> str | None:
    raw_type = schema.get("type")
    if raw_type is not None:
        types = raw_type if isinstance(raw_type, list) else [raw_type]
        if not any(_value_matches_type(value, item) for item in types):
            return f"{path}:type"
    if "const" in schema and value != schema["const"]:
        return f"{path}:const"
    if "enum" in schema and value not in schema["enum"]:
        return f"{path}:enum"
    if isinstance(value, dict):
        properties = schema["properties"]
        missing = sorted(set(schema["required"]) - set(value))
        if missing:
            return f"{path}:missing:{missing[0]}"
        extra = sorted(set(value) - set(properties))
        if extra:
            return f"{path}:extra:{extra[0]}"
        for name in sorted(value):
            finding = _schema_finding(value[name], properties[name], f"{path}.{name}")
            if finding:
                return finding
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            return f"{path}:minItems"
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return f"{path}:maxItems"
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(encoded) != len(set(encoded)):
                return f"{path}:uniqueItems"
        if "items" in schema:
            for index, item in enumerate(value):
                finding = _schema_finding(item, schema["items"], f"{path}[{index}]")
                if finding:
                    return finding
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            return f"{path}:minLength"
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return f"{path}:maxLength"
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return f"{path}:pattern"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            return f"{path}:minimum"
        if "maximum" in schema and value > schema["maximum"]:
            return f"{path}:maximum"
    return None


def _expected_response_identity(route_name: str, identity: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "declared_route": route_name,
        "actual_provider": identity.get("provider"),
        "actual_model": identity.get("model"),
        "fallback_used": False,
        "retry_count": 0,
    }
    for field in ("declared_route", "actual_provider", "actual_model"):
        if expected[field] in (None, "", "unknown"):
            raise DispatchError("invalid_resolution", f"expected response identity missing {field}")
    return expected


def _bound_prompt(prompt: str, response_schema: dict[str, Any], expected_identity: dict[str, Any]) -> str:
    return (
        prompt
        + "\n\n## Headless dispatch response contract\n"
        + "Return exactly one raw JSON object matching the schema below. Do not use markdown fences, "
        + "prose, or a provider wrapper. Return the route_identity tuple exactly as supplied; do not "
        + "guess, omit, null, or substitute identity.\n"
        + "Expected route_identity: "
        + json.dumps(expected_identity, sort_keys=True, separators=(",", ":"))
        + "\nResponse schema: "
        + json.dumps(response_schema, sort_keys=True, separators=(",", ":"))
    )


def _normalize_opencode_json_events(
    response_bytes: bytes,
) -> tuple[bytes | None, dict[str, Any] | None, int | float | None, str | None]:
    """Extract one final result from the bounded OpenCode JSON event protocol."""
    events: list[dict[str, Any]] = []
    try:
        lines = response_bytes.splitlines()
        if not lines or len(lines) > 512 or any(len(line) > 262144 for line in lines):
            return None, None, None, "opencode_event_stream_bounds_invalid"
        for line in lines:
            if not line.strip():
                continue
            event = json.loads(line, object_pairs_hook=_reject_duplicate_pairs)
            if not isinstance(event, dict):
                return None, None, None, "opencode_event_not_object"
            events.append(event)
    except (_DuplicateJsonKey, json.JSONDecodeError, UnicodeDecodeError):
        return None, None, None, "opencode_event_stream_invalid"
    if not events:
        return None, None, None, "opencode_event_stream_empty"

    allowed_types = {"step_start", "tool_use", "text", "step_finish"}
    sessions: set[str] = set()
    terminals: list[tuple[int, dict[str, Any]]] = []
    text_events: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        event_type = event.get("type")
        if event_type == "error":
            return None, None, None, "opencode_error_event"
        if event_type not in allowed_types:
            return None, None, None, "opencode_event_type_invalid"
        session_id = event.get("sessionID")
        timestamp = event.get("timestamp")
        part = event.get("part")
        if (
            not isinstance(session_id, str)
            or not session_id
            or len(session_id) > 256
            or type(timestamp) is not int
            or timestamp < 0
            or not isinstance(part, dict)
        ):
            return None, None, None, "opencode_event_shape_invalid"
        nested_session = part.get("sessionID")
        if nested_session is not None and nested_session != session_id:
            return None, None, None, "opencode_session_mismatch"
        sessions.add(session_id)
        if event_type == "text":
            if part.get("type") != "text" or not isinstance(part.get("text"), str):
                return None, None, None, "opencode_text_event_invalid"
            text_events.append(event)
        elif event_type == "step_finish":
            if part.get("type") != "step-finish" or part.get("reason") not in {"tool-calls", "stop"}:
                return None, None, None, "opencode_terminal_invalid"
            if part.get("reason") == "stop":
                terminals.append((index, event))
    if len(sessions) != 1:
        return None, None, None, "opencode_session_count_invalid"
    if len(terminals) != 1 or terminals[0][0] != len(events) - 1:
        return None, None, None, "opencode_terminal_count_invalid"

    terminal = terminals[0][1]["part"]
    terminal_message_id = terminal.get("messageID")
    if not isinstance(terminal_message_id, str) or not terminal_message_id:
        return None, None, None, "opencode_terminal_invalid"
    final_text = [
        event["part"]["text"]
        for event in text_events
        if event["part"].get("messageID") == terminal_message_id
    ]
    if len(final_text) != 1 or not final_text[0].strip():
        return None, None, None, "opencode_final_text_count_invalid"

    usage = terminal.get("tokens")
    if usage is not None:
        if not isinstance(usage, dict) or set(usage) != {"total", "input", "output", "reasoning", "cache"}:
            return None, None, None, "opencode_usage_invalid"
        cache = usage.get("cache")
        if (
            any(type(usage[field]) is not int or usage[field] < 0 for field in ("total", "input", "output", "reasoning"))
            or not isinstance(cache, dict)
            or set(cache) != {"write", "read"}
            or any(type(cache[field]) is not int or cache[field] < 0 for field in ("write", "read"))
        ):
            return None, None, None, "opencode_usage_invalid"
        if usage["total"] != (
            usage["input"] + usage["output"] + usage["reasoning"]
            + cache["write"] + cache["read"]
        ):
            return None, None, None, "opencode_usage_invalid"
    cost = terminal.get("cost")
    if cost is not None and (
        not isinstance(cost, (int, float))
        or isinstance(cost, bool)
        or not math.isfinite(cost)
        or cost < 0
    ):
        return None, None, None, "opencode_cost_invalid"
    return final_text[0].encode("utf-8"), usage, cost, None


def _normalize_output(
    capture: dict[str, Any], response_schema: dict[str, Any], expected_identity: dict[str, Any],
    *, adapter_id: str | None = None,
) -> tuple[str, bytes | None, dict[str, Any], str]:
    accounting = {
        "tokens": _unknown("provider_tokens_not_reported"),
        "quota": _unknown("provider_quota_not_reported"),
        "cost": _unknown("provider_cost_not_reported"),
    }
    if capture["timed_out"]:
        return "provider_failure", None, accounting, "timeout"
    if capture["output_limit_stream"] is not None:
        return (
            "provider_failure", None, accounting,
            f"output_limit:{capture['output_limit_stream']}",
        )
    if capture["returncode"] != 0:
        if adapter_id == "opencode_tool_loop":
            lowered = capture.get("stderr", b"").lower()
            if b"providermodelnotfounderror" in lowered or b"model not found" in lowered:
                return (
                    "provider_failure", None, accounting,
                    "backend_unavailable:model_not_found:no_retry",
                )
        return "provider_failure", None, accounting, f"nonzero_exit:{capture['returncode']}"
    response_bytes = capture["stdout"]
    if adapter_id == "opencode_tool_loop":
        response_bytes, usage, cost, finding = _normalize_opencode_json_events(response_bytes)
        if finding is not None or response_bytes is None:
            return "validation_failure", None, accounting, finding or "opencode_event_stream_invalid"
        if usage is not None:
            accounting["tokens"] = {"value": usage, "reason": "provider_reported"}
        if cost is not None:
            accounting["cost"] = {"value": cost, "reason": "provider_reported"}
    elif adapter_id == "minimax_mmx":
        try:
            kind, _, payload = _parse_minimax_turn(response_bytes)
        except DispatchError as exc:
            return "validation_failure", None, accounting, f"minimax_wrapper_invalid:{exc.code}:{exc.detail}"
        if kind != "final" or payload is None:
            return "validation_failure", None, accounting, "minimax_final_response_required"
        response_bytes = payload
    elif adapter_id == "claude_cli":
        terminals: list[dict[str, Any]] = []
        try:
            for line in response_bytes.splitlines():
                if not line:
                    continue
                event = json.loads(line, object_pairs_hook=_reject_duplicate_pairs)
                if not isinstance(event, dict):
                    return "validation_failure", None, accounting, "provider_event_not_object"
                if event.get("type") == "assistant":
                    message = event.get("message")
                    if isinstance(message, dict) and message.get("model") not in {None, expected_identity["actual_model"]}:
                        return "validation_failure", None, accounting, "provider_event_model_mismatch"
                if event.get("type") == "result":
                    terminals.append(event)
        except (_DuplicateJsonKey, json.JSONDecodeError, UnicodeDecodeError):
            return "validation_failure", None, accounting, "provider_event_stream_invalid"
        if len(terminals) != 1:
            return "validation_failure", None, accounting, "provider_terminal_count_invalid"
        terminal = terminals[0]
        if terminal.get("is_error") is not False or not isinstance(terminal.get("result"), str):
            return "validation_failure", None, accounting, "provider_terminal_invalid"
        response_bytes = terminal["result"].encode("utf-8")
    elif adapter_id == "grok_cli":
        # Grok CLI 1.0.4 can emit either streaming JSON events or one aggregate
        # JSON wrapper. Normalize both without trusting the model's own route
        # assertion as runtime identity evidence.
        try:
            aggregate = json.loads(response_bytes, object_pairs_hook=_reject_duplicate_pairs)
        except (_DuplicateJsonKey, json.JSONDecodeError, UnicodeDecodeError):
            aggregate = None
        if isinstance(aggregate, dict) and isinstance(aggregate.get("text"), str):
            model_usage = aggregate.get("modelUsage")
            if not isinstance(model_usage, dict) or not model_usage:
                return "validation_failure", None, accounting, "grok_model_usage_missing"
            observed_models = list(model_usage)
            if any(
                not isinstance(model, str)
                or not model.startswith(expected_identity["actual_model"])
                for model in observed_models
            ):
                return "validation_failure", None, accounting, "provider_event_model_mismatch"
            text = aggregate["text"].strip()
            object_start = text.find("{")
            if object_start < 0:
                return "validation_failure", None, accounting, "grok_final_object_missing"
            candidate = text[object_start:]
            try:
                value, consumed = json.JSONDecoder(
                    object_pairs_hook=_reject_duplicate_pairs
                ).raw_decode(candidate)
            except (_DuplicateJsonKey, json.JSONDecodeError):
                return "validation_failure", None, accounting, "grok_final_object_invalid"
            if candidate[consumed:].strip() or not isinstance(value, dict):
                return "validation_failure", None, accounting, "grok_final_object_invalid"
            response_bytes = json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            usage = aggregate.get("usage")
            if isinstance(usage, dict):
                accounting["tokens"] = {"value": usage, "reason": "provider_reported"}
            cost = aggregate.get("total_cost_usd")
            if isinstance(cost, (int, float)) and not isinstance(cost, bool):
                accounting["cost"] = {"value": cost, "reason": "provider_reported"}
        else:
            terminals = []
            ends = []
            text_chunks: list[str] = []
            try:
                for line in response_bytes.splitlines():
                    if not line:
                        continue
                    event = json.loads(line, object_pairs_hook=_reject_duplicate_pairs)
                    if not isinstance(event, dict):
                        return "validation_failure", None, accounting, "provider_event_not_object"
                    if event.get("type") == "assistant":
                        message = event.get("message")
                        if isinstance(message, dict) and message.get("model") not in {None, expected_identity["actual_model"]}:
                            return "validation_failure", None, accounting, "provider_event_model_mismatch"
                    if event.get("type") == "result":
                        terminals.append(event)
                    elif event.get("type") == "text":
                        data = event.get("data")
                        if not isinstance(data, str):
                            return "validation_failure", None, accounting, "grok_text_chunk_invalid"
                        text_chunks.append(data)
                    elif event.get("type") == "tool_call":
                        if event.get("toolName") != "read_file" or event.get("kind") != "read":
                            return "validation_failure", None, accounting, "grok_tool_call_forbidden"
                        raw_input = event.get("rawInput")
                        if not isinstance(raw_input, dict):
                            return "validation_failure", None, accounting, "grok_tool_call_invalid"
                        target = raw_input.get("target_file", raw_input.get("path"))
                        if (
                            not isinstance(target, str)
                            or not target
                            or target.startswith("/")
                            or ".." in Path(target).parts
                        ):
                            return "validation_failure", None, accounting, "grok_tool_path_invalid"
                    elif event.get("type") == "end":
                        ends.append(event)
            except (_DuplicateJsonKey, json.JSONDecodeError, UnicodeDecodeError):
                return "validation_failure", None, accounting, "provider_event_stream_invalid"
            if len(terminals) == 1 and not ends:
                terminal = terminals[0]
                if terminal.get("is_error") is not False or not isinstance(terminal.get("result"), str):
                    return "validation_failure", None, accounting, "provider_terminal_invalid"
                response_bytes = terminal["result"].encode("utf-8")
            elif len(ends) == 1 and not terminals and text_chunks:
                terminal = ends[0]
                if terminal.get("stopReason") != "end_turn":
                    return "validation_failure", None, accounting, "provider_terminal_invalid"
                model_usage = terminal.get("modelUsage")
                if not isinstance(model_usage, dict) or not model_usage or any(
                    not isinstance(model, str)
                    or not model.startswith(expected_identity["actual_model"])
                    for model in model_usage
                ):
                    return "validation_failure", None, accounting, "provider_event_model_mismatch"
                usage = terminal.get("usage")
                if isinstance(usage, dict):
                    accounting["tokens"] = {"value": usage, "reason": "provider_reported"}
                cost = terminal.get("total_cost_usd")
                if isinstance(cost, (int, float)) and not isinstance(cost, bool):
                    accounting["cost"] = {"value": cost, "reason": "provider_reported"}
                response_bytes = "".join(text_chunks).encode("utf-8")
            else:
                return "validation_failure", None, accounting, "provider_terminal_count_invalid"
    value, parse_failure = _strict_json_object(response_bytes)
    extracted_embedded_json = False
    if parse_failure and adapter_id == "grok_cli":
        value, parse_failure = _embedded_json_object(response_bytes)
        extracted_embedded_json = parse_failure is None
    if parse_failure:
        return "validation_failure", None, accounting, parse_failure
    assert value is not None
    schema_failure = _schema_finding(value, response_schema)
    if schema_failure:
        return "validation_failure", None, accounting, f"response_schema_invalid:{schema_failure}"
    returned_identity = value.get("route_identity")
    if returned_identity != expected_identity:
        return "validation_failure", None, accounting, "response_identity_mismatch"
    normalized_response = response_bytes
    if extracted_embedded_json:
        normalized_response = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    return "success", normalized_response, accounting, "completed"


def _atomic_write(path: Path, data: bytes) -> None:
    existing = path.exists() or path.is_symlink()
    if existing:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise DispatchError("unsafe_output", str(path))
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        if temp.exists():
            temp.unlink()


def _descriptor(path: Path, root: Path, data: bytes) -> dict[str, Any]:
    return {"path": path.relative_to(root).as_posix(), "bytes": len(data), "sha256": _sha256(data)}


def _attempt_outcome(
    result: dict[str, Any], normalized: str, accounting: dict[str, Any], detail: str,
) -> dict[str, Any]:
    return {"outcome": normalized, "detail": detail, **accounting}


def _single_attempt_hard_stop(
    receipt: dict[str, Any], outcome: str, detail: str,
) -> dict[str, Any]:
    stopped = copy.deepcopy(receipt)
    stopped.update({
        "status": "hard_stop",
        "selected_route": None,
        "actual_route": None,
        "failover_used": False,
        "stop_reason": f"hard_stop:single_attempt:{outcome}:{detail}",
    })
    if "next_attempt" in stopped:
        stopped["next_attempt"] = None
    return stopped


def _event_bundle(assignment: dict[str, Any], packet: dict[str, Any], receipt: dict[str, Any], root: Path) -> dict[str, Any]:
    timestamp = packet.get("resolution_time", "unknown")
    lane_id = assignment["supervisor_lane_id"]
    semantic_role = assignment["semantic_role"]
    direct_worker_handoff = semantic_role == "worker"
    events: list[dict[str, Any]] = []
    if direct_worker_handoff:
        events.append({
            "schema_version": 1,
            "event_id": f"{assignment['dispatch_id']}:route",
            "timestamp": timestamp,
            "event_type": "route_resolved",
            "lane_id": lane_id,
            "payload": {"route_packet": copy.deepcopy(packet)},
        })
    if direct_worker_handoff and receipt.get("status") == "selected":
        events.append({
            "schema_version": 1,
            "event_id": f"{assignment['dispatch_id']}:result",
            "timestamp": timestamp,
            "event_type": "worker_result",
            "lane_id": lane_id,
            "payload": {
                "status": "ready_for_review",
                "artifact": assignment["_expected"].relative_to(root).as_posix(),
                "changed_files": [assignment["_expected"].relative_to(root).as_posix()],
                "input_access_receipt": {
                    "compatibility_gate_decision": assignment["route_packet"].get("provider_input", {}).get("compatibility_gate", {}).get("decision", "unknown"),
                    "compatibility_gate_reason": assignment["route_packet"].get("provider_input", {}).get("compatibility_gate", {}).get("reason", "unknown"),
                },
            },
        })
    return {
        "schema_version": 1,
        "bundle_type": "SupervisorEventBundle",
        "dispatch_id": assignment["dispatch_id"],
        "semantic_role": semantic_role,
        "handoff_kind": "direct_worker_lifecycle" if direct_worker_handoff else "role_labeled_reference",
        "required_supervisor_adapter_event": {
            "planner": "advisory_reference",
            "architect": "advisory_reference",
            "worker": "worker_result",
            "tester": "independent_test",
            "documenter": "documentation_result",
            "auditor": "audit_result",
        }[semantic_role],
        "binding": {
            "supervisor_assignment_id": assignment["supervisor_assignment_id"],
            "supervisor_lane_id": lane_id,
            "expected_artifact": assignment["_expected"].relative_to(root).as_posix(),
            "expected_artifact_sha256": (
                _sha256(assignment["_expected"].read_bytes())
                if assignment["_expected"].is_file() else "unknown"
            ),
            "route_packet_sha256": _sha256(json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        },
        "applied_to_supervisor": False,
        "applied_to_goalbuddy": False,
        "events": events,
    }


def _plan(assignment: dict[str, Any], packet: dict[str, Any], resolution: dict[str, Any]) -> dict[str, Any]:
    next_attempt = resolution.get("next_attempt")
    adapter = None
    if isinstance(next_attempt, dict):
        adapter = _adapter_id(str(next_attempt.get("route_name", "")), next_attempt.get("identity", {}))
    return {
        "schema_version": 1,
        "dispatch_id": assignment["dispatch_id"],
        "command": "plan",
        "proof_mode": assignment["proof_mode"],
        "semantic_role": assignment["semantic_role"],
        "resolver_role": packet["role"],
        "status": resolution.get("status"),
        "next_attempt": copy.deepcopy(next_attempt),
        "adapter": adapter,
        "selection_executed": False,
        "external_call_performed": False,
        "writes_performed": False,
        "route_resolution": resolution,
    }


def _canonical_digest(value: Any) -> str:
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _validate_single_attempt_binding(
    assignment: dict[str, Any],
    packet: dict[str, Any],
    effective: dict[str, Any],
    binding_value: Any,
    envelope_value: Any,
) -> dict[str, Any]:
    required = {
        "schema_version", "lease_id", "fencing_token", "attempt_id", "task_id",
        "assignment_id", "route_name", "envelope_sha256", "preflight_sha256",
        "authority_sha256", "effective_config_sha256", "evidence_directory",
        "expires_at", "execution_mode", "receiver_qualification_sha256",
    }
    if not isinstance(binding_value, dict) or set(binding_value) != required:
        raise DispatchError("invalid_lease_binding", "fields must match schema exactly")
    binding = copy.deepcopy(binding_value)
    if binding["schema_version"] != 1 or binding["execution_mode"] != "single_resolved_attempt":
        raise DispatchError("invalid_lease_binding", "schema or execution_mode")
    for field in (
        "lease_id", "attempt_id", "task_id", "assignment_id", "route_name",
        "envelope_sha256", "preflight_sha256", "authority_sha256",
        "effective_config_sha256", "evidence_directory", "expires_at",
    ):
        if not isinstance(binding[field], str) or not binding[field]:
            raise DispatchError("invalid_lease_binding", field)
    receiver_qualification = binding["receiver_qualification_sha256"]
    if receiver_qualification is not None and (
        not isinstance(receiver_qualification, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", receiver_qualification) is None
    ):
        raise DispatchError("invalid_lease_binding", "receiver_qualification_sha256")
    if not isinstance(binding["fencing_token"], int) or isinstance(binding["fencing_token"], bool) or binding["fencing_token"] <= 0:
        raise DispatchError("invalid_lease_binding", "fencing_token")
    if not isinstance(envelope_value, dict):
        raise DispatchError("invalid_lease_binding", "envelope must be an object")
    checks = {
        "task_id": packet.get("task_id"),
        "assignment_id": assignment["supervisor_assignment_id"],
        "evidence_directory": assignment["evidence_directory"],
        "envelope_sha256": _canonical_digest(envelope_value),
        "authority_sha256": _canonical_digest(assignment["authority"]),
        "effective_config_sha256": _canonical_digest(effective),
    }
    preflight = packet.get("preflights", {}).get(binding["route_name"])
    if not isinstance(preflight, dict):
        raise DispatchError("lease_binding_stale", "bound route preflight is missing")
    checks["preflight_sha256"] = _canonical_digest(preflight)
    for field, actual in checks.items():
        if binding[field] != actual:
            raise DispatchError("lease_binding_stale", field)
    resolution_time = packet.get("resolution_time")
    if not isinstance(resolution_time, str) or resolution_time > binding["expires_at"]:
        raise DispatchError("lease_binding_expired", str(binding["expires_at"]))
    return binding


def _workspace_snapshot(workspace: Path, root: Path) -> tuple[dict[str, str], str]:
    """Return a symlink-free regular-file snapshot for write reconciliation."""
    files: dict[str, str] = {}
    for current, directories, names in os.walk(workspace, followlinks=False):
        base = Path(current)
        for name in [*directories, *names]:
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise DispatchError("workspace_symlink_escape", path.relative_to(root).as_posix())
        for name in names:
            path = base / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DispatchError("workspace_file_unsafe", path.relative_to(root).as_posix())
            files[path.relative_to(root).as_posix()] = _sha256(path.read_bytes())
    return files, _provider_work.canonical_digest(files)


def _scoped_write_context(
    *, task_envelope: dict[str, Any] | None, identity: dict[str, Any], route_name: str,
    root: Path, binding: dict[str, Any] | None, execution_time: str | None,
    execution_profile: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(task_envelope, dict) or task_envelope.get("mutation_mode") != "scoped_write":
        return None
    provider_work = task_envelope.get("provider_work")
    if not isinstance(provider_work, dict):
        raise DispatchError("provider_work_missing", "scoped_write requires provider_work")
    if execution_time is None:
        raise DispatchError("execution_time_required", "scoped_write requires current execution UTC")
    try:
        if binding is None or _provider_work._time(execution_time, "execution_time") >= _provider_work._time(binding["expires_at"], "binding.expires_at"):
            raise DispatchError("lease_binding_expired", str(binding and binding.get("expires_at")))
    except _provider_work.ProviderWorkError as exc:
        raise DispatchError(exc.code, exc.path) from exc
    try:
        card = _provider_work.validate_capability_card(provider_work.get("capability_card"))
        grant = _provider_work.validate_task_grant(provider_work.get("task_grant"))
        authority = _provider_work.effective_authority(
            card, grant, now=execution_time,
        )
        workspace = _provider_work.validate_workspace(root, grant)
    except _provider_work.ProviderWorkError as exc:
        raise DispatchError(exc.code, exc.path) from exc
    expected = {
        "route_name": route_name, "provider": identity.get("provider"),
        "exact_model": identity.get("model"), "route_id": identity.get("route"),
        "runtime": identity.get("runtime"), "billing_basis": identity.get("billing"),
    }
    for field, value in expected.items():
        if card.get(field) != value:
            raise DispatchError("provider_identity_substitution", field)
    qualification = binding and binding.get("receiver_qualification_sha256")
    if qualification is None or card["qualification_sha256"] != qualification:
        raise DispatchError("capability_not_receiver_bound", "qualification_sha256")
    authority_digest = task_envelope.get("bindings", {}).get("authority_sha256")
    if authority_digest is None or grant["grant_sha256"] != authority_digest:
        raise DispatchError("grant_not_authority_bound", "grant_sha256")
    if binding is None or binding.get("lease_id") != grant["lease_id"] or binding.get("fencing_token") != grant["fencing_token"]:
        raise DispatchError("provider_work_fence_mismatch", "lease_id_or_fencing_token")
    envelope_task = task_envelope.get("task_id")
    if binding.get("task_id") != grant["task_id"] or envelope_task != grant["task_id"]:
        raise DispatchError("provider_work_task_mismatch", "grant_binding_envelope_task_id")
    if grant["command_allowlist"]:
        raise DispatchError(
            "provider_command_policy_unsupported",
            "scoped provider mode permits file edits only; task command execution is not qualified",
        )
    if card["schema_version"] == 2 and (
        execution_profile is None
        or execution_profile.get("mutation_mode") != "scoped_write"
        or execution_profile.get("tool_loop") != "agentic"
        or execution_profile.get("write_transport") in {"none", "qualification_required"}
        or execution_profile.get("harness_sha256") != card.get("adapter_harness_sha256")
    ):
        raise DispatchError("provider_scoped_write_unsupported", "exact harness write transport is not qualified")
    if card["schema_version"] == 1:
        legacy_harness_id = _execution_policy.ROUTE_HARNESS.get(route_name)
        legacy_harness = _execution_policy.ADAPTER_HARNESS_CARDS.get(str(legacy_harness_id))
        if (
            legacy_harness is None
            or legacy_harness.get("tool_loop") != "agentic"
            or legacy_harness.get("write_transport") in {"none", "qualification_required"}
        ):
            raise DispatchError("provider_scoped_write_unsupported", "legacy harness write transport is not qualified")
    commandcode_guard = None
    claude_guard = None
    grok_guard = None
    if str(identity.get("provider")) == "Command Code":
        try:
            commandcode_guard = _execution_policy.validate_commandcode_scoped_write_grant(
                provider_work.get("commandcode_scoped_write_grant"),
                route_name=route_name,
                model=str(identity.get("model", "")),
                task_id=grant["task_id"],
                task_grant_sha256=grant["grant_sha256"],
                attempt_id=str(binding.get("attempt_id", "")),
                worktree_path=grant["workspace_path"],
            )
        except _execution_policy.ExecutionPolicyError as exc:
            raise DispatchError(exc.code, exc.path) from exc
        artifacts = {
            "guard_sha256": workspace / ".commandcode/hooks/scoped-write-guard.py",
            "settings_sha256": workspace / ".commandcode/settings.json",
            "descriptor_sha256": workspace / ".commandcode/scoped-write-descriptor.json",
            "assignment_sha256": workspace / "assignment.md",
            "state_sha256": workspace / ".commandcode/runtime-state.json",
        }
        for digest_field, path in artifacts.items():
            try:
                info = path.lstat()
            except OSError as exc:
                raise DispatchError("commandcode_guard_artifact_missing", digest_field) from exc
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DispatchError("commandcode_guard_artifact_identity_invalid", digest_field)
            if _sha256(path.read_bytes()) != commandcode_guard[digest_field]:
                raise DispatchError("commandcode_guard_artifact_drift", digest_field)
        target = root / commandcode_guard["target_path"]
        try:
            target.relative_to(workspace)
            if target.resolve(strict=True) != target:
                raise DispatchError("commandcode_guard_target_identity_invalid", "target_path")
            target_info = target.lstat()
        except (OSError, ValueError) as exc:
            raise DispatchError("commandcode_guard_target_invalid", "target_path") from exc
        if target.is_symlink() or not stat.S_ISREG(target_info.st_mode) or target_info.st_nlink != 1:
            raise DispatchError("commandcode_guard_target_identity_invalid", "target_path")
        if not _provider_work.path_allowed(commandcode_guard["target_path"], grant["write_scope"]):
            raise DispatchError("commandcode_guard_target_not_granted", "target_path")
        if _sha256(target.read_bytes()) != commandcode_guard["before_sha256"]:
            raise DispatchError("commandcode_guard_before_drift", "before_sha256")
    if str(identity.get("provider")) == "Anthropic":
        try:
            claude_guard = _execution_policy.validate_claude_scoped_write_grant(
                provider_work.get("claude_scoped_write_grant"), route_name=route_name,
                model=str(identity.get("model", "")), task_id=grant["task_id"],
                task_grant_sha256=grant["grant_sha256"],
                attempt_id=str(binding.get("attempt_id", "")),
                worktree_path=grant["workspace_path"],
            )
        except _execution_policy.ExecutionPolicyError as exc:
            raise DispatchError(exc.code, exc.path) from exc
        artifacts = {
            "guard_sha256": workspace / ".claude/hooks/scoped-write-guard.py",
            "settings_sha256": workspace / ".claude/settings.json",
            "mcp_sha256": workspace / ".claude/empty-mcp.json",
            "descriptor_sha256": workspace / ".claude/scoped-write-descriptor.json",
            "assignment_sha256": workspace / "assignment.md",
            "state_sha256": workspace / ".claude/runtime-state.json",
        }
        for digest_field, path in artifacts.items():
            try:
                info = path.lstat()
            except OSError as exc:
                raise DispatchError("claude_guard_artifact_missing", digest_field) from exc
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DispatchError("claude_guard_artifact_identity_invalid", digest_field)
            if _sha256(path.read_bytes()) != claude_guard[digest_field]:
                raise DispatchError("claude_guard_artifact_drift", digest_field)
        target = root / claude_guard["target_path"]
        try:
            target.relative_to(workspace)
            if target.resolve(strict=True) != target:
                raise DispatchError("claude_guard_target_identity_invalid", "target_path")
            target_info = target.lstat()
        except (OSError, ValueError) as exc:
            raise DispatchError("claude_guard_target_invalid", "target_path") from exc
        if target.is_symlink() or not stat.S_ISREG(target_info.st_mode) or target_info.st_nlink != 1:
            raise DispatchError("claude_guard_target_identity_invalid", "target_path")
        if not _provider_work.path_allowed(claude_guard["target_path"], grant["write_scope"]):
            raise DispatchError("claude_guard_target_not_granted", "target_path")
        if _sha256(target.read_bytes()) != claude_guard["before_sha256"]:
            raise DispatchError("claude_guard_before_drift", "before_sha256")
    if route_name == "worker_grok_4_6":
        try:
            grok_guard = _execution_policy.validate_grok_scoped_write_grant(
                provider_work.get("grok_scoped_write_grant"), route_name=route_name,
                model=str(identity.get("model", "")), task_id=grant["task_id"],
                task_grant_sha256=grant["grant_sha256"],
                attempt_id=str(binding.get("attempt_id", "")),
                worktree_path=grant["workspace_path"],
            )
        except _execution_policy.ExecutionPolicyError as exc:
            raise DispatchError(exc.code, exc.path) from exc
        assignment_path = workspace / "assignment.md"
        try:
            assignment_info = assignment_path.lstat()
        except OSError as exc:
            raise DispatchError("grok_assignment_missing", "assignment_sha256") from exc
        if assignment_path.is_symlink() or not stat.S_ISREG(assignment_info.st_mode) or assignment_info.st_nlink != 1:
            raise DispatchError("grok_assignment_identity_invalid", "assignment_sha256")
        if _sha256(assignment_path.read_bytes()) != grok_guard["assignment_sha256"]:
            raise DispatchError("grok_assignment_drift", "assignment_sha256")
        target = root / grok_guard["target_path"]
        try:
            target.relative_to(workspace)
            if target.resolve(strict=True) != target:
                raise DispatchError("grok_guard_target_identity_invalid", "target_path")
            target_info = target.lstat()
        except (OSError, ValueError) as exc:
            raise DispatchError("grok_guard_target_invalid", "target_path") from exc
        if target.is_symlink() or not stat.S_ISREG(target_info.st_mode) or target_info.st_nlink != 1:
            raise DispatchError("grok_guard_target_identity_invalid", "target_path")
        if not _provider_work.path_allowed(grok_guard["target_path"], grant["write_scope"]):
            raise DispatchError("grok_guard_target_not_granted", "target_path")
        if _sha256(target.read_bytes()) != grok_guard["before_sha256"]:
            raise DispatchError("grok_guard_before_drift", "before_sha256")
    before, tree = _workspace_snapshot(workspace, root)
    if tree != grant["base_tree_sha256"] or provider_work.get("observed_base_tree_sha256") != tree:
        raise DispatchError("stale_base_tree", "provider_work.observed_base_tree_sha256")
    return {
        "card": card, "grant": grant, "authority": authority, "workspace": workspace,
        "before": before, "commandcode_guard": commandcode_guard,
        "claude_guard": claude_guard, "grok_guard": grok_guard,
    }


def _reconcile_scoped_write(
    context: dict[str, Any], *, root: Path, accounting: dict[str, Any], elapsed_ms: int,
) -> tuple[dict[str, Any], bytes]:
    after, result_tree = (
        _backend_snapshot(context, root) if "execution_root" in context
        else _workspace_snapshot(context["workspace"], root)
    )
    before = context["before"]
    changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    exact_guard = context.get("commandcode_guard") or context.get("claude_guard") or context.get("grok_guard")
    if exact_guard is not None:
        prefix = "commandcode" if context.get("commandcode_guard") is not None else ("claude" if context.get("claude_guard") is not None else "grok")
        if changed != [exact_guard["target_path"]]:
            raise DispatchError(prefix + "_guard_changed_paths_invalid", ",".join(changed))
        if after.get(exact_guard["target_path"]) != exact_guard["after_sha256"]:
            raise DispatchError(prefix + "_guard_after_bytes_invalid", exact_guard["target_path"])
    outside = [path for path in changed if not _provider_work.path_allowed(path, context["grant"]["write_scope"])]
    if outside:
        raise DispatchError("provider_write_outside_scope", outside[0])
    delta = {path: {"before": before.get(path), "after": after.get(path)} for path in changed}
    inventory = [
        {"path": path, "before_sha256": before.get(path), "after_sha256": after.get(path)}
        for path in changed
    ]
    usage = {
        field: accounting.get(field, {}).get("value", "unknown")
        if isinstance(accounting.get(field), dict) else accounting.get(field, "unknown")
        for field in ("tokens", "cost")
    }
    canonical_diff: dict[str, Any] = delta
    if "execution_root" in context:
        prefix = context["grant"]["workspace_path"].rstrip("/") + "/"
        relative_changed = [path[len(prefix):] for path in changed]
        try:
            changed_bytes = _execution_backend.read_changed_bytes(
                context["workspace"], relative_changed, context["execution_root"]
            )
        except _execution_backend.BackendError as exc:
            raise DispatchError(exc.code, exc.detail) from exc
        canonical_diff = {
            "hash_delta": delta,
            "before_bytes": {path: context["before_bytes"].get(path) for path in relative_changed},
            "after_bytes": changed_bytes,
        }
    receipt = _provider_work.build_change_receipt(
        card_value=context["card"], grant_value=context["grant"],
        now=context["grant"]["issued_at"], result_tree_sha256=result_tree,
        changed_paths=changed, diff_sha256=_provider_work.canonical_digest(canonical_diff),
        commands=[], usage=usage, duration_ms=elapsed_ms,
        change_inventory=inventory, canonical_diff=canonical_diff, validation_results=[],
    )
    data = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    return receipt, data


def _backend_snapshot(context: dict[str, Any], root: Path) -> tuple[dict[str, str], str]:
    try:
        relative, tree = _execution_backend.descriptor_snapshot(
            context["workspace"], context["execution_root"]
        )
    except ValueError as exc:
        raise DispatchError("executor_root_outside_approved", str(exc)) from exc
    except _execution_backend.BackendError as exc:
        raise DispatchError(exc.code, exc.detail) from exc
    prefix = context["grant"]["workspace_path"].rstrip("/")
    return {f"{prefix}/{path}": digest for path, digest in relative.items()}, tree


def _prepare_source_local_backend(
    request: Any, roots: Any, scoped_context: dict[str, Any], binding: dict[str, Any], execution_time: str,
) -> dict[str, Any]:
    if not isinstance(request, dict) or set(request) != {"authority_reference"}:
        raise DispatchError("scoped_write_backend_pending", "exact source-local backend request required")
    if not isinstance(roots, dict) or set(roots) != {"approved_root", "receiver_root", "execution_root", "source_root"}:
        raise DispatchError("executor_root_mapping_missing", "receiver roots are executor-owned")
    try:
        approved = Path(roots["approved_root"])
        if approved.is_symlink(): raise _execution_backend.BackendError("approved_root_symlink")
        approved = approved.resolve(strict=True)
        resolved = {}
        for name in ("receiver_root", "execution_root", "source_root"):
            lexical = Path(roots[name])
            if lexical.is_symlink(): raise _execution_backend.BackendError("executor_root_symlink", name)
            value = lexical.resolve(strict=True); value.relative_to(approved); resolved[name] = value
        receiver_root, execution_root, source_root = resolved["receiver_root"], resolved["execution_root"], resolved["source_root"]
        source = scoped_context["workspace"].resolve(strict=True); source.relative_to(source_root)
        source_relative, source_tree = _execution_backend.descriptor_snapshot(source, source.parent)
        prefix = scoped_context["grant"]["workspace_path"].rstrip("/")
        source_bound = {f"{prefix}/{path}": value for path, value in source_relative.items()}
        if source_bound != scoped_context["before"]:
            raise _execution_backend.BackendError("source_base_identity_mismatch")
        record = _execution_backend.load_source_local_authority(
            receiver_root, request["authority_reference"], scoped_context["card"],
            scoped_context["grant"], now=execution_time,
        )
        if record["qualification_sha256"] != binding["receiver_qualification_sha256"]:
            raise _execution_backend.BackendError("receiver_binding_mismatch")
        attempt_id = binding["attempt_id"]
        _execution_backend.consume_source_local_authority_once(receiver_root, record, attempt_id=attempt_id)
        worktree = _execution_backend.create_source_local_worktree(
            source, execution_root, attempt_id=attempt_id,
            expected_base_sha256=source_tree,
        )
        journal = receiver_root / (attempt_id + ".jsonl")
        _execution_backend.begin_source_local_attempt(journal, receiver_root, record)
        before_relative, base = _execution_backend.descriptor_snapshot(worktree, execution_root)
        before_bytes = _execution_backend.read_changed_bytes(
            worktree, sorted(before_relative), execution_root
        )
    except _execution_backend.BackendError as exc:
        raise DispatchError(exc.code, exc.detail) from exc
    scoped_context.update({
        "source_workspace": source, "workspace": worktree, "execution_root": execution_root,
        "before": {f"{prefix}/{path}": value for path, value in before_relative.items()},
        "copy_base_tree": base,
        "before_bytes": before_bytes,
    })
    return {"receiver_root": receiver_root, "journal": journal, "source_tree": source_tree}


def _finalize_scoped_once(backend: dict[str, Any], scheduler: Any, binding: dict[str, Any],
                          state: str, now: str) -> None:
    if backend.get("terminalized"):
        raise DispatchError("attempt_already_terminal", state)
    errors = []
    try:
        if state == "execution_unknown":
            fd = os.open(backend["journal"], os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            try: _protected_receiver.recover_source_local_consuming(fd)
            finally: os.close(fd)
        else:
            _execution_backend.finish_source_local_attempt(
                backend["journal"], backend["receiver_root"], success=state == "succeeded"
            )
    except Exception as exc: errors.append("backend:" + type(exc).__name__)
    try: scheduler.finish(binding, state, now)
    except Exception as exc: errors.append("scheduler:" + type(exc).__name__)
    if errors:
        backend["reconciliation_needed"] = True
        backend["provider_retry_forbidden"] = True
        raise DispatchError("dual_store_finalization_failed", ",".join(errors))
    backend["terminalized"] = True


def _reconcile_dual_unknown(backend: dict[str, Any], scheduler: Any,
                            binding: dict[str, Any], now: str) -> None:
    errors = []
    try: _execution_backend.reconcile_source_local_unknown(backend["journal"], backend["receiver_root"])
    except Exception as exc: errors.append("backend:" + type(exc).__name__)
    try: scheduler.reconcile_unknown(binding, now)
    except Exception as exc: errors.append("scheduler:" + type(exc).__name__)
    if errors:
        backend["reconciliation_needed"] = True
        backend["provider_retry_forbidden"] = True
        raise DispatchError("dual_store_reconciliation_failed", ",".join(errors))
    backend["terminalized"] = True
    backend["reconciliation_needed"] = False
    backend["provider_retry_forbidden"] = True


def _ensure_dual_unknown(backend: dict[str, Any], scheduler: Any,
                         binding: dict[str, Any], now: str) -> None:
    if backend.get("terminalized"):
        return
    if backend.get("reconciliation_needed"):
        _reconcile_dual_unknown(backend, scheduler, binding, now)
        return
    try:
        _finalize_scoped_once(backend, scheduler, binding, "execution_unknown", now)
    except DispatchError as exc:
        if exc.code != "dual_store_finalization_failed":
            raise
        _reconcile_dual_unknown(backend, scheduler, binding, now)


def _failed_scoped_attempt_state(*, changed: bool) -> str:
    """Classify one failed attempt without changing route capability."""
    return "execution_unknown" if changed else "failed"


def _capture_deadline_seconds(
    *, configured_timeout: float, execution_profile: dict[str, Any] | None,
    task_envelope: dict[str, Any] | None, binding: dict[str, Any] | None,
    started_at: str | None,
) -> float:
    ceilings = [configured_timeout]
    if execution_profile is not None:
        ceilings.append(float(execution_profile["wall_time_seconds"]))
    # Legacy v1 provider work resolves no v2 execution profile. Preserve its
    # configured timeout behavior. Native Codex does not use the external
    # provider authority envelope. Every v2 external profile must also bind the
    # fresh capability, grant, and single-attempt expiry before process start.
    if execution_profile is None or execution_profile.get("adapter_type") == "native_codex":
        return min(ceilings)
    if started_at is None or not isinstance(task_envelope, dict) or not isinstance(binding, dict):
        raise DispatchError(
            "provider_deadline_evidence_missing",
            "started_at, capability card, task grant, and attempt binding are required",
        )
    provider_work = task_envelope.get("provider_work")
    if not isinstance(provider_work, dict):
        raise DispatchError("provider_deadline_evidence_missing", "provider_work")
    try:
        start = _provider_work._time(started_at, "started_at")
        expirations = (
            _provider_work._time(provider_work["capability_card"]["expires_at"], "capability_card.expires_at"),
            _provider_work._time(provider_work["task_grant"]["expires_at"], "task_grant.expires_at"),
            _provider_work._time(binding["expires_at"], "binding.expires_at"),
        )
    except (KeyError, TypeError, _provider_work.ProviderWorkError) as exc:
        raise DispatchError("provider_deadline_evidence_missing", "authority expiry") from exc
    for expiry in expirations:
        ceilings.append((expiry - start).total_seconds() - DEADLINE_GUARD_SECONDS)
    deadline = min(ceilings)
    if deadline <= 0:
        raise DispatchError("provider_deadline_expired", "remaining authority lifetime")
    return deadline


def _capture_absolute_deadline(
    *, configured_timeout: float, execution_profile: dict[str, Any] | None,
    task_envelope: dict[str, Any] | None, binding: dict[str, Any] | None,
    trusted_now: str | None, monotonic_now: float,
) -> float:
    """Bind the last wall-clock authority check to one monotonic deadline."""
    remaining = _capture_deadline_seconds(
        configured_timeout=configured_timeout,
        execution_profile=execution_profile,
        task_envelope=task_envelope,
        binding=binding,
        started_at=trusted_now,
    )
    return monotonic_now + remaining


def _complete_scoped_attempt(*, context: dict[str, Any], backend: dict[str, Any], scheduler: Any,
                             binding: dict[str, Any], clock: Callable[[], str], root: Path,
                             outcome: str, accounting: dict[str, Any], elapsed_ms: int) -> bytes | None:
    completion = clock()
    try:
        _provider_work.effective_authority(context["card"], context["grant"], now=completion)
        if _provider_work._time(completion, "completion_time") >= _provider_work._time(binding["expires_at"], "binding.expires_at"):
            raise DispatchError("lease_binding_expired", binding["expires_at"])
        current, _ = _backend_snapshot(context, root)
        _, source_tree = _execution_backend.descriptor_snapshot(
            context["source_workspace"], context["source_workspace"].parent
        )
        if source_tree != backend["source_tree"]:
            raise DispatchError("source_workspace_mutated", "source tree changed")
        changed = current != context["before"]
        if outcome != "success":
            state = (
                "execution_unknown"
                if outcome == "execution_unknown"
                else _failed_scoped_attempt_state(changed=changed)
            )
            _finalize_scoped_once(backend, scheduler, binding, state, completion)
            if changed and outcome != "execution_unknown":
                raise DispatchError("execution_unknown", "possible mutation; retry forbidden")
            return None
        _, data = _reconcile_scoped_write(context, root=root, accounting=accounting, elapsed_ms=elapsed_ms)
        backend["completion_time"] = completion
        return data
    except Exception:
        if not backend.get("terminalized"):
            _ensure_dual_unknown(backend, scheduler, binding, completion)
        raise


def run_dispatch(
    assignment: dict[str, Any], packet: dict[str, Any], root: Path, test_executables: dict[str, str],
    *, effective: dict[str, Any], allow_provider_call: bool, allow_simulated_process: bool,
    timeout: float, stdout_limit: int, stderr_limit: int,
    single_attempt_binding: dict[str, Any] | None = None,
    task_envelope: dict[str, Any] | None = None,
    execution_time: str | None = None,
    source_local_backend: dict[str, Any] | None = None,
    executor_roots: dict[str, Any] | None = None,
    execution_clock: Callable[[], str] | None = None,
    scheduler_lease_adapter: Any = None,
) -> dict[str, Any]:
    if assignment["proof_mode"] == "simulated" and not allow_simulated_process:
        raise DispatchError("simulated_process_not_authorized", "run requires --allow-simulated-process")
    if assignment["proof_mode"] == "task_scoped_live" and not allow_provider_call:
        raise DispatchError(
            "task_scoped_provider_call_not_authorized",
            "task_scoped_live requires --allow-provider-call",
        )
    bound_route = None
    if single_attempt_binding is not None:
        binding = _validate_single_attempt_binding(
            assignment, packet, effective, single_attempt_binding, task_envelope
        )
        bound_route = binding["route_name"]
        current_resolution = _resolve_pre_dispatch(packet)
        current_attempt = current_resolution.get("next_attempt")
        if (
            current_resolution.get("status") != "dispatch_required"
            or not isinstance(current_attempt, dict)
            or current_attempt.get("route_name") != bound_route
        ):
            raise DispatchError(
                "lease_route_not_currently_eligible",
                f"lease binds {bound_route}; current status is {current_resolution.get('status')}",
            )
    evidence = _evidence_directory(assignment["evidence_directory"], root)
    attempts: list[dict[str, Any]] = []
    external_call_performed = False
    # False is reserved for paths that prove no provider process started. A
    # started task-scoped live process has no authenticated network observer,
    # so its network state is unknown even when output parsing later fails.
    provider_network_performed: bool | str = False
    provider_change_receipt_descriptor: dict[str, Any] | None = None
    final_receipt: dict[str, Any]
    while True:
        final_receipt = _resolve_pre_dispatch(packet)
        if final_receipt.get("status") != "dispatch_required":
            break
        next_attempt = final_receipt.get("next_attempt")
        if not isinstance(next_attempt, dict):
            raise DispatchError("invalid_resolution", "dispatch_required omitted next_attempt")
        route_name = str(next_attempt.get("route_name", ""))
        if bound_route is not None and route_name != bound_route:
            raise DispatchError(
                "lease_route_mismatch", f"resolver selected {route_name}; lease binds {bound_route}"
            )
        identity = next_attempt.get("identity")
        if not isinstance(identity, dict):
            raise DispatchError("invalid_resolution", "next_attempt identity missing")
        expected_response_identity = _expected_response_identity(route_name, identity)
        execution_profile = _resolved_execution_profile(
            task_envelope=task_envelope, route_name=route_name, identity=identity,
        )
        adapter_id = (
            str(execution_profile["adapter_type"])
            if execution_profile is not None else _adapter_id(route_name, identity)
        )
        if adapter_id not in ADAPTERS:
            raise DispatchError("unsupported_adapter_harness", adapter_id)
        explicit_selection = _validate_explicit_execution_selection(
            packet, route_name=route_name, identity=identity,
            adapter_id=adapter_id, task_envelope=task_envelope,
        )
        default_executable, builder = ADAPTERS[adapter_id]
        scoped_requested = (
            execution_profile.get("mutation_mode") == "scoped_write"
            if execution_profile is not None
            else isinstance(task_envelope, dict) and task_envelope.get("mutation_mode") == "scoped_write"
        )
        if assignment["proof_mode"] == "task_scoped_live" and scoped_requested:
            raise DispatchError(
                "task_scoped_live_write_forbidden",
                "task_scoped_live is read-only; scoped writes require a protected receiver",
            )
        start_time = execution_clock() if scoped_requested and execution_clock is not None else execution_time
        scoped_context = _scoped_write_context(
            task_envelope=task_envelope, identity=identity, route_name=route_name,
            root=root, binding=single_attempt_binding,
            execution_time=start_time, execution_profile=execution_profile,
        )
        backend_context = None
        if scoped_context is not None and assignment["proof_mode"] == "simulated":
            if execution_clock is None:
                raise DispatchError("executor_clock_required", "scoped execution cannot use caller time")
            if scheduler_lease_adapter is None:
                raise DispatchError("scheduler_lease_adapter_required", "writer lease must be durably consumed")
            # Use the same executor-owned timestamp for the final pre-spawn
            # authority check and both durable start records.
            scheduler_lease_adapter.start(binding, start_time)
            try:
                backend_context = _prepare_source_local_backend(
                    source_local_backend, executor_roots, scoped_context, binding, start_time
                )
            except Exception:
                # The scheduler start is durable. Root validation may have
                # failed before a receiver journal safely existed. Do not
                # dereference unvalidated backend input during recovery.
                scheduler_lease_adapter.finish(
                    binding, "execution_unknown", execution_clock()
                )
                raise
        if assignment["proof_mode"] == "simulated":
            executable = test_executables.get(adapter_id)
            if executable is None:
                raise DispatchError("simulated_adapter_missing", adapter_id)
        else:
            executable = default_executable

        if assignment["proof_mode"] == "live":
            task_selector = packet.get("task_id")
            if not isinstance(task_selector, str):
                task_selector = assignment.get("supervisor_assignment_id")
            if scoped_context is not None and binding is not None:
                receiver_result = _protected_receiver.request_provider_authority(
                    card=scoped_context["card"], grant=scoped_context["grant"],
                    attempt_id=binding["attempt_id"],
                    expected_generation=1,
                    expected_receiver_uid=None,
                    service_start_id="dispatch-start:" + str(task_selector),
                    service_session_id="dispatch-session:" + str(task_selector),
                )
            else:
                receiver_result = _protected_receiver.request_fixed_receiver(
                    str(task_selector),
                expected_generation=1,
                service_start_id="dispatch-start:" + str(task_selector),
                service_session_id="dispatch-session:" + str(task_selector),
                )
            outcome = {
                "outcome": "authority_violation",
                "detail": "pending_receiver_owned_qualification:os_bound_protected_transaction_required:protected_receiver:"
                + str(receiver_result.get("status", "rejected"))
                + ":" + str(receiver_result.get("reason", "caller_side_provider_execution_forbidden")),
                "tokens": _unknown("provider_not_started"),
                "quota": _unknown("provider_not_started"),
                "cost": _unknown("provider_not_started"),
            }
            packet.setdefault("attempt_results", {}).setdefault(route_name, []).append(outcome)
            final_receipt = _resolve_pre_dispatch(packet)
            break

        authority_ok = all(assignment["authority"].values()) and allow_provider_call
        if assignment["proof_mode"] in {"live", "task_scoped_live"} and not authority_ok:
            outcome = {
                "outcome": "authority_violation",
                "detail": "live mode requires packet authority and --allow-provider-call",
                "tokens": _unknown("provider_tokens_not_reported"),
                "quota": _unknown("provider_quota_not_reported"),
                "cost": _unknown("provider_cost_not_reported"),
            }
            packet.setdefault("attempt_results", {}).setdefault(route_name, []).append(outcome)
            final_receipt = _resolve_pre_dispatch(packet)
            break

        try:
            bound_prompt = _bound_prompt(
                assignment["prompt"], assignment["response_schema"], expected_response_identity
            )
            bound_prompt = _behavior_bound_prompt(bound_prompt, execution_profile)
            builder_kwargs = {
                "scoped_write": scoped_requested,
                "execution_profile": execution_profile,
            }
            if adapter_id == "commandcode" and scoped_requested:
                builder_kwargs["commandcode_guard"] = (
                    scoped_context and scoped_context.get("commandcode_guard")
                )
            if adapter_id == "claude_cli" and scoped_requested:
                builder_kwargs["claude_guard"] = (
                    scoped_context and scoped_context.get("claude_guard")
                )
            if adapter_id == "grok_cli" and scoped_requested:
                builder_kwargs["grok_guard"] = (
                    scoped_context and scoped_context.get("grok_guard")
                )
            argv = builder(executable, bound_prompt, identity, **builder_kwargs)
            _validate_explicit_argv(explicit_selection, argv)
        except Exception:
            if backend_context is not None:
                _ensure_dual_unknown(backend_context, scheduler_lease_adapter, binding,
                                     execution_clock())
            raise
        spawn_failure: OSError | None = None
        structured_observation: dict[str, Any] | None = None
        completed_observation: dict[str, Any] | None = None
        minimax_final_pending: dict[str, Any] | None = None
        try:
            execution_cwd = scoped_context["workspace"] if scoped_context is not None else assignment["_working"]
            # Re-read the executor-owned clock after all preparation. Bind the
            # revalidated wall-clock expiries to an absolute monotonic deadline
            # immediately before process creation.
            deadline_owned_adapter = execution_profile is not None and adapter_id != "native_codex"
            pre_spawn_time = (
                execution_clock()
                if deadline_owned_adapter and execution_clock is not None
                else start_time
            )
            if deadline_owned_adapter and execution_clock is None:
                raise DispatchError(
                    "executor_clock_required",
                    "v2 external pre-spawn authority revalidation requires a trusted clock",
                )
            capture_deadline = _capture_absolute_deadline(
                configured_timeout=timeout, execution_profile=execution_profile,
                task_envelope=task_envelope, binding=single_attempt_binding,
                trusted_now=pre_spawn_time, monotonic_now=time.monotonic(),
            )
            if adapter_id == "minimax_mmx_tool_loop":
                if scoped_context is None:
                    raise DispatchError(
                        "minimax_tool_loop_scoped_context_required",
                        "file tools require a protected scoped worktree",
                    )
                result = _run_minimax_tool_loop(
                    executable=executable, prompt=bound_prompt, identity=identity,
                    execution_profile=execution_profile, workspace=execution_cwd,
                    root=root,
                    read_scope=scoped_context["grant"]["read_scope"],
                    write_scope=scoped_context["grant"]["write_scope"],
                    scope_base=scoped_context["grant"]["workspace_path"],
                    observation_directory=(
                        backend_context["receiver_root"]
                        / (binding["attempt_id"] + ".provider-observations")
                    ),
                    deadline_monotonic=capture_deadline,
                    stdout_limit=stdout_limit, stderr_limit=stderr_limit,
                )
                minimax_final_pending = result.pop("minimax_final_pending", None)
                if minimax_final_pending is not None:
                    provider_network_performed = "unknown"
            else:
                result = _capture(argv, execution_cwd, capture_deadline, stdout_limit, stderr_limit)
            if assignment["proof_mode"] in {"live", "task_scoped_live"}:
                provider_network_performed = "unknown"
        except MiniMaxObservationPending as exc:
            result = exc.result
            structured_observation = exc.observation
            provider_network_performed = "unknown"
        except (FileNotFoundError, PermissionError, OSError) as exc:
            spawn_failure = exc
            result = {
                "returncode": None,
                "stdout": b"",
                "stderr": type(exc).__name__.encode("ascii"),
                "timed_out": False,
                "output_limit_stream": None,
                "elapsed_time_ms": 0,
            }
        except Exception:
            if backend_context is not None:
                _ensure_dual_unknown(backend_context, scheduler_lease_adapter, binding,
                                     execution_clock())
            raise
        if structured_observation is not None:
            normalized_outcome, artifact_bytes = "execution_unknown", None
            accounting = {
                "tokens": _unknown("observation_pending"),
                "quota": _unknown("observation_pending"),
                "cost": _unknown("observation_pending"),
            }
            outcome_detail = "observation_pending:no_retry"
        elif spawn_failure is None:
            try:
                normalized_outcome, artifact_bytes, accounting, outcome_detail = _normalize_output(
                    result, assignment["response_schema"], expected_response_identity,
                    adapter_id=adapter_id,
                )
            except Exception:
                if backend_context is not None:
                    _ensure_dual_unknown(backend_context, scheduler_lease_adapter, binding,
                                         execution_clock())
                raise
        else:
            normalized_outcome, artifact_bytes = "model_start_failure", None
            accounting = {
                "tokens": _unknown("provider_not_started"),
                "quota": _unknown("provider_not_started"),
                "cost": _unknown("provider_not_started"),
            }
            outcome_detail = f"spawn_failure:{type(spawn_failure).__name__}"
        if assignment["proof_mode"] in {"live", "task_scoped_live"} and (
            (normalized_outcome == "success" and artifact_bytes is not None)
            or structured_observation is not None
            or minimax_final_pending is not None
        ):
            # A process return is not sufficient. Exact normalized provider
            # output or a validated MiniMax observation is external-call proof.
            external_call_performed = True
        if minimax_final_pending is not None:
            observation = copy.deepcopy(minimax_final_pending["observation"])
            accepted = normalized_outcome == "success" and artifact_bytes is not None
            event = "final_result_validated" if accepted else "final_result_validation_failed"
            terminal_state = "completed_source_observation" if accepted else "validation_failed"
            payload = {
                "result_sha256": _sha256(result["stdout"]),
                "result_bytes": len(result["stdout"]),
                "normalized_outcome": normalized_outcome,
                "detail": outcome_detail,
                "retry_allowed": False,
                "terminal_state": terminal_state,
            }
            try:
                _append_minimax_observation(
                    minimax_final_pending["journal_path"], event,
                    minimax_final_pending["call_index"], payload,
                )
                observation["terminal_state"] = terminal_state
                observation["validation_outcome"] = normalized_outcome
                completed_observation = observation
            except Exception as exc:
                observation["terminal_state"] = "execution_unknown"
                observation["reason"] = (
                    "final_validation_terminal_append_failed:" + type(exc).__name__
                )
                structured_observation = observation
                completed_observation = None
                normalized_outcome, artifact_bytes = "execution_unknown", None
                accounting = {
                    "tokens": _unknown("observation_pending"),
                    "quota": _unknown("observation_pending"),
                    "cost": _unknown("observation_pending"),
                }
                outcome_detail = "observation_pending:no_retry"
        if scoped_context is not None and backend_context is not None:
            change_data = _complete_scoped_attempt(
                context=scoped_context, backend=backend_context, scheduler=scheduler_lease_adapter,
                binding=binding, clock=execution_clock, root=root, outcome=normalized_outcome,
                accounting=accounting, elapsed_ms=result["elapsed_time_ms"],
            )
            if change_data is not None:
                change_path = evidence / "provider-change-receipt.json"
                try:
                    _atomic_write(change_path, change_data)
                    provider_change_receipt_descriptor = _descriptor(change_path, root, change_data)
                    _finalize_scoped_once(
                        backend_context, scheduler_lease_adapter, binding, "succeeded",
                        backend_context["completion_time"],
                    )
                except Exception:
                    if not backend_context.get("terminalized"):
                        _ensure_dual_unknown(
                            backend_context, scheduler_lease_adapter, binding,
                            execution_clock(),
                        )
                    raise
        attempt_number = len(attempts) + 1
        attempt_dir = evidence / f"attempt-{attempt_number:03d}"
        attempt_dir.mkdir(mode=0o700, exist_ok=False)
        stdout_path = attempt_dir / "stdout.bin"
        stderr_path = attempt_dir / "stderr.bin"
        _atomic_write(stdout_path, result["stdout"])
        _atomic_write(stderr_path, result["stderr"])
        attempt = {
            "attempt_index": attempt_number,
            "route_name": route_name,
            "identity": copy.deepcopy(identity),
            "adapter": adapter_id,
            "cwd": (
                scoped_context["workspace"] if scoped_context is not None else assignment["_working"]
            ).relative_to(root).as_posix(),
            "returncode": result["returncode"],
            "timed_out": result["timed_out"],
            "output_limit_stream": result["output_limit_stream"],
            "elapsed_time_ms": result["elapsed_time_ms"],
            "outcome": normalized_outcome,
            "expected_response_identity": copy.deepcopy(expected_response_identity),
            "response_identity_validated": normalized_outcome == "success",
            "stdout": _descriptor(stdout_path, root, result["stdout"]),
            "stderr": _descriptor(stderr_path, root, result["stderr"]),
            "observation": copy.deepcopy(
                structured_observation
                if structured_observation is not None
                else completed_observation
            ),
            **copy.deepcopy(accounting),
        }
        attempts.append(attempt)
        if spawn_failure is None:
            outcome = _attempt_outcome(result, normalized_outcome, accounting, outcome_detail)
        else:
            outcome = {
                "outcome": "model_start_failure",
                "detail": outcome_detail,
                **accounting,
            }
        packet.setdefault("attempt_results", {}).setdefault(route_name, []).append(outcome)
        if normalized_outcome == "success" and artifact_bytes is not None:
            _atomic_write(assignment["_expected"], artifact_bytes)
        if structured_observation is not None:
            # The legacy resolver outcome vocabulary has no execution-unknown
            # value. Preserve it in the manifest without relabeling it as a
            # provider, network, or authority fact.
            final_receipt = _single_attempt_hard_stop(
                final_receipt, normalized_outcome, outcome_detail
            )
        else:
            final_receipt = _resolve_pre_dispatch(packet)
            if normalized_outcome != "success":
                final_receipt = _single_attempt_hard_stop(
                    final_receipt, normalized_outcome, outcome_detail
                )
        break

    artifact = None
    if final_receipt.get("status") == "selected" and assignment["_expected"].is_file():
        artifact_data = assignment["_expected"].read_bytes()
        artifact = _descriptor(assignment["_expected"], root, artifact_data)
    bundle = _event_bundle(assignment, packet, final_receipt, root)
    bundle_path = evidence / "supervisor-event-bundle.json"
    bundle_data = (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode("utf-8")
    role_priority = effective["headless_dispatch"]["role_priorities"][assignment["semantic_role"]]
    failure = None
    if final_receipt.get("status") != "selected":
        failure = {
            "category": (
                attempts[-1]["outcome"] if attempts else final_receipt.get("status", "unknown")
            ),
            "detail": final_receipt.get("stop_reason", "unknown"),
            "retryable": False,
        }
    manifest = {
        "schema_version": RETURN_MANIFEST_VERSION,
        "manifest_type": "DispatchReturnManifest",
        "execution_owner": "orcastrata_managed",
        "dispatch_id": assignment["dispatch_id"],
        "proof_mode": assignment["proof_mode"],
        "semantic_role": assignment["semantic_role"],
        "resolver_role": packet["role"],
        "role_priority": copy.deepcopy(role_priority),
        "effective_config_sha256": _sha256(json.dumps(effective, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        "status": final_receipt.get("status"),
        "work_status": final_receipt.get("status", "unknown"),
        "accounting_status": "unknown",
        "failure": failure,
        "external_call_performed": external_call_performed,
        "provider_network_performed": provider_network_performed,
        "selected_route": final_receipt.get("selected_route"),
        "artifact": artifact,
        "attempts": attempts,
        "route_resolution": final_receipt,
        "usage": {
            "tokens": attempts[-1]["tokens"] if attempts else _unknown("no_provider_attempt"),
            "quota": attempts[-1]["quota"] if attempts else _unknown("no_provider_attempt"),
            "cost": attempts[-1]["cost"] if attempts else _unknown("no_provider_attempt"),
        },
        "provider_change_receipt": provider_change_receipt_descriptor,
        "acceptance_authority": "Parent Codex",
        "accepted": False,
        "applied_to_goalbuddy": False,
        "applied_to_supervisor": False,
        "supervisor_handoff": _descriptor(bundle_path, root, bundle_data),
    }
    manifest_path = evidence / "dispatch-return-manifest.json"
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    # A project usage ledger is opt-in: no `.orcastrata` marker means this
    # compatibility runtime remains side-effect free. The existing
    # DispatchLedger implementation remains the sole append-only truth.
    try:
        import project_usage
        usage_record = project_usage.append_dispatch_manifest(root, manifest)
        if usage_record:
            usage_status = "appended"
            accounting_status = "accounted"
        elif project_usage.orcastrata_project.find_nearest(root) is not None:
            usage_status = "not_recorded"
            accounting_status = "unaccounted" if external_call_performed else "unknown"
        else:
            usage_status = "not_initialized"
            accounting_status = "unaccounted" if external_call_performed else "unknown"
        manifest["accounting_status"] = accounting_status
        manifest["project_usage"] = {
            "status": usage_status,
            "accounting_status": accounting_status,
            "accounting_scope": project_usage.ACCOUNTING_SCOPE,
            "ledger": ".orcastrata/usage/dispatch.jsonl" if usage_record else None,
        }
    except Exception as exc:  # usage accounting must not hide the dispatch receipt
        accounting_status = "unaccounted" if external_call_performed else "unknown"
        manifest["accounting_status"] = accounting_status
        manifest["project_usage"] = {
            "status": "failed",
            "accounting_status": accounting_status,
            "accounting_scope": "orcastrata_admitted_executions",
            "code": getattr(exc, "code", "usage_ledger_error"),
        }
    manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(bundle_path, bundle_data)
    _atomic_write(manifest_path, manifest_data)
    return manifest


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("plan", "run", "run-one"):
        command = commands.add_parser(name)
        command.add_argument("--assignment", type=Path, required=True)
        command.add_argument("--repo-root", type=Path, required=True)
        command.add_argument("--workspace-config", type=Path)
        command.add_argument("--test-adapter-manifest", type=Path)
        command.add_argument("--allow-provider-call", action="store_true")
        command.add_argument("--allow-simulated-process", action="store_true")
        command.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
        command.add_argument("--stdout-limit-bytes", type=int, default=DEFAULT_STDOUT_LIMIT)
        command.add_argument("--stderr-limit-bytes", type=int, default=DEFAULT_STDERR_LIMIT)
        if name == "run-one":
            command.add_argument("--lease-binding", type=Path, required=True)
            command.add_argument("--task-envelope", type=Path, required=True)
            command.add_argument("--execution-time", required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.timeout_seconds <= 0 or args.stdout_limit_bytes <= 0 or args.stderr_limit_bytes <= 0:
            raise DispatchError("invalid_limits", "timeout and output limits must be positive")
        repo_root = _canonical_repo_root(args.repo_root)
        assignment_value = _read_json_file(args.assignment, repo_root, "assignment")
        assignment = _require_assignment(assignment_value, repo_root)
        effective = _effective_config(repo_root, args.workspace_config)
        single_binding = None
        task_envelope = None
        if args.command == "run-one":
            single_binding = _read_json_file(args.lease_binding, repo_root, "lease_binding")
            task_envelope = _read_json_file(args.task_envelope, repo_root, "task_envelope")
        packet = _prepare_packet(
            assignment, effective, scheduler_mode=args.command == "run-one",
            scheduler_route=(single_binding or {}).get("route_name"),
        )
        test_executables = _test_executables(args.test_adapter_manifest, repo_root, assignment["proof_mode"])
        resolution = _resolve_pre_dispatch(packet)
        if args.command == "plan":
            result = _plan(assignment, packet, resolution)
        else:
            result = run_dispatch(
                assignment, packet, repo_root, test_executables,
                effective=effective,
                allow_provider_call=args.allow_provider_call,
                allow_simulated_process=args.allow_simulated_process,
                timeout=args.timeout_seconds,
                stdout_limit=args.stdout_limit_bytes,
                stderr_limit=args.stderr_limit_bytes,
                single_attempt_binding=single_binding,
                task_envelope=task_envelope,
                execution_time=getattr(args, "execution_time", None),
                execution_clock=_utc_now if args.command == "run-one" else None,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.command == "plan" or result.get("status") == "selected":
            return EXIT_OK
        return EXIT_FAILED
    except (DispatchError, _config.ConfigError, _route.ResolutionError, OSError) as exc:
        code = getattr(exc, "code", "dispatch_error")
        detail = getattr(exc, "detail", str(exc))
        status = "profile_incompatible" if code == "profile_incompatible" else "invalid_input"
        print(json.dumps({"status": status, "code": code, "detail": detail}, sort_keys=True), file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
