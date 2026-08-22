#!/usr/bin/env python3
"""Emit deterministic read-only Codexmax status and redacted support bundles."""

from __future__ import annotations

import argparse
import errno
import functools
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable

sys.dont_write_bytecode = True


SCHEMA_VERSION = 1
PROTOCOL = "codexmax_status"
PLUGIN_NAME = "codexmax-orchestrator"
MAX_INPUT_BYTES = 4 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")
HEX_PREFIX_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
JOURNEY_KEYS = {
    "schema_version", "journey_id", "identity_inputs", "goalbuddy",
    "source_hashes", "envelope", "state", "generated_artifacts",
    "transition_history",
}
JOURNEY_SOURCE_HASH_KEYS = {
    "request", "repository_rules", "goal", "board_state",
    "accepted_artifacts", "effective_config",
}
JOURNEY_STATE_KEYS = {"phase", "classification", "status"}
JOURNEY_GOALBUDDY_KEYS = {
    "goal_path", "state_path", "goal_id", "active_checkpoint_id",
    "board_truth_owner", "read_only",
}
RECOVERY_STATUSES = {
    "reconciliation_required", "active", "paused", "revision_required", "stopped",
}
RUNTIME_STATUSES = {
    "assigned", "pending", "in_progress", "ready_for_review",
    "candidate_complete", "needs_revision", "needs_reassignment",
    "needs_parent_repair", "waiting_external", "stopped", "paused",
}
EXCLUDED_SUPPORT_CONTENT = [
    "authentication headers",
    "command output",
    "cookies",
    "credential material",
    "environment variables",
    "raw exceptions",
    "raw local paths",
    "raw transcripts",
    "secret keys and tokens",
    "thread and process identifiers",
]
ROUTE_AVAILABILITY_VALUES = {"available", "unavailable", "unknown", "unverified"}
CONFIG_BILLING_BASIS_VALUES = {
    "local_compute", "native_included", "subscription", "unknown"
}
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
ADAPTER_REGEX_CACHE_MAXSIZE = 512


class StatusError(ValueError):
    """Stable fail-closed status error without sensitive detail."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class DuplicateKeyError(StatusError):
    pass


class ReadArtifact:
    def __init__(self, path: Path, raw: bytes, status: os.stat_result):
        self.path = path
        self.raw = raw
        self.status = status
        self.sha256 = hashlib.sha256(raw).hexdigest()

    @property
    def identity(self) -> tuple[int, int]:
        return self.status.st_dev, self.status.st_ino


class _AdapterRegexProxy:
    """Adapter-local compiled-pattern cache without changing global ``re``."""

    def __init__(self, backend: Any, *, maxsize: int = ADAPTER_REGEX_CACHE_MAXSIZE):
        self._backend = backend
        self._cached_compile = functools.lru_cache(maxsize=maxsize)(backend.compile)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._backend, name)

    def cache_info(self) -> Any:
        return self._cached_compile.cache_info()

    def cache_clear(self) -> None:
        self._cached_compile.cache_clear()

    def compile(self, pattern: Any, flags: int = 0) -> Any:
        return self._cached_compile(pattern, flags)

    def fullmatch(self, pattern: Any, string: str, flags: int = 0) -> Any:
        return self.compile(pattern, flags).fullmatch(string)

    def match(self, pattern: Any, string: str, flags: int = 0) -> Any:
        return self.compile(pattern, flags).match(string)

    def search(self, pattern: Any, string: str, flags: int = 0) -> Any:
        return self.compile(pattern, flags).search(string)

    def findall(self, pattern: Any, string: str, flags: int = 0) -> Any:
        return self.compile(pattern, flags).findall(string)

    def finditer(self, pattern: Any, string: str, flags: int = 0) -> Any:
        return self.compile(pattern, flags).finditer(string)

    def split(
        self, pattern: Any, string: str, maxsplit: int = 0, flags: int = 0
    ) -> Any:
        return self.compile(pattern, flags).split(string, maxsplit)

    def sub(
        self, pattern: Any, repl: Any, string: str, count: int = 0, flags: int = 0
    ) -> str:
        return self.compile(pattern, flags).sub(repl, string, count)


_ADAPTER_REGEX_PROXY = _AdapterRegexProxy(re)


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _reject_json_constant(_: str) -> object:
    raise StatusError("json_non_finite_number")


def _valid_positive_spend(value: object) -> bool:
    if type(value) is int:
        return 0 < value <= MAX_SAFE_JSON_INTEGER
    if type(value) is float:
        return math.isfinite(value) and value > 0
    return False


def _valid_positive_token_limit(value: object) -> bool:
    return type(value) is int and 0 < value <= MAX_SAFE_JSON_INTEGER


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("json_duplicate_key")
        result[key] = value
    return result


def _safe_root(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise StatusError("repository_root_invalid")
    text = str(value)
    path = Path(text)
    if not text or "\x00" in text or not path.is_absolute() or ".." in path.parts:
        raise StatusError("repository_root_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        resolved = path.resolve(strict=True)
        named = path.lstat()
    except OSError as error:
        raise StatusError("repository_root_unreadable") from error
    if (
        resolved != lexical
        or stat.S_ISLNK(named.st_mode)
        or not stat.S_ISDIR(named.st_mode)
    ):
        raise StatusError("repository_root_alias_forbidden")
    return lexical


def _lexical_path(value: object, root: Path, *, must_exist: bool) -> Path:
    if not isinstance(value, (str, Path)):
        raise StatusError("input_path_invalid")
    text = str(value)
    path = Path(text)
    if not text or "\x00" in text or not path.is_absolute() or ".." in path.parts:
        raise StatusError("input_path_invalid")
    lexical = Path(os.path.abspath(path))
    try:
        lexical.relative_to(root)
    except ValueError as error:
        raise StatusError("input_path_outside_repository") from error
    try:
        resolved = path.resolve(strict=must_exist)
    except FileNotFoundError as error:
        raise StatusError("input_path_missing") from error
    except OSError as error:
        raise StatusError("input_path_unreadable") from error
    if resolved != lexical:
        raise StatusError("input_path_alias_forbidden")
    return lexical


def _assert_open_identity(path: Path, descriptor: int) -> os.stat_result:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise StatusError("input_path_identity_changed") from error
    if (
        resolved != path
        or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_nlink != 1
        or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise StatusError("input_path_identity_changed")
    return opened


def _read_bound(value: object, root: Path) -> ReadArtifact:
    path = _lexical_path(value, root, must_exist=True)
    try:
        named = path.lstat()
    except OSError as error:
        raise StatusError("input_path_unreadable") from error
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
        raise StatusError("input_path_alias_forbidden")
    if named.st_nlink != 1:
        raise StatusError("input_path_hardlink_forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno in {errno.ENOENT, errno.ELOOP}:
            raise StatusError("input_path_identity_changed") from error
        raise StatusError("input_path_unreadable") from error
    try:
        before = _assert_open_identity(path, descriptor)
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = _assert_open_identity(path, descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev, after.st_ino, after.st_size
        ):
            raise StatusError("input_path_identity_changed")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_INPUT_BYTES:
        raise StatusError("input_oversize")
    return ReadArtifact(path, raw, after)


def _json_object(artifact: ReadArtifact, label: str) -> dict[str, Any]:
    try:
        text = artifact.raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StatusError(f"{label}_utf8_invalid") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_json_constant,
        )
    except DuplicateKeyError as error:
        raise StatusError(f"{label}_duplicate_key") from error
    except json.JSONDecodeError as error:
        raise StatusError(f"{label}_json_invalid") from error
    if not isinstance(value, dict):
        raise StatusError(f"{label}_shape_invalid")
    return value


def _relative_locator(path: Path, root: Path) -> str:
    return "<repository>/" + path.relative_to(root).as_posix()


def _source_manifest(root: Path) -> tuple[dict[str, Any], ReadArtifact]:
    artifact = _read_bound(
        root / "plugins" / PLUGIN_NAME / ".codex-plugin" / "plugin.json", root
    )
    value = _json_object(artifact, "source_manifest")
    version = value.get("version")
    if value.get("name") != PLUGIN_NAME or not isinstance(version, str):
        raise StatusError("source_manifest_identity_invalid")
    if VERSION_RE.fullmatch(version) is None:
        raise StatusError("source_manifest_version_invalid")
    return {"version": version}, artifact


def _load_board_adapter() -> Any:
    path = Path(__file__).with_name("workgraph_goalbuddy_adapter.py")
    spec = importlib.util.spec_from_file_location("codexmax_status_board_adapter", path)
    if spec is None or spec.loader is None:
        raise StatusError("board_parser_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise StatusError("board_parser_unavailable") from error
    module.re = _ADAPTER_REGEX_PROXY
    return module


def _goal_slug(text: str) -> str:
    lines = text.splitlines()
    in_goal = False
    matches: list[str] = []
    for line in lines:
        if line == "goal:":
            in_goal = True
            continue
        if in_goal and line and not line.startswith(" "):
            break
        if in_goal:
            match = re.fullmatch(r"  slug:\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:#.*)?", line)
            if match:
                matches.append(match.group(1))
    if len(matches) != 1:
        raise StatusError("board_goal_identity_invalid")
    return matches[0]


def _board_projection(artifact: ReadArtifact) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        text = artifact.raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StatusError("board_utf8_invalid") from error
    adapter = _load_board_adapter()
    try:
        parsed = adapter._parse_board(artifact.raw)
        if parsed["version"] not in {adapter.CURRENT_BOARD_VERSION, adapter.NEXT_BOARD_VERSION}:
            raise StatusError("board_schema_unsupported")
        adapter._validate_canonical_board(parsed)
    except StatusError:
        raise
    except Exception as error:
        raise StatusError("board_state_invalid") from error
    goal_slug = _goal_slug(text)
    active_task = parsed["active_task"]
    return (
        {
            "active_task": active_task if active_task is not None else "none",
            "goal_status": parsed["goal_status"],
            "schema_version": parsed["version"],
            "status": "valid",
        },
        {"active_task": active_task, "goal_slug": goal_slug},
    )


def _inventory_projection(
    artifact: ReadArtifact, manifest: ReadArtifact, source_version: str
) -> tuple[dict[str, Any], str | None]:
    value = _json_object(artifact, "release_inventory")
    if value.get("schema_version") != 1:
        return {
            "installed_version": "unknown", "relation": "unknown", "status": "invalid"
        }, "release_inventory_invalid"
    drift = value.get("source_cache_drift")
    candidates = value.get("candidate_manifest")
    if not isinstance(drift, dict) or not isinstance(candidates, list):
        return {
            "installed_version": "unknown", "relation": "unknown", "status": "invalid"
        }, "release_inventory_invalid"
    cache_identity = drift.get("cache_identity")
    parity = drift.get("parity")
    counts = drift.get("counts")
    if (
        not isinstance(cache_identity, str)
        or VERSION_RE.fullmatch(cache_identity) is None
        or type(parity) is not bool
        or not isinstance(counts, dict)
        or set(counts) != {"cache_only", "different", "equal", "source_only"}
        or any(type(counts[key]) is not int or counts[key] < 0 for key in counts)
    ):
        return {
            "installed_version": "unknown", "relation": "unknown", "status": "invalid"
        }, "release_inventory_invalid"
    manifest_rows = [
        row for row in candidates
        if isinstance(row, dict)
        and row.get("path") == f"plugins/{PLUGIN_NAME}/.codex-plugin/plugin.json"
    ]
    if (
        len(manifest_rows) != 1
        or not isinstance(manifest_rows[0].get("sha256"), str)
        or SHA256_RE.fullmatch(manifest_rows[0]["sha256"]) is None
        or manifest_rows[0]["sha256"] != manifest.sha256
    ):
        if source_version != cache_identity:
            last_relation = "version_mismatch"
        elif not parity:
            last_relation = "same_version_content_drift"
        else:
            last_relation = "reported_parity_stale"
        return {
            "drift_counts": {key: counts[key] for key in sorted(counts)},
            "installed_version": "unknown",
            "last_reported_installed_version": cache_identity,
            "last_reported_relation": last_relation,
            "relation": "unknown",
            "status": "stale",
        }, "release_inventory_stale"
    if source_version != cache_identity:
        relation = "version_mismatch"
        failure = "source_installed_version_mismatch"
    elif not parity:
        relation = "same_version_content_drift"
        failure = "source_cache_content_drift"
    else:
        relation = "reported_parity"
        failure = None
    return {
        "drift_counts": {key: counts[key] for key in sorted(counts)},
        "installed_version": cache_identity,
        "relation": relation,
        "status": "valid",
    }, failure


def _optional_artifact(
    value: object | None,
    root: Path,
    label: str,
    parser: Callable[[ReadArtifact], tuple[dict[str, Any], dict[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any], ReadArtifact | None]:
    if value is None:
        return {"status": "not_run"}, {}, None
    try:
        artifact = _read_bound(value, root)
    except StatusError as error:
        status = {
            "input_path_missing": "missing",
            "input_path_unreadable": "unreadable",
        }.get(error.code, "invalid")
        return {"status": status}, {"failure": f"{label}_{status}"}, None
    try:
        projection, context = parser(artifact)
    except StatusError:
        return {"status": "invalid"}, {"failure": f"{label}_invalid"}, artifact
    return projection, context, artifact


def _journey_projection_factory(
    board_sha256: str, goal_slug: str, active_task: str | None
) -> Callable[[ReadArtifact], tuple[dict[str, Any], dict[str, Any]]]:
    def parse(artifact: ReadArtifact) -> tuple[dict[str, Any], dict[str, Any]]:
        value = _json_object(artifact, "journey_state")
        if set(value) != JOURNEY_KEYS or value.get("schema_version") != 1:
            raise StatusError("journey_state_shape_invalid")
        state = value.get("state")
        goalbuddy = value.get("goalbuddy")
        hashes = value.get("source_hashes")
        if (
            not isinstance(state, dict) or set(state) != JOURNEY_STATE_KEYS
            or state.get("status") not in {"active", "stopped"}
            or not isinstance(goalbuddy, dict) or set(goalbuddy) != JOURNEY_GOALBUDDY_KEYS
            or goalbuddy.get("board_truth_owner") != "GoalBuddy"
            or goalbuddy.get("read_only") is not True
            or not isinstance(hashes, dict) or set(hashes) != JOURNEY_SOURCE_HASH_KEYS
            or not all(HEX_PREFIX_RE.fullmatch(str(value)) for value in hashes.values())
        ):
            raise StatusError("journey_state_shape_invalid")
        context = {
            "checkpoint_id": goalbuddy.get("active_checkpoint_id"),
            "goal_slug": goalbuddy.get("goal_id"),
            "lifecycle": state["status"],
        }
        stale = (
            hashes["board_state"] != "sha256:" + board_sha256
            or context["goal_slug"] != goal_slug
            or (active_task is not None and context["checkpoint_id"] != active_task)
        )
        if stale:
            return {"lifecycle": state["status"], "status": "stale"}, {
                **context, "failure": "journey_state_stale"
            }
        return {"lifecycle": state["status"], "status": "valid"}, context

    return parse


def _recovery_projection_factory(
    board_sha256: str, goal_slug: str, active_task: str | None
) -> Callable[[ReadArtifact], tuple[dict[str, Any], dict[str, Any]]]:
    def parse(artifact: ReadArtifact) -> tuple[dict[str, Any], dict[str, Any]]:
        value = _json_object(artifact, "recovery_state")
        if value.get("schema_version") != 1:
            raise StatusError("recovery_state_version_invalid")
        boundary_fields = (
            "board_mutated", "transcript_used", "native_side_proof", "acceptance_claimed"
        )
        if any(value.get(field) is not False for field in boundary_fields):
            raise StatusError("recovery_state_boundary_invalid")
        board_hash = value.get("board_sha256")
        if not isinstance(board_hash, str) or SHA256_RE.fullmatch(board_hash) is None:
            raise StatusError("recovery_state_board_hash_invalid")
        state_goal = value.get("goal_slug")
        checkpoint = value.get("checkpoint_id")
        if not isinstance(state_goal, str) or not isinstance(checkpoint, str):
            raise StatusError("recovery_state_identity_invalid")
        context = {"checkpoint_id": checkpoint, "goal_slug": state_goal}
        if "pending_loop_transition" in value:
            lifecycle = value.get("status")
            if lifecycle not in RECOVERY_STATUSES:
                raise StatusError("recovery_state_status_invalid")
            pending = value.get("pending_loop_transition")
            if pending is not None and not isinstance(pending, dict):
                raise StatusError("recovery_state_interruption_invalid")
            interrupted = pending is not None
            context["lifecycle"] = lifecycle
            context["interrupted"] = interrupted
            kind = "supervisor_recovery"
        else:
            lifecycle = value.get("status")
            if lifecycle not in RUNTIME_STATUSES:
                raise StatusError("runtime_state_status_invalid")
            context["lifecycle"] = lifecycle
            context["interrupted"] = False
            kind = "supervisor_runtime"
            if value.get("board_truth_owner") != "GoalBuddy":
                raise StatusError("runtime_state_board_owner_invalid")
            if value.get("parent_acceptance_authority") != "Parent Codex":
                raise StatusError("runtime_state_authority_invalid")
        stale = (
            board_hash != board_sha256
            or state_goal != goal_slug
            or (active_task is not None and checkpoint != active_task)
        )
        if stale:
            return {"kind": kind, "lifecycle": lifecycle, "status": "stale"}, {
                **context, "failure": "recovery_state_stale"
            }
        if context["interrupted"]:
            context["failure"] = "recovery_transition_interrupted"
        return {
            "interruption": "detected" if context["interrupted"] else "none",
            "kind": kind,
            "lifecycle": lifecycle,
            "status": "valid",
        }, context

    return parse


def _config_projection(artifact: ReadArtifact) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _json_object(artifact, "config_receipt")
    config = value.get("effective_config")
    if value.get("schema_version") != 2 or value.get("execution_started") is not False:
        raise StatusError("config_receipt_identity_invalid")
    if not isinstance(config, dict):
        raise StatusError("config_receipt_shape_invalid")
    budgets = config.get("budgets")
    routing = config.get("routing")
    registry = config.get("route_registry")
    if (
        not isinstance(budgets, dict)
        or not isinstance(routing, dict)
        or not isinstance(registry, dict)
        or type(routing.get("silent_metered_fallback")) is not bool
        or not isinstance(registry.get("routes"), dict)
    ):
        raise StatusError("config_receipt_shape_invalid")
    spend = budgets.get("hard_spend_limit_usd")
    token_limit = budgets.get("token_limit")
    if spend is not None and not _valid_positive_spend(spend):
        raise StatusError("config_receipt_spend_limit_invalid")
    if token_limit is not None and not _valid_positive_token_limit(token_limit):
        raise StatusError("config_receipt_token_limit_invalid")

    availability: dict[str, int] = {}
    billing: dict[str, int] = {}
    enabled = 0
    unsupported_enum = False
    for route in registry["routes"].values():
        if not isinstance(route, dict) or type(route.get("enabled")) is not bool:
            raise StatusError("config_receipt_route_invalid")
        route_availability = route.get("availability", "unknown")
        billing_basis = route.get("billing_basis", "unknown")
        if (
            not isinstance(route_availability, str)
            or route_availability not in ROUTE_AVAILABILITY_VALUES
        ):
            route_availability = "unknown"
            unsupported_enum = True
        if (
            not isinstance(billing_basis, str)
            or billing_basis not in CONFIG_BILLING_BASIS_VALUES
        ):
            billing_basis = "unknown"
            unsupported_enum = True
        availability[route_availability] = availability.get(route_availability, 0) + 1
        billing[billing_basis] = billing.get(billing_basis, 0) + 1
        enabled += int(route["enabled"])
    projection = {
        "availability_counts": dict(sorted(availability.items())),
        "billing_basis_counts": dict(sorted(billing.items())),
        "enabled_routes": enabled,
        "execution_started": False,
        "hard_spend_limit_usd": spend,
        "silent_metered_fallback": routing["silent_metered_fallback"],
        "status": "invalid" if unsupported_enum else "valid",
        "token_limit": token_limit,
        "total_routes": len(registry["routes"]),
    }
    context: dict[str, Any] = {}
    if unsupported_enum:
        context["failure"] = "config_receipt_enum_invalid"
    if projection["silent_metered_fallback"]:
        context["failure"] = "config_silent_metered_fallback"
    return projection, context


def _install_projection(artifact: ReadArtifact) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _json_object(artifact, "install_receipt")
    proof_levels = value.get("proof_levels")
    checks = value.get("checks")
    if (
        value.get("plugin") != "codexmax-orchestrator@codexmax-orchestrator"
        or value.get("status") not in {"ok", "failed"}
        or not isinstance(proof_levels, dict)
        or not isinstance(checks, dict)
    ):
        raise StatusError("install_receipt_shape_invalid")
    proof_names = (
        "install_state", "manual_installed_cache_invocation", "automatic_skill_loader"
    )
    projected_levels: dict[str, str] = {}
    for name in proof_names:
        row = proof_levels.get(name)
        if not isinstance(row, dict) or row.get("status") not in {
            "present", "not_run", "invalid", "missing", "error"
        }:
            raise StatusError("install_receipt_proof_invalid")
        projected_levels[name] = row["status"]
    installed_version = "unknown"
    fresh = checks.get("fresh_invocation")
    if projected_levels["manual_installed_cache_invocation"] == "present":
        if not isinstance(fresh, dict):
            raise StatusError("install_receipt_proof_invalid")
        details = fresh.get("details")
        evidence = details.get("final_evidence") if isinstance(details, dict) else None
        candidate = evidence.get("installed_version") if isinstance(evidence, dict) else None
        if not isinstance(candidate, str) or VERSION_RE.fullmatch(candidate) is None:
            raise StatusError("install_receipt_version_invalid")
        installed_version = candidate
    projection = {
        "installed_version": installed_version,
        "probe_status": value["status"],
        "proof_levels": projected_levels,
        "status": "valid",
    }
    context: dict[str, Any] = {}
    if value["status"] == "failed" or any(
        status in {"invalid", "missing", "error"} for status in projected_levels.values()
    ):
        context["failure"] = "install_probe_failed"
    return projection, context


def _input_row(kind: str, artifact: ReadArtifact, root: Path, status: str = "valid") -> dict[str, Any]:
    return {
        "kind": kind,
        "locator": _relative_locator(artifact.path, root),
        "sha256": artifact.sha256,
        "status": status,
    }


def _capabilities() -> dict[str, Any]:
    return {
        "acceptance_authority": False,
        "board_mutated": False,
        "canonical_board_owner": "GoalBuddy",
        "credential_access": False,
        "native_desktop_supervision": "experimental/unavailable",
        "network": False,
        "provider_dispatch": False,
        "subprocess": False,
        "telemetry_collection": False,
        "transcript_access": False,
    }


def _telemetry() -> dict[str, Any]:
    return {
        "billing_basis": "unknown",
        "collection": "disabled",
        "marginal_cost": "unknown",
        "quota": "unknown",
        "retention": "not_collected",
        "tokens": "unknown",
    }


def _identity() -> dict[str, str]:
    return {
        "model": "unknown",
        "provider": "unknown",
        "route_id": "unknown",
        "runtime": "unknown",
    }


def _recovery_action(failure: str, board: dict[str, Any]) -> str:
    if failure in {
        "journey_state_stale", "recovery_state_stale", "state_projection_conflict",
    }:
        return "do_not_resume; inspect current durable state and repair only under existing authority"
    if failure in {
        "journey_state_invalid", "journey_state_unreadable", "journey_state_missing",
        "recovery_state_invalid", "recovery_state_unreadable", "recovery_state_missing",
        "config_receipt_invalid", "config_receipt_unreadable", "config_receipt_missing",
        "install_receipt_invalid", "install_receipt_unreadable", "install_receipt_missing",
    }:
        return "do_not_resume; replace no state and inspect the owning recovery contract"
    if failure in {
        "config_silent_metered_fallback", "install_probe_failed",
        "installed_version_evidence_conflict", "config_receipt_enum_invalid",
    }:
        return "do not dispatch or claim installation; inspect the owning config or install receipt"
    if failure == "recovery_transition_interrupted":
        return "run the owning recovery snapshot or reconciliation path before resume"
    if board["goal_status"] == "active":
        return "continue the active task from GoalBuddy board truth under existing authority"
    if board["goal_status"] == "blocked":
        return "inspect the blocked receipt and named external condition; do not infer resume"
    return "no recovery action; the canonical GoalBuddy goal is complete"


def build_status(
    *,
    repository_root: object,
    board_path: object,
    inventory_path: object | None = None,
    journey_state_path: object | None = None,
    recovery_state_path: object | None = None,
    config_receipt_path: object | None = None,
    install_receipt_path: object | None = None,
) -> tuple[dict[str, Any], int]:
    root = _safe_root(repository_root)
    manifest_data, manifest = _source_manifest(root)
    board_artifact = _read_bound(board_path, root)
    if manifest.identity == board_artifact.identity:
        raise StatusError("input_path_duplicate")
    board, board_context = _board_projection(board_artifact)

    inputs = [
        _input_row("goalbuddy_board", board_artifact, root),
        _input_row("source_manifest", manifest, root),
    ]
    used_identities = {manifest.identity, board_artifact.identity}

    versions: dict[str, Any] = {
        "evidence_status": "not_run",
        "installed": "unknown",
        "relation": "unknown",
        "source": manifest_data["version"],
    }
    version_failures: list[str] = []
    if inventory_path is not None:
        try:
            inventory_artifact = _read_bound(inventory_path, root)
            if inventory_artifact.identity in used_identities:
                raise StatusError("input_path_duplicate")
            used_identities.add(inventory_artifact.identity)
            inventory, inventory_failure = _inventory_projection(
                inventory_artifact, manifest, manifest_data["version"]
            )
            versions = {
                "evidence_status": inventory["status"],
                "installed": inventory["installed_version"],
                "relation": inventory["relation"],
                "source": manifest_data["version"],
            }
            if "drift_counts" in inventory:
                versions["drift_counts"] = inventory["drift_counts"]
            if "last_reported_installed_version" in inventory:
                versions["last_reported_installed"] = inventory[
                    "last_reported_installed_version"
                ]
                versions["last_reported_relation"] = inventory["last_reported_relation"]
            inputs.append(_input_row("release_inventory", inventory_artifact, root, inventory["status"]))
            if inventory_failure:
                version_failures.append(inventory_failure)
        except StatusError as error:
            if error.code == "input_path_missing":
                versions["evidence_status"] = "missing"
                version_failures.append("release_inventory_missing")
            elif error.code == "input_path_unreadable":
                versions["evidence_status"] = "unreadable"
                version_failures.append("release_inventory_unreadable")
            else:
                versions["evidence_status"] = "invalid"
                version_failures.append("release_inventory_invalid")

    journey, journey_context, journey_artifact = _optional_artifact(
        journey_state_path,
        root,
        "journey_state",
        _journey_projection_factory(
            board_artifact.sha256, board_context["goal_slug"], board_context["active_task"]
        ),
    )
    recovery, recovery_context, recovery_artifact = _optional_artifact(
        recovery_state_path,
        root,
        "recovery_state",
        _recovery_projection_factory(
            board_artifact.sha256, board_context["goal_slug"], board_context["active_task"]
        ),
    )
    config, config_context, config_artifact = _optional_artifact(
        config_receipt_path, root, "config_receipt", _config_projection
    )
    install, install_context, install_artifact = _optional_artifact(
        install_receipt_path, root, "install_receipt", _install_projection
    )
    state_failures: list[str] = []
    for kind, projection, artifact in (
        ("journey_state", journey, journey_artifact),
        ("recovery_state", recovery, recovery_artifact),
        ("config_receipt", config, config_artifact),
        ("install_receipt", install, install_artifact),
    ):
        if artifact is not None:
            if artifact.identity in used_identities:
                state_failures.append("input_path_duplicate")
                projection["status"] = "invalid"
            else:
                used_identities.add(artifact.identity)
                inputs.append(_input_row(kind, artifact, root, projection["status"]))
    if journey_context.get("failure"):
        state_failures.append(journey_context["failure"])
    if recovery_context.get("failure"):
        state_failures.append(recovery_context["failure"])
    if config_context.get("failure"):
        state_failures.append(config_context["failure"])
    if install_context.get("failure"):
        state_failures.append(install_context["failure"])
    if (
        journey.get("status") == "valid"
        and recovery.get("status") == "valid"
        and (
            journey_context.get("goal_slug") != recovery_context.get("goal_slug")
            or journey_context.get("checkpoint_id") != recovery_context.get("checkpoint_id")
        )
    ):
        state_failures.append("state_projection_conflict")

    failures = state_failures + version_failures
    if install.get("installed_version") not in {None, "unknown"}:
        installed = install["installed_version"]
        if versions["installed"] not in {"unknown", installed}:
            failures.insert(0, "installed_version_evidence_conflict")
        versions["installed"] = installed
        versions["evidence_status"] = "install_receipt_valid"
        versions["relation"] = (
            "match" if installed == versions["source"] else "version_mismatch"
        )
        if installed != versions["source"]:
            failures.insert(0, "source_installed_version_mismatch")
    failure = failures[0] if failures else "none"
    invalid_states = {"invalid", "unreadable", "missing"}
    fatal = (
        journey.get("status") in invalid_states
        or recovery.get("status") in invalid_states
        or config.get("status") in invalid_states
        or install.get("status") in invalid_states
        or "input_path_duplicate" in failures
    )
    attention = failure != "none"
    operational_status = "needs_parent_repair" if fatal else (
        "in_progress" if board["goal_status"] == "active" else
        "waiting_external" if board["goal_status"] == "blocked" else
        "candidate_complete"
    )
    next_action = (
        "inspect_fail_closed_input" if fatal
        else "continue_active_task" if board["goal_status"] == "active"
        else "inspect_blocked_receipt" if board["goal_status"] == "blocked"
        else "none"
    )
    decision_needed = (
        "Parent or operator must authorize any state repair before resume"
        if fatal or failure in {"journey_state_stale", "recovery_state_stale", "state_projection_conflict"}
        else "none"
    )
    result = {
        "board": board,
        "board_mutated": False,
        "capabilities": _capabilities(),
        "decision_needed": decision_needed,
        "effective_config": config,
        "identity": _identity(),
        "inputs": sorted(inputs, key=lambda row: row["kind"]),
        "journey_state": journey,
        "local_install": install,
        "material_failure": failure,
        "next_ready": {
            "action": next_action,
            "basis": "GoalBuddy canonical board; no authority granted",
            "task_id": board["active_task"],
        },
        "operation": "status",
        "operational_status": operational_status,
        "outcome": (
            "Codexmax read-only status completed with attention required"
            if attention else "Codexmax read-only status completed"
        ),
        "proof_boundary": {
            "limitation": (
                "repository-local inspection only; installation, cache parity, host behavior, "
                "publication, native Desktop supervision, and Parent acceptance are not implied"
            ),
            "value": "local",
        },
        "protocol": PROTOCOL,
        "recovery": {
            "action": _recovery_action(failure, board),
            "transcript_reconstruction": False,
        },
        "recovery_state": recovery,
        "redaction": {
            "mode": "default",
            "paths": "repository_relative_allowlist_or_omitted",
            "raw_input_projection": False,
        },
        "schema_version": SCHEMA_VERSION,
        "status": "error" if fatal else ("attention_required" if attention else "ok"),
        "telemetry": _telemetry(),
        "versions": versions,
    }
    return result, 2 if fatal else (1 if attention else 0)


def build_support_bundle(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "bundle": {
            "automatic_deletion": False,
            "automatic_upload": False,
            "contents": [
                {
                    "provenance": [row["kind"] for row in status["inputs"]],
                    "redaction": "allowlisted_normalized_projection",
                    "section": "status",
                },
                {
                    "provenance": ["codexmax_status_contract"],
                    "redaction": "fixed_capability_projection",
                    "section": "capabilities_and_privacy",
                },
            ],
            "exclusions": EXCLUDED_SUPPORT_CONTENT,
            "format": "codexmax_support_bundle_v1",
            "retention": (
                "operator_managed; delete after the support case closes; "
                "Codexmax performs no automatic retention or upload"
            ),
            "telemetry": "disabled",
        },
        "capabilities": _capabilities(),
        "operation": "support-bundle",
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "status": status,
    }


def _write_export(output: object, root: Path, payload: bytes) -> tuple[str, str]:
    path = _lexical_path(output, root, must_exist=False)
    if path.exists() or path.is_symlink():
        raise StatusError("export_destination_exists")
    try:
        parent = path.parent.resolve(strict=True)
        named_parent = path.parent.lstat()
    except OSError as error:
        raise StatusError("export_parent_unavailable") from error
    if (
        parent != path.parent
        or stat.S_ISLNK(named_parent.st_mode)
        or not stat.S_ISDIR(named_parent.st_mode)
    ):
        raise StatusError("export_parent_alias_forbidden")
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise StatusError("export_destination_exists") from error
    except OSError as error:
        raise StatusError("export_open_failed") from error
    opened_identity: os.stat_result | None = None
    try:
        opened_identity = os.fstat(descriptor)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise StatusError("export_write_failed")
            offset += written
        os.fsync(descriptor)
        opened = _assert_open_identity(path, descriptor)
        if stat.S_IMODE(opened.st_mode) != 0o600:
            raise StatusError("export_mode_invalid")
    except Exception:
        try:
            named = path.lstat()
            if (
                opened_identity is not None
                and stat.S_ISREG(named.st_mode)
                and (named.st_dev, named.st_ino)
                == (opened_identity.st_dev, opened_identity.st_ino)
            ):
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    return _relative_locator(path, root), hashlib.sha256(payload).hexdigest()


def failure_receipt(operation: str, code: str) -> dict[str, Any]:
    return {
        "board_mutated": False,
        "capabilities": _capabilities(),
        "decision_needed": "inspect fail-closed inputs before retry",
        "identity": _identity(),
        "material_failure": code,
        "operation": operation,
        "operational_status": "needs_parent_repair",
        "outcome": "Codexmax read-only status failed closed",
        "protocol": PROTOCOL,
        "recovery": {
            "action": "do not resume or export until the named input class is repaired",
            "transcript_reconstruction": False,
        },
        "schema_version": SCHEMA_VERSION,
        "status": "error",
        "telemetry": _telemetry(),
    }


def _argument_parser_kwargs() -> dict[str, Any]:
    return {"color": False} if sys.version_info >= (3, 14) else {}


def build_parser() -> argparse.ArgumentParser:
    parser_options = _argument_parser_kwargs()
    parser = argparse.ArgumentParser(description=__doc__, **parser_options)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for name in ("status", "support-bundle"):
        child = subparsers.add_parser(name, **parser_options)
        child.add_argument("--repository-root", required=True)
        child.add_argument("--board", required=True)
        child.add_argument("--inventory")
        child.add_argument("--journey-state")
        child.add_argument("--recovery-state")
        child.add_argument("--config-receipt")
        child.add_argument("--install-receipt")
        if name == "support-bundle":
            child.add_argument(
                "--output",
                help="Explicit repository-contained export path; absent means stdout only",
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result, exit_code = build_status(
            repository_root=args.repository_root,
            board_path=args.board,
            inventory_path=args.inventory,
            journey_state_path=args.journey_state,
            recovery_state_path=args.recovery_state,
            config_receipt_path=args.config_receipt,
            install_receipt_path=args.install_receipt,
        )
        output: object = result
        if args.operation == "support-bundle":
            output = build_support_bundle(result)
            if args.output:
                root = _safe_root(args.repository_root)
                payload = (canonical_json(output) + "\n").encode("utf-8")
                locator, digest = _write_export(args.output, root, payload)
                output = {
                    "board_mutated": False,
                    "mode": "0600",
                    "operation": "support-bundle-export",
                    "output": locator,
                    "protocol": PROTOCOL,
                    "schema_version": SCHEMA_VERSION,
                    "sha256": digest,
                    "status": "written",
                }
        print(canonical_json(output))
        return exit_code
    except StatusError as error:
        print(canonical_json(failure_receipt(args.operation, error.code)))
        return 2
    except Exception:
        print(canonical_json(failure_receipt(args.operation, "internal_projection_error")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
