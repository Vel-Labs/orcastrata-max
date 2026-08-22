#!/usr/bin/env python3
"""Validate least-authority grants and review receipts for provider writers.

This module does not start a provider, create a worktree, or accept a change.
It binds a qualified route capability ceiling to one task grant and verifies
the resulting repository delta for Parent review.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping


SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}$")
ACCESS = {"none", "read_only", "scoped_write"}
WORKSPACE_MODES = {"isolated_worktree", "exclusive_shared_tree"}
NETWORK_POLICIES = {"none", "provider_only"}
BILLING_POLICIES = {"subscription_only", "native_included_only", "local_compute_only"}


class ProviderWorkError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProviderWorkError("shape_invalid", path)
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ProviderWorkError("text_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    text = _text(value, path)
    if IDENTIFIER.fullmatch(text) is None:
        raise ProviderWorkError("identifier_invalid", path)
    return text


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ProviderWorkError("digest_invalid", path)
    return value


def _scope(value: Any, path: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ProviderWorkError("scope_invalid", path)
    result: list[str] = []
    for index, raw in enumerate(value):
        text = _text(raw, f"{path}[{index}]")
        item = Path(text)
        if item.is_absolute() or ".." in item.parts or "\\" in text or text.startswith("./"):
            raise ProviderWorkError("scope_escape", f"{path}[{index}]")
        if any(marker in text for marker in ("?", "[", "]")) or (
            "*" in text and (not text.endswith("/**") or "*" in text[:-3])
        ):
            raise ProviderWorkError("scope_pattern_unsafe", f"{path}[{index}]")
        result.append(item.as_posix())
    if len(result) != len(set(result)):
        raise ProviderWorkError("scope_duplicate", path)
    return sorted(result)


def _path_prefix(pattern: str) -> str:
    parts: list[str] = []
    for part in pattern.split("/"):
        if any(mark in part for mark in ("*", "?", "[", "]")):
            break
        parts.append(part)
    return "/".join(parts) or "."


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProviderWorkError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProviderWorkError("timestamp_invalid", path) from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ProviderWorkError("timestamp_invalid", path)
    return parsed.astimezone(timezone.utc)


def path_allowed(path: str, scope: list[str]) -> bool:
    candidate = Path(path).as_posix()
    for pattern in scope:
        prefix = _path_prefix(pattern)
        if pattern.endswith("/**") and (candidate == prefix or candidate.startswith(prefix + "/")):
            return True
        if not pattern.endswith("/**") and candidate == pattern:
            return True
    return False


CAPABILITY_FIELDS = {
    "schema_version", "route_name", "provider", "exact_model", "route_id", "runtime",
    "billing_basis", "source_access", "local_file_access", "commands_executable",
    "write_access", "network_access", "qualified_at", "expires_at", "qualification_sha256",
    "host_identity_sha256", "capability_sha256",
}

CAPABILITY_V2_FIELDS = CAPABILITY_FIELDS | {
    "adapter_harness_sha256", "tool_loop", "browser_access", "web_search_access",
    "connector_access", "reasoning_controls", "verbosity_controls", "context_controls",
    "max_turns", "max_wall_time_seconds", "tool_capabilities", "legacy_capability_sha256",
}


def validate_capability_card(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderWorkError("shape_invalid", "capability_card")
    version = value.get("schema_version")
    fields = CAPABILITY_FIELDS if version == 1 else CAPABILITY_V2_FIELDS
    card = copy.deepcopy(_closed(value, fields, "capability_card"))
    if version not in {1, 2}:
        raise ProviderWorkError("schema_unsupported", "capability_card.schema_version")
    _identifier(card["route_name"], "capability_card.route_name")
    for field in ("provider", "exact_model", "route_id", "runtime"):
        _text(card[field], f"capability_card.{field}")
    if card["billing_basis"] not in {"subscription", "native_included", "local_compute"}:
        raise ProviderWorkError("billing_basis_invalid", "capability_card.billing_basis")
    if card["source_access"] not in {"local_filesystem", "embedded_only", "none"}:
        raise ProviderWorkError("capability_invalid", "capability_card.source_access")
    if card["local_file_access"] not in {"none", "read_only", "read_write"}:
        raise ProviderWorkError("capability_invalid", "capability_card.local_file_access")
    if card["commands_executable"] not in {"yes", "no"} or card["write_access"] not in {"scoped", "none"}:
        raise ProviderWorkError("capability_invalid", "capability_card")
    if card["network_access"] not in {"provider_only", "none"}:
        raise ProviderWorkError("capability_invalid", "capability_card.network_access")
    if version == 2:
        _sha(card["adapter_harness_sha256"], "capability_card.adapter_harness_sha256")
        if card["legacy_capability_sha256"] is not None:
            _sha(card["legacy_capability_sha256"], "capability_card.legacy_capability_sha256")
        if card["tool_loop"] not in {"agentic", "message_only", "unknown"}:
            raise ProviderWorkError("capability_invalid", "capability_card.tool_loop")
        for field in ("browser_access", "web_search_access", "connector_access"):
            if card[field] not in {"yes", "no"}:
                raise ProviderWorkError("capability_invalid", f"capability_card.{field}")
        allowed_controls = {
            "reasoning_controls": {"minimal", "low", "medium", "high", "xhigh"},
            "verbosity_controls": {"terse", "concise", "standard", "detailed", "exhaustive"},
            "context_controls": {"embedded", "paths_only", "targeted", "full_allowed"},
        }
        for field, allowed in allowed_controls.items():
            values = card[field]
            if not isinstance(values, list) or not values or len(values) != len(set(values)) or any(item not in allowed for item in values):
                raise ProviderWorkError("capability_invalid", f"capability_card.{field}")
        for field in ("max_turns", "max_wall_time_seconds"):
            if type(card[field]) is not int or card[field] < 1:
                raise ProviderWorkError("capability_invalid", f"capability_card.{field}")
        if not isinstance(card["tool_capabilities"], list) or any(not isinstance(item, str) or not item for item in card["tool_capabilities"]):
            raise ProviderWorkError("capability_invalid", "capability_card.tool_capabilities")
        if len(card["tool_capabilities"]) != len(set(card["tool_capabilities"])):
            raise ProviderWorkError("capability_invalid", "capability_card.tool_capabilities")
    for field in ("qualification_sha256", "host_identity_sha256"):
        _sha(card[field], f"capability_card.{field}")
    supplied = _sha(card["capability_sha256"], "capability_card.capability_sha256")
    payload = copy.deepcopy(card)
    del payload["capability_sha256"]
    if canonical_digest(payload) != supplied:
        raise ProviderWorkError("capability_digest_mismatch", "capability_card.capability_sha256")
    if _time(card["qualified_at"], "capability_card.qualified_at") >= _time(card["expires_at"], "capability_card.expires_at"):
        raise ProviderWorkError("capability_lease_invalid", "capability_card.expires_at")
    return card


def migrate_capability_card_v1(value: Any, *, adapter_harness_sha256: str) -> dict[str, Any]:
    """Convert a validated v1 card without increasing its evidence ceiling."""
    card = validate_capability_card(value)
    if card["schema_version"] == 2:
        if card["adapter_harness_sha256"] != adapter_harness_sha256:
            raise ProviderWorkError("harness_binding_mismatch", "capability_card.adapter_harness_sha256")
        return card
    _sha(adapter_harness_sha256, "adapter_harness_sha256")
    legacy_digest = card["capability_sha256"]
    migrated = {
        **{key: copy.deepcopy(item) for key, item in card.items() if key != "capability_sha256"},
        "schema_version": 2,
        "adapter_harness_sha256": adapter_harness_sha256,
        "tool_loop": "unknown",
        "browser_access": "no", "web_search_access": "no", "connector_access": "no",
        "reasoning_controls": ["minimal"], "verbosity_controls": ["standard"],
        "context_controls": ["embedded"], "max_turns": 1, "max_wall_time_seconds": 1,
        "tool_capabilities": [],
        "legacy_capability_sha256": legacy_digest,
    }
    migrated["capability_sha256"] = canonical_digest(migrated)
    return validate_capability_card(migrated)


GRANT_FIELDS = {
    "schema_version", "grant_id", "task_id", "route_name", "access_mode", "read_scope",
    "write_scope", "command_allowlist", "network_policy", "billing_policy", "workspace_mode",
    "workspace_path", "base_tree_sha256", "lease_id", "fencing_token", "issued_at",
    "expires_at", "exclusive_writer", "grant_sha256",
}

GRANT_V2_FIELDS = GRANT_FIELDS | {
    "task_intent_sha256", "tool_allowlist", "browser_policy", "web_search_policy",
    "connector_policy", "validation_commands", "no_retry", "execution_unknown_policy",
    "legacy_grant_sha256",
}


def validate_task_grant(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderWorkError("shape_invalid", "task_grant")
    version = value.get("schema_version")
    fields = GRANT_FIELDS if version == 1 else GRANT_V2_FIELDS
    grant = copy.deepcopy(_closed(value, fields, "task_grant"))
    if version not in {1, 2}:
        raise ProviderWorkError("schema_unsupported", "task_grant.schema_version")
    for field in ("grant_id", "task_id", "route_name", "lease_id"):
        _identifier(grant[field], f"task_grant.{field}")
    if grant["access_mode"] not in ACCESS:
        raise ProviderWorkError("access_mode_invalid", "task_grant.access_mode")
    grant["read_scope"] = _scope(grant["read_scope"], "task_grant.read_scope", allow_empty=grant["access_mode"] == "none")
    grant["write_scope"] = _scope(grant["write_scope"], "task_grant.write_scope", allow_empty=grant["access_mode"] != "scoped_write")
    if grant["access_mode"] != "scoped_write" and grant["write_scope"]:
        raise ProviderWorkError("write_scope_without_authority", "task_grant.write_scope")
    if not isinstance(grant["command_allowlist"], list):
        raise ProviderWorkError("command_allowlist_invalid", "task_grant.command_allowlist")
    for index, argv in enumerate(grant["command_allowlist"]):
        if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or not arg for arg in argv):
            raise ProviderWorkError("command_allowlist_invalid", f"task_grant.command_allowlist[{index}]")
    if version == 2:
        _sha(grant["task_intent_sha256"], "task_grant.task_intent_sha256")
        if grant["legacy_grant_sha256"] is not None:
            _sha(grant["legacy_grant_sha256"], "task_grant.legacy_grant_sha256")
        if not isinstance(grant["tool_allowlist"], list) or any(not isinstance(item, str) or not item for item in grant["tool_allowlist"]):
            raise ProviderWorkError("tool_allowlist_invalid", "task_grant.tool_allowlist")
        if len(grant["tool_allowlist"]) != len(set(grant["tool_allowlist"])):
            raise ProviderWorkError("tool_allowlist_invalid", "task_grant.tool_allowlist")
        for field in ("browser_policy", "web_search_policy", "connector_policy"):
            if grant[field] not in {"none", "allowed"}:
                raise ProviderWorkError("policy_invalid", f"task_grant.{field}")
        if not isinstance(grant["validation_commands"], list):
            raise ProviderWorkError("validation_commands_invalid", "task_grant.validation_commands")
        for index, argv in enumerate(grant["validation_commands"]):
            if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) or not arg for arg in argv):
                raise ProviderWorkError("validation_commands_invalid", f"task_grant.validation_commands[{index}]")
            if argv not in grant["command_allowlist"]:
                raise ProviderWorkError("validation_command_not_allowed", f"task_grant.validation_commands[{index}]")
        if grant["no_retry"] is not True or grant["execution_unknown_policy"] != "preserve_and_stop":
            raise ProviderWorkError("retry_policy_unsafe", "task_grant")
    if grant["network_policy"] not in NETWORK_POLICIES or grant["billing_policy"] not in BILLING_POLICIES:
        raise ProviderWorkError("policy_invalid", "task_grant")
    if grant["workspace_mode"] not in WORKSPACE_MODES:
        raise ProviderWorkError("workspace_mode_invalid", "task_grant.workspace_mode")
    _scope([grant["workspace_path"]], "task_grant.workspace_path", allow_empty=False)
    _sha(grant["base_tree_sha256"], "task_grant.base_tree_sha256")
    if type(grant["fencing_token"]) is not int or grant["fencing_token"] < 1:
        raise ProviderWorkError("fencing_token_invalid", "task_grant.fencing_token")
    if type(grant["exclusive_writer"]) is not bool:
        raise ProviderWorkError("exclusive_writer_invalid", "task_grant.exclusive_writer")
    if grant["workspace_mode"] == "exclusive_shared_tree" and not grant["exclusive_writer"]:
        raise ProviderWorkError("shared_tree_requires_exclusive_writer", "task_grant.exclusive_writer")
    if grant["workspace_mode"] == "isolated_worktree" and grant["exclusive_writer"]:
        raise ProviderWorkError("isolated_worktree_exclusive_mismatch", "task_grant.exclusive_writer")
    if _time(grant["issued_at"], "task_grant.issued_at") >= _time(grant["expires_at"], "task_grant.expires_at"):
        raise ProviderWorkError("grant_lease_invalid", "task_grant.expires_at")
    supplied = _sha(grant["grant_sha256"], "task_grant.grant_sha256")
    payload = copy.deepcopy(grant)
    del payload["grant_sha256"]
    if canonical_digest(payload) != supplied:
        raise ProviderWorkError("grant_digest_mismatch", "task_grant.grant_sha256")
    return grant


def migrate_task_grant_v1(value: Any, *, task_intent_sha256: str) -> dict[str, Any]:
    """Convert a validated v1 grant with all new authority disabled."""
    grant = validate_task_grant(value)
    if grant["schema_version"] == 2:
        if grant["task_intent_sha256"] != task_intent_sha256:
            raise ProviderWorkError("task_intent_binding_mismatch", "task_grant.task_intent_sha256")
        return grant
    _sha(task_intent_sha256, "task_intent_sha256")
    legacy_digest = grant["grant_sha256"]
    migrated = {
        **{key: copy.deepcopy(item) for key, item in grant.items() if key != "grant_sha256"},
        "schema_version": 2, "task_intent_sha256": task_intent_sha256,
        "tool_allowlist": [], "browser_policy": "none", "web_search_policy": "none",
        "connector_policy": "none", "validation_commands": [], "no_retry": True,
        "execution_unknown_policy": "preserve_and_stop", "legacy_grant_sha256": legacy_digest,
    }
    migrated["grant_sha256"] = canonical_digest(migrated)
    return validate_task_grant(migrated)


def effective_authority(card_value: Any, grant_value: Any, *, now: str) -> dict[str, Any]:
    card = validate_capability_card(card_value)
    grant = validate_task_grant(grant_value)
    if card["route_name"] != grant["route_name"]:
        raise ProviderWorkError("route_substitution", "task_grant.route_name")
    instant = _time(now, "now")
    if instant >= _time(card["expires_at"], "capability_card.expires_at"):
        raise ProviderWorkError("qualification_expired", "capability_card.expires_at")
    if instant >= _time(grant["expires_at"], "task_grant.expires_at"):
        raise ProviderWorkError("grant_expired", "task_grant.expires_at")
    if grant["billing_policy"] == "subscription_only" and card["billing_basis"] != "subscription":
        raise ProviderWorkError("billing_fallback_forbidden", "capability_card.billing_basis")
    if grant["network_policy"] == "provider_only" and card["network_access"] != "provider_only":
        raise ProviderWorkError("network_capability_missing", "capability_card.network_access")
    if grant["access_mode"] in {"read_only", "scoped_write"} and card["local_file_access"] not in {"read_only", "read_write"}:
        raise ProviderWorkError("local_read_capability_missing", "capability_card.local_file_access")
    if grant["command_allowlist"] and card["commands_executable"] != "yes":
        raise ProviderWorkError("command_capability_missing", "capability_card.commands_executable")
    if grant["access_mode"] == "scoped_write" and not (
        card["write_access"] == "scoped" and card["local_file_access"] == "read_write"
    ):
        raise ProviderWorkError("write_capability_missing", "capability_card.write_access")
    result = {
        "schema_version": 2 if card["schema_version"] == 2 or grant["schema_version"] == 2 else 1,
        "task_id": grant["task_id"],
        "route_name": grant["route_name"],
        "access_mode": grant["access_mode"],
        "read_scope": grant["read_scope"],
        "write_scope": grant["write_scope"],
        "command_allowlist": grant["command_allowlist"],
        "network_policy": grant["network_policy"],
        "billing_policy": grant["billing_policy"],
        "workspace_mode": grant["workspace_mode"],
        "workspace_path": grant["workspace_path"],
        "base_tree_sha256": grant["base_tree_sha256"],
        "lease_id": grant["lease_id"],
        "fencing_token": grant["fencing_token"],
        "capability_sha256": card["capability_sha256"],
        "grant_sha256": grant["grant_sha256"],
        "authority_sha256": canonical_digest({"card": card["capability_sha256"], "grant": grant["grant_sha256"]}),
    }
    if grant["schema_version"] == 2:
        result.update({
            "task_intent_sha256": grant["task_intent_sha256"],
            "tool_allowlist": copy.deepcopy(grant["tool_allowlist"]),
            "browser_policy": grant["browser_policy"],
            "web_search_policy": grant["web_search_policy"],
            "connector_policy": grant["connector_policy"],
            "validation_commands": copy.deepcopy(grant["validation_commands"]),
            "no_retry": grant["no_retry"],
            "execution_unknown_policy": grant["execution_unknown_policy"],
        })
    return result


def validate_workspace(repo_root: Path, grant_value: Any) -> Path:
    grant = validate_task_grant(grant_value)
    root = repo_root.resolve(strict=True)
    lexical = root / grant["workspace_path"]
    try:
        info = lexical.lstat()
        workspace = lexical.resolve(strict=True)
        workspace.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ProviderWorkError("workspace_unavailable", "task_grant.workspace_path") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProviderWorkError("workspace_unsafe", "task_grant.workspace_path")
    if workspace == root:
        raise ProviderWorkError("isolated_worktree_required", "task_grant.workspace_path")
    return workspace


def build_change_receipt(
    *, card_value: Any, grant_value: Any, now: str, result_tree_sha256: str,
    changed_paths: list[str], diff_sha256: str, commands: list[Mapping[str, Any]],
    usage: Mapping[str, Any], duration_ms: int,
    change_inventory: list[Mapping[str, Any]] | None = None,
    canonical_diff: Mapping[str, Any] | None = None,
    validation_results: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    card = validate_capability_card(card_value)
    grant = validate_task_grant(grant_value)
    authority = effective_authority(card, grant, now=now)
    _sha(result_tree_sha256, "result_tree_sha256")
    _sha(diff_sha256, "diff_sha256")
    paths = _scope(changed_paths, "changed_paths", allow_empty=True)
    if any(not path_allowed(path, grant["write_scope"]) for path in paths):
        raise ProviderWorkError("changed_path_outside_scope", "changed_paths")
    if result_tree_sha256 == grant["base_tree_sha256"] and paths:
        raise ProviderWorkError("result_tree_unchanged", "result_tree_sha256")
    if type(duration_ms) is not int or duration_ms < 0:
        raise ProviderWorkError("duration_invalid", "duration_ms")
    observations = {}
    for field in ("tokens", "cost"):
        value = usage.get(field, "unknown")
        observations[field] = value if value != "unknown" else "unknown"
    receipt = {
        "schema_version": 1,
        "artifact_type": "ProviderChangeReceipt",
        "task_id": grant["task_id"],
        "route_identity": {
            "route_name": card["route_name"], "provider": card["provider"],
            "exact_model": card["exact_model"], "route_id": card["route_id"],
            "runtime": card["runtime"], "billing_basis": card["billing_basis"],
        },
        "capability_sha256": card["capability_sha256"],
        "grant_sha256": grant["grant_sha256"],
        "effective_authority_sha256": authority["authority_sha256"],
        "base_tree_sha256": grant["base_tree_sha256"],
        "result_tree_sha256": result_tree_sha256,
        "changed_paths": paths,
        "diff_sha256": diff_sha256,
        "change_inventory": [copy.deepcopy(dict(row)) for row in (change_inventory or [])],
        "canonical_diff": copy.deepcopy(dict(canonical_diff or {})),
        "commands": [copy.deepcopy(dict(row)) for row in commands],
        "validation_results": [copy.deepcopy(dict(row)) for row in (validation_results or [])],
        "usage": observations,
        "duration_ms": duration_ms,
        "accepted_by_parent": False,
        "unknowns": sorted(field for field, value in observations.items() if value == "unknown"),
    }
    return {**receipt, "receipt_sha256": canonical_digest(receipt)}


__all__ = [
    "ProviderWorkError", "build_change_receipt", "canonical_digest", "effective_authority",
    "migrate_capability_card_v1", "migrate_task_grant_v1", "path_allowed",
    "validate_capability_card", "validate_task_grant", "validate_workspace",
]
