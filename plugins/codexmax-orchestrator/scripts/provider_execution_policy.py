#!/usr/bin/env python3
"""Resolve provider task intent into a bounded, adapter-specific run policy.

This module is deterministic. It does not inspect credentials, call providers,
start processes, or grant repository authority.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


SCHEMA_VERSION = 1
TASK_SIZES = ("micro", "small", "medium", "large")
COMPLEXITIES = ("routine", "moderate", "complex", "expert")
CONSEQUENCES = ("low", "medium", "high", "critical")
REASONING_LEVELS = ("minimal", "low", "medium", "high", "xhigh")
VERBOSITY_LEVELS = ("terse", "concise", "standard", "detailed", "exhaustive")
CONTEXT_STRATEGIES = ("embedded", "paths_only", "targeted", "full_allowed")
MUTATION_MODES = ("read_only", "artifact_only", "scoped_write")
SOURCE_DELIVERY = ("embedded_fact_pack", "paths", "local_filesystem")
UNKNOWN = "unknown"

COMMANDCODE_ROUTE_BINDINGS = MappingProxyType({
    "worker_deepseek_v4_flash": MappingProxyType({
        "route_id": "commandcode-subscription-deepseek-v4-flash",
        "model": "deepseek/deepseek-v4-flash",
        "runtime": "Command Code", "billing_basis": "subscription",
    }),
    "worker_deepseek_v4_pro": MappingProxyType({
        "route_id": "commandcode-subscription-deepseek-v4-pro",
        "model": "deepseek/deepseek-v4-pro",
        "runtime": "Command Code", "billing_basis": "subscription",
    }),
})
COMMANDCODE_FILE_TOOLS = ("read_file", "write_file", "edit_file")
COMMANDCODE_GUARD_FIELDS = {
    "schema_version", "artifact_type", "task_id", "route_name", "route_id", "model",
    "task_grant_sha256", "attempt_id", "session_id", "worktree_path", "target_path",
    "mutation_tool", "before_sha256", "after_sha256", "content_sha256",
    "guard_sha256", "settings_sha256", "descriptor_sha256", "assignment_sha256",
    "state_sha256", "hook_event", "permission_mode", "allowed_tools", "tool_sequence",
    "tools_enable_non_authoritative", "hook_required", "isolated_worktree",
    "no_retry", "no_fallback", "no_hedge", "no_model_substitution", "shell_allowed",
    "tools_all_allowed", "proof_scope", "protected_production", "grant_sha256",
}

CLAUDE_ROUTE_BINDINGS = MappingProxyType({
    "worker_claude_code_sonnet_5": MappingProxyType({
        "route_id": "claude-code-subscription-sonnet-5",
        "model": "claude-sonnet-5", "runtime": "Claude Code 2.1.232",
        "billing_basis": "unknown",
    }),
})
CLAUDE_FILE_TOOLS = ("Read", "Write", "Edit")
CLAUDE_GUARD_FIELDS = {
    "schema_version", "artifact_type", "task_id", "route_name", "route_id", "model",
    "runtime", "billing_basis", "task_grant_sha256", "attempt_id", "session_id",
    "worktree_path", "target_path", "mutation_tool", "before_sha256", "after_sha256",
    "content_sha256", "guard_sha256", "settings_sha256", "mcp_sha256",
    "descriptor_sha256", "assignment_sha256", "state_sha256", "hook_event",
    "permission_mode", "allowed_tools", "tool_sequence", "hook_required",
    "isolated_worktree", "settings_sources", "strict_empty_mcp", "observed_turns_max",
    "no_retry", "no_fallback", "no_hedge", "no_model_substitution", "shell_allowed",
    "web_allowed", "chrome_allowed", "plugins_allowed", "skills_allowed",
    "agents_allowed", "session_persistence", "extra_directories_allowed",
    "managed_settings_absence_proved", "proof_scope", "protected_production", "grant_sha256",
}

GROK_ROUTE_BINDINGS = MappingProxyType({
    "worker_grok_4_6": MappingProxyType({
        "route_id": "grok-subscription-4-6", "model": "grok-4.6",
        "runtime": "Grok CLI 1.0.4", "billing_basis": "unknown",
    }),
})
GROK_FILE_TOOLS = ("read_file", "write_file", "edit_file")
GROK_GUARD_FIELDS = {
    "schema_version", "artifact_type", "task_id", "route_name", "route_id",
    "model", "runtime", "billing_basis", "task_grant_sha256", "attempt_id",
    "session_id", "worktree_path", "home_sha256", "config_sha256",
    "project_sha256", "assignment_sha256", "target_path", "mutation_tool",
    "before_sha256", "after_sha256", "content_sha256", "sandbox_policy",
    "allowed_tools", "disallowed_tools", "tool_sequence",
    "tools_restriction_non_authoritative", "isolated_clean_roots",
    "observed_turns_max", "no_retry", "no_fallback", "no_hedge",
    "no_model_substitution", "shell_allowed", "web_allowed", "mcp_allowed",
    "memory_allowed", "subagents_allowed", "plans_allowed", "plugins_allowed",
    "skills_allowed", "session_reuse", "custom_endpoint_allowed",
    "extra_directories_allowed", "oauth_subscription_proved", "proof_scope",
    "protected_production", "grant_sha256",
}

_PLUGIN_ROOT = Path(__file__).resolve().parents[1]
_REGISTRY_SPEC = importlib.util.spec_from_file_location(
    "provider_policy_adapter_registry", _PLUGIN_ROOT / "scripts" / "adapter_registry.py"
)
if _REGISTRY_SPEC is None or _REGISTRY_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("adapter registry validator is unavailable")
ADAPTER_REGISTRY = importlib.util.module_from_spec(_REGISTRY_SPEC)
_REGISTRY_SPEC.loader.exec_module(ADAPTER_REGISTRY)


class ExecutionPolicyError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ExecutionPolicyError("shape_invalid", path)
    return copy.deepcopy(value)


def _enum(value: Any, values: tuple[str, ...], path: str) -> str:
    if value not in values:
        raise ExecutionPolicyError("value_invalid", path)
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise ExecutionPolicyError("boolean_invalid", path)
    return value


def _positive(value: Any, path: str, *, nullable: bool = False) -> int | None:
    if value is None and nullable:
        return None
    if type(value) is not int or value < 1:
        raise ExecutionPolicyError("positive_integer_required", path)
    return value


def _string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ExecutionPolicyError("string_list_invalid", path)
    if len(value) != len(set(value)):
        raise ExecutionPolicyError("duplicate_value", path)
    return copy.deepcopy(value)


BEHAVIOR_FIELDS = {
    "reasoning_depth", "answer_verbosity", "context_strategy", "max_input_tokens",
    "max_output_tokens", "max_turns", "wall_time_seconds", "max_cost_microusd",
}
REQUIREMENT_FIELDS = {
    "local_read", "scoped_write", "commands", "browser", "web_search", "connectors",
    "provider_network", "tools",
}
INTENT_FIELDS = {
    "schema_version", "artifact_type", "preset", "task_size", "complexity", "consequence",
    "independence", "behavior", "requirements", "mutation_mode", "source_delivery",
    "no_retry", "execution_unknown_policy", "intent_sha256",
}


def _behavior(
    reasoning: str, verbosity: str, context: str, input_tokens: int | None,
    output_tokens: int | None, turns: int, seconds: int, cost_microusd: int | None,
) -> dict[str, Any]:
    return {
        "reasoning_depth": reasoning,
        "answer_verbosity": verbosity,
        "context_strategy": context,
        "max_input_tokens": input_tokens,
        "max_output_tokens": output_tokens,
        "max_turns": turns,
        "wall_time_seconds": seconds,
        "max_cost_microusd": cost_microusd,
    }


def _requirements(*, read: bool, write: bool, commands: bool) -> dict[str, Any]:
    return {
        "local_read": read, "scoped_write": write, "commands": commands,
        "browser": False, "web_search": False, "connectors": False,
        "provider_network": True, "tools": [],
    }


# Presets set behavior and requested capability. They do not grant authority.
TASK_INTENT_PRESETS: dict[str, dict[str, Any]] = {
    "advisory_micro": {
        "task_size": "micro", "complexity": "routine", "consequence": "low",
        "independence": "not_required",
        "behavior": _behavior("minimal", "concise", "embedded", 8000, 2000, 1, 120, 100_000),
        "requirements": _requirements(read=False, write=False, commands=False),
        "mutation_mode": "artifact_only", "source_delivery": "embedded_fact_pack",
    },
    "fast_read": {
        "task_size": "small", "complexity": "moderate", "consequence": "low",
        "independence": "not_required",
        "behavior": _behavior("low", "concise", "targeted", 32_000, 4_000, 3, 300, 250_000),
        "requirements": _requirements(read=True, write=False, commands=False),
        "mutation_mode": "read_only", "source_delivery": "local_filesystem",
    },
    "deep_review": {
        "task_size": "medium", "complexity": "complex", "consequence": "high",
        "independence": "preferred",
        "behavior": _behavior("high", "detailed", "targeted", 96_000, 12_000, 20, 900, 1_000_000),
        "requirements": _requirements(read=True, write=False, commands=True),
        "mutation_mode": "read_only", "source_delivery": "local_filesystem",
    },
    "bounded_implementation": {
        "task_size": "large", "complexity": "complex", "consequence": "high",
        "independence": "not_required",
        "behavior": _behavior("high", "standard", "full_allowed", 128_000, 16_000, 20, 1800, 2_000_000),
        "requirements": _requirements(read=True, write=True, commands=True),
        "mutation_mode": "scoped_write", "source_delivery": "local_filesystem",
    },
    "independent_audit": {
        "task_size": "medium", "complexity": "expert", "consequence": "critical",
        "independence": "required",
        "behavior": _behavior("xhigh", "detailed", "full_allowed", 128_000, 16_000, 20, 1800, 2_000_000),
        "requirements": _requirements(read=True, write=False, commands=True),
        "mutation_mode": "read_only", "source_delivery": "local_filesystem",
    },
}


def build_task_intent(preset: str, **overrides: Any) -> dict[str, Any]:
    if preset not in TASK_INTENT_PRESETS:
        raise ExecutionPolicyError("preset_unknown", "preset")
    core = copy.deepcopy(TASK_INTENT_PRESETS[preset])
    for field in ("task_size", "complexity", "consequence", "independence", "mutation_mode", "source_delivery"):
        if field in overrides:
            core[field] = overrides.pop(field)
    for group in ("behavior", "requirements"):
        supplied = overrides.pop(group, None)
        if supplied is not None:
            if not isinstance(supplied, Mapping):
                raise ExecutionPolicyError("mapping_required", group)
            core[group].update(copy.deepcopy(dict(supplied)))
    no_retry = overrides.pop("no_retry", True)
    unknown_policy = overrides.pop("execution_unknown_policy", "preserve_and_stop")
    if overrides:
        raise ExecutionPolicyError("unknown_override", sorted(overrides)[0])
    result = {
        "schema_version": SCHEMA_VERSION, "artifact_type": "ParentTaskIntent",
        "preset": preset, **core, "no_retry": no_retry,
        "execution_unknown_policy": unknown_policy,
    }
    result["intent_sha256"] = canonical_digest(result)
    return validate_task_intent(result)


def validate_task_intent(value: Any) -> dict[str, Any]:
    row = _closed(value, INTENT_FIELDS, "task_intent")
    if row["schema_version"] != 1 or row["artifact_type"] not in {"ParentTaskIntent", "TaskIntentProfile"}:
        raise ExecutionPolicyError("schema_unsupported", "task_intent")
    if row["preset"] not in TASK_INTENT_PRESETS:
        raise ExecutionPolicyError("preset_unknown", "task_intent.preset")
    _enum(row["task_size"], TASK_SIZES, "task_intent.task_size")
    _enum(row["complexity"], COMPLEXITIES, "task_intent.complexity")
    _enum(row["consequence"], CONSEQUENCES, "task_intent.consequence")
    _enum(row["independence"], ("not_required", "preferred", "required"), "task_intent.independence")
    _enum(row["mutation_mode"], MUTATION_MODES, "task_intent.mutation_mode")
    _enum(row["source_delivery"], SOURCE_DELIVERY, "task_intent.source_delivery")
    behavior = _closed(row["behavior"], BEHAVIOR_FIELDS, "task_intent.behavior")
    _enum(behavior["reasoning_depth"], REASONING_LEVELS, "task_intent.behavior.reasoning_depth")
    _enum(behavior["answer_verbosity"], VERBOSITY_LEVELS, "task_intent.behavior.answer_verbosity")
    _enum(behavior["context_strategy"], CONTEXT_STRATEGIES, "task_intent.behavior.context_strategy")
    for field in ("max_input_tokens", "max_output_tokens", "max_cost_microusd"):
        _positive(behavior[field], f"task_intent.behavior.{field}", nullable=True)
    _positive(behavior["max_turns"], "task_intent.behavior.max_turns")
    _positive(behavior["wall_time_seconds"], "task_intent.behavior.wall_time_seconds")
    requirements = _closed(row["requirements"], REQUIREMENT_FIELDS, "task_intent.requirements")
    for field in REQUIREMENT_FIELDS - {"tools"}:
        _boolean(requirements[field], f"task_intent.requirements.{field}")
    _string_list(requirements["tools"], "task_intent.requirements.tools")
    if requirements["scoped_write"] != (row["mutation_mode"] == "scoped_write"):
        raise ExecutionPolicyError("mutation_requirement_mismatch", "task_intent.mutation_mode")
    if requirements["local_read"] and row["source_delivery"] != "local_filesystem":
        raise ExecutionPolicyError("source_delivery_mismatch", "task_intent.source_delivery")
    if row["execution_unknown_policy"] != "preserve_and_stop" or row["no_retry"] is not True:
        raise ExecutionPolicyError("retry_policy_unsafe", "task_intent")
    supplied = row.pop("intent_sha256")
    if supplied != canonical_digest(row):
        raise ExecutionPolicyError("intent_digest_mismatch", "task_intent.intent_sha256")
    row["intent_sha256"] = supplied
    return row


def validate_commandcode_scoped_write_grant(
    value: Any, *, route_name: str | None = None, model: str | None = None,
    task_id: str | None = None, task_grant_sha256: str | None = None,
    attempt_id: str | None = None, session_id: str | None = None,
    worktree_path: str | None = None,
) -> dict[str, Any]:
    """Validate one caller-constructible, task-scoped guarded write grant."""
    row = _closed(value, COMMANDCODE_GUARD_FIELDS, "commandcode_scoped_write_grant")
    supplied = row.pop("grant_sha256")
    if supplied != canonical_digest(row):
        raise ExecutionPolicyError("commandcode_guard_grant_digest_mismatch", "commandcode_scoped_write_grant.grant_sha256")
    if row["schema_version"] != 1 or row["artifact_type"] != "CommandCodeScopedWriteGrant":
        raise ExecutionPolicyError("commandcode_guard_grant_invalid", "commandcode_scoped_write_grant")
    binding = COMMANDCODE_ROUTE_BINDINGS.get(row["route_name"])
    if binding is None or row["route_id"] != binding["route_id"] or row["model"] != binding["model"]:
        raise ExecutionPolicyError("commandcode_guard_route_binding_invalid", "commandcode_scoped_write_grant.route_name")
    expected = {
        "route_name": route_name, "model": model, "task_id": task_id,
        "task_grant_sha256": task_grant_sha256, "attempt_id": attempt_id,
        "session_id": session_id, "worktree_path": worktree_path,
    }
    for field, wanted in expected.items():
        if wanted is not None and row[field] != wanted:
            raise ExecutionPolicyError("commandcode_guard_binding_substitution", f"commandcode_scoped_write_grant.{field}")
    for field in ("task_id", "attempt_id", "session_id"):
        if not isinstance(row[field], str) or not row[field] or len(row[field]) > 128:
            raise ExecutionPolicyError("commandcode_guard_identifier_invalid", f"commandcode_scoped_write_grant.{field}")
    for field in (
        "task_grant_sha256", "before_sha256", "after_sha256", "content_sha256",
        "guard_sha256", "settings_sha256", "descriptor_sha256", "assignment_sha256",
        "state_sha256",
    ):
        digest = row[field]
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
            raise ExecutionPolicyError("commandcode_guard_digest_invalid", f"commandcode_scoped_write_grant.{field}")
    if row["before_sha256"] == row["after_sha256"] or row["content_sha256"] != row["after_sha256"]:
        raise ExecutionPolicyError("commandcode_guard_content_binding_invalid", "commandcode_scoped_write_grant.content_sha256")
    for field in ("worktree_path", "target_path"):
        path = row[field]
        if (
            not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
            or "//" in path or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ExecutionPolicyError("commandcode_guard_path_invalid", f"commandcode_scoped_write_grant.{field}")
    if row["target_path"] == row["worktree_path"] or not row["target_path"].startswith(row["worktree_path"] + "/"):
        raise ExecutionPolicyError("commandcode_guard_path_escape", "commandcode_scoped_write_grant.target_path")
    mutation = row["mutation_tool"]
    if mutation not in {"write_file", "edit_file"}:
        raise ExecutionPolicyError("commandcode_guard_mutation_invalid", "commandcode_scoped_write_grant.mutation_tool")
    if row["allowed_tools"] != list(COMMANDCODE_FILE_TOOLS) or row["tool_sequence"] != ["read_file", mutation, "read_file"]:
        raise ExecutionPolicyError("commandcode_guard_sequence_invalid", "commandcode_scoped_write_grant.tool_sequence")
    exact = {
        "hook_event": "PreToolUse", "permission_mode": "bypass",
        "tools_enable_non_authoritative": True, "hook_required": True,
        "isolated_worktree": True, "no_retry": True, "no_fallback": True,
        "no_hedge": True, "no_model_substitution": True, "shell_allowed": False,
        "tools_all_allowed": False, "proof_scope": "task_scoped_development_worker",
        "protected_production": False,
    }
    if any(row[field] != expected_value for field, expected_value in exact.items()):
        raise ExecutionPolicyError("commandcode_guard_policy_widening", "commandcode_scoped_write_grant")
    row["grant_sha256"] = supplied
    return row


def validate_claude_scoped_write_grant(
    value: Any, *, route_name: str | None = None, model: str | None = None,
    task_id: str | None = None, task_grant_sha256: str | None = None,
    attempt_id: str | None = None, session_id: str | None = None,
    worktree_path: str | None = None,
) -> dict[str, Any]:
    """Validate one caller-constructible Claude guarded task grant."""
    row = _closed(value, CLAUDE_GUARD_FIELDS, "claude_scoped_write_grant")
    supplied = row.pop("grant_sha256")
    if supplied != canonical_digest(row):
        raise ExecutionPolicyError("claude_guard_grant_digest_mismatch", "claude_scoped_write_grant.grant_sha256")
    if row["schema_version"] != 1 or row["artifact_type"] != "ClaudeScopedWriteGrant":
        raise ExecutionPolicyError("claude_guard_grant_invalid", "claude_scoped_write_grant")
    binding = CLAUDE_ROUTE_BINDINGS.get(row["route_name"])
    if binding is None or any(row[field] != binding[field] for field in ("route_id", "model", "runtime", "billing_basis")):
        raise ExecutionPolicyError("claude_guard_route_binding_invalid", "claude_scoped_write_grant.route_name")
    expected = {
        "route_name": route_name, "model": model, "task_id": task_id,
        "task_grant_sha256": task_grant_sha256, "attempt_id": attempt_id,
        "session_id": session_id, "worktree_path": worktree_path,
    }
    for field, wanted in expected.items():
        if wanted is not None and row[field] != wanted:
            raise ExecutionPolicyError("claude_guard_binding_substitution", f"claude_scoped_write_grant.{field}")
    for field in ("task_id", "attempt_id", "session_id"):
        if not isinstance(row[field], str) or not row[field] or len(row[field]) > 128:
            raise ExecutionPolicyError("claude_guard_identifier_invalid", f"claude_scoped_write_grant.{field}")
    for field in (
        "task_grant_sha256", "before_sha256", "after_sha256", "content_sha256",
        "guard_sha256", "settings_sha256", "mcp_sha256", "descriptor_sha256",
        "assignment_sha256", "state_sha256",
    ):
        digest = row[field]
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
            raise ExecutionPolicyError("claude_guard_digest_invalid", f"claude_scoped_write_grant.{field}")
    if row["before_sha256"] == row["after_sha256"] or row["content_sha256"] != row["after_sha256"]:
        raise ExecutionPolicyError("claude_guard_content_binding_invalid", "claude_scoped_write_grant.content_sha256")
    for field in ("worktree_path", "target_path"):
        path = row[field]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "//" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ExecutionPolicyError("claude_guard_path_invalid", f"claude_scoped_write_grant.{field}")
    if row["target_path"] == row["worktree_path"] or not row["target_path"].startswith(row["worktree_path"] + "/"):
        raise ExecutionPolicyError("claude_guard_path_escape", "claude_scoped_write_grant.target_path")
    mutation = row["mutation_tool"]
    if mutation not in {"Write", "Edit"} or row["allowed_tools"] != list(CLAUDE_FILE_TOOLS) or row["tool_sequence"] != ["Read", mutation, "Read"]:
        raise ExecutionPolicyError("claude_guard_sequence_invalid", "claude_scoped_write_grant.tool_sequence")
    exact = {
        "hook_event": "PreToolUse", "permission_mode": "acceptEdits",
        "hook_required": True, "isolated_worktree": True, "settings_sources": [],
        "strict_empty_mcp": True, "observed_turns_max": 20,
        "no_retry": True, "no_fallback": True, "no_hedge": True,
        "no_model_substitution": True, "shell_allowed": False, "web_allowed": False,
        "chrome_allowed": False, "plugins_allowed": False, "skills_allowed": False,
        "agents_allowed": False, "session_persistence": False,
        "extra_directories_allowed": False, "managed_settings_absence_proved": False,
        "proof_scope": "source_local_pending_billing", "protected_production": False,
    }
    if any(row[field] != wanted for field, wanted in exact.items()):
        raise ExecutionPolicyError("claude_guard_policy_widening", "claude_scoped_write_grant")
    row["grant_sha256"] = supplied
    return row


def validate_grok_scoped_write_grant(
    value: Any, *, route_name: str | None = None, model: str | None = None,
    task_id: str | None = None, task_grant_sha256: str | None = None,
    attempt_id: str | None = None, session_id: str | None = None,
    worktree_path: str | None = None,
) -> dict[str, Any]:
    """Validate one source-local Grok task grant without inventing a hook."""
    row = _closed(value, GROK_GUARD_FIELDS, "grok_scoped_write_grant")
    supplied = row.pop("grant_sha256")
    if supplied != canonical_digest(row):
        raise ExecutionPolicyError("grok_guard_grant_digest_mismatch", "grok_scoped_write_grant.grant_sha256")
    if row["schema_version"] != 1 or row["artifact_type"] != "GrokScopedWriteGrant":
        raise ExecutionPolicyError("grok_guard_grant_invalid", "grok_scoped_write_grant")
    binding = GROK_ROUTE_BINDINGS.get(row["route_name"])
    if binding is None or any(row[field] != binding[field] for field in ("route_id", "model", "runtime", "billing_basis")):
        raise ExecutionPolicyError("grok_guard_route_binding_invalid", "grok_scoped_write_grant.route_name")
    expected = {
        "route_name": route_name, "model": model, "task_id": task_id,
        "task_grant_sha256": task_grant_sha256, "attempt_id": attempt_id,
        "session_id": session_id, "worktree_path": worktree_path,
    }
    for field, wanted in expected.items():
        if wanted is not None and row[field] != wanted:
            raise ExecutionPolicyError("grok_guard_binding_substitution", f"grok_scoped_write_grant.{field}")
    for field in ("task_id", "attempt_id", "session_id"):
        if not isinstance(row[field], str) or not row[field] or len(row[field]) > 128:
            raise ExecutionPolicyError("grok_guard_identifier_invalid", f"grok_scoped_write_grant.{field}")
    for field in (
        "task_grant_sha256", "home_sha256", "config_sha256", "project_sha256",
        "assignment_sha256", "before_sha256", "after_sha256", "content_sha256",
    ):
        digest = row[field]
        if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith("sha256:"):
            raise ExecutionPolicyError("grok_guard_digest_invalid", f"grok_scoped_write_grant.{field}")
    if row["before_sha256"] == row["after_sha256"] or row["content_sha256"] != row["after_sha256"]:
        raise ExecutionPolicyError("grok_guard_content_binding_invalid", "grok_scoped_write_grant.content_sha256")
    for field in ("worktree_path", "target_path"):
        path = row[field]
        if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or "//" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ExecutionPolicyError("grok_guard_path_invalid", f"grok_scoped_write_grant.{field}")
    if row["target_path"] == row["worktree_path"] or not row["target_path"].startswith(row["worktree_path"] + "/"):
        raise ExecutionPolicyError("grok_guard_path_escape", "grok_scoped_write_grant.target_path")
    mutation = row["mutation_tool"]
    if mutation not in {"write_file", "edit_file"} or row["allowed_tools"] != list(GROK_FILE_TOOLS) or row["tool_sequence"] != ["read_file", mutation, "read_file"]:
        raise ExecutionPolicyError("grok_guard_sequence_invalid", "grok_scoped_write_grant.tool_sequence")
    exact = {
        "sandbox_policy": "strict", "disallowed_tools": ["shell", "web_search", "web_fetch", "mcp"],
        "tools_restriction_non_authoritative": True, "isolated_clean_roots": True,
        "observed_turns_max": 20, "no_retry": True, "no_fallback": True,
        "no_hedge": True, "no_model_substitution": True, "shell_allowed": False,
        "web_allowed": False, "mcp_allowed": False, "memory_allowed": False,
        "subagents_allowed": False, "plans_allowed": False, "plugins_allowed": False,
        "skills_allowed": False, "session_reuse": False, "custom_endpoint_allowed": False,
        "extra_directories_allowed": False, "oauth_subscription_proved": False,
        "proof_scope": "source_local_pending_billing", "protected_production": False,
    }
    if any(row[field] != wanted for field, wanted in exact.items()):
        raise ExecutionPolicyError("grok_guard_policy_widening", "grok_scoped_write_grant")
    row["grant_sha256"] = supplied
    return row


HARNESS_FIELDS = {
    "schema_version", "artifact_type", "adapter_id", "adapter_type", "runtime_family",
    "tool_loop", "write_transport", "command_transport", "reasoning_controls",
    "verbosity_controls", "context_controls", "max_turns", "max_wall_time_seconds",
    "mutation_turn_limit_outcome", "default_disabled_tools", "harness_sha256",
}


def _harness(
    adapter_id: str, adapter_type: str, runtime: str, *, tool_loop: str,
    write_transport: str, command_transport: str, reasoning: list[str], verbosity: list[str],
    context: list[str], turns: int, seconds: int, turn_limit_outcome: str,
    disabled: list[str],
) -> dict[str, Any]:
    row = {
        "schema_version": 1, "artifact_type": "AdapterToolLoopCapability",
        "adapter_id": adapter_id, "adapter_type": adapter_type, "runtime_family": runtime,
        "tool_loop": tool_loop, "write_transport": write_transport,
        "command_transport": command_transport, "reasoning_controls": reasoning,
        "verbosity_controls": verbosity, "context_controls": context,
        "max_turns": turns, "max_wall_time_seconds": seconds,
        "mutation_turn_limit_outcome": turn_limit_outcome,
        "default_disabled_tools": disabled,
    }
    row["harness_sha256"] = canonical_digest(row)
    return row


ADAPTER_HARNESS_CARDS: dict[str, dict[str, Any]] = {
    "commandcode_deepseek_v4_pro": _harness(
        "commandcode_deepseek_v4_pro", "commandcode", "Command Code", tool_loop="agentic",
        write_transport="pretooluse_guarded_file_tools", command_transport="none", reasoning=list(REASONING_LEVELS),
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES), turns=100, seconds=3600,
        turn_limit_outcome="execution_unknown_after_mutation", disabled=["commands", "tools_all", "browser", "web_search", "connectors"],
    ),
    "commandcode_deepseek_v4_flash": _harness(
        "commandcode_deepseek_v4_flash", "commandcode", "Command Code", tool_loop="agentic",
        write_transport="pretooluse_guarded_file_tools", command_transport="none", reasoning=list(REASONING_LEVELS[:-1]),
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES), turns=100, seconds=2400,
        turn_limit_outcome="execution_unknown_after_mutation", disabled=["commands", "tools_all", "browser", "web_search", "connectors"],
    ),
    "claude_code_sonnet_5": _harness(
        "claude_code_sonnet_5", "claude_cli", "Claude Code", tool_loop="agentic",
        write_transport="pretooluse_guarded_file_tools", command_transport="none", reasoning=list(REASONING_LEVELS),
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES), turns=20, seconds=1800,
        turn_limit_outcome="execution_unknown_after_mutation", disabled=["commands", "browser", "web_search", "connectors", "mcp", "chrome", "plugins", "skills", "agents", "sessions", "fallback"],
    ),
    "minimax_m3": _harness(
        "minimax_m3", "minimax_mmx", "MiniMax subscription CLI", tool_loop="message_only",
        write_transport="qualification_required", command_transport="qualification_required",
        reasoning=["minimal", "low", "medium", "high"], verbosity=list(VERBOSITY_LEVELS),
        context=["embedded"], turns=1, seconds=1800, turn_limit_outcome="terminal",
        disabled=["local_files", "commands", "browser", "web_search", "connectors"],
    ),
    "minimax_m3_json_text_tool_loop": _harness(
        "minimax_m3_json_text_tool_loop", "minimax_mmx_tool_loop",
        "MiniMax subscription CLI with Codexmax JSON text file-tool loop",
        tool_loop="agentic", write_transport="workspace_write",
        command_transport="none", reasoning=["minimal", "low", "medium", "high"],
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES),
        turns=16, seconds=1800,
        turn_limit_outcome="execution_unknown_after_mutation",
        disabled=["commands", "browser", "web_search", "connectors"],
    ),
    "minimax_m3_opencode": _harness(
        "minimax_m3_opencode", "opencode_tool_loop", "OpenCode with MiniMax subscription backend",
        tool_loop="agentic", write_transport="workspace_write",
        command_transport="native_tools", reasoning=list(REASONING_LEVELS),
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES),
        turns=32, seconds=3600,
        turn_limit_outcome="execution_unknown_after_mutation",
        disabled=["browser", "web_search", "connectors"],
    ),
    "grok_4_5": _harness(
        "grok_4_5", "grok_cli", "Grok CLI", tool_loop="agentic",
        write_transport="accept_edits", command_transport="native_tools", reasoning=list(REASONING_LEVELS),
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES), turns=24, seconds=2400,
        turn_limit_outcome="execution_unknown_after_mutation", disabled=["browser", "web_search", "memory", "subagents"],
    ),
    "grok_4_6": _harness(
        "grok_4_6", "grok_cli", "Grok CLI", tool_loop="agentic",
        write_transport="source_local_guarded_file_tools", command_transport="none", reasoning=list(REASONING_LEVELS),
        verbosity=list(VERBOSITY_LEVELS), context=list(CONTEXT_STRATEGIES), turns=20, seconds=1800,
        turn_limit_outcome="execution_unknown_after_mutation",
        disabled=["commands", "browser", "web_search", "memory", "subagents", "mcp", "plugins", "skills", "sessions", "fallback"],
    ),
    "qwopus_llamacpp_opencode": _harness(
        "qwopus_llamacpp_opencode", "opencode_tool_loop",
        "llama.cpp llama-server with OpenCode", tool_loop="agentic",
        write_transport="workspace_write", command_transport="native_tools",
        reasoning=list(REASONING_LEVELS), verbosity=list(VERBOSITY_LEVELS),
        context=list(CONTEXT_STRATEGIES), turns=32, seconds=7200,
        turn_limit_outcome="execution_unknown_after_mutation",
        disabled=["browser", "web_search", "connectors"],
    ),
}


ROUTE_HARNESS = {
    "worker_deepseek_v4_pro": "commandcode_deepseek_v4_pro",
    "worker_deepseek_v4_flash": "commandcode_deepseek_v4_flash",
    "worker_claude_sonnet_5": "claude_code_sonnet_5",
    "worker_claude_code_sonnet_5": "claude_code_sonnet_5",
    "worker_minimax_m3": "minimax_m3",
    "worker_minimax_m3_tool_loop": "minimax_m3_json_text_tool_loop",
    "worker_minimax_m3_opencode": "minimax_m3_opencode",
    "worker_grok_4_5": "grok_4_5",
    "worker_grok_4_6": "grok_4_6",
    "worker_qwopus_opencode": "qwopus_llamacpp_opencode",
}


def _opencode_backend(
    route_name: str, backend_variant: str, provider: str, exact_model: str,
    route_id: str, runtime: str, billing_basis: str, model_selector: str,
) -> dict[str, Any]:
    row = {
        "schema_version": 1, "artifact_type": "OpenCodeBackendBinding",
        "route_name": route_name, "adapter_type": "opencode_tool_loop",
        "backend_variant": backend_variant, "provider": provider,
        "exact_model": exact_model, "route_id": route_id, "runtime": runtime,
        "billing_basis": billing_basis, "model_selector": model_selector,
        "runner_mode": "opencode_run_pure",
        "ambient_config": "external_plugins_disabled_only_other_influence_unproven",
        "tool_permission_policy": "exact_task_grant_intersection",
        "output_protocol": "opencode_json_events_v1",
        "selector_authority": "identity_binding_only_not_backend_authority",
        "cwd_mode": "isolated_worktree",
        "turn_enforcement": "unavailable_use_wall_deadline",
        "qualification_status": "configured_session_required",
    }
    row["backend_binding_sha256"] = canonical_digest(row)
    return row


# One adapter can serve distinct backends. Each backend remains a separate,
# exact, disabled-until-qualified identity. Runtime strings never select one.
OPENCODE_BACKEND_BINDINGS = {
    "worker_minimax_m3_opencode": _opencode_backend(
        "worker_minimax_m3_opencode", "minimax_subscription",
        "MiniMax", "MiniMax-M3", "minimax-subscription-m3-opencode",
        "OpenCode with MiniMax provider-managed subscription", "subscription",
        "minimax/MiniMax-M3",
    ),
    "worker_qwopus_opencode": _opencode_backend(
        "worker_qwopus_opencode", "qwopus_llamacpp",
        "local-llm", "qwopus36-35b-a3b-coder-mtp-q5_k_m",
        "qwopus-opencode-local", "llama.cpp llama-server + OpenCode",
        "local_compute", "llama-server/qwopus36-35b-a3b-coder-mtp-q5_k_m",
    ),
}


def validate_opencode_backend_binding(
    route_name: str, identity: Mapping[str, Any]
) -> dict[str, Any]:
    binding = OPENCODE_BACKEND_BINDINGS.get(route_name)
    if binding is None:
        raise ExecutionPolicyError("opencode_backend_unregistered", "route_name")
    fields = {
        "provider": "provider", "exact_model": "model", "route_id": "route",
        "runtime": "runtime", "billing_basis": "billing",
    }
    for binding_field, identity_field in fields.items():
        if binding[binding_field] != identity.get(identity_field):
            raise ExecutionPolicyError(
                "opencode_backend_binding_mismatch", f"identity.{identity_field}"
            )
    return copy.deepcopy(binding)


def validate_harness_card(value: Any) -> dict[str, Any]:
    row = _closed(value, HARNESS_FIELDS, "harness_card")
    if row["schema_version"] != 1 or row["artifact_type"] not in {"AdapterHarnessCard", "AdapterToolLoopCapability"}:
        raise ExecutionPolicyError("schema_unsupported", "harness_card")
    for field in ("adapter_id", "adapter_type", "runtime_family"):
        if not isinstance(row[field], str) or not row[field]:
            raise ExecutionPolicyError("text_invalid", f"harness_card.{field}")
    _enum(row["tool_loop"], ("message_only", "agentic"), "harness_card.tool_loop")
    _enum(row["write_transport"], (
        "none", "qualification_required", "accept_edits", "workspace_write",
        "pretooluse_guarded_file_tools", "source_local_guarded_file_tools",
    ), "harness_card.write_transport")
    _enum(row["command_transport"], ("none", "qualification_required", "native_tools"), "harness_card.command_transport")
    for field, allowed in (("reasoning_controls", REASONING_LEVELS), ("verbosity_controls", VERBOSITY_LEVELS), ("context_controls", CONTEXT_STRATEGIES)):
        values = _string_list(row[field], f"harness_card.{field}")
        if not values or any(item not in allowed for item in values):
            raise ExecutionPolicyError("control_invalid", f"harness_card.{field}")
    _positive(row["max_turns"], "harness_card.max_turns")
    _positive(row["max_wall_time_seconds"], "harness_card.max_wall_time_seconds")
    _enum(row["mutation_turn_limit_outcome"], ("terminal", "execution_unknown_after_mutation"), "harness_card.mutation_turn_limit_outcome")
    _string_list(row["default_disabled_tools"], "harness_card.default_disabled_tools")
    supplied = row.pop("harness_sha256")
    if supplied != canonical_digest(row):
        raise ExecutionPolicyError("harness_digest_mismatch", "harness_card.harness_sha256")
    row["harness_sha256"] = supplied
    return row


for _harness_card in ADAPTER_HARNESS_CARDS.values():
    validate_harness_card(_harness_card)


# These are routing observations and preferences. Context and cache-token
# volume are not monetary cost and never create a task-size denial or authority.
PREFERRED_SUBSTANTIAL_ROUTE = "worker_deepseek_v4_pro"
COST_OBSERVATION_THRESHOLDS = {
    "worker_deepseek_v4_pro": {
        "minimum_task_size": "micro", "observed_context_tokens": 21094,
        "observed_cache_read_tokens": 4480, "observed_monetary_cost": UNKNOWN,
        "quality_fit": "preferred_substantial_delegate", "billing_basis": "subscription",
    },
    "worker_deepseek_v4_flash": {
        "minimum_task_size": "micro", "observed_context_tokens": 21430,
        "observed_cache_read_tokens": 4480, "observed_monetary_cost": UNKNOWN,
        "quality_fit": "high_quality_low_cost_alternative", "billing_basis": "subscription",
    },
    "worker_claude_code_sonnet_5": {
        "minimum_task_size": "micro", "observed_context_tokens": 25228,
        "observed_cache_read_tokens": UNKNOWN, "observed_monetary_cost": 152117,
        "quality_fit": "deep_review", "billing_basis": "subscription",
    },
    "worker_claude_sonnet_5": {
        "minimum_task_size": "micro", "observed_context_tokens": 25228,
        "observed_cache_read_tokens": UNKNOWN, "observed_monetary_cost": 152117,
        "quality_fit": "deep_review", "billing_basis": "subscription",
    },
    "worker_minimax_m3": {
        "minimum_task_size": "micro", "observed_context_tokens": UNKNOWN,
        "observed_cache_read_tokens": UNKNOWN, "observed_monetary_cost": UNKNOWN,
        "quality_fit": "advisory", "billing_basis": "subscription",
    },
    "worker_minimax_m3_tool_loop": {
        "minimum_task_size": "micro", "observed_context_tokens": 346,
        "observed_cache_read_tokens": 128, "observed_monetary_cost": UNKNOWN,
        "quality_fit": "adapter_owned_json_text_read_observed_write_unqualified",
        "billing_basis": "subscription",
    },
    "worker_minimax_m3_opencode": {
        "minimum_task_size": "micro", "observed_context_tokens": UNKNOWN,
        "observed_cache_read_tokens": UNKNOWN, "observed_monetary_cost": UNKNOWN,
        "quality_fit": "coding_harness_pending_qualification", "billing_basis": "subscription",
    },
    "worker_grok_4_5": {
        "minimum_task_size": "micro", "observed_context_tokens": UNKNOWN,
        "observed_cache_read_tokens": UNKNOWN, "observed_monetary_cost": UNKNOWN,
        "quality_fit": UNKNOWN, "billing_basis": "subscription",
    },
    "worker_grok_4_6": {
        "minimum_task_size": "micro", "observed_context_tokens": 13706,
        "observed_cache_read_tokens": 128, "observed_monetary_cost": 27698,
        "quality_fit": "implementation_candidate", "billing_basis": "subscription",
    },
    "worker_qwopus_opencode": {
        "minimum_task_size": "micro", "observed_context_tokens": UNKNOWN,
        "observed_cache_read_tokens": UNKNOWN, "observed_monetary_cost": 0,
        "quality_fit": "local_coding_harness_stale", "billing_basis": "local_compute",
    },
}


def cost_task_compatible(route_name: str, task_size: str) -> bool:
    _enum(task_size, TASK_SIZES, "task_size")
    row = COST_OBSERVATION_THRESHOLDS.get(route_name)
    return row is None or TASK_SIZES.index(task_size) >= TASK_SIZES.index(row["minimum_task_size"])


def resolve_execution_profile(
    *, intent_value: Any, harness_value: Any, capability_card: Mapping[str, Any],
    task_grant: Mapping[str, Any], runtime_constraints: Mapping[str, Any],
) -> dict[str, Any]:
    """Intersect behavior, demonstrated capability, exact grant, and live limits."""
    intent = validate_task_intent(intent_value)
    harness = validate_harness_card(harness_value)
    if not isinstance(capability_card, Mapping) or not isinstance(task_grant, Mapping):
        raise ExecutionPolicyError("authority_missing", "capability_card")
    if not isinstance(runtime_constraints, Mapping):
        raise ExecutionPolicyError("runtime_constraints_invalid", "runtime_constraints")
    runtime_fields = {
        "health", "budget_state", "lease_state", "fence_state", "worktree_state",
        "max_turns", "wall_time_seconds", "max_input_tokens", "max_output_tokens",
        "max_cost_microusd", "budget_sha256",
    }
    if set(runtime_constraints) != runtime_fields:
        raise ExecutionPolicyError("runtime_constraints_invalid", "runtime_constraints")
    route_name = capability_card.get("route_name")
    bound_harness = capability_card.get("adapter_harness_sha256")
    if bound_harness != harness["harness_sha256"]:
        raise ExecutionPolicyError("harness_capability_binding_mismatch", "capability_card.adapter_harness_sha256")
    if task_grant.get("task_intent_sha256") != intent["intent_sha256"]:
        raise ExecutionPolicyError("task_intent_grant_binding_mismatch", "task_grant.task_intent_sha256")
    if not cost_task_compatible(str(route_name), intent["task_size"]):
        raise ExecutionPolicyError("task_below_route_cost_threshold", "task_intent.task_size")

    required = intent["requirements"]
    access_mode = task_grant.get("access_mode")
    intent_rank = {"artifact_only": 0, "read_only": 1, "scoped_write": 2}[intent["mutation_mode"]]
    grant_rank = {"none": 0, "read_only": 1, "scoped_write": 2}.get(access_mode)
    if grant_rank is None:
        raise ExecutionPolicyError("grant_access_mode_invalid", "task_grant.access_mode")
    effective_rank = min(intent_rank, grant_rank)
    effective_mutation_mode = {0: "artifact_only", 1: "read_only", 2: "scoped_write"}[effective_rank]
    write_scope = task_grant.get("write_scope")
    read_scope = task_grant.get("read_scope")
    commands = task_grant.get("command_allowlist")
    if not isinstance(write_scope, list) or not isinstance(read_scope, list) or not isinstance(commands, list):
        raise ExecutionPolicyError("grant_scope_invalid", "task_grant")
    if intent["mutation_mode"] == "artifact_only" and (
        access_mode != "none" or read_scope or write_scope or commands
    ):
        raise ExecutionPolicyError("intent_grant_authority_mismatch", "task_grant.access_mode")
    if intent["mutation_mode"] == "read_only" and (access_mode != "read_only" or write_scope):
        raise ExecutionPolicyError("intent_grant_authority_mismatch", "task_grant.access_mode")
    if intent["mutation_mode"] == "scoped_write" and (access_mode != "scoped_write" or not write_scope):
        raise ExecutionPolicyError("intent_grant_authority_mismatch", "task_grant.access_mode")
    if effective_mutation_mode != intent["mutation_mode"]:
        raise ExecutionPolicyError("intent_grant_authority_mismatch", "task_grant.access_mode")
    gates = {
        "local_read": capability_card.get("local_file_access") in {"read_only", "read_write"}
        and access_mode in {"read_only", "scoped_write"},
        "scoped_write": capability_card.get("local_file_access") == "read_write"
        and capability_card.get("write_access") == "scoped" and access_mode == "scoped_write"
        and harness["write_transport"] not in {"none", "qualification_required"},
        "commands": capability_card.get("commands_executable") == "yes"
        and bool(task_grant.get("command_allowlist"))
        and harness["command_transport"] == "native_tools",
        "browser": capability_card.get("browser_access") == "yes"
        and task_grant.get("browser_policy") == "allowed",
        "web_search": capability_card.get("web_search_access") == "yes"
        and task_grant.get("web_search_policy") == "allowed",
        "connectors": capability_card.get("connector_access") == "yes"
        and task_grant.get("connector_policy") == "allowed",
        "provider_network": capability_card.get("network_access") == "provider_only"
        and task_grant.get("network_policy") == "provider_only",
    }
    for field in REQUIREMENT_FIELDS - {"tools"}:
        if required[field] and not gates[field]:
            raise ExecutionPolicyError("required_capability_missing", f"task_intent.requirements.{field}")
    granted_tools = task_grant.get("tool_allowlist", [])
    demonstrated_tools = capability_card.get("tool_capabilities", [])
    if any(tool not in granted_tools or tool not in demonstrated_tools for tool in required["tools"]):
        raise ExecutionPolicyError("tool_authority_missing", "task_intent.requirements.tools")
    for field in ("health", "budget_state", "lease_state", "fence_state", "worktree_state"):
        if runtime_constraints.get(field) != "eligible":
            raise ExecutionPolicyError("runtime_gate_closed", f"runtime_constraints.{field}")
    budget_sha256 = runtime_constraints.get("budget_sha256")
    if not isinstance(budget_sha256, str) or not budget_sha256.startswith("sha256:") or len(budget_sha256) != 71:
        raise ExecutionPolicyError("runtime_budget_digest_invalid", "runtime_constraints.budget_sha256")

    behavior = intent["behavior"]
    if behavior["reasoning_depth"] not in harness["reasoning_controls"]:
        raise ExecutionPolicyError("reasoning_control_unsupported", "task_intent.behavior.reasoning_depth")
    if behavior["answer_verbosity"] not in harness["verbosity_controls"]:
        raise ExecutionPolicyError("verbosity_control_unsupported", "task_intent.behavior.answer_verbosity")
    if behavior["context_strategy"] not in harness["context_controls"]:
        raise ExecutionPolicyError("context_control_unsupported", "task_intent.behavior.context_strategy")
    runtime_turns = runtime_constraints.get("max_turns")
    runtime_seconds = runtime_constraints.get("wall_time_seconds")
    max_turns = min(behavior["max_turns"], harness["max_turns"], _positive(runtime_turns, "runtime_constraints.max_turns"))
    wall_seconds = min(behavior["wall_time_seconds"], harness["max_wall_time_seconds"], _positive(runtime_seconds, "runtime_constraints.wall_time_seconds"))
    output_limit = runtime_constraints.get("max_output_tokens")
    max_output = behavior["max_output_tokens"]
    if output_limit is not None:
        output_limit = _positive(output_limit, "runtime_constraints.max_output_tokens")
        max_output = output_limit if max_output is None else min(max_output, output_limit)
    input_limit = runtime_constraints.get("max_input_tokens")
    max_input = behavior["max_input_tokens"]
    if input_limit is not None:
        input_limit = _positive(input_limit, "runtime_constraints.max_input_tokens")
        max_input = input_limit if max_input is None else min(max_input, input_limit)
    cost_limit = runtime_constraints.get("max_cost_microusd")
    max_cost = behavior["max_cost_microusd"]
    if cost_limit is not None:
        cost_limit = _positive(cost_limit, "runtime_constraints.max_cost_microusd")
        max_cost = cost_limit if max_cost is None else min(max_cost, cost_limit)
    result = {
        "schema_version": 1, "artifact_type": "ResolvedExecutionProfile",
        "route_name": route_name, "adapter_id": harness["adapter_id"],
        "adapter_type": harness["adapter_type"], "tool_loop": harness["tool_loop"],
        "write_transport": harness["write_transport"],
        "command_transport": harness["command_transport"],
        "intent_sha256": intent["intent_sha256"], "harness_sha256": harness["harness_sha256"],
        "capability_sha256": capability_card.get("capability_sha256"),
        "grant_sha256": task_grant.get("grant_sha256"),
        "runtime_budget_sha256": budget_sha256,
        "preset": intent["preset"], "task_size": intent["task_size"],
        "complexity": intent["complexity"], "consequence": intent["consequence"],
        "reasoning_depth": behavior["reasoning_depth"],
        "answer_verbosity": behavior["answer_verbosity"],
        "context_strategy": behavior["context_strategy"],
        "max_input_tokens": max_input, "max_output_tokens": max_output,
        "max_turns": max_turns, "wall_time_seconds": wall_seconds,
        "max_cost_microusd": max_cost,
        "mutation_mode": effective_mutation_mode,
        "enabled_tools": copy.deepcopy(required["tools"]),
        "browser_enabled": required["browser"], "web_search_enabled": required["web_search"],
        "connectors_enabled": required["connectors"], "no_retry": True,
        "execution_unknown_policy": "preserve_and_stop",
    }
    result["execution_profile_sha256"] = canonical_digest(result)
    return result


def argv_controls(profile: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return behavior controls only. This function never returns authority."""
    if profile is None:
        return {"max_turns": 3, "reasoning_depth": UNKNOWN, "answer_verbosity": "standard"}
    if not isinstance(profile, Mapping) or profile.get("artifact_type") != "ResolvedExecutionProfile":
        raise ExecutionPolicyError("execution_profile_invalid", "execution_profile")
    resolved_fields = {
        "schema_version", "artifact_type", "route_name", "adapter_id", "intent_sha256",
        "harness_sha256", "capability_sha256", "grant_sha256", "runtime_budget_sha256",
        "adapter_type", "tool_loop", "write_transport", "command_transport",
        "preset", "task_size", "complexity", "consequence", "reasoning_depth",
        "answer_verbosity", "context_strategy", "max_input_tokens", "max_output_tokens",
        "max_turns", "wall_time_seconds", "max_cost_microusd", "mutation_mode",
        "enabled_tools", "browser_enabled", "web_search_enabled", "connectors_enabled",
        "no_retry", "execution_unknown_policy", "execution_profile_sha256",
    }
    if set(profile) != resolved_fields:
        raise ExecutionPolicyError("execution_profile_invalid", "execution_profile")
    digest = profile.get("execution_profile_sha256")
    core = {key: copy.deepcopy(value) for key, value in profile.items() if key != "execution_profile_sha256"}
    if digest != canonical_digest(core):
        raise ExecutionPolicyError("execution_profile_digest_mismatch", "execution_profile.execution_profile_sha256")
    return {
        "max_turns": _positive(profile.get("max_turns"), "execution_profile.max_turns"),
        "reasoning_depth": profile.get("reasoning_depth", UNKNOWN),
        "answer_verbosity": profile.get("answer_verbosity", "standard"),
    }


def effective_concurrency(
    *, user_cap: int, adapter_cap: int, task_cap: int, fleet_cap: int,
    provider_cap: int, runtime_host_cap: int, mutation_mode: str,
) -> dict[str, Any]:
    """Lower concurrency only. Scoped-write task policy must already be one."""
    caps = {
        "user": user_cap,
        "adapter": adapter_cap,
        "task": task_cap,
        "fleet": fleet_cap,
        "provider": provider_cap,
        "runtime_host": runtime_host_cap,
    }
    for name, value in caps.items():
        _positive(value, f"concurrency.{name}")
    _enum(mutation_mode, MUTATION_MODES, "mutation_mode")
    if mutation_mode == "scoped_write" and task_cap != 1:
        raise ExecutionPolicyError(
            "scoped_write_task_cap_must_be_one", "concurrency.task"
        )
    return {
        "caps": copy.deepcopy(caps),
        "effective": min(caps.values()),
        "scoped_writes_serialized": mutation_mode != "scoped_write" or min(caps.values()) == 1,
        "authority_granted": False,
    }


def source_local_conformance(
    *, universal_registry: Mapping[str, Any], qualification_id: str,
    lane_name: str, evaluated_at: str, exact_tools: list[str] | None,
    user_cap: int, task_cap: int, fleet_cap: int, provider_cap: int,
    runtime_host_cap: int,
) -> dict[str, Any]:
    """Exercise shared contracts without provider, execution, or authority effects."""
    match = ADAPTER_REGISTRY.qualified_lane_match(
        universal_registry,
        qualification_id=qualification_id,
        lane_name=lane_name,
        evaluated_at=evaluated_at,
        exact_tools=exact_tools,
    )
    profile = ADAPTER_REGISTRY.lane_profile(lane_name, exact_tools=exact_tools)
    concurrency = effective_concurrency(
        user_cap=user_cap,
        adapter_cap=match["adapter_concurrency_cap"],
        task_cap=task_cap,
        fleet_cap=fleet_cap,
        provider_cap=provider_cap,
        runtime_host_cap=runtime_host_cap,
        mutation_mode=profile["mutation_mode"],
    )
    core = {
        "schema_version": 1,
        "artifact_type": "universal_adapter_source_local_conformance_v1",
        "qualification_id": qualification_id,
        "lane_profile": lane_name,
        "required_primitives": copy.deepcopy(match["required_primitives"]),
        "exact_tool_allowlist": copy.deepcopy(match["exact_tool_allowlist"]),
        "effective_concurrency": concurrency["effective"],
        "concurrency_caps": copy.deepcopy(concurrency["caps"]),
        "scoped_writes_serialized": concurrency["scoped_writes_serialized"],
        "proof_boundary": "source_local",
        "provider_called": False,
        "execution_started": False,
        "eligibility_granted": False,
        "authority_granted": False,
        "acceptance_granted": False,
        "no_retry": True,
        "execution_unknown_policy": "preserve_and_stop",
    }
    return {**core, "conformance_sha256": canonical_digest(core)}


__all__ = [
    "ADAPTER_HARNESS_CARDS", "CLAUDE_FILE_TOOLS", "CLAUDE_ROUTE_BINDINGS", "COMMANDCODE_ROUTE_BINDINGS", "COST_OBSERVATION_THRESHOLDS", "ExecutionPolicyError", "GROK_FILE_TOOLS", "GROK_ROUTE_BINDINGS",
    "OPENCODE_BACKEND_BINDINGS", "PREFERRED_SUBSTANTIAL_ROUTE", "TASK_INTENT_PRESETS",
    "argv_controls", "build_task_intent", "canonical_digest",
    "cost_task_compatible", "effective_concurrency", "resolve_execution_profile",
    "source_local_conformance", "validate_claude_scoped_write_grant", "validate_commandcode_scoped_write_grant", "validate_grok_scoped_write_grant", "validate_harness_card",
    "validate_opencode_backend_binding", "validate_task_intent",
]
