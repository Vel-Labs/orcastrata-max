#!/usr/bin/env python3
"""Resolve, inspect, validate, and initialize Codexmax policy configuration."""

from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXIT_SUCCESS = 0
EXIT_INVALID_CONFIG = 2
EXIT_UNSAFE_OVERRIDE = 3
EXIT_DESTINATION_EXISTS = 4
EXIT_INVOCATION_OR_IO = 5
BOARD_MAX_WRITE_WORKERS = 2
CURRENT_SCHEMA_VERSION = 3
ROUTE_REGISTRY_VERSION = 1
TASK_PROFILE_SCHEMA_VERSION = 2
HEADLESS_DISPATCH_SCHEMA_VERSION = 2
SCHEDULER_SCHEMA_VERSION = 1
CAPABILITY_PREFERENCE_SCHEMA_VERSION = 1
CAPABILITY_MODEL_SCHEMA_VERSION = 2
ROLE_PREFERENCE_SCHEMA_VERSION = 1
REASONING_POLICY_SCHEMA_VERSION = 2
ROLE_NAMES = ("planner", "architect", "worker", "tester", "documenter", "auditor")
LANE_NAMES = (
    "read", "artifact", "scoped_write", "implementation", "tool_loop", "audit",
)
ROLE_ROUTE_FIELDS = tuple(f"route_{index:02d}" for index in range(1, 7))
PROFILE_ROUTE_FIELDS = (
    "primary_route",
    *(f"secondary_{index:02d}" for index in range(1, 6)),
)
SOURCE_ORDER = ("defaults", "workspace", "repository", "goal", "checkpoint", "operator")
MAX_CONFIG_BYTES = 1024 * 1024
ADAPTER_BINDING_RECEIPT_TYPE = "codexmax_adapter_binding_authoring_receipt_v1"
ADAPTER_ONBOARDING_RECEIPT_TYPE = "codexmax_adapter_onboarding_receipt_v1"
ADAPTER_BINDING_PROFILE = "semantic_worker_implementation"
ONBOARDING_ACCOUNT_BINDINGS = {
    "opencode": ("opencode_tool_loop", "worker_minimax_m3_opencode", "opencode-host"),
    "claude": ("claude_cli", "worker_claude_code_sonnet_5", "claude-host"),
    "deepseek": ("commandcode", "worker_deepseek_v4_pro", "commandcode-host"),
    "minimax": ("minimax_mmx_tool_loop", "worker_minimax_m3_tool_loop", "minimax-host"),
    "grok": ("grok_cli", "worker_grok_4_5", "grok-host"),
}
NATIVE_REASONING_EFFORTS = {
    # These are host-selectable request settings. They are not availability,
    # identity, qualification, or task authority evidence.
    "gpt-5.6-sol": ("medium", "high", "xhigh", "max", "ultra"),
    "gpt-5.6-luna": ("low", "medium", "high", "xhigh", "max"),
    "gpt-5.6-terra": ("low", "medium", "high", "xhigh", "max", "ultra"),
}
REASONING_RANK = {
    "low": 0, "medium": 1, "high": 2, "xhigh": 3, "max": 4, "ultra": 5,
}
CONSEQUENCE_REASONING_FLOOR = {
    "low": "medium", "medium": "medium", "high": "high", "highest": "xhigh",
}

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = PLUGIN_ROOT / "assets" / "templates" / "codexmax.config.yaml"

_ADAPTER_SPEC = importlib.util.spec_from_file_location(
    "codexmax_adapter_registry", PLUGIN_ROOT / "scripts" / "adapter_registry.py"
)
if _ADAPTER_SPEC is None or _ADAPTER_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("adapter registry validator is unavailable")
ADAPTER_REGISTRY = importlib.util.module_from_spec(_ADAPTER_SPEC)
_ADAPTER_SPEC.loader.exec_module(ADAPTER_REGISTRY)

_EXPLICIT_SPEC = importlib.util.spec_from_file_location(
    "codexmax_explicit_tool_model",
    PLUGIN_ROOT / "scripts" / "verify_configured_tool_session.py",
)
if _EXPLICIT_SPEC is None or _EXPLICIT_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("explicit tool/model verifier is unavailable")
EXPLICIT_TOOL_MODEL = importlib.util.module_from_spec(_EXPLICIT_SPEC)
_EXPLICIT_SPEC.loader.exec_module(EXPLICIT_TOOL_MODEL)


def _capability_model_defaults() -> dict[str, Any]:
    """Build the package-owned capability/authority composition contract."""
    return {
        "schema_version": CAPABILITY_MODEL_SCHEMA_VERSION,
        "adapter_maximums": {
            "native_codex": {
                "adapter_type": "native_codex",
                # The shipped YAML subset accepts mappings and scalars only.
                # True-valued keys are the package-owned set members.
                "maximum_primitives": {
                    primitive: True
                    for primitive in ADAPTER_REGISTRY.ADAPTER_PRIMITIVES["native_codex"]
                },
                "maximum_lanes": {lane: True for lane in LANE_NAMES},
                "authority_mode": "task_lease_required",
            },
        },
        "task_authority": {
            "source": "task_lease",
            "access_modes": {"read_only": True, "scoped_write": True},
            "intersection": "adapter_maximum_and_task_lease",
            "write_requires": {
                "local_read": True,
                "scoped_write": True,
                "active_lease": True,
                "non_empty_write_scope": True,
            },
        },
        "reasoning": {
            "schema_version": REASONING_POLICY_SCHEMA_VERSION,
            "selection": "compositional",
            "permission_source": "task_authority",
            "quality_floor_source": "task_consequence_floor",
            "fresh_preflight_required": True,
            "governance": {
                "schema_version": 2,
                "parent_is_acceptance_owner": True,
                "child_binding_mode": "dynamic_ephemeral",
                "standing_role_thread_ids_forbidden": True,
                "historical_thread_ids_are_provenance_only": True,
                "supervisor_lifetime": "goal_persistent",
                "worker_lifetime": "assignment_ephemeral",
                "auditor_lifetime": "frozen_candidate_ephemeral",
                "provider_diversity_mode": "qualified_routes_not_model_family_lock",
                "provider_or_model_cost_ordering_forbidden": True,
                "luna_is_exclusive": False,
                "above_parent_cost_or_effort_requires_operator_approval": True,
                "sol_max_or_ultra_requires_operator_approval": True,
                "pre_escalation_work_required": True,
                "native_and_external_escalation_gate_identical": True,
                "escalation_binds_task_grant": True,
            },
            "reasoning_efforts": {
                re.sub(r"[^a-z0-9]", "_", model): {
                    effort: True for effort in efforts
                }
                for model, efforts in NATIVE_REASONING_EFFORTS.items()
            },
        },
    }


CAPABILITY_MODEL_DEFAULTS = _capability_model_defaults()


def _same_canonical_path(lexical: Path, resolved: Path) -> bool:
    return resolved == lexical or (
        str(lexical).startswith("/var/") and str(resolved) == "/private" + str(lexical)
    )


def _route(
    *,
    route_kind: str,
    candidate_label: str,
    provider: str,
    exact_model: str,
    route_id: str,
    runtime: str,
    reasoning: str,
    billing_basis: str,
    identity_status: str,
    capability_status: str,
    source_access: str,
    input_delivery: str,
    commands_executable: str,
    local_file_access: str,
    write_access: str,
    recommended_role: str,
    consequence_floor: str,
    independence_group: str,
    identity_evidence: str,
    capability_evidence: str,
    quota_observability: str = "unknown",
    availability: str = "unknown",
    health: str = "unknown",
    enabled: bool = True,
    concurrency_limit: int = 1,
    escalation_policy: str = "ordinary",
) -> dict[str, Any]:
    """Build one complete mapping-only route entry.

    Availability and health intentionally start unknown. Historical identity or
    capability evidence never substitutes for fresh dispatch preflight.
    """
    return {
        "route_schema_version": 1,
        "route_kind": route_kind,
        "candidate_label": candidate_label,
        "provider": provider,
        "exact_model": exact_model,
        "route_id": route_id,
        "runtime": runtime,
        "reasoning": reasoning,
        "billing_basis": billing_basis,
        "token_limit": None,
        "availability": availability,
        "health": health,
        "authentication": "unverified",
        "identity_status": identity_status,
        "capability_status": capability_status,
        "quota_observability": quota_observability,
        "source_access": source_access,
        "input_delivery": input_delivery,
        "commands_executable": commands_executable,
        "local_file_access": local_file_access,
        "browser_access": "unknown",
        "web_search_access": "unknown",
        "connector_access": "unknown",
        "write_access": write_access,
        "recommended_role": recommended_role,
        "concurrency_limit": concurrency_limit,
        "consequence_floor": consequence_floor,
        "independence_group": independence_group,
        "identity_evidence": identity_evidence,
        "capability_evidence": capability_evidence,
        "enabled": enabled,
        "escalation_policy": escalation_policy,
    }


ROUTE_DEFAULTS: dict[str, dict[str, Any]] = {
    "parent_sol": _route(
        route_kind="control", candidate_label="Parent Codex", provider="unknown",
        exact_model="unknown", route_id="native-codex-parent",
        runtime="unknown", reasoning="unknown", billing_basis="native_included",
        identity_status="unverified", capability_status="unknown",
        source_access="unknown", input_delivery="unknown", commands_executable="unknown",
        local_file_access="unknown", write_access="unknown", recommended_role="parent_only",
        consequence_floor="highest", independence_group="unknown",
        identity_evidence="unknown",
        capability_evidence="unknown",
    ),
    "supervisor_terra_high": _route(
        route_kind="control", candidate_label="Goal-lifetime Supervisor", provider="unknown",
        exact_model="unknown", route_id="native-codex-terra",
        runtime="unknown", reasoning="unknown", billing_basis="native_included",
        identity_status="unverified", capability_status="unknown",
        source_access="local_filesystem", input_delivery="paths_only", commands_executable="yes",
        local_file_access="read_write", write_access="scoped", recommended_role="supervisor_only",
        consequence_floor="high", independence_group="unknown",
        identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=False,
        escalation_policy="explicit_only",
    ),
    "worker_sol_high": _route(
        route_kind="worker", candidate_label="Sol high planning", provider="OpenAI",
        exact_model="gpt-5.6-sol", route_id="codex-sol-high", runtime="Codex CLI",
        reasoning="task_selected", billing_basis="native_included", identity_status="unverified",
        capability_status="unverified", source_access="local_filesystem",
        input_delivery="paths_only", commands_executable="yes", local_file_access="read_only",
        write_access="none", recommended_role="planner_or_architect",
        consequence_floor="highest", independence_group="openai_native",
        identity_evidence="unknown", capability_evidence="unknown",
    ),
    "worker_sol_medium": _route(
        route_kind="worker", candidate_label="Sol medium worker", provider="OpenAI",
        exact_model="gpt-5.6-sol", route_id="codex-sol-medium", runtime="Codex CLI",
        reasoning="task_selected", billing_basis="native_included", identity_status="unverified",
        capability_status="unverified", source_access="local_filesystem",
        input_delivery="paths_only", commands_executable="yes", local_file_access="read_write",
        write_access="scoped", recommended_role="general_worker", consequence_floor="high",
        independence_group="openai_native", identity_evidence="unknown",
        capability_evidence="unknown",
    ),
    "worker_terra_high": _route(
        route_kind="worker", candidate_label="Terra high worker", provider="OpenAI",
        exact_model="gpt-5.6-terra", route_id="codex-terra-high", runtime="Codex CLI",
        reasoning="high", billing_basis="native_included", identity_status="unverified",
        capability_status="unverified", source_access="local_filesystem",
        input_delivery="paths_only", commands_executable="yes", local_file_access="read_write",
        write_access="scoped", recommended_role="general_worker", consequence_floor="high",
        independence_group="openai_native", identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=False,
        escalation_policy="explicit_only",
    ),
    "worker_terra_medium": _route(
        route_kind="worker", candidate_label="Terra medium", provider="OpenAI",
        exact_model="gpt-5.6-terra", route_id="unknown", runtime="Codex",
        reasoning="medium", billing_basis="native_included", identity_status="unverified",
        capability_status="unknown", source_access="local_filesystem",
        input_delivery="paths_only", commands_executable="yes", local_file_access="read_write",
        write_access="scoped", recommended_role="general_worker", consequence_floor="medium",
        independence_group="openai_native",
        identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=False,
        escalation_policy="explicit_only",
    ),
    "worker_luna_xhigh": _route(
        route_kind="worker", candidate_label="Luna xhigh", provider="OpenAI",
        exact_model="gpt-5.6-luna", route_id="codex-luna", runtime="Codex CLI",
        reasoning="task_selected", billing_basis="native_included", identity_status="unverified",
        capability_status="unknown", source_access="local_filesystem",
        input_delivery="paths_only", commands_executable="yes", local_file_access="read_write",
        write_access="scoped", recommended_role="general_worker", consequence_floor="high",
        independence_group="openai_native",
        identity_evidence="unknown",
        capability_evidence="unknown",
    ),
    "worker_codex_spark": _route(
        route_kind="worker", candidate_label="Codex Spark", provider="OpenAI",
        exact_model="gpt-5.3-codex-spark", route_id="codex-spark", runtime="Codex CLI",
        reasoning="low", billing_basis="native_included", identity_status="unverified",
        capability_status="unknown", source_access="local_filesystem", input_delivery="paths_only",
        commands_executable="yes", local_file_access="read_only", write_access="unverified",
        recommended_role="fast_read_only", consequence_floor="low",
        independence_group="openai_native",
        identity_evidence="unknown",
        capability_evidence="unknown",
    ),
    "worker_claude_sonnet_5": _route(
        route_kind="worker", candidate_label="Claude Sonnet 5", provider="Anthropic",
        exact_model="unknown", route_id="unknown", runtime="unknown", reasoning="unknown",
        billing_basis="unknown", identity_status="unknown", capability_status="unknown",
        source_access="unknown", input_delivery="unknown", commands_executable="unknown",
        local_file_access="unknown", write_access="unknown", recommended_role="implementation_candidate",
        consequence_floor="unknown", independence_group="anthropic",
        identity_evidence="unknown", capability_evidence="unknown",
    ),
    "worker_claude_code_sonnet_5": _route(
        route_kind="worker", candidate_label="Claude Code Sonnet 5", provider="Anthropic",
        exact_model="claude-sonnet-5", route_id="claude-code-subscription-sonnet-5",
        runtime="Claude Code 2.1.232", reasoning="provider_default",
        billing_basis="subscription", identity_status="unverified", capability_status="unknown",
        source_access="embedded_only", input_delivery="embedded_fact_pack", commands_executable="no",
        local_file_access="none", write_access="none", recommended_role="embedded_review",
        consequence_floor="medium", independence_group="anthropic",
        identity_evidence="unknown",
        capability_evidence="unknown",
    ),
    "worker_deepseek_v4_pro": _route(
        route_kind="worker", candidate_label="CommandCode DeepSeek V4 Pro",
        provider="Command Code", exact_model="deepseek/deepseek-v4-pro",
        route_id="commandcode-subscription-deepseek-v4-pro", runtime="Command Code",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="local_filesystem", input_delivery="paths_only",
        commands_executable="unknown", local_file_access="read_only", write_access="unverified",
        recommended_role="bounded_implementation", consequence_floor="medium",
        independence_group="commandcode_gateway",
        identity_evidence="unknown",
        capability_evidence="unknown",
    ),
    "worker_deepseek_v4_flash": _route(
        route_kind="worker", candidate_label="CommandCode DeepSeek V4 Flash",
        provider="Command Code", exact_model="deepseek/deepseek-v4-flash",
        route_id="commandcode-subscription-deepseek-v4-flash", runtime="Command Code",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="embedded_only", input_delivery="embedded_fact_pack",
        commands_executable="no", local_file_access="none", write_access="none",
        recommended_role="fast_structured", consequence_floor="low",
        independence_group="commandcode_gateway",
        identity_evidence="unknown",
        capability_evidence="unknown",
        quota_observability="unsupported",
    ),
    "worker_commandcode_model": _route(
        route_kind="worker", candidate_label="Command Code exact model",
        provider="Command Code", exact_model="unknown",
        route_id="commandcode-subscription-exact-model", runtime="Command Code",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="local_filesystem", input_delivery="paths_only",
        commands_executable="unknown", local_file_access="read_only",
        write_access="unverified", recommended_role="bounded_implementation",
        consequence_floor="medium", independence_group="commandcode_gateway",
        identity_evidence="unknown", capability_evidence="unknown",
    ),
    "worker_commandcode_claude_sonnet_5": _route(
        route_kind="worker", candidate_label="Command Code Claude Sonnet 5",
        provider="Command Code", exact_model="claude-sonnet-5",
        route_id="commandcode-subscription-claude-sonnet-5", runtime="Command Code",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="embedded_only", input_delivery="embedded_fact_pack",
        commands_executable="no", local_file_access="none", write_access="none",
        recommended_role="embedded_review", consequence_floor="medium",
        independence_group="commandcode_gateway",
        identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=False,
    ),
    "worker_commandcode_minimax_m3": _route(
        route_kind="worker", candidate_label="Command Code MiniMax M3",
        provider="Command Code", exact_model="minimaxai/minimax-m3",
        route_id="commandcode-subscription-minimax-m3", runtime="Command Code",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="embedded_only", input_delivery="embedded_fact_pack",
        commands_executable="no", local_file_access="none", write_access="none",
        recommended_role="embedded_review", consequence_floor="medium",
        independence_group="commandcode_gateway",
        identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=False,
    ),
    "worker_commandcode_grok_4_5": _route(
        route_kind="worker", candidate_label="Command Code Grok 4.5",
        provider="Command Code", exact_model="xai/grok-4.5",
        route_id="commandcode-subscription-grok-4-5", runtime="Command Code",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="embedded_only", input_delivery="embedded_fact_pack",
        commands_executable="no", local_file_access="none", write_access="none",
        recommended_role="embedded_review", consequence_floor="medium",
        independence_group="commandcode_gateway",
        identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=False,
    ),
    "worker_minimax_m3": _route(
        route_kind="worker", candidate_label="MiniMax subscription M3", provider="MiniMax",
        exact_model="MiniMax-M3", route_id="minimax-subscription-m3", runtime="mmx 1.0.16",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown", source_access="embedded_only",
        input_delivery="embedded_fact_pack", commands_executable="no", local_file_access="none",
        write_access="none", recommended_role="embedded_review", consequence_floor="medium",
        independence_group="minimax",
        identity_evidence="unknown",
        capability_evidence="unknown",
        concurrency_limit=5,
    ),
    "worker_minimax_m3_opencode": _route(
        route_kind="worker", candidate_label="MiniMax M3 through OpenCode",
        provider="MiniMax", exact_model="MiniMax-M3",
        route_id="minimax-subscription-m3-opencode",
        runtime="OpenCode with MiniMax provider-managed subscription",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="unknown", input_delivery="unknown",
        commands_executable="unknown", local_file_access="unknown",
        write_access="unknown", recommended_role="implementation_candidate",
        consequence_floor="unknown", independence_group="minimax",
        identity_evidence="unknown", capability_evidence="unknown", enabled=False,
    ),
    "worker_minimax_m3_tool_loop": _route(
        route_kind="worker", candidate_label="MiniMax M3 Codexmax JSON text file-tool loop; task-scoped read/write observed",
        provider="MiniMax", exact_model="MiniMax-M3",
        route_id="minimax-subscription-m3-tool-loop", runtime="mmx 1.0.16",
        reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="local_filesystem", input_delivery="paths_only",
        commands_executable="no", local_file_access="read_write",
        write_access="unverified", recommended_role="read_only_worker",
        consequence_floor="medium", independence_group="minimax",
        identity_evidence="unknown",
        capability_evidence="unknown",
        availability="unknown", health="unknown", enabled=False,
        concurrency_limit=5,
    ),
    "worker_grok_4_5": _route(
        route_kind="worker", candidate_label="Grok subscription 4.5",
        provider="Grok", exact_model="grok-4.5", route_id="grok-subscription-4-5",
        runtime="Grok CLI 1.0.3", reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="unknown", input_delivery="unknown", commands_executable="unknown",
        local_file_access="unknown", write_access="unknown",
        recommended_role="embedded_review", consequence_floor="unknown",
        independence_group="grok", identity_evidence="unknown", capability_evidence="unknown",
        enabled=False,
    ),
    "worker_grok_4_6": _route(
        route_kind="worker", candidate_label="Grok subscription 4.6",
        provider="Grok", exact_model="grok-4.6", route_id="grok-subscription-4-6",
        runtime="Grok CLI 1.0.4", reasoning="provider_default", billing_basis="subscription",
        identity_status="unverified", capability_status="unknown",
        source_access="embedded_only", input_delivery="embedded_fact_pack", commands_executable="no",
        local_file_access="none", write_access="none",
        recommended_role="embedded_review", consequence_floor="medium",
        independence_group="grok",
        identity_evidence="unknown",
        capability_evidence="unknown",
        enabled=True,
    ),
    "worker_qwopus_opencode": _route(
        route_kind="worker", candidate_label="Local Qwopus through OpenCode",
        provider="local-llm", exact_model="qwopus36-35b-a3b-coder-mtp-q5_k_m",
        route_id="qwopus-opencode-local", runtime="llama.cpp llama-server + OpenCode",
        reasoning="provider_default", billing_basis="local_compute",
        identity_status="unverified", capability_status="unknown",
        source_access="unknown", input_delivery="unknown",
        commands_executable="unknown", local_file_access="unknown", write_access="unknown",
        recommended_role="independent_test_or_audit", consequence_floor="medium",
        independence_group="local_qwopus",
        identity_evidence="unknown", capability_evidence="unknown",
        enabled=False,
    ),
}


_ROUTE_IDENTITY_FIELDS = (
    "route_kind", "provider", "exact_model", "route_id", "runtime",
    "reasoning", "billing_basis",
)
_ROUTE_COST_RANKS = {
    "worker_sol_high": 1,
    "worker_sol_medium": 1,
    "worker_terra_high": 2,
    "worker_terra_medium": 2,
    "worker_luna_xhigh": 0,
    "worker_codex_spark": 0,
    "worker_claude_sonnet_5": 2,
    "worker_claude_code_sonnet_5": 1,
    "worker_deepseek_v4_pro": 1,
    "worker_deepseek_v4_flash": 0,
    "worker_commandcode_model": 1,
    "worker_commandcode_claude_sonnet_5": 2,
    "worker_commandcode_minimax_m3": 2,
    "worker_commandcode_grok_4_5": 2,
    "worker_minimax_m3": 1,
    "worker_minimax_m3_opencode": 1,
    "worker_minimax_m3_tool_loop": 1,
    "worker_grok_4_5": 1,
    "worker_grok_4_6": 1,
    "worker_qwopus_opencode": 0,
}


def route_identity_fingerprint(route: dict[str, Any]) -> str:
    """Bind package rank policy to one canonical route identity."""
    identity = {field: route[field] for field in _ROUTE_IDENTITY_FIELDS}
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _route_capability_policy_defaults() -> dict[str, Any]:
    """Build provider-neutral ordinal policy for every Worker route."""
    policies: dict[str, dict[str, Any]] = {}
    for name, route in ROUTE_DEFAULTS.items():
        if route["route_kind"] != "worker":
            continue
        reasoning = route["reasoning"]
        effort_mode = "native_preflight" if reasoning == "task_selected" else "fixed"
        effort_rank = REASONING_RANK.get(reasoning, 1)
        identity_complete = all(
            route[field] not in {"unknown", "unverified", ""}
            for field in _ROUTE_IDENTITY_FIELDS
        )
        policies[name] = {
            "route_fingerprint": route_identity_fingerprint(route),
            "identity_binding": "complete" if identity_complete else "incomplete",
            "cost_rank": _ROUTE_COST_RANKS[name],
            "effort_mode": effort_mode,
            "effort_rank": effort_rank,
        }
    return {
        "schema_version": 2,
        "rank_semantics": "ordinal_package_policy",
        "provider_or_model_names_define_rank": False,
        "default_parent_cost_ceiling": 1,
        "default_parent_effort_ceiling": 1,
        "legacy_v1_compatibility_cost_ceiling": 1,
        "legacy_v1_compatibility_effort_ceiling": 1,
        "unknown_identity_is_ineligible": True,
        "approval_cannot_repair_unknown_identity": True,
        "routes": policies,
    }


CAPABILITY_MODEL_DEFAULTS["reasoning"]["route_capability_policy"] = (
    _route_capability_policy_defaults()
)


_NATIVE_ROUTE_ALIASES = {
    ("gpt-5.6-sol", "medium"): "worker_sol_medium",
    ("gpt-5.6-sol", "high"): "worker_sol_high",
    ("gpt-5.6-luna", "xhigh"): "worker_luna_xhigh",
}


def native_reasoning_efforts(model: str) -> tuple[str, ...]:
    """Return host-selectable reasoning settings for one native model.

    These settings are composition inputs. They do not prove that a host is
    currently available and they never change task authority.
    """
    try:
        return NATIVE_REASONING_EFFORTS[model]
    except KeyError as exc:
        raise ValidationError(f"native model has no declared reasoning efforts: {model}") from exc


def select_native_reasoning(model: str, consequence_floor: str) -> str:
    """Select the lowest host effort that satisfies a task quality floor."""
    if consequence_floor not in CONSEQUENCE_REASONING_FLOOR:
        raise ValidationError(f"unsupported consequence floor: {consequence_floor}")
    efforts = native_reasoning_efforts(model)
    minimum = CONSEQUENCE_REASONING_FLOOR[consequence_floor]
    minimum_rank = REASONING_RANK[minimum]
    for effort in efforts:
        if REASONING_RANK[effort] >= minimum_rank:
            return effort
    raise ValidationError(
        f"native model {model} cannot meet consequence floor {consequence_floor}"
    )


def compose_native_route(model: str, reasoning: str) -> dict[str, Any]:
    """Compose a native candidate from model and host reasoning settings.

    Known model/effort pairs retain their legacy route identity. New pairs are
    unqualified candidates with an unknown callable route ID; this helper does
    not add them to the shipped registry or imply current host availability.
    """
    if reasoning not in native_reasoning_efforts(model):
        raise ValidationError(f"reasoning effort is not declared for {model}: {reasoning}")
    alias = _NATIVE_ROUTE_ALIASES.get((model, reasoning))
    if alias is not None:
        return copy.deepcopy(ROUTE_DEFAULTS[alias])

    base_name = next(
        (name for (candidate_model, _), name in _NATIVE_ROUTE_ALIASES.items()
         if candidate_model == model),
        None,
    )
    if base_name is None:  # pragma: no cover - native_reasoning_efforts guards this
        raise ValidationError(f"native model has no route base: {model}")
    candidate = copy.deepcopy(ROUTE_DEFAULTS[base_name])
    candidate.update({
        "candidate_label": f"{model} {reasoning} composition",
        "reasoning": reasoning,
        "route_id": "unknown",
        "identity_status": "unverified",
        "capability_status": "unverified",
        "identity_evidence": "unknown",
        "capability_evidence": "unknown",
        "enabled": False,
    })
    return candidate


# Stable aliases keep older packets readable while allowing newer host/model
# combinations to be selected compositionally.
native_route_for = compose_native_route


def adapter_maximum_capability(adapter_type: str) -> dict[str, Any]:
    """Return adapter potential without task authority or qualification."""
    if adapter_type not in ADAPTER_REGISTRY.ADAPTER_TYPES:
        raise ValidationError(f"unknown adapter type: {adapter_type}")
    maximum = set(ADAPTER_REGISTRY.ADAPTER_PRIMITIVES[adapter_type])
    lanes = [
        lane_name for lane_name in LANE_NAMES
        if set(ADAPTER_REGISTRY.LANE_PROFILES[lane_name]["required_primitives"]).issubset(maximum)
    ]
    return {
        "adapter_type": adapter_type,
        "maximum_primitives": sorted(maximum),
        "maximum_lanes": lanes,
        "authority_mode": "task_lease_required",
    }


def task_capability_admission(
    adapter_type: str,
    lane_name: str,
    *,
    adapter_proof: dict[str, Any] | None = None,
    task_lease: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Intersect a proved adapter capability with one active task lease.

    The result is advisory admission data for callers that already own
    qualification and lease issuance. It performs no provider call, lease
    creation, dispatch, mutation, or acceptance.
    """
    maximum = adapter_maximum_capability(adapter_type)
    if lane_name not in ADAPTER_REGISTRY.LANE_PROFILES:
        raise ValidationError(f"unknown lane profile: {lane_name}")
    required = list(ADAPTER_REGISTRY.LANE_PROFILES[lane_name]["required_primitives"])
    reasons: list[str] = []
    if not set(required).issubset(maximum["maximum_primitives"]):
        reasons.append("adapter_maximum_missing_required_primitive")

    proof = adapter_proof if isinstance(adapter_proof, dict) else {}
    proved = proof.get("proved_primitives", [])
    if proof.get("status") not in {"qualified", "verified", "active"}:
        reasons.append("adapter_qualification_required")
    if not isinstance(proved, list) or not set(required).issubset(proved):
        reasons.append("adapter_proof_missing_required_primitive")

    lease = task_lease if isinstance(task_lease, dict) else {}
    lease_active = (
        lease.get("active") is True
        or lease.get("valid") is True
        or lease.get("status") in {"active", "granted"}
    )
    if not lease_active:
        reasons.append("task_lease_not_active")
    mode = lease.get("access_mode", lease.get("mode"))
    if mode is None and isinstance(lease.get("writer"), bool):
        mode = "scoped_write" if lease["writer"] else "read_only"
    if mode not in {"read_only", "scoped_write"}:
        reasons.append("task_lease_access_mode_missing")
    if lane_name in {"scoped_write", "implementation"}:
        if mode != "scoped_write":
            reasons.append("task_lease_write_authority_missing")
        scopes = lease.get("write_scopes", lease.get("write_scope", []))
        if not isinstance(scopes, list) or not scopes:
            reasons.append("task_lease_write_scope_missing")
    admitted = not reasons
    return {
        "adapter_type": adapter_type,
        "lane_profile": lane_name,
        "maximum_primitives": maximum["maximum_primitives"],
        "required_primitives": required,
        "authority_mode": maximum["authority_mode"],
        "admitted": admitted,
        "eligibility_granted": admitted,
        "authority_granted": admitted,
        "reasons": reasons,
        "provider_called": False,
        "execution_started": False,
        "acceptance_granted": False,
    }


# Name used by task-authority consumers that prefer admission terminology.
admit_task_capability = task_capability_admission


def _profile(
    primary: str,
    secondary_01: str,
    secondary_02: str,
    secondary_03: str,
    secondary_04: str,
    secondary_05: str,
    *,
    source_access: str,
    commands: bool,
    write: bool,
    consequence_floor: str,
    independence_required: bool,
) -> dict[str, Any]:
    return {
        "profile_schema_version": TASK_PROFILE_SCHEMA_VERSION,
        "required_source_access": source_access,
        "commands_required": commands,
        "write_required": write,
        "browser_required": False,
        "web_search_required": False,
        "connector_required": False,
        "billing_ceiling": "non_metered",
        "consequence_floor": consequence_floor,
        "independence_required": independence_required,
        "primary_route": primary,
        "secondary_01": secondary_01,
        "secondary_02": secondary_02,
        "secondary_03": secondary_03,
        "secondary_04": secondary_04,
        "secondary_05": secondary_05,
    }


TASK_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "sol_plan_architecture": _profile(
        "worker_luna_xhigh", "worker_sol_high", "worker_deepseek_v4_pro",
        "worker_minimax_m3", "worker_claude_code_sonnet_5", "worker_terra_high",
        source_access="local_filesystem", commands=False, write=False,
        consequence_floor="high", independence_required=False,
    ),
    "bounded_implementation": _profile(
        "worker_deepseek_v4_pro", "worker_luna_xhigh",
        "worker_claude_code_sonnet_5", "worker_minimax_m3_tool_loop",
        "worker_grok_4_6", "worker_codex_spark",
        source_access="local_filesystem", commands=True, write=True,
        consequence_floor="medium", independence_required=False,
    ),
    "semantic_worker_implementation": _profile(
        "worker_deepseek_v4_pro", "worker_luna_xhigh",
        "worker_minimax_m3_tool_loop", "worker_claude_code_sonnet_5",
        "worker_grok_4_6", "worker_codex_spark",
        source_access="local_filesystem", commands=True, write=True,
        consequence_floor="medium", independence_required=False,
    ),
    "semantic_worker_artifact": _profile(
        "worker_deepseek_v4_flash", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_codex_spark", "worker_claude_code_sonnet_5", "worker_grok_4_6",
        source_access="embedded_only", commands=False, write=False,
        consequence_floor="medium", independence_required=False,
    ),
    "fast_read_only": _profile(
        "worker_deepseek_v4_flash", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_codex_spark", "worker_claude_code_sonnet_5", "worker_grok_4_6",
        source_access="local_filesystem", commands=False, write=False,
        consequence_floor="low", independence_required=False,
    ),
    "deep_review": _profile(
        "worker_luna_xhigh", "worker_sol_high", "worker_deepseek_v4_pro",
        "worker_minimax_m3", "worker_claude_code_sonnet_5", "worker_terra_high",
        source_access="local_filesystem", commands=False, write=False,
        consequence_floor="high", independence_required=False,
    ),
    "independent_test": _profile(
        "worker_deepseek_v4_pro", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_grok_4_6", "worker_codex_spark",
        source_access="local_filesystem", commands=True, write=False,
        consequence_floor="high", independence_required=True,
    ),
    "semantic_independent_test": _profile(
        "worker_deepseek_v4_pro", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_grok_4_6", "worker_codex_spark",
        source_access="local_filesystem", commands=True, write=False,
        consequence_floor="high", independence_required=True,
    ),
    "semantic_independent_artifact": _profile(
        "worker_deepseek_v4_pro", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_grok_4_6", "worker_codex_spark",
        source_access="embedded_only", commands=False, write=False,
        consequence_floor="high", independence_required=True,
    ),
    "semantic_document_artifact": _profile(
        "worker_deepseek_v4_flash", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_codex_spark", "worker_claude_code_sonnet_5", "worker_grok_4_6",
        source_access="embedded_only", commands=False, write=False,
        consequence_floor="low", independence_required=False,
    ),
    "embedded_audit": _profile(
        "worker_deepseek_v4_flash", "worker_luna_xhigh", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_grok_4_6", "worker_codex_spark",
        source_access="embedded_only", commands=False, write=False,
        consequence_floor="medium", independence_required=True,
    ),
    "semantic_embedded_audit": _profile(
        "worker_luna_xhigh", "worker_deepseek_v4_pro", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_grok_4_6", "worker_terra_high",
        source_access="embedded_only", commands=False, write=False,
        consequence_floor="medium", independence_required=True,
    ),
}


ROUTE_ADAPTER_TYPES = {
    **{
        name: "native_codex" for name in ROUTE_DEFAULTS
        if name.startswith("worker_sol_") or name.startswith("worker_terra_")
        or name in {"worker_luna_xhigh", "worker_codex_spark"}
    },
    **{
        name: "claude_cli" for name in ROUTE_DEFAULTS
        if name.startswith("worker_claude_")
    },
    **{
        name: "commandcode" for name in ROUTE_DEFAULTS
        if name.startswith("worker_deepseek_") or name.startswith("worker_commandcode_")
    },
    "worker_minimax_m3": "minimax_mmx",
    "worker_minimax_m3_tool_loop": "minimax_mmx_tool_loop",
    "worker_minimax_m3_opencode": "opencode_tool_loop",
    "worker_grok_4_5": "grok_cli",
    "worker_grok_4_6": "grok_cli",
    "worker_qwopus_opencode": "opencode_qwopus",
}
LANE_TASK_PROFILES = {
    "read": "fast_read_only",
    "artifact": "semantic_worker_artifact",
    "scoped_write": "semantic_worker_implementation",
    "implementation": "semantic_worker_implementation",
    "tool_loop": "semantic_worker_implementation",
    "audit": "semantic_independent_test",
}


def _lane_candidate_defaults(lane_name: str) -> list[str]:
    requirements = set(ADAPTER_REGISTRY.LANE_PROFILES[lane_name]["required_primitives"])
    task_profile = TASK_PROFILE_DEFAULTS[LANE_TASK_PROFILES[lane_name]]
    candidates = []
    for route_name in (task_profile[field] for field in PROFILE_ROUTE_FIELDS):
        if (
            route_name == "none"
            or ROUTE_DEFAULTS[route_name]["escalation_policy"] == "explicit_only"
            or route_name == "worker_qwopus_opencode"
        ):
            continue
        adapter_type = ROUTE_ADAPTER_TYPES.get(route_name)
        if adapter_type is None:
            continue
        if requirements.issubset(ADAPTER_REGISTRY.ADAPTER_PRIMITIVES[adapter_type]):
            candidates.append(route_name)
    return candidates


def _capability_preference(lane_name: str) -> dict[str, Any]:
    candidates = _lane_candidate_defaults(lane_name)
    padded = [*candidates, *('none' for _ in range(len(ROLE_ROUTE_FIELDS) - len(candidates)))]
    return {
        "lane_schema_version": CAPABILITY_PREFERENCE_SCHEMA_VERSION,
        "lane_profile": lane_name,
        "user_concurrency_limit": 5,
        **{field: route for field, route in zip(ROLE_ROUTE_FIELDS, padded, strict=True)},
    }


CAPABILITY_PREFERENCE_DEFAULTS = {
    lane_name: _capability_preference(lane_name) for lane_name in LANE_NAMES
}

ROLE_PREFERENCE_DEFAULTS: dict[str, dict[str, Any]] = {
    role: {
        "selection_mode": "default",
        "exact_model": "unknown",
        "reasoning_effort": "unknown",
    }
    for role in ROLE_NAMES
}


def _role_priority(task_profile: str, *routes: str) -> dict[str, Any]:
    if len(routes) > len(ROLE_ROUTE_FIELDS):
        raise ValueError("role priority exceeds available route slots")
    padded = [*routes, *("none" for _ in range(len(ROLE_ROUTE_FIELDS) - len(routes)))]
    return {
        "role_schema_version": HEADLESS_DISPATCH_SCHEMA_VERSION,
        "task_profile": task_profile,
        **{field: route for field, route in zip(ROLE_ROUTE_FIELDS, padded, strict=True)},
    }


ROLE_PRIORITY_DEFAULTS: dict[str, dict[str, Any]] = {
    "planner": _role_priority(
        "sol_plan_architecture", "worker_luna_xhigh", "worker_sol_high",
        "worker_deepseek_v4_pro", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_terra_high",
    ),
    "architect": _role_priority(
        "sol_plan_architecture", "worker_luna_xhigh", "worker_sol_high",
        "worker_deepseek_v4_pro", "worker_minimax_m3",
        "worker_claude_code_sonnet_5", "worker_terra_high",
    ),
    "worker": _role_priority(
        "semantic_worker_implementation", "worker_deepseek_v4_pro",
        "worker_luna_xhigh", "worker_minimax_m3_tool_loop",
        "worker_claude_code_sonnet_5", "worker_grok_4_6", "worker_codex_spark",
    ),
    "tester": _role_priority(
        "semantic_independent_test", "worker_deepseek_v4_pro", "worker_luna_xhigh",
        "worker_minimax_m3", "worker_claude_code_sonnet_5",
        "worker_grok_4_6", "worker_codex_spark",
    ),
    "documenter": _role_priority(
        "fast_read_only", "worker_deepseek_v4_flash", "worker_luna_xhigh",
        "worker_minimax_m3", "worker_codex_spark",
        "worker_claude_code_sonnet_5", "worker_grok_4_6",
    ),
    "auditor": _role_priority(
        "semantic_embedded_audit", "worker_luna_xhigh", "worker_deepseek_v4_pro",
        "worker_minimax_m3", "worker_claude_code_sonnet_5",
        "worker_grok_4_6", "worker_terra_high",
    ),
}


ADAPTER_REGISTRY_DEFAULTS = ADAPTER_REGISTRY.build_registry({
    "example_commandcode_deepseek": ADAPTER_REGISTRY.build_binding(
        binding_id="example_commandcode_deepseek",
        adapter_type="commandcode",
        route_name="worker_deepseek_v4_pro",
        route=ROUTE_DEFAULTS["worker_deepseek_v4_pro"],
        task_profile=TASK_PROFILE_DEFAULTS["semantic_worker_implementation"],
        credential_kind="host_managed",
        opaque_id="commandcode-default",
        enabled=False,
        concurrency_cap=1,
        token_cap=12000,
    ),
    "example_standalone_minimax": ADAPTER_REGISTRY.build_binding(
        binding_id="example_standalone_minimax",
        adapter_type="minimax_mmx",
        route_name="worker_minimax_m3",
        route=ROUTE_DEFAULTS["worker_minimax_m3"],
        task_profile=TASK_PROFILE_DEFAULTS["semantic_worker_implementation"],
        credential_kind="external_profile",
        opaque_id="minimax-default",
        enabled=False,
        concurrency_cap=1,
        token_cap=12000,
    ),
    "example_minimax_opencode": ADAPTER_REGISTRY.build_binding(
        binding_id="example_minimax_opencode",
        adapter_type="opencode_tool_loop",
        route_name="worker_minimax_m3_opencode",
        route=ROUTE_DEFAULTS["worker_minimax_m3_opencode"],
        task_profile=TASK_PROFILE_DEFAULTS["semantic_worker_implementation"],
        credential_kind="external_profile",
        opaque_id="minimax-opencode-default",
        enabled=False,
        concurrency_cap=1,
        token_cap=12000,
    ),
    "example_minimax_mmx_tool_loop": ADAPTER_REGISTRY.build_binding(
        binding_id="example_minimax_mmx_tool_loop",
        adapter_type="minimax_mmx_tool_loop",
        route_name="worker_minimax_m3_tool_loop",
        route=ROUTE_DEFAULTS["worker_minimax_m3_tool_loop"],
        task_profile=TASK_PROFILE_DEFAULTS["semantic_worker_implementation"],
        credential_kind="external_profile", opaque_id="minimax-tool-loop-default",
        enabled=False, concurrency_cap=5, token_cap=12000,
    ),
})

DEFAULTS: dict[str, Any] = {
    "schema_version": CURRENT_SCHEMA_VERSION,
    "journey": {
        "mode": "guided",
        "question_batch_max": 3,
        "progressive_disclosure": True,
        "resume_existing": "prompt",
        "simple_task_fast_path": True,
    },
    "execution": {
        "default_active_workers": 5,
        "max_write_workers": 1,
        "max_turns_safety_ceiling": 20,
        "max_attempts_per_checkpoint": 3,
        "no_improvement_window": 2,
    },
    "budgets": {
        "token_limit": None,
        "hard_spend_limit_usd": None,
        "record_usage_when_exposed": True,
        "unknown_usage_policy": "preserve_unknown",
    },
    "routing": {
        "silent_metered_fallback": False,
        "auxiliary": {
            "spark": {"enabled": True, "token_limit": None},
            "qwopus": {"enabled": False, "token_limit": None},
            "commandcode_deepseek": {
                "enabled": True,
                "billing_policy": "subscription_first",
                "token_limit": None,
            },
            "standalone_minimax": {
                "enabled": True,
                "model": "MiniMax-M3",
                "route_id": "standalone-minimax-m3",
                "billing_policy": "subscription_only",
                "token_limit": None,
            },
        },
    },
    "route_registry": {
        "registry_version": ROUTE_REGISTRY_VERSION,
        "selection_policy": "capability_first",
        "fresh_preflight_required": True,
        "model_identity_implies_tools": False,
        "routes": ROUTE_DEFAULTS,
        "task_profiles": TASK_PROFILE_DEFAULTS,
    },
    "capability_model": CAPABILITY_MODEL_DEFAULTS,
    "adapter_registry": ADAPTER_REGISTRY_DEFAULTS,
    "capability_preferences": {
        "schema_version": CAPABILITY_PREFERENCE_SCHEMA_VERSION,
        "lanes": CAPABILITY_PREFERENCE_DEFAULTS,
    },
    "role_preferences": {
        "schema_version": ROLE_PREFERENCE_SCHEMA_VERSION,
        "roles": ROLE_PREFERENCE_DEFAULTS,
        # Controller is an execution-package preference. It is deliberately
        # outside the six semantic task-priority roles below.
        "controller": {
            "selection_mode": "default",
            "exact_model": "unknown",
            "reasoning_effort": "unknown",
        },
    },
    "headless_dispatch": {
        "schema_version": HEADLESS_DISPATCH_SCHEMA_VERSION,
        "role_priorities": ROLE_PRIORITY_DEFAULTS,
    },
    "scheduler": {
        "schema_version": SCHEDULER_SCHEMA_VERSION,
        "activation": "explicit_only",
        "default_preflight_ttl_seconds": 60,
        "maximum_preflight_ttl_seconds": 300,
        "maximum_queue_age_seconds": 900,
        "lease_ttl_seconds": 900,
        "provider_concurrency_default": 1,
        "runtime_host_concurrency_default": 1,
        "provider_concurrency_limits": {
            "anthropic": 1,
            "command_code": 2,
            "grok": 1,
            "minimax": 5,
            "openai": 2,
        },
        "runtime_host_concurrency_limits": {
            "mmx_1_0_16": 5,
        },
        "diversity_min_quality_observations": 5,
        "role_rank_displacement": {
            "planner": 0,
            "architect": 0,
            "worker": 1,
            "tester": 1,
            "documenter": 1,
            "auditor": 1,
        },
        "task_class_profiles": {
            "planner": "sol_plan_architecture",
            "architect": "sol_plan_architecture",
            "worker": "semantic_worker_artifact",
            "tester": "semantic_independent_artifact",
            "documenter": "semantic_document_artifact",
            "auditor": "semantic_embedded_audit",
        },
        "mutation_task_profiles": {
            "worker_scoped_write": "semantic_worker_implementation",
        },
        "artifact_quality_policy": "provider_neutral_result_v1",
        "unknown_cost_policy": "preserve_unknown_and_reject_cash",
        "hedging_enabled": False,
        "direct_repository_writes_enabled": False,
    },
    "authority": {
        "network": "ask",
        "external_model_calls": "ask_unless_goal_authorized",
        "installs": "ask",
        "destructive_changes": "ask",
        "push": "ask",
        "publish": "ask",
    },
}

HARD_CONSTRAINTS = {
    "routing.silent_metered_fallback": False,
    "route_registry.fresh_preflight_required": True,
    "route_registry.model_identity_implies_tools": False,
    "route_registry.control.parent_model": "unknown",
    "routing.terra_cost_guard": "deny_before_preflight",
    "execution.max_write_workers_ceiling": BOARD_MAX_WRITE_WORKERS,
    "acceptance_authority": "parent_codex_only",
    "configuration_executes_work": False,
    "configuration_authorizes_billing": False,
    "scheduler.activation": "explicit_only",
    "scheduler.hedging_enabled": False,
    "capability_preferences.create_qualification": False,
    "capability_preferences.create_authority": False,
}


class ConfigError(Exception):
    """Base configuration error."""


class ParseError(ConfigError):
    pass


class ValidationError(ConfigError):
    pass


class UnsafeOverrideError(ConfigError):
    pass


class InvocationError(ConfigError):
    pass


class DestinationExistsError(ConfigError):
    pass


class ConfigArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        raise InvocationError(message)


@dataclass(frozen=True)
class Layer:
    name: str
    path: str
    lifetime: str
    active: bool
    inactive_reason: str | None
    value: dict[str, Any]
    migration: dict[str, Any] | None = None


def migrate_config(value: dict[str, Any], *, source: str) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Migrate top-level and additive nested policy schemas without widening routes."""
    version = value.get("schema_version", CURRENT_SCHEMA_VERSION)
    if version not in {1, 2, CURRENT_SCHEMA_VERSION}:
        raise ValidationError(f"schema_version must equal 1, 2, or {CURRENT_SCHEMA_VERSION}")

    migrated = copy.deepcopy(value)
    mapped_fields: list[str] = []
    routes = migrated.get("route_registry", {}).get("routes", {})
    if isinstance(routes, dict):
        for name, route in routes.items():
            if (
                isinstance(route, dict)
                and "route_schema_version" in route
                and "quota_observability" not in route
            ):
                route["quota_observability"] = "unknown"
                mapped_fields.append(
                    f"route_registry.routes.{name}.quota_observability"
                )
            if isinstance(route, dict) and "escalation_policy" not in route:
                route["escalation_policy"] = "ordinary"
                mapped_fields.append(
                    f"route_registry.routes.{name}.escalation_policy"
                )
    if version in {1, 2}:
        migrated["schema_version"] = CURRENT_SCHEMA_VERSION
        mapped_fields.append("schema_version")
        if "scheduler" not in migrated:
            migrated["scheduler"] = copy.deepcopy(DEFAULTS["scheduler"])
            mapped_fields.append("scheduler")
    if version == 1:
        auxiliary = migrated.get("routing", {}).get("auxiliary", {})
        routes = migrated.setdefault("route_registry", {}).setdefault("routes", {})
        legacy_routes = {
            "spark": ("worker_codex_spark",),
            "qwopus": ("worker_qwopus_opencode",),
            "commandcode_deepseek": ("worker_deepseek_v4_pro", "worker_deepseek_v4_flash"),
            "standalone_minimax": ("worker_minimax_m3",),
        }
        for legacy_name, registry_names in legacy_routes.items():
            legacy = auxiliary.get(legacy_name)
            if not isinstance(legacy, dict):
                continue
            for registry_name in registry_names:
                target = routes.setdefault(registry_name, {})
                for field in ("enabled", "token_limit"):
                    if field in legacy:
                        target[field] = copy.deepcopy(legacy[field])
                        mapped_fields.append(
                            f"routing.auxiliary.{legacy_name}.{field}->"
                            f"route_registry.routes.{registry_name}.{field}"
                        )

    profiles = migrated.get("route_registry", {}).get("task_profiles", {})
    if isinstance(profiles, dict):
        for name, profile in profiles.items():
            if not isinstance(profile, dict) or profile.get("profile_schema_version") != 1:
                continue
            profile["profile_schema_version"] = TASK_PROFILE_SCHEMA_VERSION
            mapped_fields.append(
                f"route_registry.task_profiles.{name}.profile_schema_version"
            )
            if "secondary_05" not in profile:
                profile["secondary_05"] = "none"
                mapped_fields.append(f"route_registry.task_profiles.{name}.secondary_05")

    headless = migrated.get("headless_dispatch")
    if isinstance(headless, dict) and headless.get("schema_version") == 1:
        headless["schema_version"] = HEADLESS_DISPATCH_SCHEMA_VERSION
        mapped_fields.append("headless_dispatch.schema_version")
    priorities = headless.get("role_priorities", {}) if isinstance(headless, dict) else {}
    if isinstance(priorities, dict):
        for role, priority in priorities.items():
            if not isinstance(priority, dict) or priority.get("role_schema_version") != 1:
                continue
            priority["role_schema_version"] = HEADLESS_DISPATCH_SCHEMA_VERSION
            mapped_fields.append(
                f"headless_dispatch.role_priorities.{role}.role_schema_version"
            )
            if "route_06" not in priority:
                priority["route_06"] = "none"
                mapped_fields.append(f"headless_dispatch.role_priorities.{role}.route_06")

    if not mapped_fields:
        return migrated, None
    return migrated, {
        "source": source,
        "from_schema_version": version,
        "to_schema_version": CURRENT_SCHEMA_VERSION,
        "mapped_fields": mapped_fields,
        "semantic_change": "none",
    }


def _scalar(text: str, line_number: int) -> Any:
    value = text.strip()
    if not value:
        raise ParseError(f"line {line_number}: empty values are unsupported")
    if value in {"null", "~"}:
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value):
        return int(value)
    if re.fullmatch(r"-?(?:0|[1-9][0-9]*)\.[0-9]+", value):
        return float(value)
    if value.startswith(('"', "'")):
        if len(value) < 2 or value[-1] != value[0]:
            raise ParseError(f"line {line_number}: unterminated quoted scalar")
        if value[0] == '"':
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as exc:
                raise ParseError(f"line {line_number}: invalid quoted scalar") from exc
            if not isinstance(parsed, str):
                raise ParseError(f"line {line_number}: scalar must be a string")
            return parsed
        return value[1:-1].replace("''", "'")
    if any(marker in value for marker in ("[", "]", "{", "}", "&", "*", "!", "|", ">")):
        raise ParseError(f"line {line_number}: unsupported YAML syntax")
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def parse_yaml_subset(text: str) -> dict[str, Any]:
    """Parse the shipped mapping/scalar YAML subset and reject everything else."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-2, root)]
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise ParseError(f"line {line_number}: tabs are unsupported")
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            raise ParseError(f"line {line_number}: indentation must use two-space steps")
        content = raw.strip()
        if content.startswith("-") or ":" not in content:
            raise ParseError(f"line {line_number}: only mappings are supported")
        key, raw_value = content.split(":", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ParseError(f"line {line_number}: invalid key {key!r}")
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack or indent != stack[-1][0] + 2:
            raise ParseError(f"line {line_number}: invalid indentation")
        parent = stack[-1][1]
        if key in parent:
            raise ParseError(f"line {line_number}: duplicate key {key!r}")
        if not raw_value.strip():
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _scalar(raw_value, line_number)
    return root


def _canonical_repository_root(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ConfigError("repository root must be absolute and canonical")
    lexical = Path(os.path.abspath(path))
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConfigError("repository root is unavailable") from exc
    if not _same_canonical_path(lexical, resolved) or stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode):
        raise ConfigError("repository root alias is forbidden")
    return resolved


def _file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def _read_config_snapshot(
    path: Path, repository_root: Path | None = None
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ConfigError("configuration path must be absolute and canonical")
    lexical = Path(os.path.abspath(path))
    if repository_root is not None:
        try:
            resolved_candidate = path.resolve(strict=True)
            resolved_candidate.relative_to(repository_root)
        except ValueError as exc:
            raise ConfigError("configuration path is outside repository root") from exc
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ConfigError("configuration path is unavailable") from exc
    if not _same_canonical_path(lexical, resolved) or stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode):
        raise ConfigError("configuration path alias is forbidden")
    if named.st_nlink != 1:
        raise ConfigError("configuration hardlink is forbidden")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOENT}:
            raise ConfigError("configuration identity changed") from exc
        raise ConfigError("configuration path is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ConfigError("configuration identity changed")
        raw = bytearray()
        while len(raw) <= MAX_CONFIG_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_CONFIG_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if _file_identity(before) != _file_identity(after) or _file_identity(after) != _file_identity(current):
            raise ConfigError("configuration identity changed")
    finally:
        os.close(descriptor)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file is oversized")
    return bytes(raw), _file_identity(after)


def _read_config_bytes(path: Path, repository_root: Path | None = None) -> bytes:
    return _read_config_snapshot(path, repository_root)[0]


def load_config(path: Path, repository_root: Path | None = None) -> dict[str, Any]:
    try:
        text = _read_config_bytes(path, repository_root).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("configuration is not valid UTF-8") from exc
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid JSON in {path}: {exc.msg}") from exc
    else:
        value = parse_yaml_subset(text)
    if not isinstance(value, dict):
        raise ValidationError(f"configuration root in {path} must be a mapping")
    return value


def _binding_overlay_path(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ConfigError("adapter overlay path must be absolute and canonical")
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ConfigError("adapter overlay must use .json, .yaml, or .yml")
    parent = _canonical_repository_root(path.parent)
    lexical = Path(os.path.abspath(path))
    if not _same_canonical_path(lexical.parent, parent):
        raise ConfigError("adapter overlay parent alias is forbidden")
    return parent / path.name


def _empty_binding_overlay() -> dict[str, Any]:
    return {"adapter_registry": {"bindings": {}}}


def _validate_binding_overlay(value: dict[str, Any]) -> None:
    if set(value) != {"adapter_registry"}:
        raise UnsafeOverrideError("adapter overlay root must contain only adapter_registry")
    registry = value["adapter_registry"]
    if not isinstance(registry, dict) or set(registry) != {"bindings"}:
        raise UnsafeOverrideError("adapter overlay must contain only adapter_registry.bindings")
    bindings = registry["bindings"]
    if not isinstance(bindings, dict):
        raise ValidationError("adapter_registry.bindings must be a mapping")
    collisions = sorted(set(bindings) & set(ADAPTER_REGISTRY_DEFAULTS["bindings"]))
    if collisions:
        raise UnsafeOverrideError(
            f"adapter overlay cannot replace package binding {collisions[0]}"
        )
    validate_config(value, partial=True)
    validate_adapter_registry_layer(value)
    combined = {
        **copy.deepcopy(ADAPTER_REGISTRY_DEFAULTS["bindings"]),
        **copy.deepcopy(bindings),
    }
    document = ADAPTER_REGISTRY.build_registry(combined)
    try:
        ADAPTER_REGISTRY.validate_registry(
            document,
            evaluated_at="1970-01-01T00:00:00Z",
            configuration_only=True,
        )
    except ADAPTER_REGISTRY.AdapterRegistryError as exc:
        raise ValidationError(f"adapter overlay invalid: {exc}") from exc
    validate_adapter_registry_routes(document, DEFAULTS["route_registry"])


def _read_binding_overlay(
    path: Path,
) -> tuple[dict[str, Any], bytes | None, tuple[int, int, int, int, int] | None]:
    try:
        path.lstat()
    except FileNotFoundError:
        return _empty_binding_overlay(), None, None
    raw, identity = _read_config_snapshot(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError("adapter overlay is not valid UTF-8") from exc
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ParseError(f"invalid JSON in {path}: {exc.msg}") from exc
    else:
        value = parse_yaml_subset(text)
    if not isinstance(value, dict):
        raise ValidationError("adapter overlay root must be a mapping")
    _validate_binding_overlay(value)
    return value, raw, identity


def _yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError("non-finite values cannot be serialized")
        return json.dumps(value, allow_nan=False)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    raise ValidationError("adapter overlay contains a non-scalar value")


def _yaml_mapping_lines(value: dict[str, Any], indent: int = 0) -> list[str]:
    lines: list[str] = []
    for key in sorted(value):
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
            raise ValidationError(f"adapter overlay key is not YAML-safe: {key}")
        item = value[key]
        prefix = " " * indent + key + ":"
        if isinstance(item, dict):
            lines.append(prefix)
            lines.extend(_yaml_mapping_lines(item, indent + 2))
        else:
            lines.append(prefix + " " + _yaml_scalar(item))
    return lines


def _serialize_binding_overlay(path: Path, value: dict[str, Any]) -> bytes:
    _validate_binding_overlay(value)
    if path.suffix.lower() == ".json":
        text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        text = "\n".join(_yaml_mapping_lines(value)) + "\n"
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ValidationError("adapter overlay is oversized")
    return encoded


def _validate_onboarding_overlay(value: dict[str, Any]) -> None:
    if set(value) != {"adapter_registry", "route_registry"}:
        raise UnsafeOverrideError(
            "onboarding overlay must contain only adapter_registry and route_registry"
        )
    _validate_binding_overlay({"adapter_registry": value["adapter_registry"]})
    route_registry = value["route_registry"]
    if not isinstance(route_registry, dict) or set(route_registry) != {"routes"}:
        raise UnsafeOverrideError("onboarding route registry must contain only routes")
    routes = route_registry["routes"]
    if not isinstance(routes, dict):
        raise ValidationError("onboarding routes must be a mapping")
    bound_routes = {
        binding["route"]["route_name"]
        for binding in value["adapter_registry"]["bindings"].values()
    }
    if set(routes) != bound_routes:
        raise ValidationError("onboarding enabled routes must match configured bindings")
    for route_name, route in routes.items():
        if route != {"enabled": True}:
            raise UnsafeOverrideError(
                f"onboarding route {route_name} may set only enabled true"
            )
    validate_config(value, partial=True)
    validate_route_registry_layer(value)


def _serialize_onboarding_overlay(path: Path, value: dict[str, Any]) -> bytes:
    _validate_onboarding_overlay(value)
    if path.suffix.lower() == ".json":
        text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    else:
        text = "\n".join(_yaml_mapping_lines(value)) + "\n"
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_CONFIG_BYTES:
        raise ValidationError("onboarding overlay is oversized")
    return encoded


def _digest_bytes(value: bytes | None) -> str | None:
    if value is None:
        return None
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _binding_profile(binding: dict[str, Any]) -> dict[str, Any]:
    matches = [
        profile for profile in TASK_PROFILE_DEFAULTS.values()
        if ADAPTER_REGISTRY.canonical_digest(profile) == binding["task_profile_sha256"]
    ]
    if len(matches) != 1:
        raise ValidationError("binding task profile identity is not uniquely code-owned")
    return matches[0]


def _build_authored_binding(
    *, adapter_type: str, route_name: str, credential_kind: str,
    opaque_id: str, enabled: bool, concurrency_cap: int | None,
    token_cap: int, exact_model: str | None = None,
    task_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    route = ROUTE_DEFAULTS.get(route_name)
    if route is None or route.get("route_kind") != "worker":
        raise UnsafeOverrideError("adapter binding route must be a package-owned Worker route")
    if not ADAPTER_REGISTRY.adapter_route_compatible(adapter_type, route_name):
        raise UnsafeOverrideError("adapter type and Worker route are not code-owned compatible")
    route_model = route.get("exact_model")
    if route_model == "unknown":
        if exact_model in {None, "", "unknown", "unverified"}:
            raise ValidationError("generic adapter route requires --exact-model")
    elif exact_model is not None and exact_model != route_model:
        raise UnsafeOverrideError(
            "model override requires a package-owned generic transport route"
        )
    profile = task_profile or TASK_PROFILE_DEFAULTS[ADAPTER_BINDING_PROFILE]
    try:
        binding_id = ADAPTER_REGISTRY.derive_binding_id(
            adapter_type=adapter_type,
            route_name=route_name,
            credential_kind=credential_kind,
            opaque_id=opaque_id,
            exact_model=exact_model,
        )
        binding = ADAPTER_REGISTRY.build_binding(
            binding_id=binding_id,
            adapter_type=adapter_type,
            route_name=route_name,
            route=route,
            task_profile=profile,
            credential_kind=credential_kind,
            opaque_id=opaque_id,
            enabled=enabled,
            concurrency_cap=concurrency_cap,
            token_cap=token_cap,
            exact_model=exact_model,
        )
        ADAPTER_REGISTRY.validate_registry(
            ADAPTER_REGISTRY.build_registry({binding_id: binding}),
            evaluated_at="1970-01-01T00:00:00Z",
            configuration_only=True,
        )
    except ADAPTER_REGISTRY.AdapterRegistryError as exc:
        raise ValidationError(f"adapter binding invalid: {exc}") from exc
    return binding


def _mutate_binding_overlay(
    value: dict[str, Any], args: argparse.Namespace,
) -> tuple[dict[str, Any], str, str | None]:
    result = copy.deepcopy(value)
    bindings = result["adapter_registry"]["bindings"]
    if args.binding_action == "add":
        candidate = _build_authored_binding(
            adapter_type=args.adapter_type,
            route_name=args.route,
            credential_kind=args.credential_kind,
            opaque_id=args.opaque_id,
            enabled=args.enabled,
            concurrency_cap=args.concurrency_cap,
            token_cap=args.token_cap,
            exact_model=args.exact_model,
        )
        binding_id = candidate["binding_id"]
        existing = bindings.get(binding_id)
        if existing is not None and existing != candidate:
            raise UnsafeOverrideError(
                f"binding {binding_id} exists; mutable changes require update"
            )
        bindings[binding_id] = candidate
    elif args.binding_action == "update":
        binding_id = args.binding_id
        existing = bindings.get(binding_id)
        if existing is None:
            raise ValidationError(f"adapter binding does not exist: {binding_id}")
        if not any((args.enabled is not None, args.concurrency_cap is not None,
                    args.clear_concurrency_cap, args.token_cap is not None)):
            raise InvocationError("update requires a mutable field")
        credential = existing["credential_reference"]
        existing_model = existing["route"]["exact_model"]
        legacy_id = ADAPTER_REGISTRY.derive_binding_id(
            adapter_type=existing["adapter_type"],
            route_name=existing["route"]["route_name"],
            credential_kind=credential["kind"],
            opaque_id=credential["opaque_id"],
        )
        candidate = _build_authored_binding(
            adapter_type=existing["adapter_type"],
            route_name=existing["route"]["route_name"],
            credential_kind=credential["kind"],
            opaque_id=credential["opaque_id"],
            enabled=existing["enabled"] if args.enabled is None else args.enabled,
            concurrency_cap=(
                None if args.clear_concurrency_cap else
                existing["concurrency_cap"] if args.concurrency_cap is None else args.concurrency_cap
            ),
            token_cap=existing["token_cap"] if args.token_cap is None else args.token_cap,
            # Preserve the legacy ID for bindings authored before model
            # overrides existed. New candidates bind model identity in the ID.
            exact_model=None if binding_id == legacy_id else existing_model,
            task_profile=_binding_profile(existing),
        )
        if candidate["binding_id"] != binding_id:
            raise UnsafeOverrideError("binding identity changes require remove then add")
        bindings[binding_id] = candidate
    else:
        binding_id = args.binding_id
        if binding_id not in bindings:
            raise ValidationError(f"adapter binding does not exist: {binding_id}")
        del bindings[binding_id]
        candidate = None
    _validate_binding_overlay(result)
    digest = None if candidate is None else candidate["adapter_binding_sha256"]
    return result, binding_id, digest


def _relative_identity(directory: int, name: str) -> tuple[int, int, int, int, int] | None:
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
        raise ConfigError("adapter overlay path alias is forbidden")
    return _file_identity(current)


def _assert_overlay_parent_identity(path: Path, directory: int) -> None:
    try:
        named = path.parent.lstat()
    except OSError as exc:
        raise ConfigError("adapter overlay parent identity changed") from exc
    opened = os.fstat(directory)
    if (
        not stat.S_ISDIR(named.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise ConfigError("adapter overlay parent identity changed")


def _open_verified_parent(path: Path) -> int:
    flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    directory = os.open(path.parent, flags)
    try:
        _assert_overlay_parent_identity(path, directory)
    except Exception:
        os.close(directory)
        raise
    return directory


def _assert_input_snapshot(
    path: Path, directory: int,
    expected: tuple[int, int, int, int, int],
) -> None:
    _assert_overlay_parent_identity(path, directory)
    if _relative_identity(directory, path.name) != expected:
        raise ConfigError("adapter input identity changed")


def _ensure_output_absent(path: Path, directory: int) -> None:
    _assert_overlay_parent_identity(path, directory)
    try:
        os.stat(path.name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise DestinationExistsError(f"adapter output already exists: {path}")


def _assert_new_output_identity(
    descriptor: int, directory: int, output_name: str, expected_raw: bytes
) -> None:
    opened_before = os.fstat(descriptor)
    try:
        named = os.stat(output_name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        raise ConfigError("adapter output identity changed") from exc
    if (
        not stat.S_ISREG(opened_before.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened_before.st_nlink != 1
        or named.st_nlink != 1
        or _file_identity(opened_before) != _file_identity(named)
    ):
        raise ConfigError("adapter output identity changed")
    observed = bytearray()
    offset = 0
    while len(observed) <= len(expected_raw):
        chunk = os.pread(
            descriptor,
            min(65536, len(expected_raw) + 1 - len(observed)),
            offset,
        )
        if not chunk:
            break
        observed.extend(chunk)
        offset += len(chunk)
    opened_after = os.fstat(descriptor)
    if (
        _file_identity(opened_before) != _file_identity(opened_after)
        or bytes(observed) != expected_raw
    ):
        raise ConfigError("adapter output content changed")


def _write_new_binding_overlay(path: Path, raw: bytes, directory: int) -> None:
    _ensure_output_absent(path, directory)
    flags = (
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
    except FileExistsError as exc:
        raise DestinationExistsError(f"adapter output already exists: {path}") from exc
    try:
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count < 1:
                raise ConfigError("adapter output write made no progress")
            written += count
        os.fsync(descriptor)
        _assert_overlay_parent_identity(path, directory)
        _assert_new_output_identity(descriptor, directory, path.name, raw)
        os.fsync(directory)
        _assert_overlay_parent_identity(path, directory)
        _assert_new_output_identity(descriptor, directory, path.name, raw)
    finally:
        os.close(descriptor)


def author_adapter_binding(args: argparse.Namespace) -> dict[str, Any]:
    output = _binding_overlay_path(args.output)
    output_directory = _open_verified_parent(output)
    input_path: Path | None = None
    input_directory: int | None = None
    try:
        _ensure_output_absent(output, output_directory)
        if args.binding_action == "add" and args.input is None:
            value, before, identity = _empty_binding_overlay(), None, None
        else:
            input_path = _binding_overlay_path(args.input)
            input_directory = _open_verified_parent(input_path)
            value, before, identity = _read_binding_overlay(input_path)
            if before is None or identity is None:
                raise ConfigError("adapter input is unavailable")
            _assert_input_snapshot(input_path, input_directory, identity)
        updated, binding_id, binding_digest = _mutate_binding_overlay(value, args)
        after = _serialize_binding_overlay(output, updated)
        changed = before != after
        created = False
        if args.write_new:
            _ensure_output_absent(output, output_directory)
            if input_path is not None and input_directory is not None and identity is not None:
                _assert_input_snapshot(input_path, input_directory, identity)
            _write_new_binding_overlay(output, after, output_directory)
            created = True
            if input_path is not None and input_directory is not None and identity is not None:
                _assert_input_snapshot(input_path, input_directory, identity)
        return {
            "artifact_type": ADAPTER_BINDING_RECEIPT_TYPE,
            "action": args.binding_action,
            "input": None if input_path is None else str(input_path),
            "output": str(output),
            "binding_id": binding_id,
            "adapter_binding_sha256": binding_digest,
            "input_file_sha256": _digest_bytes(before),
            "output_file_sha256": _digest_bytes(after),
            "binding_count": len(updated["adapter_registry"]["bindings"]),
            "changed": changed,
            "write_new_requested": args.write_new,
            "candidate_created": created,
            "immutable_candidate": True,
            "mutable_write_supported": False,
            "input_replaced": False,
            "input_deleted": False,
            "input_mutated": False,
            "status": "configured",
            "identity_change_requires_remove_add": True,
            "credentials_resolved": False,
            "provider_called": False,
            "execution_started": False,
            "eligibility_granted": False,
            "authority_granted": False,
            "acceptance_granted": False,
        }
    finally:
        if input_directory is not None:
            os.close(input_directory)
        os.close(output_directory)


def author_onboarding_overlay(args: argparse.Namespace) -> dict[str, Any]:
    repository_root = _canonical_repository_root(args.repo_root)
    if args.native_only:
        return {
            "artifact_type": ADAPTER_ONBOARDING_RECEIPT_TYPE,
            "action": "native_only",
            "native_ready": True,
            "accounts": [],
            "output": None,
            "binding_ids": [],
            "candidate_created": False,
            "configuration_written": False,
            "credentials_resolved": False,
            "provider_called": False,
            "authenticated": False,
            "qualified": False,
            "authority_granted": False,
            "execution_started": False,
        }

    selected = list(args.account or [])
    if len(selected) != len(set(selected)):
        raise InvocationError("onboarding accounts must not contain duplicates")
    accounts = [name for name in ONBOARDING_ACCOUNT_BINDINGS if name in selected]
    bindings: dict[str, Any] = {}
    routes: dict[str, dict[str, bool]] = {}
    for account in accounts:
        adapter_type, route_name, opaque_id = ONBOARDING_ACCOUNT_BINDINGS[account]
        binding = _build_authored_binding(
            adapter_type=adapter_type,
            route_name=route_name,
            credential_kind="host_managed",
            opaque_id=opaque_id,
            enabled=True,
            concurrency_cap=1,
            token_cap=args.token_cap,
        )
        bindings[binding["binding_id"]] = binding
        routes[route_name] = {"enabled": True}
    overlay = {
        "adapter_registry": {"bindings": bindings},
        "route_registry": {"routes": routes},
    }
    output = _binding_overlay_path(repository_root / "codexmax.adapters.yaml")
    output_directory = _open_verified_parent(output)
    try:
        _ensure_output_absent(output, output_directory)
        raw = _serialize_onboarding_overlay(output, overlay)
        created = False
        if args.write_new:
            _write_new_binding_overlay(output, raw, output_directory)
            created = True
        return {
            "artifact_type": ADAPTER_ONBOARDING_RECEIPT_TYPE,
            "action": "configure_optional_accounts",
            "native_ready": True,
            "accounts": accounts,
            "output": str(output),
            "output_file_sha256": _digest_bytes(raw),
            "binding_ids": sorted(bindings),
            "enabled_routes": sorted(routes),
            "candidate_created": created,
            "configuration_written": created,
            "credentials_resolved": False,
            "provider_called": False,
            "authenticated": False,
            "qualified": False,
            "authority_granted": False,
            "execution_started": False,
        }
    finally:
        os.close(output_directory)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: Any, path: str) -> None:
    if not _is_int(value) or value <= 0:
        raise ValidationError(f"{path} must be a positive integer")


def _nullable_positive_int(value: Any, path: str) -> None:
    if value is not None:
        _positive_int(value, path)


def _same_type(value: Any, expected: Any, path: str) -> None:
    if expected is None:
        return
    if isinstance(expected, bool):
        valid = isinstance(value, bool)
    elif isinstance(expected, int):
        valid = _is_int(value)
    elif isinstance(expected, str):
        valid = isinstance(value, str)
    else:
        valid = isinstance(value, type(expected))
    if not valid:
        raise ValidationError(f"{path} has wrong type")


def _enum(value: Any, allowed: set[str], path: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValidationError(f"{path} must be one of {', '.join(sorted(allowed))}")


def _validate_named_mapping(
    candidate: dict[str, Any],
    item_schema: dict[str, Any],
    *,
    path: str,
    partial: bool,
) -> None:
    if not isinstance(candidate, dict):
        raise ValidationError(f"{path} must be a mapping")
    for name, item in candidate.items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise ValidationError(f"{path}.{name} has an invalid identifier")
        if not isinstance(item, dict):
            raise ValidationError(f"{path}.{name} must be a mapping")
        unknown = sorted(set(item) - set(item_schema))
        if unknown:
            raise ValidationError(f"unknown field: {path}.{name}.{unknown[0]}")
        if not partial:
            missing = sorted(set(item_schema) - set(item))
            if missing:
                raise ValidationError(f"missing field: {path}.{name}.{missing[0]}")
        for field, field_value in item.items():
            _same_type(field_value, item_schema[field], f"{path}.{name}.{field}")


def validate_route_registry(registry: dict[str, Any], *, partial: bool) -> None:
    route_schema = next(iter(ROUTE_DEFAULTS.values()))
    profile_schema = next(iter(TASK_PROFILE_DEFAULTS.values()))
    routes = registry.get("routes", {})
    profiles = registry.get("task_profiles", {})
    _validate_named_mapping(
        routes, route_schema, path="route_registry.routes", partial=partial
    )
    _validate_named_mapping(
        profiles, profile_schema, path="route_registry.task_profiles", partial=partial
    )

    if "registry_version" in registry and registry["registry_version"] != ROUTE_REGISTRY_VERSION:
        raise ValidationError(f"route_registry.registry_version must equal {ROUTE_REGISTRY_VERSION}")
    if "selection_policy" in registry and registry["selection_policy"] != "capability_first":
        raise UnsafeOverrideError("route selection must remain capability_first")
    if registry.get("fresh_preflight_required") is False:
        raise UnsafeOverrideError("fresh route preflight cannot be disabled")
    if registry.get("model_identity_implies_tools") is True:
        raise UnsafeOverrideError("model identity cannot imply tool access")

    all_routes = set(ROUTE_DEFAULTS) | set(routes)
    for name, route in routes.items():
        prefix = f"route_registry.routes.{name}"
        enum_fields = {
            "route_kind": {"control", "worker"},
            "availability": {"available", "unavailable", "unknown", "unverified"},
            "health": {"healthy", "degraded", "unhealthy", "unknown", "unverified"},
            "authentication": {"verified", "unverified", "unknown", "not_required"},
            "identity_status": {"proven", "unknown", "unverified"},
            "capability_status": {"proven", "partially_proven", "unknown", "unverified"},
            "quota_observability": {"supported", "unsupported", "unknown"},
            "source_access": {
                "local_filesystem", "embedded_only", "connector_resource", "mixed",
                "none", "unknown", "unverified",
            },
            "input_delivery": {
                "paths_only", "embedded_fact_pack", "connector_references", "mixed",
                "none", "unknown", "unverified",
            },
            "commands_executable": {"yes", "no", "unknown"},
            "local_file_access": {"read_only", "read_write", "none", "unknown", "unverified"},
            "browser_access": {"yes", "no", "unknown", "unverified"},
            "web_search_access": {"yes", "no", "unknown", "unverified"},
            "connector_access": {"yes", "no", "unknown", "unverified"},
            "write_access": {"scoped", "none", "unknown", "unverified"},
            "escalation_policy": {"ordinary", "explicit_only"},
        }
        for field, allowed in enum_fields.items():
            if field in route:
                _enum(route[field], allowed, f"{prefix}.{field}")
        if "route_schema_version" in route and route["route_schema_version"] != 1:
            raise ValidationError(f"{prefix}.route_schema_version must equal 1")
        if "token_limit" in route:
            _nullable_positive_int(route["token_limit"], f"{prefix}.token_limit")
        if "concurrency_limit" in route:
            _positive_int(route["concurrency_limit"], f"{prefix}.concurrency_limit")
        if route.get("route_kind") == "control" and name not in {
            "parent_sol", "supervisor_terra_high"
        }:
            raise UnsafeOverrideError(f"{prefix} cannot add a control authority route")
        if route.get("identity_status") == "proven" and route.get("identity_evidence") == "unknown":
            raise ValidationError(f"{prefix}.identity_status proven requires identity_evidence")
        if route.get("capability_status") in {"proven", "partially_proven"} and (
            route.get("capability_evidence") == "unknown"
        ):
            raise ValidationError(f"{prefix}.capability_status requires capability_evidence")

    for name, profile in profiles.items():
        prefix = f"route_registry.task_profiles.{name}"
        if "profile_schema_version" in profile and (
            profile["profile_schema_version"] != TASK_PROFILE_SCHEMA_VERSION
        ):
            raise ValidationError(
                f"{prefix}.profile_schema_version must equal {TASK_PROFILE_SCHEMA_VERSION}"
            )
        if "billing_ceiling" in profile and profile["billing_ceiling"] != "non_metered":
            raise UnsafeOverrideError(f"{prefix}.billing_ceiling cannot permit metered billing")
        seen: set[str] = set()
        none_seen = False
        for field in PROFILE_ROUTE_FIELDS:
            if field not in profile:
                continue
            route_name = profile[field]
            if route_name == "none":
                none_seen = True
                continue
            if none_seen:
                raise ValidationError(f"{prefix}.{field} cannot follow an empty secondary slot")
            if route_name not in all_routes:
                raise ValidationError(f"{prefix}.{field} references unknown route {route_name}")
            if route_name in seen:
                raise ValidationError(f"{prefix}.{field} duplicates route {route_name}")
            route = routes.get(route_name, ROUTE_DEFAULTS.get(route_name, {}))
            if route.get("route_kind") != "worker":
                raise UnsafeOverrideError(f"{prefix}.{field} cannot select a control route")
            seen.add(route_name)
        if profile.get("primary_route") == "none":
            raise ValidationError(f"{prefix}.primary_route cannot be none")


def validate_route_registry_layer(value: dict[str, Any]) -> None:
    """Prevent configuration from self-attesting routes or weakening shipped profiles."""
    registry = value.get("route_registry")
    if not isinstance(registry, dict):
        return
    routes = registry.get("routes", {})
    immutable_fields = {
        "route_kind", "provider", "exact_model", "route_id", "runtime", "reasoning",
        "billing_basis", "availability", "health", "authentication", "identity_status",
        "capability_status", "source_access", "input_delivery", "commands_executable",
        "quota_observability",
        "local_file_access", "browser_access", "web_search_access", "connector_access",
        "write_access", "recommended_role", "consequence_floor", "independence_group",
        "identity_evidence", "capability_evidence", "escalation_policy",
    }
    if isinstance(routes, dict):
        for name, route in routes.items():
            if not isinstance(route, dict):
                continue
            baseline = ROUTE_DEFAULTS.get(name)
            if (
                isinstance(baseline, dict)
                and baseline.get("escalation_policy") == "explicit_only"
                and route.get("enabled") is True
            ):
                raise UnsafeOverrideError(
                    f"route_registry.routes.{name}.enabled blocked by explicit escalation policy"
                )
            if baseline is None:
                for field in (
                    "exact_model", "route_id", "runtime", "billing_basis", "availability",
                    "health", "authentication", "identity_status", "capability_status", "source_access",
                    "quota_observability",
                    "input_delivery", "commands_executable", "local_file_access",
                    "browser_access", "web_search_access", "connector_access", "write_access",
                ):
                    if route.get(field, "unknown") not in {"unknown", "unverified"}:
                        raise UnsafeOverrideError(
                            f"route_registry.routes.{name}.{field} requires runtime evidence, not configuration"
                        )
                if route.get("route_kind", "worker") != "worker":
                    raise UnsafeOverrideError(
                        f"route_registry.routes.{name} cannot add control authority"
                    )
                continue
            for field in immutable_fields & set(route):
                if route[field] != baseline[field]:
                    raise UnsafeOverrideError(
                        f"route_registry.routes.{name}.{field} is evidence-owned and cannot be overridden"
                    )

    profiles = registry.get("task_profiles", {})
    if isinstance(profiles, dict):
        for name, profile in profiles.items():
            if not isinstance(profile, dict):
                continue
            baseline = TASK_PROFILE_DEFAULTS.get(name)
            if baseline is None:
                continue
            for field in set(profile):
                if profile[field] != baseline[field]:
                    raise UnsafeOverrideError(
                        f"route_registry.task_profiles.{name}.{field} is policy-owned and cannot be overridden"
                    )


def validate_adapter_registry_layer(value: dict[str, Any]) -> None:
    """Configuration may add bindings but cannot provide evidence or adapter code."""
    registry = value.get("adapter_registry")
    if not isinstance(registry, dict):
        return
    forbidden_root = sorted(set(registry) - {"bindings"})
    if forbidden_root:
        raise UnsafeOverrideError(
            f"adapter_registry.{forbidden_root[0]} is package-owned"
        )
    bindings = registry.get("bindings", {})
    if not isinstance(bindings, dict):
        return

    def scan(candidate: Any, path: str, *, binding_root: bool = False) -> None:
        if not isinstance(candidate, dict):
            return
        for field, item in candidate.items():
            field_path = f"{path}.{field}"
            token_cap_field = binding_root and field == "token_cap"
            credential_field = binding_root and field == "credential_reference"
            if ADAPTER_REGISTRY.FORBIDDEN_FIELD_RE.search(field) and not (
                token_cap_field or credential_field
            ):
                raise UnsafeOverrideError(f"{field_path} cannot configure transport or secrets")
            if credential_field:
                if not isinstance(item, dict) or set(item) != {
                    "kind", "opaque_id", "reference_sha256"
                }:
                    raise UnsafeOverrideError(
                        f"{field_path} must remain the closed opaque reference shape"
                    )
            if field in {
                "certificate_sha256", "preflight_sha256", "capability_sha256",
                "evaluation_sha256", "bound_adapter_binding_sha256", "issued_at",
                "expires_at", "ttl_seconds", "recall_sha256", "recalled_at",
            } and item is not None:
                raise UnsafeOverrideError(f"{field_path} is qualification-evidence-owned")
            if field == "status" and item != "configured":
                raise UnsafeOverrideError(f"{field_path} must remain configured")
            if field in {"retry_allowed", "fallback_allowed"} and item is not False:
                raise UnsafeOverrideError(f"{field_path} cannot enable automatic recovery")
            if field in {"billing_observation", "usage_observation", "cost_observation"} and item != "unknown":
                raise UnsafeOverrideError(f"{field_path} must preserve unknown")
            if isinstance(item, str) and ADAPTER_REGISTRY.SECRET_VALUE_RE.search(item):
                raise UnsafeOverrideError(f"{field_path} contains a secret-like or location-like value")
            scan(item, field_path)

    for name, binding in bindings.items():
        scan(binding, f"adapter_registry.bindings.{name}", binding_root=True)


def validate_adapter_registry_routes(
    registry: dict[str, Any], route_registry: dict[str, Any]
) -> None:
    routes = route_registry["routes"]
    profile_digests = {
        ADAPTER_REGISTRY.canonical_digest(profile)
        for profile in route_registry["task_profiles"].values()
    }
    identity_fields = (
        "provider", "route_id", "runtime", "reasoning",
        "billing_basis", "independence_group",
    )
    for name, binding in registry["bindings"].items():
        route_identity = binding["route"]
        route_name = route_identity["route_name"]
        route = routes.get(route_name)
        if route is None or route.get("route_kind") != "worker":
            raise ValidationError(
                f"adapter_registry.bindings.{name}.route references a non-worker or unknown route"
            )
        for field in identity_fields:
            if route_identity[field] != route[field]:
                raise UnsafeOverrideError(
                    f"adapter_registry.bindings.{name}.route.{field} must match route registry"
                )
        # The approved route supplies the transport and immutable runtime
        # identity. Only a generic transport route can receive a new exact
        # model. A model-specific route cannot be relabeled as another model.
        if not isinstance(route_identity["exact_model"], str) or not route_identity["exact_model"]:
            raise ValidationError(
                f"adapter_registry.bindings.{name}.route.exact_model must be a non-empty exact model"
            )
        if route["exact_model"] == "unknown":
            if route_identity["exact_model"] in {"unknown", "unverified"}:
                raise ValidationError(
                    f"adapter_registry.bindings.{name}.route.exact_model must resolve the generic route"
                )
        elif route_identity["exact_model"] != route["exact_model"]:
            raise UnsafeOverrideError(
                f"adapter_registry.bindings.{name}.route.exact_model cannot relabel a model-specific route"
            )
        if binding["task_profile_sha256"] not in profile_digests:
            raise ValidationError(
                f"adapter_registry.bindings.{name}.task_profile_sha256 is unknown"
            )


def _profile_route_names(profile: dict[str, Any]) -> list[str]:
    return [profile[field] for field in PROFILE_ROUTE_FIELDS]


def validate_capability_preferences(
    preferences: dict[str, Any], *, route_registry: dict[str, Any], partial: bool,
) -> None:
    """Allow lane candidate reordering/subsets and lower user caps only."""
    if "schema_version" in preferences and preferences["schema_version"] != CAPABILITY_PREFERENCE_SCHEMA_VERSION:
        raise ValidationError(
            f"capability_preferences.schema_version must equal {CAPABILITY_PREFERENCE_SCHEMA_VERSION}"
        )
    lanes = preferences.get("lanes", {})
    if not isinstance(lanes, dict):
        raise ValidationError("capability_preferences.lanes must be a mapping")
    unknown = sorted(set(lanes) - set(LANE_NAMES))
    if unknown:
        raise ValidationError(f"unknown field: capability_preferences.lanes.{unknown[0]}")
    if not partial:
        missing = sorted(set(LANE_NAMES) - set(lanes))
        if missing:
            raise ValidationError(f"missing field: capability_preferences.lanes.{missing[0]}")
    routes = route_registry.get("routes", {})
    for lane_name, lane in lanes.items():
        prefix = f"capability_preferences.lanes.{lane_name}"
        if not isinstance(lane, dict):
            raise ValidationError(f"{prefix} must be a mapping")
        if "lane_schema_version" in lane and lane["lane_schema_version"] != CAPABILITY_PREFERENCE_SCHEMA_VERSION:
            raise ValidationError(f"{prefix}.lane_schema_version is unsupported")
        if "lane_profile" in lane and lane["lane_profile"] != lane_name:
            raise UnsafeOverrideError(f"{prefix}.lane_profile is policy-owned")
        if "user_concurrency_limit" in lane:
            _positive_int(lane["user_concurrency_limit"], f"{prefix}.user_concurrency_limit")
            if lane["user_concurrency_limit"] > CAPABILITY_PREFERENCE_DEFAULTS[lane_name]["user_concurrency_limit"]:
                raise UnsafeOverrideError(f"{prefix}.user_concurrency_limit cannot raise concurrency")
        allowed = set(_lane_candidate_defaults(lane_name))
        seen: set[str] = set()
        none_seen = False
        for field in ROLE_ROUTE_FIELDS:
            if field not in lane:
                continue
            route_name = lane[field]
            if route_name == "none":
                none_seen = True
                continue
            if none_seen:
                raise ValidationError(f"{prefix}.{field} cannot follow an empty route slot")
            if route_name in seen:
                raise ValidationError(f"{prefix}.{field} duplicates route {route_name}")
            route = routes.get(route_name, ROUTE_DEFAULTS.get(route_name, {}))
            if route.get("escalation_policy") == "explicit_only":
                raise UnsafeOverrideError(f"{prefix}.{field} cannot enable an escalation-only route")
            if route_name == "worker_qwopus_opencode":
                raise UnsafeOverrideError(f"{prefix}.{field} cannot release Qwopus")
            if route_name not in allowed:
                raise UnsafeOverrideError(f"{prefix}.{field} is not a compatible candidate")
            if route.get("route_kind") != "worker":
                raise UnsafeOverrideError(f"{prefix}.{field} cannot select a control route")
            seen.add(route_name)
        if lane.get("route_01") == "none":
            raise ValidationError(f"{prefix}.route_01 cannot be none")


def validate_role_preferences(value: dict[str, Any], *, partial: bool) -> None:
    prefs = value.get("role_preferences")
    if prefs is None:
        return
    if not isinstance(prefs, dict):
        raise ValidationError("role_preferences must be a mapping")
    unknown_fields = sorted(set(prefs) - {"schema_version", "roles", "controller"})
    if unknown_fields:
        raise ValidationError(f"unknown field: role_preferences.{unknown_fields[0]}")
    if prefs.get("schema_version", ROLE_PREFERENCE_SCHEMA_VERSION) != ROLE_PREFERENCE_SCHEMA_VERSION:
        raise ValidationError(f"role_preferences.schema_version must equal {ROLE_PREFERENCE_SCHEMA_VERSION}")
    roles = prefs.get("roles", {})
    if not isinstance(roles, dict):
        raise ValidationError("role_preferences.roles must be a mapping")
    unknown_roles = sorted(set(roles) - set(ROLE_NAMES))
    if unknown_roles:
        raise ValidationError(f"unknown field: role_preferences.roles.{unknown_roles[0]}")
    if not partial:
        missing_roles = sorted(set(ROLE_NAMES) - set(roles))
        if missing_roles:
            raise ValidationError(f"missing field: role_preferences.roles.{missing_roles[0]}")
    for role, entry in roles.items():
        prefix = f"role_preferences.roles.{role}"
        if not isinstance(entry, dict):
            raise ValidationError(f"{prefix} must be a mapping")
        allowed_fields = {"selection_mode", "exact_model", "reasoning_effort"}
        unknown_entry = sorted(set(entry) - allowed_fields)
        if unknown_entry:
            raise ValidationError(f"unknown field: {prefix}.{unknown_entry[0]}")
        mode = entry.get("selection_mode", "default")
        _enum(mode, {"default", "prefer", "exact"}, f"{prefix}.selection_mode")
        for field in ("exact_model", "reasoning_effort"):
            if field in entry and (not isinstance(entry[field], str) or not entry[field].strip()):
                raise ValidationError(f"{prefix}.{field} must be a non-empty string")
        if mode == "exact" and not partial and entry.get("exact_model", "").strip() in {"", "unknown", "unset", "unverified"}:
            raise ValidationError(f"{prefix}.exact_model required for exact selection_mode")
    controller = prefs.get("controller")
    if controller is not None:
        if not isinstance(controller, dict):
            raise ValidationError("role_preferences.controller must be a mapping")
        allowed_fields = {"selection_mode", "exact_model", "reasoning_effort"}
        unknown_controller = sorted(set(controller) - allowed_fields)
        if unknown_controller:
            raise ValidationError(f"unknown field: role_preferences.controller.{unknown_controller[0]}")
        mode = controller.get("selection_mode", "default")
        _enum(mode, {"default", "prefer", "exact"}, "role_preferences.controller.selection_mode")
        for field in ("exact_model", "reasoning_effort"):
            if field in controller and (not isinstance(controller[field], str) or not controller[field].strip()):
                raise ValidationError(f"role_preferences.controller.{field} must be a non-empty string")
        if mode == "exact" and not partial and controller.get("exact_model", "").strip() in {"", "unknown", "unset", "unverified"}:
            raise ValidationError("role_preferences.controller.exact_model required for exact selection_mode")

def _assert_capability_model_matches_package(
    candidate: dict[str, Any], *, partial: bool, path: str = "capability_model"
) -> None:
    """Keep capability potential and authority semantics package-owned."""
    def walk(value: Any, baseline: Any, current_path: str) -> None:
        if isinstance(value, dict):
            if not isinstance(baseline, dict):
                raise UnsafeOverrideError(f"{current_path} is package-owned")
            for key, item in value.items():
                if key not in baseline:
                    raise ValidationError(f"unknown field: {current_path}.{key}")
                walk(item, baseline[key], f"{current_path}.{key}")
            return
        if value != baseline:
            raise UnsafeOverrideError(f"{current_path} is package-owned")

    walk(candidate, CAPABILITY_MODEL_DEFAULTS, path)
    if not partial and candidate != CAPABILITY_MODEL_DEFAULTS:
        raise UnsafeOverrideError("capability_model must remain package-owned")


def validate_capability_model(value: dict[str, Any], *, partial: bool) -> None:
    model = value.get("capability_model")
    if model is None:
        return
    if not isinstance(model, dict):
        raise ValidationError("capability_model must be a mapping")
    _assert_capability_model_matches_package(model, partial=partial)


def capability_preference_receipt(effective_config: dict[str, Any]) -> dict[str, Any]:
    lanes = effective_config["capability_preferences"]["lanes"]
    return {
        "schema_version": CAPABILITY_PREFERENCE_SCHEMA_VERSION,
        "lanes": {
            name: {
                "lane_profile": name,
                "required_primitives": copy.deepcopy(
                    ADAPTER_REGISTRY.LANE_PROFILES[name]["required_primitives"]
                ),
                "ordered_compatible_candidates": [
                    lane[field] for field in ROLE_ROUTE_FIELDS if lane[field] != "none"
                ],
                "user_concurrency_limit": lane["user_concurrency_limit"],
            }
            for name, lane in lanes.items()
        },
        "configuration_can_qualify": False,
        "configuration_can_grant_capability": False,
        "eligibility_granted": False,
        "authority_granted": False,
        "provider_called": False,
        "execution_started": False,
        "acceptance_granted": False,
    }


def validate_headless_dispatch(
    headless: dict[str, Any],
    *,
    route_registry: dict[str, Any],
    partial: bool,
) -> None:
    if "schema_version" in headless and (
        headless["schema_version"] != HEADLESS_DISPATCH_SCHEMA_VERSION
    ):
        raise ValidationError(
            f"headless_dispatch.schema_version must equal {HEADLESS_DISPATCH_SCHEMA_VERSION}"
        )
    priorities = headless.get("role_priorities", {})
    if not isinstance(priorities, dict):
        raise ValidationError("headless_dispatch.role_priorities must be a mapping")
    unknown_roles = sorted(set(priorities) - set(ROLE_NAMES))
    if unknown_roles:
        raise ValidationError(
            f"unknown field: headless_dispatch.role_priorities.{unknown_roles[0]}"
        )
    if not partial:
        missing_roles = sorted(set(ROLE_NAMES) - set(priorities))
        if missing_roles:
            raise ValidationError(
                f"missing field: headless_dispatch.role_priorities.{missing_roles[0]}"
            )

    role_schema = next(iter(ROLE_PRIORITY_DEFAULTS.values()))
    _validate_named_mapping(
        priorities,
        role_schema,
        path="headless_dispatch.role_priorities",
        partial=partial,
    )
    routes = route_registry.get("routes", {})
    profiles = route_registry.get("task_profiles", {})
    all_routes = copy.deepcopy(ROUTE_DEFAULTS)
    for name, route in routes.items():
        all_routes.setdefault(name, {}).update(route)
    all_profiles = copy.deepcopy(TASK_PROFILE_DEFAULTS)
    for name, profile in profiles.items():
        all_profiles.setdefault(name, {}).update(profile)
    for role, priority in priorities.items():
        prefix = f"headless_dispatch.role_priorities.{role}"
        if "role_schema_version" in priority and (
            priority["role_schema_version"] != HEADLESS_DISPATCH_SCHEMA_VERSION
        ):
            raise ValidationError(
                f"{prefix}.role_schema_version must equal {HEADLESS_DISPATCH_SCHEMA_VERSION}"
            )
        profile_name = priority.get("task_profile")
        if profile_name is not None and profile_name not in all_profiles:
            raise ValidationError(f"{prefix}.task_profile references unknown profile {profile_name}")
        expected_profile = ROLE_PRIORITY_DEFAULTS[role]["task_profile"]
        if profile_name is not None and profile_name != expected_profile:
            raise UnsafeOverrideError(
                f"{prefix}.task_profile must remain {expected_profile}"
            )

        seen: set[str] = set()
        none_seen = False
        for field in ROLE_ROUTE_FIELDS:
            if field not in priority:
                continue
            route_name = priority[field]
            if route_name == "none":
                none_seen = True
                continue
            if none_seen:
                raise ValidationError(f"{prefix}.{field} cannot follow an empty route slot")
            if route_name in seen:
                raise ValidationError(f"{prefix}.{field} duplicates route {route_name}")
            route = all_routes.get(route_name)
            if route is None:
                raise ValidationError(f"{prefix}.{field} references unknown route {route_name}")
            if route.get("route_kind") != "worker":
                raise UnsafeOverrideError(f"{prefix}.{field} cannot select a control route")
            seen.add(route_name)
        if priority.get("route_01") == "none":
            raise ValidationError(f"{prefix}.route_01 cannot be none")

        if profile_name is not None:
            allowed = set(_profile_route_names(all_profiles[profile_name])) - {"none"}
            external = sorted(seen - allowed)
            if external:
                raise UnsafeOverrideError(
                    f"{prefix} cannot select profile-external route {external[0]}"
                )


def registry_for_role(effective_config: dict[str, Any], role: str) -> dict[str, Any]:
    """Return a validated copied registry with one semantic role order applied."""
    validate_config(effective_config, partial=False)
    if role not in ROLE_NAMES:
        raise ValidationError(f"unknown headless dispatch role: {role}")
    priority = effective_config["headless_dispatch"]["role_priorities"][role]
    registry = copy.deepcopy(effective_config["route_registry"])
    profile = registry["task_profiles"][priority["task_profile"]]
    ordered = [priority[field] for field in ROLE_ROUTE_FIELDS]
    profile["primary_route"] = ordered[0]
    for index, route_name in enumerate(ordered[1:], start=1):
        profile[f"secondary_{index:02d}"] = route_name
    validate_route_registry(registry, partial=False)
    return registry


def semantic_task_profile(
    effective_config: dict[str, Any], role: str, *, mutation_mode: str = "artifact_only"
) -> str:
    """Resolve a semantic role to a task profile from the effective policy."""
    validate_config(effective_config, partial=False)
    if role not in ROLE_NAMES:
        raise ValidationError(f"unknown semantic role: {role}")
    if role == "worker" and mutation_mode == "scoped_write":
        return effective_config["scheduler"]["mutation_task_profiles"]["worker_scoped_write"]
    return effective_config["scheduler"]["task_class_profiles"][role]


def registry_for_scheduler_role(
    effective_config: dict[str, Any], role: str, *, selected_route: str | None = None
) -> tuple[dict[str, Any], str]:
    """Return the artifact-only scheduler profile with operator route order."""
    validate_config(effective_config, partial=False)
    if role not in ROLE_NAMES:
        raise ValidationError(f"unknown scheduler role: {role}")
    profile_name = semantic_task_profile(effective_config, role)
    registry = copy.deepcopy(effective_config["route_registry"])
    profile = registry["task_profiles"][profile_name]
    ordered = _profile_route_names(profile)
    if selected_route is not None:
        if selected_route not in ordered or selected_route == "none":
            raise UnsafeOverrideError(
                f"scheduler selected route {selected_route} incompatible with {profile_name}"
            )
        ordered = [selected_route, *("none" for _ in range(len(ROLE_ROUTE_FIELDS) - 1))]
    profile["primary_route"] = ordered[0]
    for index, route_name in enumerate(ordered[1:], start=1):
        profile[f"secondary_{index:02d}"] = route_name
    validate_route_registry(registry, partial=False)
    return registry, profile_name


def validate_scheduler(
    scheduler: dict[str, Any],
    *,
    route_registry: dict[str, Any],
    partial: bool,
) -> None:
    """Validate the non-executing scheduler policy and immutable task classes."""
    if "schema_version" in scheduler and scheduler["schema_version"] != SCHEDULER_SCHEMA_VERSION:
        raise ValidationError(
            f"scheduler.schema_version must equal {SCHEDULER_SCHEMA_VERSION}"
        )
    positive_fields = (
        "default_preflight_ttl_seconds", "maximum_preflight_ttl_seconds",
        "maximum_queue_age_seconds", "lease_ttl_seconds",
        "provider_concurrency_default", "runtime_host_concurrency_default",
        "diversity_min_quality_observations",
    )
    for field in positive_fields:
        if field in scheduler:
            _positive_int(scheduler[field], f"scheduler.{field}")
    for field in ("provider_concurrency_limits", "runtime_host_concurrency_limits"):
        limits = scheduler.get(field, {})
        if not isinstance(limits, dict):
            raise ValidationError(f"scheduler.{field} must be a mapping")
        for name, limit in limits.items():
            if not isinstance(name, str) or not name:
                raise ValidationError(f"scheduler.{field} keys must be non-empty strings")
            _positive_int(limit, f"scheduler.{field}.{name}")
    if scheduler.get("default_preflight_ttl_seconds", 60) > scheduler.get(
        "maximum_preflight_ttl_seconds", 300
    ):
        raise UnsafeOverrideError("scheduler default preflight TTL exceeds maximum")
    if scheduler.get("maximum_preflight_ttl_seconds", 300) > 300:
        raise UnsafeOverrideError("scheduler maximum preflight TTL cannot exceed 300 seconds")
    if scheduler.get("activation", "explicit_only") != "explicit_only":
        raise UnsafeOverrideError("scheduler activation must remain explicit_only")
    if scheduler.get("hedging_enabled") is True:
        raise UnsafeOverrideError("scheduler hedging is not qualified")
    if "direct_repository_writes_enabled" in scheduler and type(scheduler["direct_repository_writes_enabled"]) is not bool:
        raise ValidationError("scheduler.direct_repository_writes_enabled must be a boolean")
    if scheduler.get("artifact_quality_policy", "provider_neutral_result_v1") not in {
        "provider_neutral_result_v1", "markdown_sections_v1", "json_object_v1",
        "opaque_nonempty_v1",
    }:
        raise ValidationError("scheduler.artifact_quality_policy is unknown")
    if scheduler.get("unknown_cost_policy", "preserve_unknown_and_reject_cash") != (
        "preserve_unknown_and_reject_cash"
    ):
        raise UnsafeOverrideError("scheduler must preserve unknown cost and reject required cash")

    displacement = scheduler.get("role_rank_displacement", {})
    if not isinstance(displacement, dict):
        raise ValidationError("scheduler.role_rank_displacement must be a mapping")
    unknown_roles = sorted(set(displacement) - set(ROLE_NAMES))
    if unknown_roles:
        raise ValidationError(
            f"unknown field: scheduler.role_rank_displacement.{unknown_roles[0]}"
        )
    if not partial:
        missing_roles = sorted(set(ROLE_NAMES) - set(displacement))
        if missing_roles:
            raise ValidationError(
                f"missing field: scheduler.role_rank_displacement.{missing_roles[0]}"
            )
    for role, value in displacement.items():
        if not _is_int(value) or value < 0 or value > 1:
            raise UnsafeOverrideError(
                f"scheduler.role_rank_displacement.{role} must be 0 or 1"
            )
        if role in {"planner", "architect"} and value != 0:
            raise UnsafeOverrideError(
                f"scheduler.role_rank_displacement.{role} must remain 0"
            )

    task_profiles = scheduler.get("task_class_profiles", {})
    if not isinstance(task_profiles, dict):
        raise ValidationError("scheduler.task_class_profiles must be a mapping")
    unknown_task_roles = sorted(set(task_profiles) - set(ROLE_NAMES))
    if unknown_task_roles:
        raise ValidationError(
            f"unknown field: scheduler.task_class_profiles.{unknown_task_roles[0]}"
        )
    if not partial:
        missing_roles = sorted(set(ROLE_NAMES) - set(task_profiles))
        if missing_roles:
            raise ValidationError(
                f"missing field: scheduler.task_class_profiles.{missing_roles[0]}"
            )
    available_profiles = set(TASK_PROFILE_DEFAULTS) | set(route_registry.get("task_profiles", {}))
    for role, profile in task_profiles.items():
        if profile not in available_profiles:
            raise ValidationError(
                f"scheduler.task_class_profiles.{role} references unknown profile {profile}"
            )
        expected = DEFAULTS["scheduler"]["task_class_profiles"][role]
        if profile != expected:
            raise UnsafeOverrideError(
                f"scheduler.task_class_profiles.{role} must remain {expected}"
            )
    mutation_profiles = scheduler.get("mutation_task_profiles")
    if mutation_profiles is not None and mutation_profiles != {
        "worker_scoped_write": "semantic_worker_implementation"
    }:
        raise UnsafeOverrideError(
            "scheduler.mutation_task_profiles must keep the scoped Worker profile"
        )


def validate_config(value: dict[str, Any], *, partial: bool) -> None:
    def walk(candidate: dict[str, Any], schema: dict[str, Any], prefix: str = "") -> None:
        unknown = sorted(set(candidate) - set(schema))
        if unknown:
            path = f"{prefix}.{unknown[0]}" if prefix else unknown[0]
            raise ValidationError(f"unknown field: {path}")
        if not partial:
            missing = sorted(set(schema) - set(candidate))
            if missing:
                path = f"{prefix}.{missing[0]}" if prefix else missing[0]
                raise ValidationError(f"missing field: {path}")
        for key, item in candidate.items():
            path = f"{prefix}.{key}" if prefix else key
            expected = schema[key]
            if isinstance(expected, dict):
                if not isinstance(item, dict):
                    raise ValidationError(f"{path} must be a mapping")
                if path == "route_registry.routes":
                    _validate_named_mapping(
                        item, next(iter(ROUTE_DEFAULTS.values())), path=path, partial=partial
                    )
                    continue
                if path == "route_registry.task_profiles":
                    _validate_named_mapping(
                        item, next(iter(TASK_PROFILE_DEFAULTS.values())), path=path, partial=partial
                    )
                    continue
                if path == "headless_dispatch.role_priorities":
                    _validate_named_mapping(
                        item,
                        next(iter(ROLE_PRIORITY_DEFAULTS.values())),
                        path=path,
                        partial=partial,
                    )
                    continue
                if path == "adapter_registry.adapters":
                    _validate_named_mapping(
                        item,
                        next(iter(ADAPTER_REGISTRY.APPROVED_ADAPTER_CARDS.values())),
                        path=path,
                        partial=partial,
                    )
                    continue
                if path == "adapter_registry.bindings":
                    binding_schema = copy.deepcopy(
                        next(iter(ADAPTER_REGISTRY_DEFAULTS["bindings"].values()))
                    )
                    binding_schema["concurrency_cap"] = None
                    _validate_named_mapping(
                        item,
                        binding_schema,
                        path=path,
                        partial=partial,
                    )
                    continue
                if path == "capability_preferences.lanes":
                    _validate_named_mapping(
                        item,
                        next(iter(CAPABILITY_PREFERENCE_DEFAULTS.values())),
                        path=path,
                        partial=partial,
                    )
                    continue
                walk(item, expected, path)
            else:
                _same_type(item, expected, path)
    walk(value, DEFAULTS)

    validate_capability_model(value, partial=partial)

    if "capability_preferences" in value:
        registry = copy.deepcopy(DEFAULTS["route_registry"])
        supplied_registry = value.get("route_registry", {})
        for section in ("routes", "task_profiles"):
            for name, row in supplied_registry.get(section, {}).items():
                registry[section].setdefault(name, {}).update(row)
        validate_capability_preferences(
            value["capability_preferences"], route_registry=registry, partial=partial
        )

    validate_role_preferences(value, partial=partial)

    if "schema_version" in value and value["schema_version"] != CURRENT_SCHEMA_VERSION:
        raise ValidationError(f"schema_version must equal {CURRENT_SCHEMA_VERSION} after migration")
    journey = value.get("journey", {})
    if "mode" in journey and journey["mode"] != "guided":
        raise ValidationError("journey.mode must equal guided")
    if "question_batch_max" in journey:
        _positive_int(journey["question_batch_max"], "journey.question_batch_max")
        if journey["question_batch_max"] > 3:
            raise UnsafeOverrideError("journey.question_batch_max cannot exceed 3")
    if "resume_existing" in journey and journey["resume_existing"] != "prompt":
        raise UnsafeOverrideError("journey.resume_existing cannot bypass the conflict prompt")

    execution = value.get("execution", {})
    for key in (
        "default_active_workers", "max_write_workers", "max_turns_safety_ceiling",
        "max_attempts_per_checkpoint", "no_improvement_window",
    ):
        if key in execution:
            _positive_int(execution[key], f"execution.{key}")
    if execution.get("max_write_workers", 1) > BOARD_MAX_WRITE_WORKERS:
        raise UnsafeOverrideError(
            f"execution.max_write_workers exceeds board ceiling {BOARD_MAX_WRITE_WORKERS}"
        )
    hard_execution_ceilings = {
        "max_turns_safety_ceiling": 20,
        "max_attempts_per_checkpoint": 3,
        "no_improvement_window": 2,
    }
    for key, ceiling in hard_execution_ceilings.items():
        if execution.get(key, ceiling) > ceiling:
            raise UnsafeOverrideError(f"execution.{key} cannot exceed safety ceiling {ceiling}")

    budgets = value.get("budgets", {})
    if "token_limit" in budgets:
        _nullable_positive_int(budgets["token_limit"], "budgets.token_limit")
    if "hard_spend_limit_usd" in budgets:
        spend = budgets["hard_spend_limit_usd"]
        if spend is not None and (
            isinstance(spend, bool) or not isinstance(spend, (int, float)) or spend <= 0
        ):
            raise ValidationError("budgets.hard_spend_limit_usd must be null or positive")
    if "unknown_usage_policy" in budgets and budgets["unknown_usage_policy"] != "preserve_unknown":
        raise UnsafeOverrideError("missing usage must remain unknown")
    if budgets.get("record_usage_when_exposed") is False:
        raise UnsafeOverrideError("exposed usage must remain recorded")

    routing = value.get("routing", {})
    if routing.get("silent_metered_fallback") is True:
        raise UnsafeOverrideError("silent metered fallback is forbidden")
    for route, route_value in routing.get("auxiliary", {}).items():
        if "token_limit" in route_value:
            _nullable_positive_int(route_value["token_limit"], f"routing.auxiliary.{route}.token_limit")
    commandcode = routing.get("auxiliary", {}).get("commandcode_deepseek", {})
    if "billing_policy" in commandcode and commandcode["billing_policy"] != "subscription_first":
        raise UnsafeOverrideError("CommandCode billing must remain subscription_first")
    minimax = routing.get("auxiliary", {}).get("standalone_minimax", {})
    for field, expected in {
        "model": "MiniMax-M3",
        "route_id": "standalone-minimax-m3",
        "billing_policy": "subscription_only",
    }.items():
        if field in minimax and minimax[field] != expected:
            raise UnsafeOverrideError(f"standalone_minimax.{field} cannot weaken the frozen route")

    registry = value.get("route_registry")
    if registry is not None:
        if not isinstance(registry, dict):
            raise ValidationError("route_registry must be a mapping")
        validate_route_registry(registry, partial=partial)

    adapter_registry = value.get("adapter_registry")
    if adapter_registry is not None and not partial:
        try:
            ADAPTER_REGISTRY.validate_registry(
                adapter_registry,
                evaluated_at="1970-01-01T00:00:00Z",
                configuration_only=True,
            )
        except ADAPTER_REGISTRY.AdapterRegistryError as exc:
            raise ValidationError(f"adapter registry invalid: {exc}") from exc
        validate_adapter_registry_routes(
            adapter_registry,
            value.get("route_registry", DEFAULTS["route_registry"]),
        )

    headless = value.get("headless_dispatch")
    if headless is not None:
        if not isinstance(headless, dict):
            raise ValidationError("headless_dispatch must be a mapping")
        validate_headless_dispatch(
            headless,
            route_registry=value.get("route_registry", DEFAULTS["route_registry"]),
            partial=partial,
        )

    scheduler = value.get("scheduler")
    if scheduler is not None:
        if not isinstance(scheduler, dict):
            raise ValidationError("scheduler must be a mapping")
        validate_scheduler(
            scheduler,
            route_registry=value.get("route_registry", DEFAULTS["route_registry"]),
            partial=partial,
        )

    if not partial:
        controls = value["route_registry"]["routes"]
        fixed = {
            ("parent_sol", "route_kind"): "control",
            ("supervisor_terra_high", "route_kind"): "control",
            ("supervisor_terra_high", "enabled"): False,
            ("supervisor_terra_high", "escalation_policy"): "explicit_only",
            ("worker_terra_high", "enabled"): False,
            ("worker_terra_high", "escalation_policy"): "explicit_only",
            ("worker_terra_medium", "enabled"): False,
            ("worker_terra_medium", "escalation_policy"): "explicit_only",
        }
        for (route_name, field), expected in fixed.items():
            if controls[route_name][field] != expected:
                raise UnsafeOverrideError(
                    f"route_registry.routes.{route_name}.{field} must remain {expected}"
                )

    authority = value.get("authority", {})
    allowed_authority = {
        "network": {"ask", "deny"},
        "external_model_calls": {"ask_unless_goal_authorized", "ask", "deny"},
        "installs": {"ask", "deny"},
        "destructive_changes": {"ask", "deny"},
        "push": {"ask", "deny"},
        "publish": {"ask", "deny"},
    }
    for key, item in authority.items():
        if item not in allowed_authority[key]:
            raise UnsafeOverrideError(f"authority.{key} cannot grant authorization")


def _leaf_items(value: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    result: list[tuple[str, Any]] = []
    for key in sorted(value):
        path = f"{prefix}.{key}" if prefix else key
        item = value[key]
        if isinstance(item, dict):
            result.extend(_leaf_items(item, path))
        else:
            result.append((path, item))
    return result


def _set_path(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cursor = target
    for part in parts[:-1]:
        child = cursor.get(part)
        if child is None:
            child = {}
            cursor[part] = child
        if not isinstance(child, dict):
            raise ValidationError(f"cannot merge mapping through scalar path {part}")
        cursor = child
    cursor[parts[-1]] = copy.deepcopy(value)


def resolve(layers: list[Layer]) -> dict[str, Any]:
    effective = copy.deepcopy(DEFAULTS)
    history: dict[str, list[dict[str, Any]]] = {}
    for path, value in _leaf_items(DEFAULTS):
        history[path] = [{
            "source": "defaults", "source_path": "built_in", "lifetime": "plugin",
            "active": True, "effective": True, "value": value,
        }]
    for layer in layers:
        validate_config(layer.value, partial=True)
        validate_route_registry_layer(layer.value)
        validate_adapter_registry_layer(layer.value)
        for path, value in _leaf_items(layer.value):
            row = {
                "source": layer.name,
                "source_path": layer.path,
                "lifetime": layer.lifetime,
                "active": layer.active,
                "effective": False,
                "value": value,
            }
            if layer.inactive_reason:
                row["inactive_reason"] = layer.inactive_reason
            history.setdefault(path, []).append(row)
            if layer.active:
                for previous in history[path]:
                    previous["effective"] = False
                row["effective"] = True
                _set_path(effective, path, value)
    validate_config(effective, partial=False)
    provenance = {
        path: next(row for row in reversed(rows) if row["effective"])
        for path, rows in sorted(history.items())
    }
    return {
        "schema_version": CURRENT_SCHEMA_VERSION,
        "effective_config": effective,
        "provenance": provenance,
        "history": {path: rows for path, rows in sorted(history.items())},
        "hard_constraints": HARD_CONSTRAINTS,
        "migrations": [layer.migration for layer in layers if layer.migration is not None],
        "route_registry_receipt": {
            "registry_version": effective["route_registry"]["registry_version"],
            "route_count": len(effective["route_registry"]["routes"]),
            "task_profile_count": len(effective["route_registry"]["task_profiles"]),
            "fresh_preflight_required": True,
            "availability_claimed_by_config": False,
            "current_health_observed": "unknown",
            "selection_executed": False,
        },
        "adapter_registry_receipt": {
            "registry_sha256": effective["adapter_registry"]["registry_sha256"],
            "configured_binding_count": len(effective["adapter_registry"]["bindings"]),
            "qualified_binding_count": 0,
            "configuration_can_qualify": False,
            "credentials_resolved": False,
            "provider_called": False,
            "execution_started": False,
            "eligibility_granted": False,
            "authority_granted": False,
            "acceptance_granted": False,
        },
        "capability_preference_receipt": capability_preference_receipt(effective),
        "usage_semantics": {
            "configured_token_limit": effective["budgets"]["token_limit"],
            "observed_token_usage": "unknown",
            "null_disables_safety_controls": False,
        },
        "execution_started": False,
    }


def _layer(
    name: str, path: Path | None, lifetime: str, active: bool = True,
    reason: str | None = None, repository_root: Path | None = None,
) -> Layer | None:
    if path is None:
        return None
    migrated, receipt = migrate_config(
        load_config(path, repository_root), source=str(path)
    )
    resolved_path = str(path)
    return Layer(name, resolved_path, lifetime, active, reason, migrated, receipt)


def build_layers(args: argparse.Namespace) -> list[Layer]:
    layers: list[Layer] = []
    repository_root = _canonical_repository_root(args.repo_root)
    workspace = _layer(
        "workspace", args.workspace_config, "file", repository_root=repository_root
    )
    if workspace:
        layers.append(workspace)
    repo_path = repository_root / "codexmax.config.yaml"
    if repo_path.exists() or repo_path.is_symlink():
        layers.append(_layer(
            "repository", repo_path, "file", repository_root=repository_root
        ))  # type: ignore[arg-type]
    # Adapter-binding authoring emits this stable repository-local overlay. Keep
    # it optional and deterministic: native defaults remain file-free, while a
    # configured binding becomes visible to ordinary resolution without a
    # second pointer. An explicit pointer to the same file must not duplicate
    # the layer or its provenance history.
    adapter_path = repository_root / "codexmax.adapters.yaml"
    explicit_workspace = (
        None if args.workspace_config is None
        else Path(os.path.realpath(args.workspace_config))
    )
    if (
        (adapter_path.exists() or adapter_path.is_symlink())
        and explicit_workspace != adapter_path
    ):
        layers.append(_layer(
            "repository_adapters", adapter_path, "file", repository_root=repository_root
        ))  # type: ignore[arg-type]
    goal_active = args.goal_override is not None and args.goal_id == args.active_goal_id
    goal_reason = None if goal_active else "expired_goal_or_identity_mismatch"
    goal = _layer(
        "goal", args.goal_override, f"goal:{args.goal_id or 'unknown'}",
        goal_active, goal_reason, repository_root,
    )
    if goal:
        layers.append(goal)
    goal_context_active = args.goal_override is None or goal_active
    checkpoint_active = (
        args.checkpoint_override is not None
        and goal_context_active
        and args.checkpoint_id == args.active_checkpoint_id
    )
    checkpoint_reason = None if checkpoint_active else "expired_checkpoint_or_identity_mismatch"
    checkpoint = _layer(
        "checkpoint", args.checkpoint_override,
        f"checkpoint:{args.checkpoint_id or 'unknown'}", checkpoint_active, checkpoint_reason,
        repository_root,
    )
    if checkpoint:
        layers.append(checkpoint)
    operator = _layer(
        "operator", args.operator_override, "current_invocation",
        repository_root=repository_root,
    )
    if operator:
        layers.append(operator)
    return layers


def human_show(receipt: dict[str, Any]) -> str:
    lines = ["Codexmax effective configuration"]
    for path, value in _leaf_items(receipt["effective_config"]):
        source = receipt["provenance"][path]
        lines.append(f"{path} = {json.dumps(value)} [{source['source']}; {source['lifetime']}]")
    lines.append("execution_started = false")
    return "\n".join(lines)


def roles_receipt(effective_config: dict[str, Any]) -> dict[str, Any]:
    rows = []
    used_routes: set[str] = set()
    for role in ROLE_NAMES:
        priority = effective_config["headless_dispatch"]["role_priorities"][role]
        used_routes.update(priority[field] for field in ROLE_ROUTE_FIELDS if priority[field] != "none")
        rows.append({
            "role": role,
            "task_profile": priority["task_profile"],
            **{field: priority[field] for field in ROLE_ROUTE_FIELDS},
        })
    routes = effective_config["route_registry"]["routes"]
    catalog_fields = (
        "provider", "exact_model", "reasoning", "billing_basis", "enabled",
        "identity_status", "capability_status", "health",
    )
    return {
        "schema_version": HEADLESS_DISPATCH_SCHEMA_VERSION,
        "roles": rows,
        "route_catalog": {
            route_name: {field: routes[route_name][field] for field in catalog_fields}
            for route_name in sorted(used_routes)
        },
        "execution_started": False,
    }


def human_roles(value: dict[str, Any]) -> str:
    headers = ("ROLE", "TASK_PROFILE", *(field.upper() for field in ROLE_ROUTE_FIELDS))
    rows = [
        (
            row["role"], row["task_profile"],
            *(row[field] for field in ROLE_ROUTE_FIELDS),
        )
        for row in value["roles"]
    ]
    widths = [max(len(headers[index]), *(len(row[index]) for row in rows)) for index in range(len(headers))]
    lines = ["  ".join(item.ljust(widths[index]) for index, item in enumerate(headers))]
    lines.extend("  ".join(item.ljust(widths[index]) for index, item in enumerate(row)) for row in rows)
    lines.append("route_catalog:")
    for route_name, route in value["route_catalog"].items():
        lines.append(
            f"  {route_name}: {route['provider']} / {route['exact_model']} / "
            f"reasoning={route['reasoning']} / enabled={str(route['enabled']).lower()} / "
            f"identity={route['identity_status']} / capability={route['capability_status']} / "
            f"health={route['health']}"
        )
    lines.append("execution_started = false")
    return "\n".join(lines)


def schedule_policy_receipt(effective_config: dict[str, Any]) -> dict[str, Any]:
    scheduler = effective_config["scheduler"]
    profiles = effective_config["route_registry"]["task_profiles"]
    return {
        "schema_version": SCHEDULER_SCHEMA_VERSION,
        "activation": scheduler["activation"],
        "global_active_limit": effective_config["execution"]["default_active_workers"],
        "write_limit": effective_config["execution"]["max_write_workers"],
        "write_ceiling": BOARD_MAX_WRITE_WORKERS,
        "provider_concurrency_default": scheduler["provider_concurrency_default"],
        "runtime_host_concurrency_default": scheduler["runtime_host_concurrency_default"],
        "provider_concurrency_limits": copy.deepcopy(
            scheduler["provider_concurrency_limits"]
        ),
        "runtime_host_concurrency_limits": copy.deepcopy(
            scheduler["runtime_host_concurrency_limits"]
        ),
        "preflight_ttl_seconds": scheduler["default_preflight_ttl_seconds"],
        "preflight_ttl_max_seconds": scheduler["maximum_preflight_ttl_seconds"],
        "maximum_queue_age_seconds": scheduler["maximum_queue_age_seconds"],
        "lease_ttl_seconds": scheduler["lease_ttl_seconds"],
        "diversity_min_quality_observations": scheduler["diversity_min_quality_observations"],
        "unknown_cost_policy": scheduler["unknown_cost_policy"],
        "artifact_quality_policy": scheduler["artifact_quality_policy"],
        "hedging_enabled": False,
        "direct_repository_writes_enabled": False,
        "roles": [
            {
                "role": role,
                "task_profile": scheduler["task_class_profiles"][role],
                "rank_displacement": scheduler["role_rank_displacement"][role],
                "ordered_routes": [
                    route_name
                    for route_name in _profile_route_names(
                        profiles[scheduler["task_class_profiles"][role]]
                    )
                    if route_name != "none"
                ],
            }
            for role in ROLE_NAMES
        ],
        "execution_started": False,
    }


def human_schedule_policy(value: dict[str, Any]) -> str:
    lines = [
        "Codexmax scheduler policy",
        f"activation = {value['activation']}",
        f"global_active_limit = {value['global_active_limit']}",
        f"write_limit = {value['write_limit']} (ceiling {value['write_ceiling']})",
        f"preflight_ttl_seconds = {value['preflight_ttl_seconds']} (max {value['preflight_ttl_max_seconds']})",
        f"maximum_queue_age_seconds = {value['maximum_queue_age_seconds']}",
        f"lease_ttl_seconds = {value['lease_ttl_seconds']}",
        f"artifact_quality_policy = {value['artifact_quality_policy']}",
        f"unknown_cost_policy = {value['unknown_cost_policy']}",
        "roles:",
    ]
    for row in value["roles"]:
        lines.append(
            f"  {row['role']}: profile={row['task_profile']} "
            f"displacement={row['rank_displacement']} routes={','.join(row['ordered_routes'])}"
        )
    lines.append("hedging_enabled = false")
    lines.append("direct_repository_writes_enabled = false")
    lines.append("execution_started = false")
    return "\n".join(lines)


def emit(value: Any, *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(value)


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace-config", type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--goal-override", type=Path)
    parser.add_argument("--goal-id")
    parser.add_argument("--active-goal-id")
    parser.add_argument("--checkpoint-override", type=Path)
    parser.add_argument("--checkpoint-id")
    parser.add_argument("--active-checkpoint-id")
    parser.add_argument("--operator-override", type=Path)
    parser.add_argument("--json", action="store_true")


def parser() -> argparse.ArgumentParser:
    root = ConfigArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("show", "validate", "roles", "schedule-policy"):
        add_common(commands.add_parser(name))
    explain = commands.add_parser("explain")
    explain.add_argument("key")
    add_common(explain)
    init = commands.add_parser("init")
    init.add_argument("--path", type=Path, default=Path("codexmax.config.yaml"))
    init.add_argument("--write", action="store_true")
    init.add_argument("--json", action="store_true")
    adapter_binding = commands.add_parser("adapter-binding")
    binding_commands = adapter_binding.add_subparsers(
        dest="binding_action", required=True
    )
    onboard = binding_commands.add_parser("onboard")
    onboard.add_argument("--repo-root", type=Path, default=Path.cwd())
    onboarding_choice = onboard.add_mutually_exclusive_group(required=True)
    onboarding_choice.add_argument("--native-only", action="store_true")
    onboarding_choice.add_argument(
        "--account", action="append", choices=tuple(ONBOARDING_ACCOUNT_BINDINGS)
    )
    onboard.add_argument("--token-cap", type=int, default=2400)
    onboard.add_argument("--write-new", action="store_true")
    onboard.add_argument("--json", action="store_true")
    add = binding_commands.add_parser("add")
    add.add_argument(
        "--input",
        type=Path,
        help="immutable prior adapter overlay to extend; the input is never modified",
    )
    add.add_argument("--output", type=Path, required=True)
    add.add_argument("--adapter-type", choices=ADAPTER_REGISTRY.ADAPTER_TYPES, required=True)
    add.add_argument("--route", required=True)
    add.add_argument(
        "--exact-model",
        help="exact model identifier for this approved transport (defaults to the route model)",
    )
    add.add_argument("--credential-kind", choices=ADAPTER_REGISTRY.REFERENCE_KINDS, required=True)
    add.add_argument("--opaque-id", required=True)
    add_enabled = add.add_mutually_exclusive_group(required=True)
    add_enabled.add_argument("--enabled", dest="enabled", action="store_true")
    add_enabled.add_argument("--disabled", dest="enabled", action="store_false")
    add.add_argument("--concurrency-cap", type=int)
    add.add_argument("--token-cap", type=int, required=True)
    add.add_argument("--write-new", action="store_true")
    add.add_argument("--json", action="store_true")
    update = binding_commands.add_parser("update")
    update.add_argument("--input", type=Path, required=True)
    update.add_argument("--output", type=Path, required=True)
    update.add_argument("--binding-id", required=True)
    update_enabled = update.add_mutually_exclusive_group()
    update_enabled.add_argument("--enabled", dest="enabled", action="store_true")
    update_enabled.add_argument("--disabled", dest="enabled", action="store_false")
    update.set_defaults(enabled=None)
    update_cap = update.add_mutually_exclusive_group()
    update_cap.add_argument("--concurrency-cap", type=int)
    update_cap.add_argument("--clear-concurrency-cap", action="store_true")
    update.add_argument("--token-cap", type=int)
    update.add_argument("--write-new", action="store_true")
    update.add_argument("--json", action="store_true")
    remove = binding_commands.add_parser("remove")
    remove.add_argument("--input", type=Path, required=True)
    remove.add_argument("--output", type=Path, required=True)
    remove.add_argument("--binding-id", required=True)
    remove.add_argument("--write-new", action="store_true")
    remove.add_argument("--json", action="store_true")
    explicit_route = commands.add_parser("explicit-route")
    explicit_commands = explicit_route.add_subparsers(
        dest="explicit_action", required=True
    )
    preview = explicit_commands.add_parser("preview")
    preview.add_argument("--request", required=True)
    preview.add_argument("--task-id", required=True)
    preview.add_argument("--task-grant-sha256", required=True)
    preview.add_argument("--probe-timeout-seconds", type=int, default=15)
    add_common(preview)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "adapter-binding":
            if args.binding_action == "onboard":
                result = author_onboarding_overlay(args)
            else:
                result = author_adapter_binding(args)
            if args.json:
                emit(result, json_output=True)
            elif args.binding_action == "onboard":
                if result["action"] == "native_only":
                    print("native Codex ready; configuration_written = false")
                else:
                    verb = "created" if result["candidate_created"] else "previewed"
                    print(
                        f"optional account overlay {verb}: "
                        f"{','.join(result['accounts'])} -> {result['output']}"
                    )
                    print("status = configured; authenticated = false; qualified = false")
            else:
                verb = "created" if result["candidate_created"] else "previewed"
                print(
                    f"adapter binding {result['action']} {verb}: "
                    f"{result['binding_id']} -> {result['output']}"
                )
                print("status = configured; execution_started = false")
            return EXIT_SUCCESS
        if args.command == "init":
            destination = args.path.resolve()
            if destination.exists():
                print(f"destination already exists: {destination}", file=sys.stderr)
                return EXIT_DESTINATION_EXISTS
            if not destination.parent.is_dir():
                print(f"parent directory does not exist: {destination.parent}", file=sys.stderr)
                return EXIT_INVOCATION_OR_IO
            template = TEMPLATE_PATH.read_text(encoding="utf-8")
            if args.write:
                try:
                    with destination.open("x", encoding="utf-8") as stream:
                        stream.write(template)
                except FileExistsError:
                    print(f"destination already exists: {destination}", file=sys.stderr)
                    return EXIT_DESTINATION_EXISTS
            result = {"action": "write" if args.write else "dry_run", "destination": str(destination), "created": args.write}
            emit(result if args.json else f"init {result['action']}: {destination}", json_output=args.json)
            return EXIT_SUCCESS

        receipt = resolve(build_layers(args))
        if args.command == "explicit-route":
            if args.probe_timeout_seconds < 1 or args.probe_timeout_seconds > 30:
                raise ValidationError("probe timeout must be from 1 through 30 seconds")
            result = EXPLICIT_TOOL_MODEL.compile_selection(
                args.request,
                task_id=args.task_id,
                task_grant_sha256=args.task_grant_sha256,
                effective_config=receipt["effective_config"],
                timeout_seconds=args.probe_timeout_seconds,
            )
            if args.json:
                emit(result, json_output=True)
            else:
                print(
                    f"preview: {result['requested_model']} through {result['tool']} "
                    f"-> {result['route_name']}"
                )
                print("session = verified; exact_model = verified; persistence = none")
                print("authority = task_grant_only; execution_started = false")
        elif args.command == "show":
            emit(receipt if args.json else human_show(receipt), json_output=args.json)
        elif args.command == "roles":
            result = roles_receipt(receipt["effective_config"])
            emit(result if args.json else human_roles(result), json_output=args.json)
        elif args.command == "schedule-policy":
            result = schedule_policy_receipt(receipt["effective_config"])
            emit(result if args.json else human_schedule_policy(result), json_output=args.json)
        elif args.command == "validate":
            result = {"valid": True, "execution_started": False}
            emit(result if args.json else "configuration valid; execution_started = false", json_output=args.json)
        else:
            if args.key not in receipt["provenance"]:
                raise ValidationError(f"unknown config leaf: {args.key}")
            result = {
                "key": args.key,
                "value": dict(_leaf_items(receipt["effective_config"]))[args.key],
                "effective": receipt["provenance"][args.key],
                "history": receipt["history"][args.key],
                "execution_started": False,
            }
            if args.json:
                emit(result, json_output=True)
            else:
                print(f"{args.key} = {json.dumps(result['value'])}")
                for row in result["history"]:
                    state = "effective" if row["effective"] else "history"
                    print(f"- {row['source']} ({row['lifetime']}): {json.dumps(row['value'])} [{state}]")
                print("execution_started = false")
        return EXIT_SUCCESS
    except DestinationExistsError as exc:
        print(f"destination already exists: {exc}", file=sys.stderr)
        return EXIT_DESTINATION_EXISTS
    except UnsafeOverrideError as exc:
        print(f"unsafe override: {exc}", file=sys.stderr)
        return EXIT_UNSAFE_OVERRIDE
    except (ParseError, ValidationError, EXPLICIT_TOOL_MODEL.ExplicitSelectionError) as exc:
        print(f"invalid configuration: {exc}", file=sys.stderr)
        return EXIT_INVALID_CONFIG
    except (ConfigError, OSError) as exc:
        print(f"invocation or I/O error: {exc}", file=sys.stderr)
        return EXIT_INVOCATION_OR_IO


if __name__ == "__main__":
    raise SystemExit(main())
