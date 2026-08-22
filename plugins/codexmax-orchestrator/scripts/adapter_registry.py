#!/usr/bin/env python3
"""Closed, non-executing Codexmax adapter registry validation.

Configuration selects package-owned adapter cards.  This module never loads an
adapter, resolves a credential reference, probes a provider, or starts work.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from typing import Any, Mapping


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "codexmax_adapter_registry_v1"
REGISTRY_REVISION = "builtin-v1"
ADAPTER_TYPES = (
    "native_codex",
    "claude_cli",
    "commandcode",
    "minimax_mmx",
    "minimax_mmx_tool_loop",
    "opencode_tool_loop",
    "grok_cli",
    "opencode_qwopus",
)
REFERENCE_KINDS = ("none", "host_managed", "external_profile")
QUALIFICATION_STATUSES = {
    "unconfigured", "configured", "qualification_required", "qualified",
    "expired", "stale", "recalled", "revoked", "unavailable",
    "qualification_failed", "execution_unknown",
}
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+~-]{0,127}$")
OPAQUE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
FORBIDDEN_FIELD_RE = re.compile(
    r"(?i)(?:argv|command|executable|endpoint|url|module|environment|env|path|"
    r"secret|token|password|credential|transport|socket|shell|provider_transport)"
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:bearer\s|api[_-]?key|password|passwd|secret|token|credential|"
    r"authorization|://|^/|^~|\\|\.\./|\$\{|\$[A-Z_])"
)
STATIC_EXECUTION_POLICY = {
    "shell": False,
    "arbitrary_argv": False,
    "arbitrary_url": False,
    "arbitrary_module": False,
    "arbitrary_environment": False,
}
ADAPTER_REFERENCE_KINDS = {
    "native_codex": ("none", "host_managed"),
    "claude_cli": ("none", "host_managed", "external_profile"),
    "commandcode": ("none", "host_managed", "external_profile"),
    "minimax_mmx": ("none", "host_managed", "external_profile"),
    "minimax_mmx_tool_loop": ("host_managed", "external_profile"),
    "opencode_tool_loop": ("host_managed", "external_profile"),
    "grok_cli": ("none", "host_managed", "external_profile"),
    "opencode_qwopus": ("none", "host_managed", "external_profile"),
}
ADAPTER_ROUTE_ALLOWLIST = {
    "native_codex": (
        "worker_sol_high", "worker_sol_medium", "worker_terra_high",
        "worker_terra_medium", "worker_luna_xhigh", "worker_codex_spark",
    ),
    "claude_cli": ("worker_claude_sonnet_5", "worker_claude_code_sonnet_5"),
    "minimax_mmx": ("worker_minimax_m3",),
    "minimax_mmx_tool_loop": ("worker_minimax_m3_tool_loop",),
    "opencode_tool_loop": ("worker_minimax_m3_opencode",),
    "grok_cli": ("worker_grok_4_5", "worker_grok_4_6"),
    "opencode_qwopus": ("worker_qwopus_opencode",),
}

# Universal capability v1 is provider-neutral. Adapter cards declare only
# potential behavior. Exact model qualification proves a subset. Neither
# surface contains task authority.
CAPABILITY_PRIMITIVES = (
    "local_read",
    "artifact_output",
    "tool_loop",
    "command_execution",
    "scoped_write",
    "browser_control",
    "web_search",
    "connector_access",
)
LANE_PROFILES = {
    "read": {"required_primitives": ["local_read"], "mutation_mode": "read_only"},
    "artifact": {"required_primitives": ["artifact_output"], "mutation_mode": "artifact_only"},
    "scoped_write": {
        "required_primitives": ["local_read", "scoped_write"],
        "mutation_mode": "scoped_write",
    },
    "implementation": {
        "required_primitives": [
            "local_read", "artifact_output", "tool_loop",
            "command_execution", "scoped_write",
        ],
        "mutation_mode": "scoped_write",
    },
    "tool_loop": {"required_primitives": ["tool_loop"], "mutation_mode": "artifact_only"},
    "audit": {
        "required_primitives": ["local_read", "artifact_output", "command_execution"],
        "mutation_mode": "read_only",
    },
}
ADAPTER_TRANSPORTS = {
    "native_codex": "native_codex_child",
    "claude_cli": "claude_cli",
    "commandcode": "commandcode_subscription",
    "minimax_mmx": "minimax_mmx_subscription",
    "minimax_mmx_tool_loop": "minimax_mmx_json_text_loop",
    "opencode_tool_loop": "opencode_tool_loop",
    "grok_cli": "grok_cli",
    "opencode_qwopus": "opencode_qwopus",
}
ADAPTER_PRIMITIVES = {
    "native_codex": CAPABILITY_PRIMITIVES,
    "claude_cli": CAPABILITY_PRIMITIVES,
    "commandcode": CAPABILITY_PRIMITIVES,
    "minimax_mmx": ("artifact_output",),
    "minimax_mmx_tool_loop": (
        "local_read", "artifact_output", "tool_loop", "scoped_write",
    ),
    "opencode_tool_loop": (
        "local_read", "artifact_output", "tool_loop", "command_execution", "scoped_write",
    ),
    "grok_cli": (
        "local_read", "artifact_output", "tool_loop", "command_execution", "scoped_write",
    ),
    "opencode_qwopus": (
        "local_read", "artifact_output", "tool_loop", "command_execution", "scoped_write",
    ),
}
UNIVERSAL_SCHEMA_VERSION = 1
UNIVERSAL_ARTIFACT_TYPE = "codexmax_universal_adapter_capability_v1"
MODEL_QUALIFICATION_STATUSES = {
    "unknown", "qualified", "expired", "stale", "recalled",
    "revoked", "qualification_failed", "execution_unknown",
}


class AdapterRegistryError(ValueError):
    def __init__(self, code: str, path: str) -> None:
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def _universal_adapter_card(adapter_type: str) -> dict[str, Any]:
    core = {
        "adapter_type": adapter_type,
        "adapter_id": f"builtin.{adapter_type}.v1",
        "adapter_version": "1.0.0",
        "provider_transport": ADAPTER_TRANSPORTS[adapter_type],
        "supported_primitives": list(ADAPTER_PRIMITIVES[adapter_type]),
        "authority_fields": [],
    }
    return {**core, "capability_sha256": canonical_digest(core)}


def _canonical_value(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AdapterRegistryError("nonfinite_number", path)
        return value
    if isinstance(value, list):
        return [_canonical_value(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise AdapterRegistryError("object_key_invalid", path)
            result[key] = _canonical_value(value[key], f"{path}.{key}")
        return result
    raise AdapterRegistryError("canonical_type_invalid", path)


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        _canonical_value(value), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def adapter_route_compatible(adapter_type: str, route_name: str) -> bool:
    """Return only code-owned adapter/Worker-route compatibility."""
    if adapter_type == "commandcode":
        return route_name.startswith("worker_deepseek_") or route_name.startswith(
            "worker_commandcode_"
        )
    return route_name in ADAPTER_ROUTE_ALLOWLIST.get(adapter_type, ())


def derive_binding_id(
    *, adapter_type: str, route_name: str, credential_kind: str, opaque_id: str
) -> str:
    """Derive a stable identifier from the immutable binding selector."""
    if adapter_type not in APPROVED_ADAPTER_CARDS:
        raise AdapterRegistryError("adapter_type_unknown", "$.adapter_type")
    _identifier(route_name, "$.route_name")
    if credential_kind not in REFERENCE_KINDS:
        raise AdapterRegistryError("credential_reference_kind_unknown", "$.credential_kind")
    _opaque_id(opaque_id, "$.opaque_id")
    selector = {
        "adapter_type": adapter_type,
        "route_name": route_name,
        "credential_kind": credential_kind,
        "opaque_id": opaque_id,
    }
    suffix = canonical_digest(selector).removeprefix("sha256:")[:20]
    return f"binding_{adapter_type}_{suffix}"


def _card(adapter_type: str) -> dict[str, Any]:
    core = {
        "adapter_type": adapter_type,
        "adapter_id": f"builtin.{adapter_type}.v1",
        "supported_route_kind": "worker",
        "credential_reference_kinds": {
            kind: kind in ADAPTER_REFERENCE_KINDS[adapter_type]
            for kind in REFERENCE_KINDS
        },
        "static_execution_policy": copy.deepcopy(STATIC_EXECUTION_POLICY),
    }
    return {**core, "adapter_sha256": canonical_digest(core)}


APPROVED_ADAPTER_CARDS = {adapter_type: _card(adapter_type) for adapter_type in ADAPTER_TYPES}
REGISTRY_SHA256 = canonical_digest({
    "registry_revision": REGISTRY_REVISION,
    "adapters": APPROVED_ADAPTER_CARDS,
})
UNIVERSAL_ADAPTER_CARDS = {
    adapter_type: _universal_adapter_card(adapter_type) for adapter_type in ADAPTER_TYPES
}
UNIVERSAL_CATALOG_SHA256 = canonical_digest({
    "primitives": list(CAPABILITY_PRIMITIVES),
    "lane_profiles": LANE_PROFILES,
    "adapter_capabilities": UNIVERSAL_ADAPTER_CARDS,
})


def qualification_template(status: str = "configured") -> dict[str, Any]:
    if status not in QUALIFICATION_STATUSES:
        raise AdapterRegistryError("qualification_status_unknown", "$.qualification.status")
    return {
        "status": status,
        "certificate_sha256": None,
        "preflight_sha256": None,
        "capability_sha256": None,
        "evaluation_sha256": None,
        "bound_adapter_binding_sha256": None,
        "issued_at": None,
        "expires_at": None,
        "ttl_seconds": None,
        "recall_sha256": None,
        "recalled_at": None,
        "retry_allowed": False,
        "fallback_allowed": False,
    }


def _route_identity(route_name: str, route: Mapping[str, Any]) -> dict[str, Any]:
    required = (
        "provider", "exact_model", "route_id", "runtime", "reasoning",
        "billing_basis", "independence_group",
    )
    missing = [field for field in required if field not in route]
    if missing:
        raise AdapterRegistryError("route_identity_missing", f"$.route.{missing[0]}")
    return {
        "route_name": route_name,
        **{field: copy.deepcopy(route[field]) for field in required},
    }


def build_binding(
    *, binding_id: str, adapter_type: str, route_name: str,
    route: Mapping[str, Any], task_profile: Mapping[str, Any],
    credential_kind: str = "none", opaque_id: str = "none",
    enabled: bool = False, concurrency_cap: int | None = None,
    token_cap: int = 1,
) -> dict[str, Any]:
    if adapter_type not in APPROVED_ADAPTER_CARDS:
        raise AdapterRegistryError("adapter_type_unknown", "$.adapter_type")
    if not adapter_route_compatible(adapter_type, route_name):
        raise AdapterRegistryError("adapter_route_incompatible", "$.route.route_name")
    card = APPROVED_ADAPTER_CARDS[adapter_type]
    credential_core = {"kind": credential_kind, "opaque_id": opaque_id}
    core = {
        "binding_id": binding_id,
        "enabled": enabled,
        "adapter_type": adapter_type,
        "adapter_id": card["adapter_id"],
        "adapter_sha256": card["adapter_sha256"],
        "route": _route_identity(route_name, route),
        "credential_reference": {
            **credential_core,
            "reference_sha256": canonical_digest(credential_core),
        },
        "concurrency_cap": concurrency_cap,
        "token_cap": token_cap,
        "task_profile_sha256": canonical_digest(task_profile),
        "provider_input_sha256": canonical_digest(_route_identity(route_name, route)),
        "adapter_registry_sha256": REGISTRY_SHA256,
    }
    binding_digest = canonical_digest(core)
    return {
        **core,
        "adapter_binding_sha256": binding_digest,
        "qualification": qualification_template(),
        "billing_observation": "unknown",
        "usage_observation": "unknown",
        "cost_observation": "unknown",
    }


def build_registry(bindings: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "registry_revision": REGISTRY_REVISION,
        "adapters": copy.deepcopy(APPROVED_ADAPTER_CARDS),
        "bindings": copy.deepcopy(dict(bindings)),
        "registry_sha256": REGISTRY_SHA256,
    }


def _closed_mapping(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterRegistryError("mapping_required", path)
    unknown = sorted(set(value) - fields)
    if unknown:
        code = "forbidden_configuration_field" if FORBIDDEN_FIELD_RE.search(unknown[0]) else "unknown_field"
        raise AdapterRegistryError(code, f"{path}.{unknown[0]}")
    missing = sorted(fields - set(value))
    if missing:
        raise AdapterRegistryError("missing_field", f"{path}.{missing[0]}")
    return value


def _digest(value: Any, path: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise AdapterRegistryError("digest_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise AdapterRegistryError("identifier_invalid", path)
    return value


def _opaque_id(value: Any, path: str) -> str:
    if not isinstance(value, str) or not OPAQUE_ID_RE.fullmatch(value):
        raise AdapterRegistryError("opaque_reference_invalid", path)
    if SECRET_VALUE_RE.search(value):
        raise AdapterRegistryError("opaque_reference_unsafe", path)
    return value


def _safe_scalar(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise AdapterRegistryError("route_identity_invalid", path)
    if any(character in value for character in ("\x00", "\n", "\r")) or SECRET_VALUE_RE.search(value):
        raise AdapterRegistryError("route_identity_unsafe", path)
    return value


def _timestamp(value: Any, path: str, *, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AdapterRegistryError("timestamp_invalid", path)
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AdapterRegistryError("timestamp_invalid", path) from exc
    return result


def _binding_digest_core(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(binding[key])
        for key in (
            "binding_id", "enabled", "adapter_type", "adapter_id", "adapter_sha256",
            "route", "credential_reference", "concurrency_cap", "token_cap",
            "task_profile_sha256", "provider_input_sha256", "adapter_registry_sha256",
        )
    }


def qualification_state(binding: Mapping[str, Any], evaluated_at: str) -> str:
    qualification = binding["qualification"]
    status = qualification["status"]
    if status == "execution_unknown":
        return "execution_unknown"
    if status in {"revoked", "unavailable", "qualification_failed", "unconfigured", "configured", "qualification_required"}:
        return status
    now = _timestamp(evaluated_at, "$.evaluated_at")
    recalled_at = _timestamp(qualification["recalled_at"], "$.qualification.recalled_at", nullable=True)
    if recalled_at is not None or qualification["recall_sha256"] is not None:
        return "recalled"
    expires_at = _timestamp(qualification["expires_at"], "$.qualification.expires_at", nullable=True)
    if expires_at is not None and now is not None and now >= expires_at:
        return "expired"
    if qualification["bound_adapter_binding_sha256"] != binding["adapter_binding_sha256"]:
        return "stale"
    return "qualified"


def _validate_qualification(binding: dict[str, Any], path: str, evaluated_at: str) -> str:
    fields = {
        "status", "certificate_sha256", "preflight_sha256", "capability_sha256",
        "evaluation_sha256", "bound_adapter_binding_sha256", "issued_at", "expires_at",
        "ttl_seconds", "recall_sha256", "recalled_at", "retry_allowed", "fallback_allowed",
    }
    q = _closed_mapping(binding["qualification"], fields, f"{path}.qualification")
    status = q["status"]
    if status not in QUALIFICATION_STATUSES:
        raise AdapterRegistryError("qualification_status_unknown", f"{path}.qualification.status")
    for field in (
        "certificate_sha256", "preflight_sha256", "capability_sha256",
        "evaluation_sha256", "bound_adapter_binding_sha256", "recall_sha256",
    ):
        _digest(q[field], f"{path}.qualification.{field}", nullable=True)
    issued = _timestamp(q["issued_at"], f"{path}.qualification.issued_at", nullable=True)
    expires = _timestamp(q["expires_at"], f"{path}.qualification.expires_at", nullable=True)
    recalled = _timestamp(q["recalled_at"], f"{path}.qualification.recalled_at", nullable=True)
    if q["retry_allowed"] is not False or q["fallback_allowed"] is not False:
        raise AdapterRegistryError("automatic_recovery_forbidden", f"{path}.qualification")
    evidence_fields = (
        q["certificate_sha256"], q["preflight_sha256"], q["capability_sha256"],
        q["evaluation_sha256"], q["bound_adapter_binding_sha256"], issued, expires,
        q["ttl_seconds"],
    )
    if status in {"unconfigured", "configured", "qualification_required"}:
        if any(item is not None for item in evidence_fields) or recalled is not None or q["recall_sha256"] is not None:
            raise AdapterRegistryError("configured_claims_qualification", f"{path}.qualification")
        return status
    if any(item is None for item in evidence_fields):
        raise AdapterRegistryError("qualification_evidence_incomplete", f"{path}.qualification")
    ttl = q["ttl_seconds"]
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1 or ttl > 300:
        raise AdapterRegistryError("qualification_ttl_invalid", f"{path}.qualification.ttl_seconds")
    assert issued is not None and expires is not None
    if expires <= issued or int((expires - issued).total_seconds()) != ttl:
        raise AdapterRegistryError("qualification_ttl_incoherent", f"{path}.qualification")
    if (recalled is None) != (q["recall_sha256"] is None):
        raise AdapterRegistryError("recall_evidence_incoherent", f"{path}.qualification")
    derived = qualification_state(binding, evaluated_at)
    if status != derived:
        raise AdapterRegistryError("qualification_status_incoherent", f"{path}.qualification.status")
    return derived


def validate_registry(
    document: Mapping[str, Any], *, evaluated_at: str,
    configuration_only: bool = False,
) -> dict[str, Any]:
    original = copy.deepcopy(document)
    root_fields = {
        "schema_version", "artifact_type", "registry_revision", "adapters",
        "bindings", "registry_sha256",
    }
    root = _closed_mapping(document, root_fields, "$")
    if root["schema_version"] != SCHEMA_VERSION or root["artifact_type"] != ARTIFACT_TYPE:
        raise AdapterRegistryError("registry_identity_invalid", "$")
    if root["registry_revision"] != REGISTRY_REVISION or root["registry_sha256"] != REGISTRY_SHA256:
        raise AdapterRegistryError("registry_digest_mismatch", "$.registry_sha256")
    if root["adapters"] != APPROVED_ADAPTER_CARDS:
        raise AdapterRegistryError("adapter_card_mismatch", "$.adapters")

    bindings = root["bindings"]
    if not isinstance(bindings, dict):
        raise AdapterRegistryError("mapping_required", "$.bindings")
    if len(bindings) > 64:
        raise AdapterRegistryError("binding_count_exceeded", "$.bindings")
    seen_ids: set[str] = set()
    states: dict[str, str] = {}
    binding_fields = {
        "binding_id", "enabled", "adapter_type", "adapter_id", "adapter_sha256",
        "route", "credential_reference", "concurrency_cap", "token_cap",
        "task_profile_sha256", "provider_input_sha256", "adapter_registry_sha256",
        "adapter_binding_sha256", "qualification", "billing_observation",
        "usage_observation", "cost_observation",
    }
    route_fields = {
        "route_name", "provider", "exact_model", "route_id", "runtime", "reasoning",
        "billing_basis", "independence_group",
    }
    credential_fields = {"kind", "opaque_id", "reference_sha256"}
    for name, raw in bindings.items():
        path = f"$.bindings.{name}"
        _identifier(name, path)
        binding = _closed_mapping(raw, binding_fields, path)
        binding_id = _identifier(binding["binding_id"], f"{path}.binding_id")
        if name != binding_id or binding_id in seen_ids:
            raise AdapterRegistryError("binding_id_duplicate_or_mismatch", f"{path}.binding_id")
        seen_ids.add(binding_id)
        adapter_type = binding["adapter_type"]
        if adapter_type not in APPROVED_ADAPTER_CARDS:
            raise AdapterRegistryError("adapter_type_unknown", f"{path}.adapter_type")
        card = APPROVED_ADAPTER_CARDS[adapter_type]
        if binding["adapter_id"] != card["adapter_id"] or binding["adapter_sha256"] != card["adapter_sha256"]:
            raise AdapterRegistryError("adapter_card_binding_mismatch", path)
        if binding["adapter_registry_sha256"] != REGISTRY_SHA256:
            raise AdapterRegistryError("registry_digest_mismatch", f"{path}.adapter_registry_sha256")
        route = _closed_mapping(binding["route"], route_fields, f"{path}.route")
        if not adapter_route_compatible(adapter_type, route["route_name"]):
            raise AdapterRegistryError("adapter_route_incompatible", f"{path}.route.route_name")
        for field, value in route.items():
            _safe_scalar(value, f"{path}.route.{field}")
        if binding["provider_input_sha256"] != canonical_digest(route):
            raise AdapterRegistryError(
                "provider_input_digest_mismatch", f"{path}.provider_input_sha256"
            )
        credential = _closed_mapping(binding["credential_reference"], credential_fields, f"{path}.credential_reference")
        if not card["credential_reference_kinds"].get(credential["kind"], False):
            raise AdapterRegistryError("credential_reference_kind_forbidden", f"{path}.credential_reference.kind")
        _opaque_id(credential["opaque_id"], f"{path}.credential_reference.opaque_id")
        expected_reference = canonical_digest({"kind": credential["kind"], "opaque_id": credential["opaque_id"]})
        if credential["reference_sha256"] != expected_reference:
            raise AdapterRegistryError("credential_reference_digest_mismatch", f"{path}.credential_reference.reference_sha256")
        if not isinstance(binding["enabled"], bool):
            raise AdapterRegistryError("enabled_invalid", f"{path}.enabled")
        cap = binding["concurrency_cap"]
        if cap is not None and (isinstance(cap, bool) or not isinstance(cap, int) or cap < 1):
            raise AdapterRegistryError("concurrency_cap_invalid", f"{path}.concurrency_cap")
        token_cap = binding["token_cap"]
        if isinstance(token_cap, bool) or not isinstance(token_cap, int) or token_cap < 1:
            raise AdapterRegistryError("token_cap_invalid", f"{path}.token_cap")
        for field in ("task_profile_sha256", "provider_input_sha256", "adapter_binding_sha256"):
            _digest(binding[field], f"{path}.{field}")
        expected_binding = canonical_digest(_binding_digest_core(binding))
        if binding["adapter_binding_sha256"] != expected_binding:
            raise AdapterRegistryError("adapter_binding_digest_mismatch", f"{path}.adapter_binding_sha256")
        for field in ("billing_observation", "usage_observation", "cost_observation"):
            if binding[field] != "unknown":
                raise AdapterRegistryError("observation_not_owned_by_config", f"{path}.{field}")
        state = _validate_qualification(binding, path, evaluated_at)
        if state == "qualified":
            raise AdapterRegistryError("detached_qualification_forbidden", f"{path}.qualification.status")
        if configuration_only and state != "configured":
            raise AdapterRegistryError("configuration_cannot_qualify", f"{path}.qualification.status")
        states[name] = state

    if document != original:
        raise AdapterRegistryError("input_mutated", "$")
    return {
        "artifact_type": "adapter_registry_validation_receipt_v1",
        "valid": True,
        "registry_sha256": REGISTRY_SHA256,
        "binding_states": states,
        "configured_binding_count": sum(state == "configured" for state in states.values()),
        "qualified_binding_count": sum(state == "qualified" for state in states.values()),
        "execution_unknown_blocks_retry": True,
        "billing_observation": "unknown",
        "usage_observation": "unknown",
        "provider_called": False,
        "execution_started": False,
        "eligibility_granted": False,
        "authority_granted": False,
        "acceptance_granted": False,
    }


def lane_profile(name: str, *, exact_tools: list[str] | None = None) -> dict[str, Any]:
    """Return one closed primitive composition without task authority."""
    if name not in LANE_PROFILES:
        raise AdapterRegistryError("lane_profile_unknown", "$.lane_profile")
    tools = [] if exact_tools is None else _primitive_tool_list(exact_tools, "$.exact_tools")
    if name == "tool_loop" and not tools:
        raise AdapterRegistryError("exact_tool_allowlist_required", "$.exact_tools")
    if name != "tool_loop" and tools:
        raise AdapterRegistryError("tool_allowlist_not_applicable", "$.exact_tools")
    result = copy.deepcopy(LANE_PROFILES[name])
    result.update({"lane_profile": name, "exact_tool_allowlist": tools})
    return result


def _primitive_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise AdapterRegistryError("primitive_list_invalid", path)
    if any(item not in CAPABILITY_PRIMITIVES for item in value):
        raise AdapterRegistryError("primitive_unknown", path)
    return list(value)


def _primitive_tool_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise AdapterRegistryError("tool_allowlist_invalid", path)
    for item in value:
        if not isinstance(item, str) or not IDENTIFIER_RE.fullmatch(item):
            raise AdapterRegistryError("tool_allowlist_invalid", path)
    return list(value)


def model_adapter_key(
    *, provider: str, provider_transport: str, exact_model: str,
    adapter_id: str, adapter_version: str,
) -> str:
    """Return the exact compatibility key. No field may be substituted."""
    _identifier(provider_transport, "$.provider_transport")
    _identifier(adapter_id, "$.adapter_id")
    _identifier(adapter_version, "$.adapter_version")
    core = {
        "provider": _safe_scalar(provider, "$.provider"),
        "provider_transport": provider_transport,
        "exact_model": _safe_scalar(exact_model, "$.exact_model"),
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
    }
    return "qualification_" + canonical_digest(core).removeprefix("sha256:")[:32]


def build_model_qualification(
    *, provider: str, exact_model: str, adapter_type: str,
    proved_primitives: list[str], evidence_digests: list[str],
    issued_at: str, expires_at: str, max_concurrency: int,
    status: str = "qualified", exact_tool_allowlist: list[str] | None = None,
) -> dict[str, Any]:
    """Build source-local evidence. Configuration must never call this builder."""
    card = UNIVERSAL_ADAPTER_CARDS.get(adapter_type)
    if card is None:
        raise AdapterRegistryError("adapter_type_unknown", "$.adapter_type")
    compatibility = {
        "provider": provider,
        "provider_transport": card["provider_transport"],
        "exact_model": exact_model,
        "adapter_id": card["adapter_id"],
        "adapter_version": card["adapter_version"],
    }
    qualification_id = model_adapter_key(**compatibility)
    core = {
        "qualification_id": qualification_id,
        "compatibility": compatibility,
        "proved_primitives": list(proved_primitives),
        "exact_tool_allowlist": [] if exact_tool_allowlist is None else list(exact_tool_allowlist),
        "limits": {"max_concurrency": max_concurrency},
        "evidence_digests": list(evidence_digests),
        "proof_boundary": "source_local",
        "status": status,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "recalled_at": None,
        "recall_sha256": None,
        "retry_allowed": False,
        "fallback_allowed": False,
    }
    return {**core, "qualification_sha256": canonical_digest(core)}


def build_universal_registry(
    qualifications: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    core = {
        "schema_version": UNIVERSAL_SCHEMA_VERSION,
        "artifact_type": UNIVERSAL_ARTIFACT_TYPE,
        "primitives": list(CAPABILITY_PRIMITIVES),
        "lane_profiles": copy.deepcopy(LANE_PROFILES),
        "adapter_capabilities": copy.deepcopy(UNIVERSAL_ADAPTER_CARDS),
        "qualifications": copy.deepcopy(dict(qualifications)),
        "catalog_sha256": UNIVERSAL_CATALOG_SHA256,
    }
    return {**core, "registry_sha256": canonical_digest(core)}


def _qualification_policy_state(compatibility: Mapping[str, Any]) -> str:
    model = str(compatibility["exact_model"]).lower()
    provider = str(compatibility["provider"]).lower()
    adapter_id = str(compatibility["adapter_id"]).lower()
    if "terra" in model:
        return "terra_denied"
    if "qwopus" in model or "qwopus" in adapter_id or provider == "local-llm":
        return "qwopus_on_hold"
    return "allowed"


def _validate_model_qualification(
    value: Any, *, path: str, evaluated_at: str,
) -> dict[str, Any]:
    fields = {
        "qualification_id", "compatibility", "proved_primitives",
        "exact_tool_allowlist", "limits", "evidence_digests", "proof_boundary",
        "status", "issued_at", "expires_at", "recalled_at", "recall_sha256",
        "retry_allowed", "fallback_allowed", "qualification_sha256",
    }
    row = _closed_mapping(value, fields, path)
    compatibility = _closed_mapping(row["compatibility"], {
        "provider", "provider_transport", "exact_model", "adapter_id", "adapter_version",
    }, f"{path}.compatibility")
    expected_id = model_adapter_key(**compatibility)
    if row["qualification_id"] != expected_id:
        raise AdapterRegistryError("compatibility_key_mismatch", f"{path}.qualification_id")
    matching_cards = [
        card for card in UNIVERSAL_ADAPTER_CARDS.values()
        if card["adapter_id"] == compatibility["adapter_id"]
    ]
    if len(matching_cards) != 1:
        raise AdapterRegistryError("adapter_id_unknown", f"{path}.compatibility.adapter_id")
    card = matching_cards[0]
    if compatibility["adapter_version"] != card["adapter_version"]:
        raise AdapterRegistryError("adapter_version_mismatch", f"{path}.compatibility.adapter_version")
    if compatibility["provider_transport"] != card["provider_transport"]:
        raise AdapterRegistryError("provider_transport_mismatch", f"{path}.compatibility.provider_transport")
    primitives = _primitive_list(row["proved_primitives"], f"{path}.proved_primitives")
    if not set(primitives).issubset(card["supported_primitives"]):
        raise AdapterRegistryError("primitive_not_supported_by_adapter", f"{path}.proved_primitives")
    _primitive_tool_list(row["exact_tool_allowlist"], f"{path}.exact_tool_allowlist")
    limits = _closed_mapping(row["limits"], {"max_concurrency"}, f"{path}.limits")
    if isinstance(limits["max_concurrency"], bool) or not isinstance(limits["max_concurrency"], int) or limits["max_concurrency"] < 1:
        raise AdapterRegistryError("concurrency_cap_invalid", f"{path}.limits.max_concurrency")
    if not isinstance(row["evidence_digests"], list) or not row["evidence_digests"]:
        raise AdapterRegistryError("qualification_evidence_incomplete", f"{path}.evidence_digests")
    for index, digest in enumerate(row["evidence_digests"]):
        _digest(digest, f"{path}.evidence_digests[{index}]")
    if row["proof_boundary"] != "source_local":
        raise AdapterRegistryError("proof_boundary_invalid", f"{path}.proof_boundary")
    if row["status"] not in MODEL_QUALIFICATION_STATUSES:
        raise AdapterRegistryError("qualification_status_unknown", f"{path}.status")
    issued = _timestamp(row["issued_at"], f"{path}.issued_at")
    expires = _timestamp(row["expires_at"], f"{path}.expires_at")
    now = _timestamp(evaluated_at, "$.evaluated_at")
    if issued is None or expires is None or expires <= issued:
        raise AdapterRegistryError("qualification_ttl_incoherent", path)
    recalled = _timestamp(row["recalled_at"], f"{path}.recalled_at", nullable=True)
    _digest(row["recall_sha256"], f"{path}.recall_sha256", nullable=True)
    if (recalled is None) != (row["recall_sha256"] is None):
        raise AdapterRegistryError("recall_evidence_incoherent", path)
    if row["retry_allowed"] is not False or row["fallback_allowed"] is not False:
        raise AdapterRegistryError("automatic_recovery_forbidden", path)
    supplied = row["qualification_sha256"]
    core = {key: copy.deepcopy(item) for key, item in row.items() if key != "qualification_sha256"}
    if supplied != canonical_digest(core):
        raise AdapterRegistryError("qualification_digest_mismatch", f"{path}.qualification_sha256")
    derived = row["status"]
    if recalled is not None:
        derived = "recalled"
    elif now is not None and now < issued:
        derived = "not_yet_valid"
    elif now is not None and now >= expires:
        derived = "expired"
    elif row["status"] == "qualified":
        derived = "qualified"
    policy_state = _qualification_policy_state(compatibility)
    return {
        "qualification_id": expected_id,
        "state": derived,
        "policy_state": policy_state,
        "eligible": derived == "qualified" and policy_state == "allowed",
        "proved_primitives": primitives,
        "exact_tool_allowlist": copy.deepcopy(row["exact_tool_allowlist"]),
        "max_concurrency": limits["max_concurrency"],
        "qualification_sha256": supplied,
    }


def validate_universal_registry(
    document: Mapping[str, Any], *, evaluated_at: str, configuration_only: bool = False,
) -> dict[str, Any]:
    """Validate source-local compatibility evidence without executing work."""
    original = copy.deepcopy(document)
    fields = {
        "schema_version", "artifact_type", "primitives", "lane_profiles",
        "adapter_capabilities", "qualifications", "catalog_sha256", "registry_sha256",
    }
    root = _closed_mapping(document, fields, "$")
    if root["schema_version"] != UNIVERSAL_SCHEMA_VERSION or root["artifact_type"] != UNIVERSAL_ARTIFACT_TYPE:
        raise AdapterRegistryError("registry_identity_invalid", "$")
    if root["primitives"] != list(CAPABILITY_PRIMITIVES):
        raise AdapterRegistryError("primitive_catalog_mismatch", "$.primitives")
    if root["lane_profiles"] != LANE_PROFILES:
        raise AdapterRegistryError("lane_profile_catalog_mismatch", "$.lane_profiles")
    if root["adapter_capabilities"] != UNIVERSAL_ADAPTER_CARDS:
        raise AdapterRegistryError("adapter_capability_catalog_mismatch", "$.adapter_capabilities")
    if root["catalog_sha256"] != UNIVERSAL_CATALOG_SHA256:
        raise AdapterRegistryError("catalog_digest_mismatch", "$.catalog_sha256")
    qualifications = root["qualifications"]
    if not isinstance(qualifications, dict):
        raise AdapterRegistryError("mapping_required", "$.qualifications")
    if configuration_only and qualifications:
        raise AdapterRegistryError("configuration_cannot_supply_qualification", "$.qualifications")
    states: dict[str, dict[str, Any]] = {}
    for qualification_id, value in qualifications.items():
        if qualification_id != value.get("qualification_id"):
            raise AdapterRegistryError("qualification_id_mismatch", f"$.qualifications.{qualification_id}")
        states[qualification_id] = _validate_model_qualification(
            value, path=f"$.qualifications.{qualification_id}", evaluated_at=evaluated_at,
        )
    supplied = root["registry_sha256"]
    core = {key: copy.deepcopy(item) for key, item in root.items() if key != "registry_sha256"}
    if supplied != canonical_digest(core):
        raise AdapterRegistryError("registry_digest_mismatch", "$.registry_sha256")
    if document != original:
        raise AdapterRegistryError("input_mutated", "$")
    return {
        "artifact_type": "universal_adapter_capability_validation_receipt_v1",
        "valid": True,
        "qualification_states": states,
        "provider_called": False,
        "execution_started": False,
        "eligibility_granted": False,
        "authority_granted": False,
        "acceptance_granted": False,
    }


def qualified_lane_match(
    document: Mapping[str, Any], *, qualification_id: str, lane_name: str,
    evaluated_at: str, exact_tools: list[str] | None = None,
) -> dict[str, Any]:
    validation = validate_universal_registry(document, evaluated_at=evaluated_at)
    state = validation["qualification_states"].get(qualification_id)
    if state is None or not state["eligible"]:
        raise AdapterRegistryError("qualification_not_current", f"$.qualifications.{qualification_id}")
    profile = lane_profile(lane_name, exact_tools=exact_tools)
    if not set(profile["required_primitives"]).issubset(state["proved_primitives"]):
        raise AdapterRegistryError("required_primitive_unqualified", "$.lane_profile")
    if lane_name == "tool_loop" and any(
        tool not in state["exact_tool_allowlist"] for tool in profile["exact_tool_allowlist"]
    ):
        raise AdapterRegistryError("exact_tool_unqualified", "$.exact_tools")
    return {
        "qualification_id": qualification_id,
        "lane_profile": lane_name,
        "required_primitives": copy.deepcopy(profile["required_primitives"]),
        "exact_tool_allowlist": copy.deepcopy(profile["exact_tool_allowlist"]),
        "adapter_concurrency_cap": state["max_concurrency"],
        "compatibility_verified": True,
        "qualification_current": True,
        "eligibility_granted": False,
        "authority_granted": False,
    }
