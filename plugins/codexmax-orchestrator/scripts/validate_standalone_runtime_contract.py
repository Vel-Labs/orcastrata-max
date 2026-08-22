#!/usr/bin/env python3
"""Validate StandaloneRuntimeContract v1 without effects or authority mutation."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


CONTRACT = "StandaloneRuntimeContract"
VERSION = 1
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SOURCE_SCOPE_DOMAIN = "standalone-runtime-source-scope-v1"
ASSIGNMENT_AUTHORITY_DOMAIN = "standalone-runtime-assignment-authority-v1"
QUALIFICATION_DOMAIN = "standalone-runtime-qualification-v1"
CONTAINMENT_EVIDENCE_DOMAIN = "standalone-runtime-containment-evidence-v1"
EFFECT_RECHECK_REQUIREMENTS_DOMAIN = "standalone-runtime-effect-recheck-requirements-v1"
EFFECT_RECHECK_DOMAIN = "standalone-runtime-effect-recheck-v1"
EFFECT_BOUNDARY_DOMAIN = "standalone-runtime-effect-boundary-v1"
COMPONENTS = {
    "assignment_authority",
    "capability_evidence",
    "capacity_authority",
    "compatibility",
    "continuation",
    "delegation",
    "downstream_fork",
    "event",
    "plan",
    "preflight",
    "qualification",
    "receipt",
    "role_policy",
    "route_identity",
    "run",
    "runtime_manifest",
    "task_journal",
}
TOP_LEVEL = {
    "contract",
    "contract_version",
    "component_versions",
    "runtime_manifest",
    "source_identity",
    "route",
    "capability_evidence",
    "qualification",
    "role_policy",
    "assignment_authority",
    "preflight_result",
    "plan_result",
    "capacity_authority",
    "run",
    "events",
    "receipts",
    "continuation",
    "delegation",
    "task_journal",
    "recall",
    "compatibility",
    "downstream_fork",
    "integrity",
}
LIMIT_KEYS = {
    "attempts",
    "runtime_seconds",
    "uninterrupted_action_seconds",
    "tokens",
    "disclosure_bytes",
    "journal_messages",
    "message_bytes",
    "ttl_seconds",
    "external_cost_microunits",
}
EFFECT_ORDER = ("filesystem_write", "command", "browser", "connector", "network", "provider")
EFFECT_KEYS = set(EFFECT_ORDER)
ROOT_LIMITS = {
    "attempts": 2,
    "runtime_seconds": 600,
    "uninterrupted_action_seconds": 120,
    "tokens": 20000,
    "disclosure_bytes": 65536,
    "journal_messages": 20,
    "message_bytes": 4096,
    "ttl_seconds": 3600,
    "external_cost_microunits": 0,
}
CHILD_LIMITS = {
    "attempts": 1,
    "runtime_seconds": 300,
    "uninterrupted_action_seconds": 60,
    "tokens": 10000,
    "disclosure_bytes": 32768,
    "journal_messages": 10,
    "message_bytes": 2048,
    "ttl_seconds": 1800,
    "external_cost_microunits": 0,
}
EFFECT_CAPABILITIES = {
    "filesystem_write": "filesystem_write",
    "command": "command",
    "browser": "browser",
    "connector": "connector",
    "network": "network",
    "provider": "provider",
}
TOOL_CAPABILITIES = {
    "read_file": ("local_file_read", "read_only"),
    "write_fixture": ("filesystem_write", "scoped"),
}
CAPABILITY_LEVEL_RANK = {"none": 0, "unknown": 0, "read_only": 1, "scoped": 2}
CAPABILITY_LEVELS = {
    "local_file_read": {"none", "unknown", "read_only", "scoped"},
    "filesystem_write": {"none", "unknown", "read_only", "scoped"},
    "command": {"none", "unknown", "read_only", "scoped"},
    "browser": {"none", "unknown", "read_only", "scoped"},
    "connector": {"none", "unknown", "read_only", "scoped"},
    "network": {"none", "unknown", "read_only", "scoped"},
    "provider": {"none", "unknown", "read_only", "scoped"},
}
EFFECT_MINIMUM_LEVEL = {key: "scoped" for key in EFFECT_CAPABILITIES}
MUTATION_MODES = {"read_only", "new_files_only"}
EFFECT_GATE_POLICY = {
    "recheck_timing": "immediately_before_each_effect",
    "missing_evidence": "deny",
    "stale_evidence": "deny",
    "identity_mismatch": "deny",
    "outside_workspace": "deny",
    "ambiguous_resolution": "deny",
}
DOWNSTREAM_AUTHORITIES = {"capacity", "assignment_authority", "acceptance"}
DOWNSTREAM_OVERLAY_CLASSES = {"client_adapter", "read_model_projection"}
DOWNSTREAM_COMPONENTS = {
    "runtime", "event", "receipt", "adapter", "route_identity",
    "assignment_authority", "delegation", "task_journal", "capacity_authority",
}
ELIGIBILITY_ORDER = [
    "identity_schema",
    "task_source",
    "capability_freshness",
    "assignment_authority",
    "privacy_consequence_independence",
    "billing_fallback",
    "health_quota_capacity",
]
EVENT_LIFECYCLE = {
    "run_created": "created",
    "run_preflighted": "preflighted",
    "run_planned": "planned",
    "run_admitted": "admitted",
    "run_launching": "launching",
    "run_running": "running",
    "run_reconciling": "reconciling",
    "run_quality_checked": "quality_checked",
    "run_review_pending": "review_pending",
    "run_terminal": "terminal",
}
CREDENTIAL_CONTENT = re.compile(
    r"(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|authorization|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|token|private[_-]?key)\s*[:=]\s*[^\s,;]{6,}"
    r"|bearer\s+[a-z0-9._~+/-]{8,}=*|sk-proj-[a-z0-9_-]{8,}"
    r"|(?:sk|rk|pk)[-_](?:live|test)[-_][a-z0-9_-]{8,}|gh[pousr]_[a-z0-9]{12,}"
    r"|://[^/\s:@]+:[^/\s@]+@"
)
LOCAL_TRANSPORTS = {"local_cli", "in_process", "unix_" + "sock" + "et", "loopback_http"}
BILLING_PROVENANCE_BY_BASIS = {
    "non_metered": {"local_fixture", "subscription_entitlement", "included_local"},
    "metered": {"provider_metered", "api_metered"},
    "unknown": {"unknown"},
}


class ContractError(ValueError):
    def __init__(self, code: str, path: str = "$"):
        self.code = code
        self.path = path
        super().__init__(f"{code}:{path}")


def canonical_json(value: object) -> str:
    return json.dumps(value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def object_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _reject_floats(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise ContractError("canonical_float_forbidden", path)
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("mapping_required", path)
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ContractError("list_required", path)
    return value


def _keys(value: Any, expected: set[str], path: str) -> dict[str, Any]:
    row = _mapping(value, path)
    if set(row) != expected:
        raise ContractError("fields_invalid", path)
    return row


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or "\x00" in value:
        raise ContractError("text_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    text = _text(value, path)
    if not IDENTIFIER.fullmatch(text):
        raise ContractError("identifier_invalid", path)
    return text


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ContractError("digest_invalid", path)
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError("integer_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    text = _text(value, path)
    if not TIMESTAMP.fullmatch(text):
        raise ContractError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError("timestamp_invalid", path) from error
    if parsed.microsecond:
        raise ContractError("timestamp_invalid", path)
    return parsed


def _enum(value: Any, allowed: set[str], path: str) -> str:
    if value not in allowed:
        raise ContractError("enum_invalid", path)
    return value


def _bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError("boolean_required", path)
    return value


def _string_set(value: Any, path: str) -> set[str]:
    rows = _list(value, path)
    result: set[str] = set()
    for index, item in enumerate(rows):
        text = _text(item, f"{path}[{index}]")
        if text in result:
            raise ContractError("duplicate_value", path)
        result.add(text)
    return result


def _workspace_relative_path(value: Any, path: str) -> str:
    text = _text(value, path)
    if (
        text.startswith(("/", "\\"))
        or "\\" in text
        or re.match(r"^[A-Za-z]:", text)
        or "%" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
    ):
        raise ContractError("authority_scope_path_outside_workspace", path)
    return text


def _source_scope_digest(
    authority: dict[str, Any], runtime: dict[str, Any], source: dict[str, Any]
) -> str:
    return object_digest({
        "domain": SOURCE_SCOPE_DOMAIN,
        "workspace_root_sha256": runtime["workspace_root_sha256"],
        "source_tree_sha256": source["source_tree_sha256"],
        "manifest_sha256": source["manifest_sha256"],
        "scope_paths": authority["scope_paths"],
    })


def _authority_digest(authority: dict[str, Any]) -> str:
    body = {key: value for key, value in authority.items() if key != "authority_sha256"}
    return object_digest({"domain": ASSIGNMENT_AUTHORITY_DOMAIN, "authority": body})


def _qualification_digest(
    qualification: dict[str, Any], evidence: list[dict[str, Any]]
) -> str:
    qualification_body = {
        key: value for key, value in qualification.items() if key != "qualification_sha256"
    }
    return object_digest({
        "domain": QUALIFICATION_DOMAIN,
        "qualification": qualification_body,
        "ordered_capability_evidence_sha256": [object_digest(item) for item in evidence],
    })


def _containment_evidence_digest(containment: dict[str, Any]) -> str:
    body = {
        key: value for key, value in containment.items()
        if key != "resolution_evidence_sha256"
    }
    return object_digest({"domain": CONTAINMENT_EVIDENCE_DOMAIN, "containment": body})


def _effect_recheck_requirements_digest(authority: dict[str, Any]) -> str:
    return object_digest({
        "domain": EFFECT_RECHECK_REQUIREMENTS_DOMAIN,
        "requested_effects": authority["requested_effects"],
        "effect_targets": authority["effect_targets"],
        "containment_evidence_sha256": authority["scope_containment"]["resolution_evidence_sha256"],
        "effect_gate_policy": authority["scope_containment"]["effect_gate_policy"],
    })


def _effect_boundary_digest(receipt: dict[str, Any]) -> str:
    return object_digest({
        "domain": EFFECT_BOUNDARY_DOMAIN,
        "run_id": receipt["run_id"],
        "effect_kind": receipt["effect_kind"],
        "effect_sequence": receipt["effect_sequence"],
        "target_identity_sha256": receipt["target_identity_sha256"],
        "authority_sha256": receipt["authority_sha256"],
        "source_scope_sha256": receipt["source_scope_sha256"],
        "qualification_sha256": receipt["qualification_sha256"],
        "containment_evidence_sha256": receipt["containment_evidence_sha256"],
        "effect_gate_policy_sha256": receipt["effect_gate_policy_sha256"],
        "effect_boundary_at": receipt["effect_boundary_at"],
    })


def _effect_recheck_digest(receipt: dict[str, Any]) -> str:
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return object_digest({"domain": EFFECT_RECHECK_DOMAIN, "receipt": body})


def _percent_decode_once(text: str, path: str) -> tuple[str, bool]:
    encoded = re.compile(r"%[0-9A-Fa-f]{2}")
    if not encoded.search(text):
        return text, False
    malformed = re.search(r"%(?![0-9A-Fa-f]{2})", text)
    if malformed:
        raise ContractError("credential_encoding_invalid", path)
    decoded = encoded.sub(lambda match: chr(int(match.group(0)[1:], 16)), text)
    return decoded, True


def _screen_credential_text(text: str, path: str, code: str) -> str:
    candidate = text
    for _ in range(3):
        if CREDENTIAL_CONTENT.search(candidate):
            raise ContractError(code, path)
        candidate, changed = _percent_decode_once(candidate, path)
        if not changed:
            return text
    if re.search(r"%[0-9A-Fa-f]{2}", candidate):
        raise ContractError("credential_encoding_depth_exceeded", path)
    if CREDENTIAL_CONTENT.search(candidate):
        raise ContractError(code, path)
    return text


def _forbid_credentials_everywhere(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _forbid_credentials_everywhere(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _forbid_credentials_everywhere(item, f"{path}[{index}]")
    elif isinstance(value, str):
        _screen_credential_text(value, path, "credential_material_detected")


def _forbid_credential_reference(value: Any, path: str, code: str) -> str:
    text = _text(value, path)
    _screen_credential_text(text, path, code)
    return text


def _validate_effects(value: Any, path: str) -> dict[str, bool]:
    row = _keys(value, EFFECT_KEYS, path)
    for key, item in row.items():
        _bool(item, f"{path}.{key}")
    return row


def _validate_limits(value: Any, path: str) -> dict[str, int]:
    row = _keys(value, LIMIT_KEYS, path)
    for key, item in row.items():
        _integer(item, f"{path}.{key}", minimum=0 if key == "external_cost_microunits" else 1)
    return row


def _validate_route(value: Any) -> dict[str, Any]:
    row = _keys(value, {
        "route_id", "provider_id", "exact_model", "runtime_id", "runtime_version",
        "adapter_id", "adapter_version", "adapter_sha256", "transport_id",
        "service_reference_class", "billing_basis", "billing_provenance",
        "independence_group", "input_delivery_profile",
    }, "$.route")
    for key in row:
        if key.endswith("sha256"):
            _digest(row[key], f"$.route.{key}")
        else:
            _text(row[key], f"$.route.{key}")
    _forbid_credential_reference(
        row["service_reference_class"],
        "$.route.service_reference_class",
        "route_service_reference_credential",
    )
    return row


def _validate_capability(value: Any, route: dict[str, Any], evaluated_at: datetime) -> list[dict[str, Any]]:
    rows = _list(value, "$.capability_evidence")
    if not rows:
        raise ContractError("capability_evidence_required", "$.capability_evidence")
    seen: set[str] = set()
    for index, item in enumerate(rows):
        path = f"$.capability_evidence[{index}]"
        row = _keys(item, {
            "capability", "level", "status", "polarity", "evidence_ref", "evidence_sha256",
            "route_id", "provider_id", "exact_model", "runtime_id", "host_id", "adapter_sha256",
            "task_profile_sha256", "evaluation_manifest_sha256", "collected_at", "expires_at",
            "invalidated_by", "contradiction_refs",
        }, path)
        capability = _identifier(row["capability"], f"{path}.capability")
        if capability in seen:
            raise ContractError("duplicate_capability", path)
        seen.add(capability)
        level = _text(row["level"], f"{path}.level")
        allowed_levels = CAPABILITY_LEVELS.get(capability)
        if allowed_levels is None or level not in allowed_levels:
            raise ContractError("capability_level_invalid", f"{path}.level")
        _enum(row["status"], {"declared", "observed", "unknown", "stale", "contradictory", "recalled"}, f"{path}.status")
        _enum(row["polarity"], {"positive", "negative", "unknown"}, f"{path}.polarity")
        for key in ("evidence_sha256", "adapter_sha256", "task_profile_sha256", "evaluation_manifest_sha256"):
            _digest(row[key], f"{path}.{key}")
        for key in ("evidence_ref", "host_id"):
            _text(row[key], f"{path}.{key}")
        for key in ("route_id", "provider_id", "exact_model", "runtime_id", "adapter_sha256"):
            expected_key = key
            if row[key] != route[expected_key]:
                raise ContractError("capability_identity_mismatch", f"{path}.{key}")
        collected = _timestamp(row["collected_at"], f"{path}.collected_at")
        expires = _timestamp(row["expires_at"], f"{path}.expires_at")
        if expires <= collected:
            raise ContractError("evidence_expiry_invalid", path)
        if row["invalidated_by"] is not None:
            _digest(row["invalidated_by"], f"{path}.invalidated_by")
        _string_set(row["contradiction_refs"], f"{path}.contradiction_refs")
        if row["status"] == "observed" and (row["polarity"] != "positive" or row["invalidated_by"] is not None or row["contradiction_refs"]):
            raise ContractError("observed_evidence_not_active", path)
        if evaluated_at < collected:
            raise ContractError("evidence_evaluated_before_collection", path)
        derived = "active"
        if row["invalidated_by"] is not None:
            derived = "stale"
        elif row["contradiction_refs"]:
            derived = "contradictory"
        elif evaluated_at >= expires:
            derived = "expired"
        elif row["status"] != "observed" or row["polarity"] != "positive":
            derived = "unknown"
        if derived != "active":
            raise ContractError("capability_not_active", path)
    return rows


def _validate_authority(
    value: Any,
    evaluated_at: datetime,
    runtime: dict[str, Any],
    source: dict[str, Any],
) -> dict[str, Any]:
    row = _keys(value, {
        "assignment_id", "authority_id", "authority_sha256", "source_scope_sha256", "scope_paths",
        "allowed_tools", "requested_effects", "effect_targets", "consequence_level", "mutation_mode", "route_policy",
        "allowed_route_ids", "fallback_policy", "billing_ceiling", "limits", "issued_at", "expires_at",
        "approver_ref", "revocation_ref", "expected_artifacts", "validation_policy_sha256",
        "return_schema_sha256", "scope_containment", "status",
    }, "$.assignment_authority")
    for key in ("authority_sha256", "source_scope_sha256", "validation_policy_sha256", "return_schema_sha256"):
        _digest(row[key], f"$.assignment_authority.{key}")
    for key in ("assignment_id", "authority_id", "consequence_level", "route_policy", "fallback_policy", "billing_ceiling", "approver_ref"):
        _text(row[key], f"$.assignment_authority.{key}")
    if row["mutation_mode"] not in MUTATION_MODES:
        raise ContractError("mutation_mode_invalid", "$.assignment_authority.mutation_mode")
    _enum(row["status"], {"active", "expired", "revoked", "unknown"}, "$.assignment_authority.status")
    if row["status"] != "active":
        raise ContractError("authority_not_active", "$.assignment_authority.status")
    issued = _timestamp(row["issued_at"], "$.assignment_authority.issued_at")
    expires = _timestamp(row["expires_at"], "$.assignment_authority.expires_at")
    if expires <= issued:
        raise ContractError("authority_expiry_invalid", "$.assignment_authority")
    if issued > evaluated_at:
        raise ContractError("authority_issued_after_evaluation", "$.assignment_authority.issued_at")
    if evaluated_at >= expires:
        raise ContractError("authority_expired", "$.assignment_authority.expires_at")
    if row["revocation_ref"] is not None:
        _digest(row["revocation_ref"], "$.assignment_authority.revocation_ref")
        raise ContractError("authority_revoked", "$.assignment_authority.revocation_ref")
    scope_paths = _string_set(row["scope_paths"], "$.assignment_authority.scope_paths")
    for index, item in enumerate(row["scope_paths"]):
        _workspace_relative_path(item, f"$.assignment_authority.scope_paths[{index}]")
    if not scope_paths:
        raise ContractError("authority_scope_path_outside_workspace", "$.assignment_authority.scope_paths")
    expected_source_scope = _source_scope_digest(row, runtime, source)
    if row["source_scope_sha256"] != expected_source_scope:
        raise ContractError("source_scope_digest_mismatch", "$.assignment_authority.source_scope_sha256")
    containment = _keys(row["scope_containment"], {
        "resolution_policy", "workspace_root_sha256", "source_scope_sha256",
        "declared_scope_paths", "resolved_path_identities", "resolved_scope_paths_sha256",
        "resolution_evidence_sha256", "checked_at", "result", "effect_gate_policy",
        "pre_effect_recheck_required", "fail_closed", "filesystem_proof_claimed",
    }, "$.assignment_authority.scope_containment")
    if containment["resolution_policy"] != "realpath_symlink_containment_v1":
        raise ContractError("scope_containment_policy_invalid", "$.assignment_authority.scope_containment.resolution_policy")
    for key in ("workspace_root_sha256", "source_scope_sha256", "resolved_scope_paths_sha256", "resolution_evidence_sha256"):
        _digest(containment[key], f"$.assignment_authority.scope_containment.{key}")
    declared_scope_paths = _list(
        containment["declared_scope_paths"],
        "$.assignment_authority.scope_containment.declared_scope_paths",
    )
    for index, item in enumerate(declared_scope_paths):
        _workspace_relative_path(
            item, f"$.assignment_authority.scope_containment.declared_scope_paths[{index}]"
        )
    resolved_identities = _list(
        containment["resolved_path_identities"],
        "$.assignment_authority.scope_containment.resolved_path_identities",
    )
    resolved_declared_paths: list[str] = []
    for index, item in enumerate(resolved_identities):
        path = f"$.assignment_authority.scope_containment.resolved_path_identities[{index}]"
        identity = _keys(item, {
            "requested_path", "resolved_path_sha256", "containing_workspace_root_sha256",
            "resolution_status",
        }, path)
        resolved_declared_paths.append(
            _workspace_relative_path(identity["requested_path"], f"{path}.requested_path")
        )
        _digest(identity["resolved_path_sha256"], f"{path}.resolved_path_sha256")
        _digest(identity["containing_workspace_root_sha256"], f"{path}.containing_workspace_root_sha256")
        if identity["containing_workspace_root_sha256"] != runtime["workspace_root_sha256"]:
            raise ContractError("scope_containment_binding_mismatch", path)
        _enum(identity["resolution_status"], {"resolved_contained"}, f"{path}.resolution_status")
    gate_policy = _keys(
        containment["effect_gate_policy"], set(EFFECT_GATE_POLICY),
        "$.assignment_authority.scope_containment.effect_gate_policy",
    )
    if gate_policy != EFFECT_GATE_POLICY:
        raise ContractError(
            "scope_containment_evidence_invalid",
            "$.assignment_authority.scope_containment.effect_gate_policy",
        )
    if (
        containment["workspace_root_sha256"] != runtime["workspace_root_sha256"]
        or containment["source_scope_sha256"] != row["source_scope_sha256"]
        or declared_scope_paths != row["scope_paths"]
        or resolved_declared_paths != row["scope_paths"]
        or containment["resolved_scope_paths_sha256"] != object_digest(resolved_identities)
    ):
        raise ContractError("scope_containment_binding_mismatch", "$.assignment_authority.scope_containment")
    if _timestamp(containment["checked_at"], "$.assignment_authority.scope_containment.checked_at") != evaluated_at:
        raise ContractError("scope_containment_time_invalid", "$.assignment_authority.scope_containment.checked_at")
    if (
        containment["result"] != "contained"
        or not _bool(containment["pre_effect_recheck_required"], "$.assignment_authority.scope_containment.pre_effect_recheck_required")
        or not _bool(containment["fail_closed"], "$.assignment_authority.scope_containment.fail_closed")
        or _bool(containment["filesystem_proof_claimed"], "$.assignment_authority.scope_containment.filesystem_proof_claimed")
    ):
        raise ContractError("scope_containment_evidence_invalid", "$.assignment_authority.scope_containment")
    if containment["resolution_evidence_sha256"] != _containment_evidence_digest(containment):
        raise ContractError(
            "scope_containment_digest_mismatch",
            "$.assignment_authority.scope_containment.resolution_evidence_sha256",
        )
    for key in ("allowed_tools", "allowed_route_ids", "expected_artifacts"):
        _string_set(row[key], f"$.assignment_authority.{key}")
    for index, item in enumerate(row["expected_artifacts"]):
        _forbid_credential_reference(
            item,
            f"$.assignment_authority.expected_artifacts[{index}]",
            "authority_expected_artifact_credential",
        )
    requested_effects = _validate_effects(
        row["requested_effects"], "$.assignment_authority.requested_effects"
    )
    effect_targets = _keys(
        row["effect_targets"], EFFECT_KEYS, "$.assignment_authority.effect_targets"
    )
    for effect in EFFECT_ORDER:
        target = effect_targets[effect]
        if requested_effects[effect]:
            _digest(target, f"$.assignment_authority.effect_targets.{effect}")
        elif target is not None:
            _digest(target, f"$.assignment_authority.effect_targets.{effect}")
    _validate_limits(row["limits"], "$.assignment_authority.limits")
    if row["limits"] != ROOT_LIMITS:
        raise ContractError("root_limits_not_frozen", "$.assignment_authority.limits")
    return row


def _validate_preflight(
    value: Any,
    route: dict[str, Any],
    authority: dict[str, Any],
    role: dict[str, Any],
    runtime: dict[str, Any],
    evidence: list[dict[str, Any]],
    qualification_sha256: str,
) -> dict[str, Any]:
    row = _keys(value, {
        "preflight_id", "qualification_id", "qualification_sha256", "authority_sha256",
        "source_scope_sha256", "containment_evidence_sha256", "effect_recheck_requirements_sha256",
        "route_id", "assignment_id", "configured_preference", "effective_eligibility",
        "gate_order", "gates", "evidence_state", "health", "quota", "capacity", "billing",
        "billing_basis", "billing_provenance", "fallback_allowed", "probe_lease_ref",
        "evaluated_at", "side_effects",
    }, "$.preflight_result")
    if row["route_id"] != route["route_id"] or row["assignment_id"] != authority["assignment_id"]:
        raise ContractError("preflight_identity_mismatch", "$.preflight_result")
    expected_bindings = {
        "qualification_sha256": qualification_sha256,
        "authority_sha256": authority["authority_sha256"],
        "source_scope_sha256": authority["source_scope_sha256"],
        "containment_evidence_sha256": authority["scope_containment"]["resolution_evidence_sha256"],
    }
    for key, expected in expected_bindings.items():
        _digest(row[key], f"$.preflight_result.{key}")
        if row[key] != expected:
            raise ContractError("preflight_authority_binding_mismatch", f"$.preflight_result.{key}")
    _digest(
        row["effect_recheck_requirements_sha256"],
        "$.preflight_result.effect_recheck_requirements_sha256",
    )
    if row["effect_recheck_requirements_sha256"] != _effect_recheck_requirements_digest(authority):
        raise ContractError(
            "preflight_effect_recheck_requirements_mismatch",
            "$.preflight_result.effect_recheck_requirements_sha256",
        )
    if row["gate_order"] != ELIGIBILITY_ORDER:
        raise ContractError("eligibility_order_invalid", "$.preflight_result.gate_order")
    gates = _list(row["gates"], "$.preflight_result.gates")
    if len(gates) != len(ELIGIBILITY_ORDER):
        raise ContractError("gate_count_invalid", "$.preflight_result.gates")
    all_pass = True
    for index, gate in enumerate(gates):
        path = f"$.preflight_result.gates[{index}]"
        item = _keys(gate, {"gate", "status", "reason_codes"}, path)
        if item["gate"] != ELIGIBILITY_ORDER[index]:
            raise ContractError("eligibility_order_invalid", path)
        _enum(item["status"], {"pass", "fail", "unknown", "stale"}, f"{path}.status")
        _string_set(item["reason_codes"], f"{path}.reason_codes")
        all_pass = all_pass and item["status"] == "pass"
    _enum(row["effective_eligibility"], {"eligible", "ineligible"}, "$.preflight_result.effective_eligibility")
    _enum(row["evidence_state"], {"active", "stale", "contradictory", "unknown", "recalled"}, "$.preflight_result.evidence_state")
    for key in ("health", "quota", "capacity", "billing"):
        _enum(row[key], {"eligible", "ineligible", "unknown", "stale", "unavailable"}, f"$.preflight_result.{key}")
    _bool(row["fallback_allowed"], "$.preflight_result.fallback_allowed")
    expected_fallback = authority["fallback_policy"] != "none" and role["fallback_ceiling"] != "none"
    if row["fallback_allowed"] != expected_fallback:
        raise ContractError("preflight_fallback_ceiling_mismatch", "$.preflight_result.fallback_allowed")
    for key in ("billing_basis", "billing_provenance"):
        _text(row[key], f"$.preflight_result.{key}")
    if (
        route["billing_basis"] == "unknown"
        or route["billing_provenance"] == "unknown"
        or row["billing_basis"] == "unknown"
        or row["billing_provenance"] == "unknown"
        or row["billing"] == "unknown"
    ):
        raise ContractError("billing_identity_unknown", "$.preflight_result.billing_basis")
    if (
        row["billing_basis"] != route["billing_basis"]
        or row["billing_provenance"] != route["billing_provenance"]
        or route["billing_basis"] != authority["billing_ceiling"]
        or route["billing_basis"] != role["billing_ceiling"]
        or route["billing_provenance"] not in BILLING_PROVENANCE_BY_BASIS.get(route["billing_basis"], set())
    ):
        raise ContractError("preflight_billing_identity_mismatch", "$.preflight_result.billing_basis")
    _text(row["configured_preference"], "$.preflight_result.configured_preference")
    _text(row["probe_lease_ref"], "$.preflight_result.probe_lease_ref")
    _timestamp(row["evaluated_at"], "$.preflight_result.evaluated_at")
    side = _keys(row["side_effects"], {"capacity_allocated", "route_selected", "provider_called", "ledger_appended", "policy_activated"}, "$.preflight_result.side_effects")
    if any(_bool(item, f"$.preflight_result.side_effects.{key}") for key, item in side.items()):
        raise ContractError("preflight_effect_forbidden", "$.preflight_result.side_effects")
    active_evidence = all(item["status"] == "observed" for item in evidence)
    eligible_facts = row["evidence_state"] == "active" and all(row[key] == "eligible" for key in ("health", "quota", "capacity", "billing"))
    runtime_healthy = runtime["health"] == "healthy" and not runtime["degraded_reasons"]
    if row["effective_eligibility"] == "eligible" and not runtime_healthy:
        raise ContractError("preflight_runtime_health_mismatch", "$.preflight_result.health")
    if row["effective_eligibility"] == "eligible" and not (all_pass and active_evidence and eligible_facts and authority["status"] == "active"):
        raise ContractError("eligibility_not_proven", "$.preflight_result.effective_eligibility")
    return row


def _validate_capacity(value: Any, preflight: dict[str, Any]) -> dict[str, Any]:
    row = _keys(value, {"authority_domain", "selected_adapter_id", "adapters", "dispatch_scheduler", "dispatch_ledger", "preflight_broker"}, "$.capacity_authority")
    _identifier(row["authority_domain"], "$.capacity_authority.authority_domain")
    selected = _identifier(row["selected_adapter_id"], "$.capacity_authority.selected_adapter_id")
    adapters = _list(row["adapters"], "$.capacity_authority.adapters")
    qualified_live: list[str] = []
    selected_live = False
    selected_compatibility = False
    selected_is_sole = False
    sole = 0
    kinds: set[str] = set()
    adapter_ids: set[str] = set()
    expected_kind = {
        "workspace-shared": "shared_sqlite_fleet",
        "isolated-local": "isolated_local",
    }.get(row["authority_domain"])
    if expected_kind is None:
        raise ContractError("capacity_domain_kind_mismatch", "$.capacity_authority.authority_domain")
    for index, adapter in enumerate(adapters):
        path = f"$.capacity_authority.adapters[{index}]"
        item = _keys(adapter, {"adapter_id", "adapter_version", "authority_domain", "kind", "qualified", "sole_capacity_authority", "compatibility_only"}, path)
        adapter_id = _identifier(item["adapter_id"], f"{path}.adapter_id")
        if adapter_id in adapter_ids:
            raise ContractError("capacity_adapter_id_duplicate", f"{path}.adapter_id")
        adapter_ids.add(adapter_id)
        _text(item["adapter_version"], f"{path}.adapter_version")
        if item["authority_domain"] != row["authority_domain"]:
            raise ContractError("capacity_domain_mismatch", path)
        _enum(item["kind"], {"shared_sqlite_fleet", "isolated_local"}, f"{path}.kind")
        kinds.add(item["kind"])
        for key in ("qualified", "sole_capacity_authority", "compatibility_only"):
            _bool(item[key], f"{path}.{key}")
        if item["qualified"] and not item["compatibility_only"]:
            qualified_live.append(item["adapter_id"])
        if item["sole_capacity_authority"]:
            sole += 1
        if item["adapter_id"] == selected and item["qualified"] and item["compatibility_only"]:
            selected_compatibility = True
        if item["adapter_id"] == selected and item["qualified"] and not item["compatibility_only"]:
            selected_live = True
            selected_is_sole = item["sole_capacity_authority"]
    if sole != 1:
        raise ContractError("capacity_authority_not_exclusive", "$.capacity_authority.adapters")
    if selected_compatibility:
        raise ContractError("capacity_compatibility_selection_forbidden", "$.capacity_authority.selected_adapter_id")
    if len(qualified_live) != 1:
        raise ContractError("capacity_live_authority_not_unique", "$.capacity_authority.adapters")
    if not selected_live:
        raise ContractError("capacity_compatibility_selection_forbidden", "$.capacity_authority.selected_adapter_id")
    if not selected_is_sole:
        raise ContractError("capacity_authority_not_exclusive", "$.capacity_authority.adapters")
    if len(kinds) != 1:
        raise ContractError("capacity_adapter_coexistence_forbidden", "$.capacity_authority.adapters")
    if kinds != {expected_kind}:
        raise ContractError("capacity_domain_kind_mismatch", "$.capacity_authority.adapters")
    scheduler = _keys(row["dispatch_scheduler"], {"owns_run_scheduling", "allocates_shared_capacity"}, "$.capacity_authority.dispatch_scheduler")
    ledger = _keys(row["dispatch_ledger"], {"records_run_accounting", "allocates_shared_capacity", "capacity_lease_ref_external"}, "$.capacity_authority.dispatch_ledger")
    broker = _keys(row["preflight_broker"], {"probe_serialization_only", "probe_lease_ref"}, "$.capacity_authority.preflight_broker")
    if not _bool(scheduler["owns_run_scheduling"], "$.capacity_authority.dispatch_scheduler.owns_run_scheduling") or _bool(scheduler["allocates_shared_capacity"], "$.capacity_authority.dispatch_scheduler.allocates_shared_capacity"):
        raise ContractError("scheduler_capacity_conflation", "$.capacity_authority.dispatch_scheduler")
    if not _bool(ledger["records_run_accounting"], "$.capacity_authority.dispatch_ledger.records_run_accounting") or _bool(ledger["allocates_shared_capacity"], "$.capacity_authority.dispatch_ledger.allocates_shared_capacity") or not _bool(ledger["capacity_lease_ref_external"], "$.capacity_authority.dispatch_ledger.capacity_lease_ref_external"):
        raise ContractError("ledger_capacity_conflation", "$.capacity_authority.dispatch_ledger")
    if not _bool(broker["probe_serialization_only"], "$.capacity_authority.preflight_broker.probe_serialization_only") or broker["probe_lease_ref"] != preflight["probe_lease_ref"]:
        raise ContractError("probe_lease_conflation", "$.capacity_authority.preflight_broker")
    return row


def _validate_delegation(value: Any, parent: dict[str, Any], route: dict[str, Any], run: dict[str, Any], remaining: dict[str, int]) -> dict[str, Any]:
    row = _keys(value, {
        "request_id", "status", "proposed_by", "admitted_by", "parent_run_id", "child_run_id", "parent_route_id",
        "child_route_preference", "child_route_requirement", "objective", "expected_artifact", "scope_paths", "allowed_tools",
        "effects", "disclosure_refs", "egress", "network", "billing_ceiling", "fallback_policy", "limits", "structural_limits",
        "validation_policy_sha256", "return_schema_sha256", "cycle_check", "independent_admission", "direct_spawn", "authority_relation",
    }, "$.delegation")
    _enum(row["status"], {"proposed", "admitted", "denied", "cancelled", "recalled"}, "$.delegation.status")
    _enum(row["authority_relation"], {"strict_subset"}, "$.delegation.authority_relation")
    if row["parent_route_id"] != route["route_id"]:
        raise ContractError("parent_route_mismatch", "$.delegation.parent_route_id")
    if row["parent_run_id"] != run["run_id"] or row["proposed_by"] != run["run_id"]:
        raise ContractError("delegation_parent_lineage_mismatch", "$.delegation.parent_run_id")
    if row["child_run_id"] in {run["run_id"], row["parent_run_id"], row["proposed_by"]}:
        raise ContractError("delegation_identity_cycle", "$.delegation.child_run_id")
    for key in ("request_id", "proposed_by", "admitted_by", "parent_run_id", "child_run_id", "child_route_preference", "objective", "expected_artifact", "egress", "network", "billing_ceiling", "fallback_policy", "cycle_check"):
        _text(row[key], f"$.delegation.{key}")
    if row["child_route_requirement"] is not None:
        _text(row["child_route_requirement"], "$.delegation.child_route_requirement")
    for key in ("validation_policy_sha256", "return_schema_sha256"):
        _digest(row[key], f"$.delegation.{key}")
    scope = _string_set(row["scope_paths"], "$.delegation.scope_paths")
    tools = _string_set(row["allowed_tools"], "$.delegation.allowed_tools")
    disclosure = _string_set(row["disclosure_refs"], "$.delegation.disclosure_refs")
    _forbid_credential_reference(
        row["expected_artifact"],
        "$.delegation.expected_artifact",
        "delegation_disclosure_reference_credential",
    )
    for index, item in enumerate(row["disclosure_refs"]):
        _forbid_credential_reference(
            item,
            f"$.delegation.disclosure_refs[{index}]",
            "delegation_disclosure_reference_credential",
        )
    effects = _validate_effects(row["effects"], "$.delegation.effects")
    limits = _validate_limits(row["limits"], "$.delegation.limits")
    structural = _keys(row["structural_limits"], {"depth", "children_per_parent", "active_children_per_parent", "active_descendants_per_root", "child_to_child_message_edges"}, "$.delegation.structural_limits")
    for key, item in structural.items():
        _integer(item, f"$.delegation.structural_limits.{key}")
    expected_structural = {"depth": 1, "children_per_parent": 1, "active_children_per_parent": 1, "active_descendants_per_root": 1, "child_to_child_message_edges": 0}
    if structural != expected_structural:
        raise ContractError("delegation_structural_limit_invalid", "$.delegation.structural_limits")
    _bool(row["independent_admission"], "$.delegation.independent_admission")
    _bool(row["direct_spawn"], "$.delegation.direct_spawn")
    if row["status"] == "admitted" and (not row["independent_admission"] or row["direct_spawn"]):
        raise ContractError("delegation_admission_invalid", "$.delegation")
    if row["status"] == "admitted" and row["admitted_by"] != "codexmax-runtime":
        raise ContractError("model_created_authority", "$.delegation.admitted_by")
    if row["cycle_check"] != "pass":
        raise ContractError("delegation_cycle_check_failed", "$.delegation.cycle_check")
    if row["child_route_preference"] not in parent["allowed_route_ids"]:
        raise ContractError("child_route_widening", "$.delegation.child_route_preference")
    if row["child_route_requirement"] is not None and row["child_route_requirement"] not in parent["allowed_route_ids"]:
        raise ContractError("child_route_widening", "$.delegation.child_route_requirement")
    if row["egress"] != "none" or row["network"] != "none":
        raise ContractError("child_egress_widening", "$.delegation")
    if not scope < _string_set(parent["scope_paths"], "$.assignment_authority.scope_paths"):
        raise ContractError("child_scope_not_strict_subset", "$.delegation.scope_paths")
    if not tools.issubset(_string_set(parent["allowed_tools"], "$.assignment_authority.allowed_tools")):
        raise ContractError("child_tool_widening", "$.delegation.allowed_tools")
    if not disclosure.issubset(_string_set(parent["expected_artifacts"], "$.assignment_authority.expected_artifacts")):
        raise ContractError("child_disclosure_widening", "$.delegation.disclosure_refs")
    for key, permitted in parent["requested_effects"].items():
        if effects[key] and not permitted:
            raise ContractError("child_effect_widening", f"$.delegation.effects.{key}")
    for key, amount in limits.items():
        if amount > remaining[key]:
            raise ContractError("child_limit_widening", f"$.delegation.limits.{key}")
    if limits != CHILD_LIMITS:
        raise ContractError("child_limits_not_frozen", "$.delegation.limits")
    if row["billing_ceiling"] != parent["billing_ceiling"] or row["fallback_policy"] != parent["fallback_policy"]:
        raise ContractError("child_billing_or_fallback_widening", "$.delegation")
    if row["validation_policy_sha256"] != parent["validation_policy_sha256"]:
        raise ContractError("child_validation_policy_mismatch", "$.delegation.validation_policy_sha256")
    if row["return_schema_sha256"] != parent["return_schema_sha256"]:
        raise ContractError("child_return_schema_mismatch", "$.delegation.return_schema_sha256")
    return row


def validate(document: Any) -> dict[str, Any]:
    _reject_floats(document)
    payload = _keys(document, TOP_LEVEL, "$")
    if not isinstance(payload["contract"], str) or payload["contract"] != CONTRACT:
        raise ContractError("contract_version_unsupported", "$")
    _integer(payload["contract_version"], "$.contract_version", minimum=1)
    if payload["contract_version"] != VERSION:
        raise ContractError("contract_version_unsupported", "$")
    versions = _keys(payload["component_versions"], COMPONENTS, "$.component_versions")
    for key, value in versions.items():
        _integer(value, f"$.component_versions.{key}", minimum=1)
        if value != 1:
            raise ContractError("component_version_unsupported", f"$.component_versions.{key}")

    runtime = _keys(payload["runtime_manifest"], {"runtime_id", "runtime_version", "api_version", "source_sha256", "candidate_sha256", "workspace_root_sha256", "isolation_id", "process_mode", "endpoint_kind", "supported_transports", "health", "degraded_reasons", "recovery_instructions", "mandatory_model_hop", "model_can_admit"}, "$.runtime_manifest")
    for key in ("source_sha256", "candidate_sha256", "workspace_root_sha256"):
        _digest(runtime[key], f"$.runtime_manifest.{key}")
    for key in ("runtime_id", "runtime_version", "api_version", "isolation_id", "process_mode", "endpoint_kind", "health", "recovery_instructions"):
        _text(runtime[key], f"$.runtime_manifest.{key}")
    supported_transports = _string_set(runtime["supported_transports"], "$.runtime_manifest.supported_transports")
    _string_set(runtime["degraded_reasons"], "$.runtime_manifest.degraded_reasons")
    if runtime["process_mode"] != "foreground":
        raise ContractError("runtime_process_mode_invalid", "$.runtime_manifest.process_mode")
    local_endpoint_kinds = {"unix_" + "sock" + "et", "loopback_http"}
    if runtime["endpoint_kind"] not in local_endpoint_kinds:
        raise ContractError("runtime_endpoint_kind_invalid", "$.runtime_manifest.endpoint_kind")
    endpoint_transport = runtime["endpoint_kind"]
    if (
        not supported_transports
        or not supported_transports.issubset(LOCAL_TRANSPORTS)
        or endpoint_transport not in supported_transports
        or ({"unix_" + "sock" + "et", "loopback_http"} - {endpoint_transport}) & supported_transports
    ):
        raise ContractError("runtime_transport_invalid", "$.runtime_manifest.supported_transports")
    if _bool(runtime["mandatory_model_hop"], "$.runtime_manifest.mandatory_model_hop") or _bool(runtime["model_can_admit"], "$.runtime_manifest.model_can_admit"):
        raise ContractError("model_authority_boundary_invalid", "$.runtime_manifest")

    source = _keys(payload["source_identity"], {"repository_commit", "repository_tree", "plugin_version", "manifest_sha256", "source_tree_sha256", "release_status"}, "$.source_identity")
    for key in ("manifest_sha256", "source_tree_sha256"):
        _digest(source[key], f"$.source_identity.{key}")
    for key in ("repository_commit", "repository_tree"):
        if not isinstance(source[key], str) or not re.fullmatch(r"[0-9a-f]{40}", source[key]):
            raise ContractError("git_identity_invalid", f"$.source_identity.{key}")
    _enum(source["release_status"], {"development_anchor", "candidate", "released"}, "$.source_identity.release_status")
    if runtime["source_sha256"] != source["source_tree_sha256"]:
        raise ContractError("runtime_source_mismatch", "$.runtime_manifest.source_sha256")

    route = _validate_route(payload["route"])
    qualification = _keys(payload["qualification"], {"qualification_id", "qualification_sha256", "route_id", "adapter_sha256", "task_profile_sha256", "evaluation_manifest_sha256", "observed_at", "expires_at", "evaluated_at", "effective_status", "signature_state"}, "$.qualification")
    if qualification["route_id"] != route["route_id"] or qualification["adapter_sha256"] != route["adapter_sha256"]:
        raise ContractError("qualification_identity_mismatch", "$.qualification")
    for key in ("qualification_sha256", "adapter_sha256", "task_profile_sha256", "evaluation_manifest_sha256"):
        _digest(qualification[key], f"$.qualification.{key}")
    observed = _timestamp(qualification["observed_at"], "$.qualification.observed_at")
    expires = _timestamp(qualification["expires_at"], "$.qualification.expires_at")
    evaluated_at = _timestamp(qualification["evaluated_at"], "$.qualification.evaluated_at")
    if expires <= observed:
        raise ContractError("qualification_expiry_invalid", "$.qualification")
    if evaluated_at < observed:
        raise ContractError("qualification_evaluated_before_observation", "$.qualification.evaluated_at")
    _enum(qualification["effective_status"], {"recalled", "expired", "stale", "active"}, "$.qualification.effective_status")
    _enum(qualification["signature_state"], {"not_configured", "unknown"}, "$.qualification.signature_state")
    evidence = _validate_capability(payload["capability_evidence"], route, evaluated_at)
    for index, item in enumerate(evidence):
        if item["task_profile_sha256"] != qualification["task_profile_sha256"]:
            raise ContractError("qualification_task_profile_mismatch", f"$.capability_evidence[{index}].task_profile_sha256")
        if item["evaluation_manifest_sha256"] != qualification["evaluation_manifest_sha256"]:
            raise ContractError("qualification_evaluation_mismatch", f"$.capability_evidence[{index}].evaluation_manifest_sha256")
    derived_qualification = "expired" if evaluated_at >= expires else "active"
    if qualification["effective_status"] != derived_qualification:
        raise ContractError("qualification_status_mismatch", "$.qualification.effective_status")
    qualification_sha256 = _qualification_digest(qualification, evidence)
    if qualification["qualification_sha256"] != qualification_sha256:
        raise ContractError("qualification_digest_mismatch", "$.qualification.qualification_sha256")

    role = _keys(payload["role_policy"], {"role_id", "requirements", "maximum_effects", "affinity_weights", "independence_requirement", "consequence_ceiling", "billing_ceiling", "fallback_ceiling", "allowed_route_filters", "incompatibility_reasons"}, "$.role_policy")
    _identifier(role["role_id"], "$.role_policy.role_id")
    _mapping(role["requirements"], "$.role_policy.requirements")
    _validate_effects(role["maximum_effects"], "$.role_policy.maximum_effects")
    weights = _mapping(role["affinity_weights"], "$.role_policy.affinity_weights")
    for key, value in weights.items():
        _identifier(key, "$.role_policy.affinity_weights")
        _integer(value, f"$.role_policy.affinity_weights.{key}")
        if key != route["route_id"]:
            raise ContractError("role_affinity_route_mismatch", f"$.role_policy.affinity_weights.{key}")
    for key in ("independence_requirement", "consequence_ceiling", "billing_ceiling", "fallback_ceiling"):
        _text(role[key], f"$.role_policy.{key}")
    role_routes = _string_set(role["allowed_route_filters"], "$.role_policy.allowed_route_filters")
    _string_set(role["incompatibility_reasons"], "$.role_policy.incompatibility_reasons")
    if route["route_id"] not in role_routes:
        raise ContractError("role_route_filter_mismatch", "$.role_policy.allowed_route_filters")

    authority = _validate_authority(payload["assignment_authority"], evaluated_at, runtime, source)
    if route["route_id"] not in authority["allowed_route_ids"]:
        raise ContractError("route_not_authorized", "$.assignment_authority.allowed_route_ids")
    if authority["consequence_level"] != role["consequence_ceiling"]:
        raise ContractError("role_consequence_ceiling_exceeded", "$.assignment_authority.consequence_level")
    if authority["billing_ceiling"] != role["billing_ceiling"]:
        raise ContractError("role_billing_ceiling_exceeded", "$.assignment_authority.billing_ceiling")
    if authority["fallback_policy"] != role["fallback_ceiling"]:
        raise ContractError("role_fallback_ceiling_exceeded", "$.assignment_authority.fallback_policy")
    evidence_by_capability = {item["capability"]: item for item in evidence}
    for capability, level in role["requirements"].items():
        _identifier(capability, "$.role_policy.requirements")
        _text(level, f"$.role_policy.requirements.{capability}")
        item = evidence_by_capability.get(capability)
        if item is None or item["level"] != level:
            raise ContractError("role_capability_requirement_unmet", f"$.role_policy.requirements.{capability}")
    for effect, requested in authority["requested_effects"].items():
        if requested and not role["maximum_effects"][effect]:
            raise ContractError("assignment_exceeds_role_effects", f"$.assignment_authority.requested_effects.{effect}")
        capability = EFFECT_CAPABILITIES[effect]
        evidence_item = evidence_by_capability.get(capability)
        if requested and evidence_item is None:
            raise ContractError("assignment_effect_unproven", f"$.assignment_authority.requested_effects.{effect}")
        if requested and CAPABILITY_LEVEL_RANK[evidence_item["level"]] < CAPABILITY_LEVEL_RANK[EFFECT_MINIMUM_LEVEL[effect]]:
            raise ContractError("assignment_effect_level_insufficient", f"$.assignment_authority.requested_effects.{effect}")
    for tool in authority["allowed_tools"]:
        tool_requirement = TOOL_CAPABILITIES.get(tool)
        if tool_requirement is None:
            raise ContractError("assignment_tool_unproven", "$.assignment_authority.allowed_tools")
        capability, minimum_level = tool_requirement
        if capability not in evidence_by_capability:
            raise ContractError("assignment_tool_unproven", "$.assignment_authority.allowed_tools")
        if CAPABILITY_LEVEL_RANK[evidence_by_capability[capability]["level"]] < CAPABILITY_LEVEL_RANK[minimum_level]:
            raise ContractError("assignment_tool_level_insufficient", "$.assignment_authority.allowed_tools")
    tools = set(authority["allowed_tools"])
    filesystem_write = authority["requested_effects"]["filesystem_write"]
    if authority["mutation_mode"] == "read_only" and (filesystem_write or "write_fixture" in tools):
        raise ContractError("mutation_mode_effect_mismatch", "$.assignment_authority.mutation_mode")
    if authority["mutation_mode"] == "new_files_only" and (filesystem_write != ("write_fixture" in tools)):
        raise ContractError("mutation_mode_tool_mismatch", "$.assignment_authority.mutation_mode")
    preflight = _validate_preflight(
        payload["preflight_result"], route, authority, role, runtime, evidence,
        qualification_sha256,
    )
    if preflight["evaluated_at"] != qualification["evaluated_at"]:
        raise ContractError("preflight_evaluation_time_mismatch", "$.preflight_result.evaluated_at")
    if qualification["effective_status"] != "active" and preflight["effective_eligibility"] == "eligible":
        raise ContractError("qualification_not_eligible", "$.preflight_result.effective_eligibility")
    if preflight["qualification_id"] != qualification["qualification_id"]:
        raise ContractError("preflight_qualification_identity_mismatch", "$.preflight_result.qualification_id")
    if route["billing_basis"] == "metered" and authority["limits"]["external_cost_microunits"] == 0:
        raise ContractError("metered_zero_cost_budget", "$.preflight_result.billing_basis")
    if authority["authority_sha256"] != _authority_digest(authority):
        raise ContractError("authority_digest_mismatch", "$.assignment_authority.authority_sha256")
    plan = _keys(payload["plan_result"], {"plan_id", "preflight_id", "assignment_id", "authority_sha256", "source_scope_sha256", "qualification_sha256", "containment_evidence_sha256", "effect_recheck_requirements_sha256", "selected_route_id", "eligibility_basis", "capacity_lease_ref", "provider_effect", "filesystem_effect", "ledger_effect", "admission_status"}, "$.plan_result")
    if plan["assignment_id"] != authority["assignment_id"] or plan["selected_route_id"] != route["route_id"]:
        raise ContractError("plan_identity_mismatch", "$.plan_result")
    if plan["capacity_lease_ref"] is not None or any(_bool(plan[key], f"$.plan_result.{key}") for key in ("provider_effect", "filesystem_effect", "ledger_effect")):
        raise ContractError("plan_effect_forbidden", "$.plan_result")
    _enum(plan["admission_status"], {"not_requested"}, "$.plan_result.admission_status")
    eligibility_basis = _string_set(plan["eligibility_basis"], "$.plan_result.eligibility_basis")
    if preflight["effective_eligibility"] != "eligible":
        raise ContractError("plan_preflight_not_eligible", "$.plan_result")
    if plan["preflight_id"] != preflight["preflight_id"] or eligibility_basis != {preflight["preflight_id"]}:
        raise ContractError("plan_preflight_identity_mismatch", "$.plan_result.preflight_id")
    plan_bindings = {
        "authority_sha256": authority["authority_sha256"],
        "source_scope_sha256": authority["source_scope_sha256"],
        "qualification_sha256": qualification_sha256,
        "containment_evidence_sha256": authority["scope_containment"]["resolution_evidence_sha256"],
        "effect_recheck_requirements_sha256": preflight["effect_recheck_requirements_sha256"],
    }
    for key, expected in plan_bindings.items():
        _digest(plan[key], f"$.plan_result.{key}")
        if plan[key] != expected:
            raise ContractError("plan_authority_binding_mismatch", f"$.plan_result.{key}")

    capacity = _validate_capacity(payload["capacity_authority"], preflight)
    run = _keys(payload["run"], {"run_id", "preflight_id", "assignment_id", "authority_sha256", "source_scope_sha256", "qualification_sha256", "containment_evidence_sha256", "effect_recheck_receipts", "route_id", "adapter_sha256", "capacity_authority_domain", "capacity_lease_ref", "run_execution_fence", "preflight_probe_lease_ref", "lifecycle", "terminal_outcome", "successor_run_id", "predecessor_run_id", "acceptance_claimed"}, "$.run")
    if run["preflight_id"] != preflight["preflight_id"] or run["assignment_id"] != authority["assignment_id"] or run["route_id"] != route["route_id"] or run["adapter_sha256"] != route["adapter_sha256"] or run["capacity_authority_domain"] != capacity["authority_domain"]:
        raise ContractError("run_identity_mismatch", "$.run")
    run_bindings = {
        "authority_sha256": authority["authority_sha256"],
        "source_scope_sha256": authority["source_scope_sha256"],
        "qualification_sha256": qualification_sha256,
        "containment_evidence_sha256": authority["scope_containment"]["resolution_evidence_sha256"],
    }
    for key, expected in run_bindings.items():
        _digest(run[key], f"$.run.{key}")
        if run[key] != expected:
            raise ContractError("run_authority_binding_mismatch", f"$.run.{key}")
    effect_rechecks = _list(run["effect_recheck_receipts"], "$.run.effect_recheck_receipts")
    for key in ("capacity_lease_ref", "run_execution_fence", "preflight_probe_lease_ref"):
        _text(run[key], f"$.run.{key}")
    if len({run["capacity_lease_ref"], run["run_execution_fence"], run["preflight_probe_lease_ref"]}) != 3 or run["preflight_probe_lease_ref"] != preflight["probe_lease_ref"]:
        raise ContractError("lease_domain_conflation", "$.run")
    lifecycle = _list(run["lifecycle"], "$.run.lifecycle")
    allowed_lifecycle = ["created", "preflighted", "planned", "admitted", "launching", "running", "reconciling", "quality_checked", "review_pending", "terminal"]
    if lifecycle != allowed_lifecycle[:len(lifecycle)] or lifecycle[-1:] != ["terminal"]:
        raise ContractError("run_lifecycle_invalid", "$.run.lifecycle")
    _enum(run["terminal_outcome"], {"completed", "denied", "cancelled", "failed", "timed_out", "unavailable", "unreconciled", "superseded", "recovered_to_successor"}, "$.run.terminal_outcome")
    successor_outcomes = {"superseded", "recovered_to_successor"}
    if run["terminal_outcome"] in successor_outcomes and run["successor_run_id"] is None:
        raise ContractError("successor_required", "$.run.successor_run_id")
    if run["terminal_outcome"] not in successor_outcomes and run["successor_run_id"] is not None:
        raise ContractError("successor_terminal_mismatch", "$.run.successor_run_id")
    if run["successor_run_id"] is not None:
        _identifier(run["successor_run_id"], "$.run.successor_run_id")
    if run["predecessor_run_id"] is not None:
        _identifier(run["predecessor_run_id"], "$.run.predecessor_run_id")
    if run["successor_run_id"] is not None and run["successor_run_id"] in {run["run_id"], run["predecessor_run_id"]}:
        raise ContractError("recovery_identity_cycle", "$.run.successor_run_id")
    if _bool(run["acceptance_claimed"], "$.run.acceptance_claimed"):
        raise ContractError("runtime_acceptance_forbidden", "$.run.acceptance_claimed")

    events = _list(payload["events"], "$.events")
    previous: str | None = None
    previous_recorded: datetime | None = None
    previous_lifecycle_index = -1
    event_ids: set[str] = set()
    event_types: list[str] = []
    event_times: list[datetime] = []
    authority_issued = _timestamp(authority["issued_at"], "$.assignment_authority.issued_at")
    authority_expires = _timestamp(authority["expires_at"], "$.assignment_authority.expires_at")
    qualification_expires = _timestamp(qualification["expires_at"], "$.qualification.expires_at")
    for index, event in enumerate(events):
        path = f"$.events[{index}]"
        item = _keys(event, {"event_id", "sequence", "event_type", "run_id", "predecessor_event_sha256", "object_sha256", "recorded_at"}, path)
        event_id = _identifier(item["event_id"], f"{path}.event_id")
        if event_id in event_ids:
            raise ContractError("event_id_duplicate", f"{path}.event_id")
        event_ids.add(event_id)
        _integer(item["sequence"], f"{path}.sequence", minimum=1)
        if item["sequence"] != index + 1 or item["predecessor_event_sha256"] != previous or item["run_id"] != run["run_id"]:
            raise ContractError("event_chain_invalid", path)
        event_type = _text(item["event_type"], f"{path}.event_type")
        lifecycle_state = EVENT_LIFECYCLE.get(event_type)
        if lifecycle_state is None:
            raise ContractError("event_type_unsupported", f"{path}.event_type")
        lifecycle_index = lifecycle.index(lifecycle_state)
        if lifecycle_index < previous_lifecycle_index:
            raise ContractError("event_lifecycle_order_invalid", f"{path}.event_type")
        previous_lifecycle_index = lifecycle_index
        _digest(item["object_sha256"], f"{path}.object_sha256")
        recorded_at = _timestamp(item["recorded_at"], f"{path}.recorded_at")
        if previous_recorded is not None and recorded_at <= previous_recorded:
            raise ContractError("event_timestamp_regression", f"{path}.recorded_at")
        if (
            recorded_at < authority_issued
            or recorded_at < evaluated_at
            or recorded_at >= authority_expires
            or recorded_at >= qualification_expires
        ):
            raise ContractError("event_time_outside_authority", f"{path}.recorded_at")
        previous_recorded = recorded_at
        event_times.append(recorded_at)
        body = {key: value for key, value in item.items() if key != "object_sha256"}
        if item["object_sha256"] != object_digest(body):
            raise ContractError("event_digest_mismatch", f"{path}.object_sha256")
        previous = item["object_sha256"]
        event_types.append(item["event_type"])
    if event_types[:1] != ["run_created"] or event_types[-1:] != ["run_terminal"]:
        raise ContractError("event_lifecycle_mismatch", "$.events")
    if event_types.count("run_created") != 1 or event_types.count("run_terminal") != 1:
        raise ContractError("event_terminal_legality_invalid", "$.events")
    earliest_capability_expiry = min(
        _timestamp(item["expires_at"], "$.capability_evidence.expires_at") for item in evidence
    )
    if event_times and event_times[-1] >= earliest_capability_expiry:
        raise ContractError("terminal_after_capability_expiry", "$.events[-1].recorded_at")
    expected_effects = [effect for effect in EFFECT_ORDER if authority["requested_effects"][effect]]
    receipt_ids: set[str] = set()
    receipt_digests: set[str] = set()
    boundary_digests: set[str] = set()
    validated_rechecks: list[dict[str, Any]] = []
    previous_checked: datetime | None = None
    previous_boundary: datetime | None = None
    for index, item in enumerate(effect_rechecks):
        path = f"$.run.effect_recheck_receipts[{index}]"
        receipt = _keys(item, {
            "receipt_id", "receipt_sha256", "run_id", "effect_kind", "effect_sequence",
            "target_identity_sha256", "authority_sha256", "source_scope_sha256",
            "qualification_sha256", "containment_evidence_sha256", "checked_at", "result",
            "effect_phase", "effect_gate_policy_sha256", "effect_boundary_at",
            "effect_boundary_sha256",
        }, path)
        receipt_id = _identifier(receipt["receipt_id"], f"{path}.receipt_id")
        for key in (
            "receipt_sha256", "target_identity_sha256", "authority_sha256",
            "source_scope_sha256", "qualification_sha256", "containment_evidence_sha256",
            "effect_gate_policy_sha256", "effect_boundary_sha256",
        ):
            _digest(receipt[key], f"{path}.{key}")
        _integer(receipt["effect_sequence"], f"{path}.effect_sequence", minimum=1)
        if (
            receipt_id in receipt_ids
            or receipt["receipt_sha256"] in receipt_digests
            or receipt["effect_boundary_sha256"] in boundary_digests
        ):
            raise ContractError("effect_recheck_receipt_reused", path)
        receipt_ids.add(receipt_id)
        receipt_digests.add(receipt["receipt_sha256"])
        boundary_digests.add(receipt["effect_boundary_sha256"])
        validated_rechecks.append(receipt)
    if len(validated_rechecks) != len(expected_effects):
        raise ContractError("effect_recheck_effect_uncovered", "$.run.effect_recheck_receipts")
    for index, (receipt, expected_effect) in enumerate(zip(validated_rechecks, expected_effects)):
        path = f"$.run.effect_recheck_receipts[{index}]"
        if receipt["effect_kind"] != expected_effect or receipt["effect_sequence"] != index + 1:
            raise ContractError("effect_recheck_order_mismatch", path)
        if receipt["target_identity_sha256"] != authority["effect_targets"][expected_effect]:
            raise ContractError("effect_recheck_target_mismatch", f"{path}.target_identity_sha256")
        expected_recheck_bindings = {
            "run_id": run["run_id"],
            "authority_sha256": authority["authority_sha256"],
            "source_scope_sha256": authority["source_scope_sha256"],
            "qualification_sha256": qualification_sha256,
            "containment_evidence_sha256": authority["scope_containment"]["resolution_evidence_sha256"],
            "effect_gate_policy_sha256": object_digest(EFFECT_GATE_POLICY),
        }
        if any(receipt[key] != expected for key, expected in expected_recheck_bindings.items()):
            raise ContractError("effect_recheck_binding_mismatch", path)
        if receipt["result"] != "pass" or receipt["effect_phase"] != "execution":
            raise ContractError("effect_recheck_denied", path)
        checked_at = _timestamp(receipt["checked_at"], f"{path}.checked_at")
        boundary_at = _timestamp(receipt["effect_boundary_at"], f"{path}.effect_boundary_at")
        if checked_at < event_times[0]:
            raise ContractError("effect_recheck_pre_run", f"{path}.checked_at")
        if checked_at >= authority_expires or checked_at >= qualification_expires:
            raise ContractError("effect_recheck_time_invalid", f"{path}.checked_at")
        if boundary_at < checked_at or boundary_at > event_times[-1]:
            raise ContractError("effect_recheck_boundary_time_invalid", f"{path}.effect_boundary_at")
        if int((boundary_at - checked_at).total_seconds()) > 1:
            raise ContractError("effect_recheck_stale", f"{path}.checked_at")
        if (
            previous_checked is not None
            and (checked_at <= previous_checked or boundary_at <= previous_boundary)
        ):
            raise ContractError("effect_recheck_order_mismatch", path)
        previous_checked = checked_at
        previous_boundary = boundary_at
        if receipt["effect_boundary_sha256"] != _effect_boundary_digest(receipt):
            raise ContractError("effect_recheck_boundary_mismatch", f"{path}.effect_boundary_sha256")
        if receipt["receipt_sha256"] != _effect_recheck_digest(receipt):
            raise ContractError("effect_recheck_digest_mismatch", f"{path}.receipt_sha256")

    receipts = _keys(payload["receipts"], {"execution", "quality", "usage", "artifacts", "lineage", "recovery"}, "$.receipts")
    execution = _keys(receipts["execution"], {"status", "preflight_id", "run_id", "route_id", "adapter_sha256", "authority_sha256", "source_scope_sha256", "qualification_sha256", "containment_evidence_sha256", "effect_recheck_receipt_sha256s", "capacity_lease_ref", "source_sha256"}, "$.receipts.execution")
    if execution["preflight_id"] != preflight["preflight_id"] or execution["run_id"] != run["run_id"] or execution["route_id"] != route["route_id"] or execution["adapter_sha256"] != route["adapter_sha256"] or execution["authority_sha256"] != authority["authority_sha256"] or execution["capacity_lease_ref"] != run["capacity_lease_ref"]:
        raise ContractError("execution_receipt_mismatch", "$.receipts.execution")
    execution_bindings = {
        "source_scope_sha256": authority["source_scope_sha256"],
        "qualification_sha256": qualification_sha256,
        "containment_evidence_sha256": authority["scope_containment"]["resolution_evidence_sha256"],
    }
    for key, expected in execution_bindings.items():
        _digest(execution[key], f"$.receipts.execution.{key}")
        if execution[key] != expected:
            raise ContractError("execution_authority_binding_mismatch", f"$.receipts.execution.{key}")
    execution_rechecks = _list(
        execution["effect_recheck_receipt_sha256s"],
        "$.receipts.execution.effect_recheck_receipt_sha256s",
    )
    for index, digest in enumerate(execution_rechecks):
        _digest(digest, f"$.receipts.execution.effect_recheck_receipt_sha256s[{index}]")
    if execution_rechecks != [receipt["receipt_sha256"] for receipt in validated_rechecks]:
        raise ContractError(
            "execution_authority_binding_mismatch",
            "$.receipts.execution.effect_recheck_receipt_sha256s",
        )
    _enum(execution["status"], {"completed", "failed", "unknown", "unreconciled"}, "$.receipts.execution.status")
    _digest(execution["source_sha256"], "$.receipts.execution.source_sha256")
    if execution["source_sha256"] != source["source_tree_sha256"] or execution["source_sha256"] != runtime["source_sha256"]:
        raise ContractError("execution_source_mismatch", "$.receipts.execution.source_sha256")
    expected_execution = "completed" if run["terminal_outcome"] == "completed" else ("unreconciled" if run["terminal_outcome"] == "unreconciled" else "failed")
    if execution["status"] != expected_execution:
        raise ContractError("execution_terminal_mismatch", "$.receipts.execution.status")
    quality = _keys(receipts["quality"], {"disposition", "execution_success_implied", "evidence_sha256"}, "$.receipts.quality")
    _enum(quality["disposition"], {"accepted", "rejected", "unknown", "not_evaluated"}, "$.receipts.quality.disposition")
    if _bool(quality["execution_success_implied"], "$.receipts.quality.execution_success_implied"):
        raise ContractError("quality_execution_conflation", "$.receipts.quality")
    _digest(quality["evidence_sha256"], "$.receipts.quality.evidence_sha256")
    if quality["disposition"] == "accepted" and execution["status"] != "completed":
        raise ContractError("quality_execution_mismatch", "$.receipts.quality.disposition")
    usage = _keys(receipts["usage"], {"tokens", "external_cost", "provenance", "anti_double_counting_id"}, "$.receipts.usage")
    for key in ("tokens", "external_cost"):
        if usage[key] != "unknown" and (isinstance(usage[key], bool) or not isinstance(usage[key], int) or usage[key] < 0):
            raise ContractError("usage_invalid", f"$.receipts.usage.{key}")
    _enum(usage["provenance"], {"observed", "estimated", "unknown"}, "$.receipts.usage.provenance")
    unknown_usage = [usage[key] == "unknown" for key in ("tokens", "external_cost")]
    if any(unknown_usage) and usage["provenance"] != "unknown":
        raise ContractError("unknown_usage_coerced", "$.receipts.usage")
    if all(not item for item in unknown_usage) and usage["provenance"] not in {"observed", "estimated"}:
        raise ContractError("numeric_usage_provenance_invalid", "$.receipts.usage.provenance")
    if any(unknown_usage) and not all(unknown_usage):
        raise ContractError("usage_provenance_mixed", "$.receipts.usage")
    _identifier(usage["anti_double_counting_id"], "$.receipts.usage.anti_double_counting_id")
    if (
        route["billing_basis"] == "metered"
        and authority["limits"]["external_cost_microunits"] == 0
        and (
            usage["external_cost"] == "unknown"
            or run["terminal_outcome"] == "completed"
            or execution["status"] == "completed"
            or quality["disposition"] == "accepted"
        )
    ):
        raise ContractError("metered_zero_cost_budget", "$.receipts.usage.external_cost")
    usage_overrun = (
        isinstance(usage["tokens"], int) and usage["tokens"] > authority["limits"]["tokens"]
    ) or (
        isinstance(usage["external_cost"], int)
        and usage["external_cost"] > authority["limits"]["external_cost_microunits"]
    )
    if usage_overrun and (
        run["terminal_outcome"] == "completed"
        or execution["status"] == "completed"
        or quality["disposition"] == "accepted"
    ):
        raise ContractError("usage_authority_limit_exceeded", "$.receipts.usage")
    artifacts = _list(receipts["artifacts"], "$.receipts.artifacts")
    artifact_refs: set[str] = set()
    for index, artifact in enumerate(artifacts):
        path = f"$.receipts.artifacts[{index}]"
        item = _keys(artifact, {"artifact_ref", "sha256", "redaction_class", "run_id", "source_sha256", "authority_sha256"}, path)
        ref = _text(item["artifact_ref"], f"{path}.artifact_ref")
        _forbid_credential_reference(
            ref,
            f"{path}.artifact_ref",
            "artifact_receipt_reference_credential",
        )
        if ref in artifact_refs:
            raise ContractError("artifact_duplicate", path)
        artifact_refs.add(ref)
        _digest(item["sha256"], f"{path}.sha256")
        _enum(item["redaction_class"], {"public_fixture", "internal", "restricted"}, f"{path}.redaction_class")
        if item["run_id"] != run["run_id"] or item["source_sha256"] != source["source_tree_sha256"] or item["authority_sha256"] != authority["authority_sha256"]:
            raise ContractError("artifact_binding_mismatch", path)
    lineage = _keys(receipts["lineage"], {"root_run_id", "parent_run_id", "child_run_ids", "current_run_id"}, "$.receipts.lineage")
    if lineage["root_run_id"] != run["run_id"] or lineage["parent_run_id"] is not None or lineage["current_run_id"] != run["run_id"]:
        raise ContractError("lineage_root_mismatch", "$.receipts.lineage")
    if run["predecessor_run_id"] is not None:
        raise ContractError("lineage_predecessor_mismatch", "$.run.predecessor_run_id")
    child_run_ids = _string_set(lineage["child_run_ids"], "$.receipts.lineage.child_run_ids")
    recovery = _keys(receipts["recovery"], {"attempted", "predecessor_run_id", "successor_run_id", "outcome"}, "$.receipts.recovery")
    attempted = _bool(recovery["attempted"], "$.receipts.recovery.attempted")
    _enum(recovery["outcome"], {"not_attempted", "recovered_to_successor", "superseded", "failed"}, "$.receipts.recovery.outcome")
    if run["terminal_outcome"] == "recovered_to_successor":
        if not attempted or recovery["successor_run_id"] != run["successor_run_id"] or recovery["outcome"] != "recovered_to_successor":
            raise ContractError("recovery_successor_mismatch", "$.receipts.recovery")
    elif run["terminal_outcome"] == "superseded":
        if attempted or recovery["successor_run_id"] != run["successor_run_id"] or recovery["outcome"] != "superseded":
            raise ContractError("recovery_successor_mismatch", "$.receipts.recovery")
    elif attempted or recovery["successor_run_id"] is not None or recovery["outcome"] != "not_attempted":
        raise ContractError("recovery_terminal_mismatch", "$.receipts.recovery")
    if recovery["predecessor_run_id"] != run["predecessor_run_id"]:
        raise ContractError("recovery_predecessor_mismatch", "$.receipts.recovery.predecessor_run_id")

    continuation = _keys(payload["continuation"], {"checkpoint_id", "run_id", "context_rollover_id", "handoff_sha256", "remaining_limits", "message_cursor", "predecessor_immutable", "authority_recheck_required", "capability_recheck_required"}, "$.continuation")
    if continuation["run_id"] != run["run_id"]:
        raise ContractError("continuation_run_mismatch", "$.continuation.run_id")
    _digest(continuation["handoff_sha256"], "$.continuation.handoff_sha256")
    remaining = _validate_limits(continuation["remaining_limits"], "$.continuation.remaining_limits")
    for key, amount in remaining.items():
        if amount > authority["limits"][key]:
            raise ContractError("continuation_limit_widening", f"$.continuation.remaining_limits.{key}")
    if remaining != CHILD_LIMITS:
        raise ContractError("continuation_limits_not_frozen", "$.continuation.remaining_limits")
    for key in ("predecessor_immutable", "authority_recheck_required", "capability_recheck_required"):
        if not _bool(continuation[key], f"$.continuation.{key}"):
            raise ContractError("continuation_safety_required", f"$.continuation.{key}")

    delegation = _validate_delegation(payload["delegation"], authority, route, run, remaining)
    if delegation["status"] == "admitted":
        if child_run_ids != {delegation["child_run_id"]}:
            raise ContractError("delegation_lineage_mismatch", "$.receipts.lineage.child_run_ids")
        if delegation["expected_artifact"] not in artifact_refs:
            raise ContractError("delegation_artifact_mismatch", "$.delegation.expected_artifact")
    elif delegation["child_run_id"] in child_run_ids or delegation["expected_artifact"] in artifact_refs:
        raise ContractError("delegation_status_materialization_mismatch", "$.delegation.status")
    if run["terminal_outcome"] == "denied" and (
        any(state in lifecycle for state in ("admitted", "launching", "running", "reconciling", "quality_checked", "review_pending"))
        or delegation["status"] == "admitted"
        or bool(child_run_ids)
        or delegation["expected_artifact"] in artifact_refs
        or quality["disposition"] == "accepted"
    ):
        raise ContractError("denied_run_materialization_mismatch", "$.run.terminal_outcome")
    journal = _keys(payload["task_journal"], {"journal_id", "storage_kind", "scope_workgraph_id", "append_only", "global_discovery", "canonical_standalone_store", "messages", "covert_channel_controls", "recalled", "channel_open"}, "$.task_journal")
    if journal["storage_kind"] != "standalone_task_journal" or not _bool(journal["append_only"], "$.task_journal.append_only") or _bool(journal["global_discovery"], "$.task_journal.global_discovery") or not _bool(journal["canonical_standalone_store"], "$.task_journal.canonical_standalone_store"):
        raise ContractError("journal_boundary_invalid", "$.task_journal")
    controls = _string_set(journal["covert_channel_controls"], "$.task_journal.covert_channel_controls")
    required_controls = {"filenames_paths", "metadata_artifact_names", "caches_logs_error_text", "timing", "registries_services", "indirect_egress", "channel_reconstruction_after_recall"}
    if not required_controls.issubset(controls):
        raise ContractError("covert_channel_controls_incomplete", "$.task_journal.covert_channel_controls")
    messages = _list(journal["messages"], "$.task_journal.messages")
    previous_message: str | None = None
    message_ids: set[str] = set()
    sender_counts: dict[str, int] = {}
    if len(messages) > authority["limits"]["journal_messages"]:
        raise ContractError("journal_count_exceeded", "$.task_journal.messages")
    for index, message in enumerate(messages):
        path = f"$.task_journal.messages[{index}]"
        item = _keys(message, {"message_id", "message_type", "sender_run_id", "recipient_scope", "authority_sha256", "predecessor_message_sha256", "reply_to", "recorded_at", "expires_at", "redaction_class", "content", "content_bytes", "content_sha256", "message_sha256", "artifact_refs", "untrusted_evidence", "executable", "grants_authority", "mutates_policy", "mutates_goalbuddy"}, path)
        _enum(item["message_type"], {"finding", "artifact_ready", "question", "response", "blocker", "handoff_request", "delegation_request", "lease_or_budget_notice", "claim_challenge", "supersession"}, f"{path}.message_type")
        if item["predecessor_message_sha256"] != previous_message:
            raise ContractError("journal_chain_invalid", path)
        for key in ("authority_sha256", "content_sha256", "message_sha256"):
            _digest(item[key], f"{path}.{key}")
        child_materialized = delegation["status"] == "admitted" and delegation["child_run_id"] in child_run_ids
        authorized_senders = {run["run_id"]}
        if child_materialized:
            authorized_senders.add(delegation["child_run_id"])
        if item["sender_run_id"] not in authorized_senders:
            code = "journal_child_not_materially_admitted" if item["sender_run_id"] == delegation["child_run_id"] else "journal_sender_unauthorized"
            raise ContractError(code, f"{path}.sender_run_id")
        sender_limits = delegation["limits"] if item["sender_run_id"] == delegation["child_run_id"] else authority["limits"]
        sender_counts[item["sender_run_id"]] = sender_counts.get(item["sender_run_id"], 0) + 1
        if sender_counts[item["sender_run_id"]] > sender_limits["journal_messages"]:
            code = "journal_child_count_exceeded" if item["sender_run_id"] == delegation["child_run_id"] else "journal_count_exceeded"
            raise ContractError(code, path)
        if item["authority_sha256"] != authority["authority_sha256"]:
            raise ContractError("journal_authority_mismatch", f"{path}.authority_sha256")
        expected_recipient = f"workgraph:{journal['scope_workgraph_id']}:subtree"
        if item["recipient_scope"] != expected_recipient:
            raise ContractError("journal_scope_invalid", f"{path}.recipient_scope")
        _enum(item["redaction_class"], {"public_fixture", "internal", "restricted"}, f"{path}.redaction_class")
        content = _text(item["content"], f"{path}.content")
        content_bytes = len(content.encode("utf-8"))
        _integer(item["content_bytes"], f"{path}.content_bytes", minimum=1)
        if item["content_bytes"] != content_bytes:
            raise ContractError("journal_message_size_invalid", f"{path}.content_bytes")
        if content_bytes > sender_limits["message_bytes"]:
            code = "journal_child_message_size_exceeded" if item["sender_run_id"] == delegation["child_run_id"] else "journal_message_size_invalid"
            raise ContractError(code, f"{path}.content_bytes")
        if CREDENTIAL_CONTENT.search(content):
            raise ContractError("journal_credential_redaction_required", f"{path}.content")
        if item["content_sha256"] != object_digest(content):
            raise ContractError("journal_content_digest_mismatch", f"{path}.content_sha256")
        recorded = _timestamp(item["recorded_at"], f"{path}.recorded_at")
        expires_at = _timestamp(item["expires_at"], f"{path}.expires_at")
        if recorded < authority_issued or recorded > evaluated_at or recorded >= authority_expires or recorded >= qualification_expires:
            raise ContractError("journal_time_outside_authority", f"{path}.recorded_at")
        if expires_at <= recorded:
            raise ContractError("message_expiry_invalid", path)
        if int((expires_at - recorded).total_seconds()) > sender_limits["ttl_seconds"]:
            code = "journal_child_ttl_exceeded" if item["sender_run_id"] == delegation["child_run_id"] else "message_expiry_invalid"
            raise ContractError(code, path)
        if expires_at > authority_expires or expires_at > qualification_expires:
            raise ContractError("journal_time_outside_authority", f"{path}.expires_at")
        refs = _string_set(item["artifact_refs"], f"{path}.artifact_refs")
        for ref_index, ref in enumerate(item["artifact_refs"]):
            _forbid_credential_reference(
                ref,
                f"{path}.artifact_refs[{ref_index}]",
                "journal_artifact_reference_credential",
            )
        if not refs.issubset(artifact_refs):
            raise ContractError("journal_artifact_scope_invalid", f"{path}.artifact_refs")
        if item["reply_to"] is not None and item["reply_to"] not in message_ids:
            raise ContractError("journal_reply_invalid", f"{path}.reply_to")
        if not _bool(item["untrusted_evidence"], f"{path}.untrusted_evidence") or any(_bool(item[key], f"{path}.{key}") for key in ("executable", "grants_authority", "mutates_policy", "mutates_goalbuddy")):
            raise ContractError("journal_message_authority_forbidden", path)
        body = {key: value for key, value in item.items() if key != "message_sha256"}
        if item["message_sha256"] != object_digest(body):
            raise ContractError("journal_message_digest_mismatch", f"{path}.message_sha256")
        previous_message = item["message_sha256"]
        if item["message_id"] in message_ids:
            raise ContractError("journal_message_id_duplicate", f"{path}.message_id")
        message_ids.add(item["message_id"])

    if continuation["message_cursor"] is not None and continuation["message_cursor"] not in message_ids:
        raise ContractError("continuation_cursor_invalid", "$.continuation.message_cursor")

    recall = _keys(payload["recall"], {"status_precedence", "events", "blocks_new_admission", "fences_cancellation_and_reconciliation", "deletes_history"}, "$.recall")
    if recall["status_precedence"] != ["recalled", "expired", "stale", "active"]:
        raise ContractError("recall_precedence_invalid", "$.recall.status_precedence")
    recall_events = _list(recall["events"], "$.recall.events")
    run_recall_times: list[datetime] = []
    recall_time_violations: list[str] = []
    recall_ids: set[str] = set()
    for index, event in enumerate(recall_events):
        path = f"$.recall.events[{index}]"
        item = _keys(event, {"recall_id", "subject_kind", "subject_id", "authority_sha256", "recorded_at", "event_sha256"}, path)
        recall_id = _identifier(item["recall_id"], f"{path}.recall_id")
        if recall_id in recall_ids:
            raise ContractError("recall_id_duplicate", f"{path}.recall_id")
        recall_ids.add(recall_id)
        _enum(item["subject_kind"], {"qualification", "journal", "run"}, f"{path}.subject_kind")
        _text(item["subject_id"], f"{path}.subject_id")
        if item["authority_sha256"] != authority["authority_sha256"]:
            raise ContractError("recall_authority_mismatch", f"{path}.authority_sha256")
        expected_subjects = {
            "qualification": qualification["qualification_id"],
            "journal": journal["journal_id"],
            "run": run["run_id"],
        }
        if item["subject_id"] != expected_subjects[item["subject_kind"]]:
            raise ContractError("recall_subject_mismatch", f"{path}.subject_id")
        recall_recorded = _timestamp(item["recorded_at"], f"{path}.recorded_at")
        if (
            recall_recorded < authority_issued
            or recall_recorded < observed
            or recall_recorded < evaluated_at
            or recall_recorded >= authority_expires
            or recall_recorded >= qualification_expires
        ):
            recall_time_violations.append(f"{path}.recorded_at")
        if item["subject_kind"] == "run" and not (
            recall_recorded < authority_issued
            or recall_recorded < observed
            or recall_recorded >= authority_expires
            or recall_recorded >= qualification_expires
        ):
            run_recall_times.append(recall_recorded)
        _digest(item["event_sha256"], f"{path}.event_sha256")
        body = {key: value for key, value in item.items() if key != "event_sha256"}
        if item["event_sha256"] != object_digest(body):
            raise ContractError("recall_digest_mismatch", f"{path}.event_sha256")
    if not _bool(recall["blocks_new_admission"], "$.recall.blocks_new_admission") or not _bool(recall["fences_cancellation_and_reconciliation"], "$.recall.fences_cancellation_and_reconciliation") or _bool(recall["deletes_history"], "$.recall.deletes_history"):
        raise ContractError("recall_semantics_invalid", "$.recall")
    recalled_qualification = any(item["subject_kind"] == "qualification" and item["subject_id"] == qualification["qualification_id"] for item in recall_events)
    recalled_journal = any(item["subject_kind"] == "journal" and item["subject_id"] == journal["journal_id"] for item in recall_events)
    expected_qualification = "recalled" if recalled_qualification else ("expired" if evaluated_at >= expires else "active")
    if qualification["effective_status"] != expected_qualification:
        raise ContractError("qualification_recall_precedence_mismatch", "$.qualification.effective_status")
    if journal["recalled"] != recalled_journal:
        raise ContractError("journal_recall_mismatch", "$.task_journal.recalled")
    channel_open = _bool(journal["channel_open"], "$.task_journal.channel_open")
    if channel_open == recalled_journal:
        raise ContractError("recalled_journal_channel_open", "$.task_journal.channel_open")
    if run_recall_times and event_times and min(run_recall_times) <= event_times[-1]:
        effective_recall = min(run_recall_times)
        events_after_recall = [
            event_type for event_type, recorded_at in zip(event_types, event_times)
            if recorded_at >= effective_recall
        ]
        if (
            run["terminal_outcome"] not in {"cancelled", "failed", "unreconciled"}
            or execution["status"] == "completed"
            or quality["disposition"] == "accepted"
            or delegation["status"] == "admitted"
            or any(event_type not in {"run_reconciling", "run_terminal"} for event_type in events_after_recall)
        ):
            raise ContractError("run_recall_lifecycle_violation", "$.recall.events")
    if recall_time_violations:
        raise ContractError("recall_time_outside_authority", recall_time_violations[0])

    compatibility = _keys(payload["compatibility"], {"legacy_contracts_unchanged", "aggregate_version_implies_components", "unknown_versions_fail_closed", "adapters"}, "$.compatibility")
    if not _bool(compatibility["legacy_contracts_unchanged"], "$.compatibility.legacy_contracts_unchanged") or _bool(compatibility["aggregate_version_implies_components"], "$.compatibility.aggregate_version_implies_components") or not _bool(compatibility["unknown_versions_fail_closed"], "$.compatibility.unknown_versions_fail_closed"):
        raise ContractError("compatibility_boundary_invalid", "$.compatibility")
    required_adapters = {"DispatchScheduler v1", "DispatchLedger v1", "PreflightBroker v1", "RouteFabric v1", "WorkGraph v1", "ExecutionContinuity v1", "TrajectoryMemory v1"}
    if _string_set(compatibility["adapters"], "$.compatibility.adapters") != required_adapters:
        raise ContractError("legacy_adapter_set_invalid", "$.compatibility.adapters")

    fork = _keys(payload["downstream_fork"], {"upstream_version", "upstream_commit", "upstream_tree_sha256", "downstream_distribution_id", "fork_commit", "fork_sha256", "divergence_ledger_sha256", "overlay_classes", "forbidden_duplicate_authorities", "conformance_versions", "sanitized", "aol_admitted"}, "$.downstream_fork")
    for key in ("upstream_tree_sha256", "fork_sha256", "divergence_ledger_sha256"):
        _digest(fork[key], f"$.downstream_fork.{key}")
    overlays = _string_set(fork["overlay_classes"], "$.downstream_fork.overlay_classes")
    if overlays != DOWNSTREAM_OVERLAY_CLASSES:
        raise ContractError("downstream_overlay_set_invalid", "$.downstream_fork.overlay_classes")
    if _string_set(fork["forbidden_duplicate_authorities"], "$.downstream_fork.forbidden_duplicate_authorities") != DOWNSTREAM_AUTHORITIES:
        raise ContractError("downstream_authority_set_invalid", "$.downstream_fork.forbidden_duplicate_authorities")
    versions = _keys(fork["conformance_versions"], DOWNSTREAM_COMPONENTS, "$.downstream_fork.conformance_versions")
    for key, value in versions.items():
        _integer(value, f"$.downstream_fork.conformance_versions.{key}", minimum=1)
        if value != 1:
            raise ContractError("downstream_conformance_version_invalid", "$.downstream_fork.conformance_versions")
    if not _bool(fork["sanitized"], "$.downstream_fork.sanitized") or _bool(fork["aol_admitted"], "$.downstream_fork.aol_admitted"):
        raise ContractError("downstream_boundary_invalid", "$.downstream_fork")
    for key in ("downstream_distribution_id", "fork_commit"):
        _forbid_credential_reference(
            fork[key],
            f"$.downstream_fork.{key}",
            "downstream_identifier_credential",
        )
    if (
        fork["upstream_version"] != source["plugin_version"]
        or fork["upstream_commit"] != source["repository_commit"]
        or fork["upstream_tree_sha256"] != source["source_tree_sha256"]
    ):
        raise ContractError("downstream_source_identity_mismatch", "$.downstream_fork")

    _forbid_credentials_everywhere(payload)

    integrity = _keys(payload["integrity"], {"digest_algorithm", "canonicalization", "digest_scope", "object_digest", "predecessor_chains", "signature_state", "authenticity_claimed"}, "$.integrity")
    if integrity["digest_algorithm"] != "sha256":
        raise ContractError("digest_algorithm_unsupported", "$.integrity.digest_algorithm")
    _digest(integrity["object_digest"], "$.integrity.object_digest")
    if integrity["canonicalization"] != "rfc8785-profile:sorted-ascii-no-floats-v1" or integrity["digest_scope"] != "entire_document_excluding_integrity.object_digest":
        raise ContractError("digest_domain_invalid", "$.integrity")
    if not _bool(integrity["predecessor_chains"], "$.integrity.predecessor_chains"):
        raise ContractError("predecessor_chain_required", "$.integrity.predecessor_chains")
    _enum(integrity["signature_state"], {"not_configured", "unknown"}, "$.integrity.signature_state")
    if _bool(integrity["authenticity_claimed"], "$.integrity.authenticity_claimed"):
        raise ContractError("authenticity_claim_forbidden", "$.integrity.authenticity_claimed")
    digest_payload = copy.deepcopy(payload)
    del digest_payload["integrity"]["object_digest"]
    if integrity["object_digest"] != object_digest(digest_payload):
        raise ContractError("document_digest_mismatch", "$.integrity.object_digest")

    return {
        "authority": "standalone_runtime_contract_validator",
        "contract": CONTRACT,
        "contract_version": VERSION,
        "side_effect_free": True,
        "status": "pass",
    }


def load_document(path: Path) -> Any:
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ContractError("input_unavailable", "$") from error
    if named.st_mode != resolved.stat().st_mode or not path.is_file() or path.is_symlink():
        raise ContractError("input_not_regular", "$")
    try:
        return parse_json_text(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError("input_json_invalid", "$") from error


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate_json_key", f"$.{key}")
        result[key] = value
    return result


def parse_json_text(source: str) -> Any:
    try:
        return json.loads(source, object_pairs_hook=_unique_object)
    except ContractError:
        raise
    except json.JSONDecodeError as error:
        raise ContractError("input_json_invalid", "$") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate(load_document(args.input))
    except ContractError as error:
        print(canonical_json({
            "authority": "standalone_runtime_contract_validator",
            "code": error.code,
            "path": error.path,
            "side_effect_free": True,
            "status": "failed",
        }))
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
