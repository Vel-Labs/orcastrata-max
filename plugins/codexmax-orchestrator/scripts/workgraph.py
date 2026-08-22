#!/usr/bin/env python3
"""Validate versioned Codexmax WorkGraph documents deterministically."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA_VERSION = 1
WORK_ITEM_KINDS = {
    "goal", "checkpoint", "ticket", "task", "subtask", "test", "audit", "decision"
}
WORK_ITEM_STATUSES = {
    "queued", "active", "blocked", "ready_for_review", "candidate_complete",
    "needs_revision", "needs_reassignment", "needs_parent_repair", "waiting_external",
}
CLARITY_TIERS = ("direct", "bounded", "governed")
RELATIONSHIP_KEYS = ("parent_of", "blocked_by", "related_to", "produces", "consumes")
EVIDENCE_KINDS = {"artifact", "command_result", "receipt", "source_reference"}
EVIDENCE_STATES = {"expected", "observed", "validated", "rejected"}
PROVENANCE = {"unknown", "declared", "parent_assigned", "runtime_observed", "receipt_backed"}
CAPABILITY_PROVENANCE = {"unknown", "runtime_observed", "receipt_backed"}
CAPABILITY_KEYS = {"filesystem", "browser", "command", "network", "connector", "billing"}

ROOT_KEYS = {"schema_version", "graph_id", "evidence", "work_items"}
BASE_ITEM_KEYS = {
    "id", "kind", "objective", "status", "clarity_tier", "scope", "done_condition",
    "validation", "relationships", "owner_role", "expected_artifacts", "retry_policy",
    "stop_rule", "identity", "authority", "provider_policy", "independent_verification",
    "receipts", "recovery", "parent_acceptance",
}
DIRECT_REQUIRED = {
    "id", "kind", "objective", "status", "clarity_tier", "scope", "done_condition", "validation"
}
BOUNDED_REQUIRED = DIRECT_REQUIRED | {
    "relationships", "owner_role", "expected_artifacts", "retry_policy", "stop_rule"
}
GOVERNED_REQUIRED = BOUNDED_REQUIRED | {
    "identity", "authority", "provider_policy", "independent_verification", "receipts",
    "recovery", "parent_acceptance",
}
EVIDENCE_KEYS = {
    "id", "kind", "locator", "digest", "state", "claim_ids", "authority_effect", "acceptance_effect"
}
IDENTITY_KEYS = {
    "agent_name", "agent_id", "provider", "model", "route_id", "runtime", "billing",
    "source_access", "commands_executable", "token_usage", "cost", "capabilities",
}


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _object(value: Any, path: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}:expected_object")
        return None
    return value


def _strict_keys(value: dict[str, Any], allowed: set[str], required: set[str], path: str, errors: list[str]) -> None:
    for key in sorted(set(value) - allowed):
        errors.append(f"{path}:unknown_field:{key}")
    for key in sorted(required - set(value)):
        errors.append(f"{path}:missing_field:{key}")


def _string(value: Any, path: str, errors: list[str], *, enum: set[str] | None = None) -> None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}:expected_nonempty_string")
    elif enum is not None and value not in enum:
        errors.append(f"{path}:unsupported_value:{value}")


def _string_list(value: Any, path: str, errors: list[str], *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{path}:expected_array")
        return []
    if nonempty and not value:
        errors.append(f"{path}:must_not_be_empty")
    result: list[str] = []
    for index, entry in enumerate(value):
        if not isinstance(entry, str) or not entry.strip():
            errors.append(f"{path}[{index}]:expected_nonempty_string")
        else:
            result.append(entry)
    if len(result) != len(set(result)):
        errors.append(f"{path}:duplicate_value")
    return result


def _validate_scope(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    _strict_keys(obj, {"read", "write"}, {"read", "write"}, path, errors)
    _string_list(obj.get("read"), f"{path}.read", errors)
    _string_list(obj.get("write"), f"{path}.write", errors)


def _validate_checks(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not value:
        errors.append(f"{path}:expected_nonempty_array")
        return
    seen: set[str] = set()
    for index, entry in enumerate(value):
        item_path = f"{path}[{index}]"
        obj = _object(entry, item_path, errors)
        if obj is None:
            continue
        required = {"id", "kind", "instruction", "expected_result"}
        _strict_keys(obj, required, required, item_path, errors)
        for key in required:
            _string(obj.get(key), f"{item_path}.{key}", errors)
        check_id = obj.get("id")
        if isinstance(check_id, str):
            if check_id in seen:
                errors.append(f"{path}:duplicate_id:{check_id}")
            seen.add(check_id)


def _validate_relationships(value: Any, path: str, errors: list[str]) -> dict[str, list[str]]:
    obj = _object(value, path, errors)
    if obj is None:
        return {key: [] for key in RELATIONSHIP_KEYS}
    _strict_keys(obj, set(RELATIONSHIP_KEYS), set(RELATIONSHIP_KEYS), path, errors)
    return {key: _string_list(obj.get(key), f"{path}.{key}", errors) for key in RELATIONSHIP_KEYS}


def _validate_retry(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    allowed = {"max_attempts", "no_improvement_window"}
    _strict_keys(obj, allowed, allowed, path, errors)
    for key in sorted(allowed):
        number = obj.get(key)
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            errors.append(f"{path}.{key}:expected_positive_integer")


def _validate_evidence(value: Any, path: str, errors: list[str]) -> tuple[str | None, str | None]:
    obj = _object(value, path, errors)
    if obj is None:
        return None, None
    _strict_keys(obj, EVIDENCE_KEYS, EVIDENCE_KEYS, path, errors)
    evidence_id = obj.get("id")
    _string(evidence_id, f"{path}.id", errors)
    kind = obj.get("kind")
    _string(kind, f"{path}.kind", errors, enum=EVIDENCE_KINDS)
    _string(obj.get("locator"), f"{path}.locator", errors)
    digest = obj.get("digest")
    if not isinstance(digest, str) or (digest != "unknown" and not (
        digest.startswith("sha256:") and len(digest) == 71
        and all(character in "0123456789abcdef" for character in digest[7:])
    )):
        errors.append(f"{path}.digest:expected_unknown_or_sha256")
    state = obj.get("state")
    _string(state, f"{path}.state", errors, enum=EVIDENCE_STATES)
    if state == "validated" and digest == "unknown":
        errors.append(f"{path}.digest:validated_evidence_requires_sha256")
    _string_list(obj.get("claim_ids"), f"{path}.claim_ids", errors)
    if obj.get("authority_effect") != "none":
        errors.append(f"{path}.authority_effect:must_be_none")
    if obj.get("acceptance_effect") != "none":
        errors.append(f"{path}.acceptance_effect:must_be_none")
    return evidence_id if isinstance(evidence_id, str) else None, kind if isinstance(kind, str) else None


def _validate_fact(
    value: Any,
    path: str,
    errors: list[str],
    *,
    capability: bool = False,
    measurement: bool = False,
    observed_text: bool = False,
) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    _strict_keys(obj, {"value", "provenance"}, {"value", "provenance"}, path, errors)
    fact = obj.get("value")
    provenance = obj.get("provenance")
    allowed_provenance = CAPABILITY_PROVENANCE if capability or measurement or observed_text else PROVENANCE
    _string(provenance, f"{path}.provenance", errors, enum=allowed_provenance)
    if measurement:
        if fact != "unknown" and (not isinstance(fact, (int, float)) or isinstance(fact, bool) or fact < 0):
            errors.append(f"{path}.value:expected_unknown_or_nonnegative_number")
    elif capability:
        if fact not in {"yes", "no", "unknown"}:
            errors.append(f"{path}.value:expected_yes_no_or_unknown")
    elif not isinstance(fact, str) or not fact.strip():
        errors.append(f"{path}.value:expected_nonempty_string")
    if fact == "unknown" and provenance != "unknown":
        errors.append(f"{path}:unknown_value_requires_unknown_provenance")
    if fact != "unknown" and provenance == "unknown":
        errors.append(f"{path}:known_value_requires_known_provenance")
    if (capability or measurement or observed_text) and fact != "unknown" and provenance not in {"runtime_observed", "receipt_backed"}:
        errors.append(f"{path}:known_value_requires_observed_or_receipt_provenance")


def _validate_identity(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    _strict_keys(obj, IDENTITY_KEYS, IDENTITY_KEYS, path, errors)
    observed_text_keys = {"runtime", "billing", "source_access", "commands_executable"}
    for key in sorted(IDENTITY_KEYS - {"capabilities", "token_usage", "cost"} - observed_text_keys):
        _validate_fact(obj.get(key), f"{path}.{key}", errors)
    for key in sorted(observed_text_keys):
        _validate_fact(obj.get(key), f"{path}.{key}", errors, observed_text=True)
    _validate_fact(obj.get("token_usage"), f"{path}.token_usage", errors, measurement=True)
    _validate_fact(obj.get("cost"), f"{path}.cost", errors, measurement=True)
    capabilities = _object(obj.get("capabilities"), f"{path}.capabilities", errors)
    if capabilities is not None:
        _strict_keys(capabilities, CAPABILITY_KEYS, CAPABILITY_KEYS, f"{path}.capabilities", errors)
        for key in sorted(CAPABILITY_KEYS):
            _validate_fact(capabilities.get(key), f"{path}.capabilities.{key}", errors, capability=True)


def _validate_authority(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    allowed = {
        "source", "receipt_id", "provenance", "write_scope", "forbidden_actions",
        "may_accept", "may_mutate_canonical_state",
    }
    _strict_keys(obj, allowed, allowed, path, errors)
    source = obj.get("source")
    _string(source, f"{path}.source", errors)
    _string(obj.get("receipt_id"), f"{path}.receipt_id", errors)
    provenance = obj.get("provenance")
    _string(provenance, f"{path}.provenance", errors, enum={"operator_issued", "parent_issued"})
    if isinstance(source, str):
        prefix = "operator:" if provenance == "operator_issued" else "parent:"
        if not source.startswith(prefix) or len(source) == len(prefix):
            errors.append(f"{path}.source:authority_provenance_mismatch")
    _string_list(obj.get("write_scope"), f"{path}.write_scope", errors)
    _string_list(obj.get("forbidden_actions"), f"{path}.forbidden_actions", errors, nonempty=True)
    if obj.get("may_accept") is not False:
        errors.append(f"{path}.may_accept:must_be_false")
    if obj.get("may_mutate_canonical_state") is not False:
        errors.append(f"{path}.may_mutate_canonical_state:must_be_false")


def _validate_provider_policy(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    allowed = {"source_access", "input_delivery", "commands_executable", "billing", "token_limit", "fallback"}
    _strict_keys(obj, allowed, allowed, path, errors)
    _string(
        obj.get("source_access"), f"{path}.source_access", errors,
        enum={"local_filesystem", "embedded_only", "connector_resource", "mixed", "none", "unknown", "unverified"},
    )
    _string(
        obj.get("input_delivery"), f"{path}.input_delivery", errors,
        enum={"paths_only", "embedded_fact_pack", "connector_references", "mixed", "none", "unknown", "unverified"},
    )
    _string(obj.get("commands_executable"), f"{path}.commands_executable", errors, enum={"yes", "no", "unknown"})
    _string(obj.get("billing"), f"{path}.billing", errors, enum={"unknown", "local", "non_metered", "subscription", "metered"})
    _string(obj.get("fallback"), f"{path}.fallback", errors)
    token_limit = obj.get("token_limit")
    if token_limit is not None and (
        not isinstance(token_limit, int) or isinstance(token_limit, bool) or token_limit < 1
    ):
        errors.append(f"{path}.token_limit:expected_null_or_positive_integer")


def _validate_independent_verification(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    _strict_keys(obj, {"required", "roles"}, {"required", "roles"}, path, errors)
    if obj.get("required") is not True:
        errors.append(f"{path}.required:must_be_true")
    roles = _string_list(obj.get("roles"), f"{path}.roles", errors, nonempty=True)
    if "Tester" not in roles and "Auditor" not in roles:
        errors.append(f"{path}.roles:tester_or_auditor_required")


def _validate_recovery(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    allowed = {"preserve_failed_attempts", "preserve_changed_files", "on_failure", "max_attempts"}
    _strict_keys(obj, allowed, allowed, path, errors)
    for key in ("preserve_failed_attempts", "preserve_changed_files"):
        if obj.get(key) is not True:
            errors.append(f"{path}.{key}:must_be_true")
    _string(obj.get("on_failure"), f"{path}.on_failure", errors, enum={"revision", "reassignment", "parent_repair"})
    attempts = obj.get("max_attempts")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1:
        errors.append(f"{path}.max_attempts:expected_positive_integer")


def _validate_parent_acceptance(value: Any, path: str, errors: list[str]) -> None:
    obj = _object(value, path, errors)
    if obj is None:
        return
    allowed = {"required", "authority", "status"}
    _strict_keys(obj, allowed, allowed, path, errors)
    if obj.get("required") is not True:
        errors.append(f"{path}.required:must_be_true")
    if obj.get("authority") != "Parent Codex":
        errors.append(f"{path}.authority:must_be_parent_codex")
    if obj.get("status") != "pending":
        errors.append(f"{path}.status:must_be_pending")


def _validate_item(value: Any, index: int, errors: list[str]) -> tuple[str | None, dict[str, list[str]]]:
    path = f"work_items[{index}]"
    obj = _object(value, path, errors)
    empty = {key: [] for key in RELATIONSHIP_KEYS}
    if obj is None:
        return None, empty
    _strict_keys(obj, BASE_ITEM_KEYS, DIRECT_REQUIRED, path, errors)
    tier = obj.get("clarity_tier")
    _string(tier, f"{path}.clarity_tier", errors, enum=set(CLARITY_TIERS))
    required = {"direct": DIRECT_REQUIRED, "bounded": BOUNDED_REQUIRED, "governed": GOVERNED_REQUIRED}.get(tier, DIRECT_REQUIRED)
    for key in sorted(required - set(obj)):
        errors.append(f"{path}:tier_missing_field:{tier}:{key}")
    item_id = obj.get("id")
    _string(item_id, f"{path}.id", errors)
    _string(obj.get("kind"), f"{path}.kind", errors, enum=WORK_ITEM_KINDS)
    _string(obj.get("objective"), f"{path}.objective", errors)
    _string(obj.get("status"), f"{path}.status", errors, enum=WORK_ITEM_STATUSES)
    _string(obj.get("done_condition"), f"{path}.done_condition", errors)
    _validate_scope(obj.get("scope"), f"{path}.scope", errors)
    _validate_checks(obj.get("validation"), f"{path}.validation", errors)
    relationships = empty
    if "relationships" in obj:
        relationships = _validate_relationships(obj["relationships"], f"{path}.relationships", errors)
    if "owner_role" in obj:
        _string(obj["owner_role"], f"{path}.owner_role", errors)
    if "expected_artifacts" in obj:
        _string_list(obj["expected_artifacts"], f"{path}.expected_artifacts", errors, nonempty=tier in {"bounded", "governed"})
    if "retry_policy" in obj:
        _validate_retry(obj["retry_policy"], f"{path}.retry_policy", errors)
    if "stop_rule" in obj:
        _string(obj["stop_rule"], f"{path}.stop_rule", errors)
    if "identity" in obj:
        _validate_identity(obj["identity"], f"{path}.identity", errors)
    if "authority" in obj:
        _validate_authority(obj["authority"], f"{path}.authority", errors)
    if "provider_policy" in obj:
        _validate_provider_policy(obj["provider_policy"], f"{path}.provider_policy", errors)
    if "independent_verification" in obj:
        _validate_independent_verification(obj["independent_verification"], f"{path}.independent_verification", errors)
    if "receipts" in obj:
        _string_list(obj["receipts"], f"{path}.receipts", errors, nonempty=tier == "governed")
    if "recovery" in obj:
        _validate_recovery(obj["recovery"], f"{path}.recovery", errors)
    if "parent_acceptance" in obj:
        _validate_parent_acceptance(obj["parent_acceptance"], f"{path}.parent_acceptance", errors)
    return item_id if isinstance(item_id, str) else None, relationships


def _cycle_members(edges: dict[str, list[str]]) -> set[str]:
    visiting: set[str] = set()
    visited: set[str] = set()
    cycle: set[str] = set()

    def visit(node: str, stack: list[str]) -> None:
        if node in visiting:
            cycle.update(stack[stack.index(node):])
            return
        if node in visited:
            return
        visiting.add(node)
        stack.append(node)
        for target in edges.get(node, []):
            if target in edges:
                visit(target, stack)
        stack.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(edges):
        visit(node, [])
    return cycle


def validate_document(document: Any) -> dict[str, Any]:
    """Return a deterministic validation receipt; never mutate *document*."""
    errors: list[str] = []
    root = _object(document, "document", errors)
    if root is None:
        return {"errors": errors, "schema_version": SCHEMA_VERSION, "status": "invalid"}
    _strict_keys(root, ROOT_KEYS, ROOT_KEYS, "document", errors)
    version = root.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        errors.append("document.schema_version:expected_integer")
    elif version != SCHEMA_VERSION:
        errors.append(f"document.schema_version:unsupported:{version!r}")
    _string(root.get("graph_id"), "document.graph_id", errors)
    evidence = root.get("evidence")
    evidence_ids: list[str] = []
    evidence_kinds: dict[str, str] = {}
    if not isinstance(evidence, list):
        errors.append("document.evidence:expected_array")
        evidence = []
    else:
        for index, entry in enumerate(evidence):
            evidence_id, kind = _validate_evidence(entry, f"evidence[{index}]", errors)
            if evidence_id is not None:
                if evidence_id in evidence_ids:
                    errors.append(f"document.evidence:duplicate_id:{evidence_id}")
                evidence_ids.append(evidence_id)
                if kind is not None:
                    evidence_kinds[evidence_id] = kind
    items = root.get("work_items")
    if not isinstance(items, list) or not items:
        errors.append("document.work_items:expected_nonempty_array")
        items = []
    identities: list[str] = []
    relationships_by_id: dict[str, dict[str, list[str]]] = {}
    for index, item in enumerate(items):
        item_id, relationships = _validate_item(item, index, errors)
        if item_id is not None:
            if item_id in identities:
                errors.append(f"document.work_items:duplicate_id:{item_id}")
            identities.append(item_id)
            relationships_by_id[item_id] = relationships
    known = set(identities)
    known_evidence = set(evidence_ids)
    parent_edges = {source: row["parent_of"] for source, row in relationships_by_id.items()}
    blocked_edges = {source: row["blocked_by"] for source, row in relationships_by_id.items()}
    for source, relationships in relationships_by_id.items():
        for relation in ("parent_of", "blocked_by", "related_to"):
            for target in relationships[relation]:
                if target == source:
                    errors.append(f"relationship:{source}:{relation}:self_reference")
                elif target not in known:
                    errors.append(f"relationship:{source}:{relation}:missing_target:{target}")
        for relation in ("produces", "consumes"):
            for target in relationships[relation]:
                if target not in known_evidence:
                    errors.append(f"relationship:{source}:{relation}:missing_evidence:{target}")
        overlap = set(relationships["produces"]) & set(relationships["consumes"])
        for target in sorted(overlap):
            errors.append(f"relationship:{source}:artifact_direction_conflict:{target}")
        for target in relationships["related_to"]:
            if target in relationships_by_id and source not in relationships_by_id[target]["related_to"]:
                errors.append(f"relationship:{source}:related_to:not_reciprocal:{target}")
        for target in set(relationships["parent_of"]) & set(relationships["blocked_by"]):
            errors.append(f"relationship:{source}:parent_and_blocker_conflict:{target}")

    for relation, edges in (("parent_of", parent_edges), ("blocked_by", blocked_edges)):
        members = _cycle_members(edges)
        if members:
            errors.append(f"relationship:{relation}:cycle:{','.join(sorted(members))}")
    parent_counts: dict[str, int] = {}
    for targets in parent_edges.values():
        for target in targets:
            parent_counts[target] = parent_counts.get(target, 0) + 1
    for target, count in sorted(parent_counts.items()):
        if count > 1:
            errors.append(f"relationship:parent_of:multiple_parents:{target}")

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        item_id = item.get("id")
        if not isinstance(item_id, str):
            continue
        expected = item.get("expected_artifacts", [])
        receipts = item.get("receipts", [])
        for reference in expected if isinstance(expected, list) else []:
            if reference not in known_evidence:
                errors.append(f"work_item:{item_id}:expected_artifact_missing:{reference}")
            elif reference not in relationships_by_id.get(item_id, {}).get("produces", []):
                errors.append(f"work_item:{item_id}:expected_artifact_not_produced:{reference}")
        for reference in receipts if isinstance(receipts, list) else []:
            if reference not in known_evidence:
                errors.append(f"work_item:{item_id}:receipt_missing:{reference}")
            elif evidence_kinds.get(reference) != "receipt":
                errors.append(f"work_item:{item_id}:receipt_wrong_kind:{reference}")
        authority = item.get("authority")
        if isinstance(authority, dict):
            authority_receipt = authority.get("receipt_id")
            if authority_receipt not in known_evidence:
                errors.append(f"work_item:{item_id}:authority_receipt_missing:{authority_receipt}")
            elif evidence_kinds.get(authority_receipt) != "receipt":
                errors.append(f"work_item:{item_id}:authority_receipt_wrong_kind:{authority_receipt}")
            elif authority_receipt not in receipts:
                errors.append(f"work_item:{item_id}:authority_receipt_not_declared:{authority_receipt}")
            scope = item.get("scope")
            if isinstance(scope, dict) and isinstance(scope.get("write"), list):
                authority_writes = authority.get("write_scope")
                if isinstance(authority_writes, list):
                    for write_path in scope["write"]:
                        if write_path not in authority_writes:
                            errors.append(f"work_item:{item_id}:write_outside_authority:{write_path}")
    return {
        "errors": sorted(set(errors)),
        "graph_id": root.get("graph_id", "unknown"),
        "schema_version": SCHEMA_VERSION,
        "status": "valid" if not errors else "invalid",
        "summary": {
            "clarity_lint": [
                {
                    "work_item_id": item.get("id", "unknown"),
                    "tier": item.get("clarity_tier", "unknown"),
                    "missing_fields": sorted(
                        ({"direct": DIRECT_REQUIRED, "bounded": BOUNDED_REQUIRED, "governed": GOVERNED_REQUIRED}
                         .get(item.get("clarity_tier"), DIRECT_REQUIRED)) - set(item)
                    ),
                }
                for item in items if isinstance(item, dict)
            ],
            "clarity_tiers": {
                tier: sum(1 for item in items if isinstance(item, dict) and item.get("clarity_tier") == tier)
                for tier in CLARITY_TIERS
            },
            "evidence_count": len(evidence),
            "work_item_count": len(items),
        },
    }


def validate_path(path: Path) -> tuple[dict[str, Any], int]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        return ({"errors": [f"input_unavailable:{error.__class__.__name__}"], "schema_version": SCHEMA_VERSION, "status": "error"}, 2)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ({"errors": ["input_json_malformed"], "schema_version": SCHEMA_VERSION, "status": "invalid"}, 2)
    receipt = validate_document(document)
    receipt["document_sha256"] = hashlib.sha256(raw).hexdigest()
    return receipt, 0 if receipt["status"] == "valid" else 2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    validate_parser = subparsers.add_parser("validate", help="Validate one WorkGraph JSON document.")
    validate_parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    receipt, status = validate_path(args.path)
    print(_canonical(receipt))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
