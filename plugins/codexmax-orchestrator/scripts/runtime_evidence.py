#!/usr/bin/env python3
"""Deterministic Runtime Evidence v1 normalization and governance checks.

This module validates typed synthetic records and returns receipts.  It does
not dispatch, resume, cancel, write a journal, call a provider, or grant any
authority.  In particular, model output and journal content remain untrusted
evidence.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence


VERSION = 1
PACKET_TYPE = "runtime_evidence_packet_v1"
CASES_TYPE = "runtime_evidence_cases_v1"
RECEIPT_TYPE = "runtime_evidence_receipt_v1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CREDENTIAL = re.compile(
    r"(?i)(?:sk-proj-[a-z0-9_-]+|bearer\s+[a-z0-9._~+/-]+=*|"
    r"(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*\S+)"
)

AUTHORITY_SET_FIELDS = {
    "scope_paths", "tools", "effects", "disclosure_refs", "egress_targets",
    "network_routes", "route_ids", "billing_bases", "fallbacks",
}
LIMIT_FIELDS = {
    "attempts", "runtime_seconds", "uninterrupted_action_seconds", "tokens",
    "external_cost_microunits", "disclosure_bytes", "journal_messages",
    "message_bytes", "ttl_seconds", "fanout", "concurrency", "depth",
    "retention_seconds",
}
JOURNAL_TYPES = {
    "finding", "artifact_ready", "question", "response", "blocker",
    "handoff_request", "delegation_request", "lease_or_budget_notice",
    "claim_challenge", "supersession",
}
PROGRESS_KINDS = {
    "oracle_passed", "artifact_accepted", "defect_removed",
    "dependency_completed", "uncertainty_reduced", "none",
}
USAGE_STATUS = {"observed", "estimated", "unknown"}
USAGE_PROVENANCE = {"provider_report", "adapter_report", "runtime_measurement", "bounded_estimate"}
BINDING_DIGEST_FIELDS = (
    "assignment_sha256", "authority_sha256", "source_sha256", "policy_sha256",
    "route_sha256", "lease_sha256", "adapter_sha256",
)
PROVENANCE_FIELDS = {"run_id", *BINDING_DIGEST_FIELDS, "accepted_artifact_ids"}


class EvidenceError(ValueError):
    """Stable typed failure for malformed or unsafe evidence."""

    def __init__(self, code: str, path: str):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceError("canonical_json_invalid", "$") from exc


def canonical_digest(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json({"domain": domain, "value": value})).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError("object_required", path)
    extra = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if extra:
        raise EvidenceError("unknown_field", f"{path}.{extra[0]}")
    if missing:
        raise EvidenceError("missing_field", f"{path}.{missing[0]}")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise EvidenceError("identifier_invalid", path)
    return value


def _digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise EvidenceError("digest_invalid", path)
    return value


def _integer(value: Any, path: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError("integer_invalid", path)
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise EvidenceError("boolean_required", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise EvidenceError("timestamp_invalid", path)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("timestamp_invalid", path) from exc


def _strings(
    value: Any, path: str, *, identifiers: bool = True, unique: bool = True
) -> list[str]:
    if not isinstance(value, list):
        raise EvidenceError("array_required", path)
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or (identifiers and not IDENTIFIER.fullmatch(item)):
            raise EvidenceError("string_invalid", f"{path}[{index}]")
        result.append(item)
    if unique and len(result) != len(set(result)):
        raise EvidenceError("array_duplicate", path)
    return result


def _portable_paths(value: Any, path: str) -> list[str]:
    result = _strings(value, path, identifiers=False)
    for index, item in enumerate(result):
        parts = item.split("/")
        if not item or item.startswith("/") or "\\" in item or "%" in item or any(p in {"", ".", ".."} for p in parts):
            raise EvidenceError("path_invalid", f"{path}[{index}]")
    return result


def _contains_credential(value: Any) -> bool:
    if isinstance(value, str):
        return CREDENTIAL.search(value) is not None
    if isinstance(value, list):
        return any(_contains_credential(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_credential(key) or _contains_credential(item) for key, item in value.items())
    return False


def _authority(value: Any, path: str) -> dict[str, Any]:
    fields = AUTHORITY_SET_FIELDS | {"network_allowed", "egress_allowed", "retention_seconds"}
    authority = _closed(value, fields, path)
    for field in sorted(AUTHORITY_SET_FIELDS):
        if field == "scope_paths":
            _portable_paths(authority[field], f"{path}.{field}")
        elif field == "disclosure_refs":
            _strings(authority[field], f"{path}.{field}", identifiers=False)
        else:
            _strings(authority[field], f"{path}.{field}")
    _boolean(authority["network_allowed"], f"{path}.network_allowed")
    _boolean(authority["egress_allowed"], f"{path}.egress_allowed")
    _integer(authority["retention_seconds"], f"{path}.retention_seconds", 1)
    if _contains_credential(authority):
        raise EvidenceError("credential_reference_forbidden", path)
    return authority


def _limits(value: Any, path: str) -> dict[str, int]:
    limits = _closed(value, LIMIT_FIELDS, path)
    for field in sorted(LIMIT_FIELDS):
        _integer(limits[field], f"{path}.{field}")
    for field in LIMIT_FIELDS - {"external_cost_microunits"}:
        if limits[field] == 0:
            raise EvidenceError("limit_must_be_positive", f"{path}.{field}")
    return limits


def _subset(child: Mapping[str, Any], parent: Mapping[str, Any], path: str) -> None:
    for field in sorted(AUTHORITY_SET_FIELDS):
        if not set(child[field]) <= set(parent[field]):
            raise EvidenceError("child_authority_widened", f"{path}.{field}")
    for field in ("network_allowed", "egress_allowed"):
        if child[field] and not parent[field]:
            raise EvidenceError("child_authority_widened", f"{path}.{field}")
    if child["retention_seconds"] > parent["retention_seconds"]:
        raise EvidenceError("child_authority_widened", f"{path}.retention_seconds")


def _bound_digests(value: Mapping[str, Any], bindings: Mapping[str, Any], path: str) -> None:
    """Require an evidence/delegation record to name the exact packet fence."""
    for field in BINDING_DIGEST_FIELDS:
        _digest(value[field], f"{path}.{field}")
        if value[field] != bindings[field]:
            raise EvidenceError("evidence_binding_mismatch", f"{path}.{field}")


def _provenance(
    value: Any,
    path: str,
    bindings: Mapping[str, Any],
    accepted_artifact_ids: Sequence[str],
    artifact_ids: set[str],
    eligible_artifact_ids: set[str],
) -> dict[str, Any]:
    provenance = _closed(value, PROVENANCE_FIELDS, path)
    _identifier(provenance["run_id"], f"{path}.run_id")
    if provenance["run_id"] != bindings["run_id"]:
        raise EvidenceError("evidence_binding_mismatch", f"{path}.run_id")
    _bound_digests(provenance, bindings, path)
    accepted = _strings(provenance["accepted_artifact_ids"], f"{path}.accepted_artifact_ids")
    if not set(accepted) <= artifact_ids:
        raise EvidenceError("accepted_evidence_binding_mismatch", f"{path}.accepted_artifact_ids")
    if not set(accepted) <= eligible_artifact_ids:
        raise EvidenceError("recalled_artifact_accepted", f"{path}.accepted_artifact_ids")
    if accepted != list(accepted_artifact_ids):
        raise EvidenceError("accepted_evidence_binding_mismatch", f"{path}.accepted_artifact_ids")
    return provenance


def _usage_measure(value: Any, path: str) -> dict[str, Any]:
    measure = _closed(value, {"status", "value", "provenance", "evidence_sha256", "unknown_reason"}, path)
    if measure["status"] not in USAGE_STATUS:
        raise EvidenceError("usage_status_invalid", f"{path}.status")
    if measure["status"] == "unknown":
        if measure["value"] is not None or measure["provenance"] is not None or measure["evidence_sha256"] is not None:
            raise EvidenceError("usage_unknown_coerced", path)
        _identifier(measure["unknown_reason"], f"{path}.unknown_reason")
    else:
        _integer(measure["value"], f"{path}.value")
        if measure["provenance"] not in USAGE_PROVENANCE:
            raise EvidenceError("usage_provenance_invalid", f"{path}.provenance")
        _digest(measure["evidence_sha256"], f"{path}.evidence_sha256")
        if measure["unknown_reason"] is not None:
            raise EvidenceError("usage_known_has_unknown_reason", path)
    return measure


def normalize_usage(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        raise EvidenceError("array_required", "$.usage")
    seen: set[str] = set()
    fields = ("input_tokens", "output_tokens", "total_tokens", "external_cost_microunits")
    subtotals = {field: 0 for field in fields}
    unknowns = {field: 0 for field in fields}
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        path = f"$.usage[{index}]"
        row = _closed(raw, {"usage_id", "anti_double_counting_id", "run_id", "lineage_run_id", *fields}, path)
        for field in ("usage_id", "anti_double_counting_id", "run_id", "lineage_run_id"):
            _identifier(row[field], f"{path}.{field}")
        identity = row["anti_double_counting_id"]
        if identity in seen:
            raise EvidenceError("usage_double_count", f"{path}.anti_double_counting_id")
        seen.add(identity)
        for field in fields:
            measure = _usage_measure(row[field], f"{path}.{field}")
            if measure["status"] == "unknown":
                unknowns[field] += 1
            else:
                subtotals[field] += measure["value"]
        i, o, total = row["input_tokens"], row["output_tokens"], row["total_tokens"]
        if all(item["status"] != "unknown" for item in (i, o, total)) and i["value"] + o["value"] != total["value"]:
            raise EvidenceError("usage_total_mismatch", path)
        rows.append(copy.deepcopy(row))
    aggregate = {
        field: {
            "status": "unknown" if unknowns[field] else "known",
            "value": None if unknowns[field] else subtotals[field],
            "known_subtotal": subtotals[field],
            "unknown_receipts": unknowns[field],
        }
        for field in fields
    }
    return {"receipts": rows, "aggregate": aggregate, "anti_double_counting_ids": sorted(seen)}


def evaluate_delegation(
    value: Any,
    bindings: Mapping[str, Any],
    eligible_artifact_refs: set[str],
    recalled_artifact_refs: set[str],
) -> dict[str, Any]:
    fields = {"proposal", "parent", "child", "admission"}
    delegation = _closed(value, fields, "$.delegation")
    proposal = _closed(delegation["proposal"], {
        "proposal_id", "proposed_by", "objective", "expected_artifact", "requested_role",
        "reason", "validation_schema_sha256", "return_schema_sha256", "launch_requested",
        *BINDING_DIGEST_FIELDS, "requested_limits",
    }, "$.delegation.proposal")
    for field in ("proposal_id", "proposed_by", "expected_artifact", "requested_role"):
        _identifier(proposal[field], f"$.delegation.proposal.{field}")
    for field in ("validation_schema_sha256", "return_schema_sha256"):
        _digest(proposal[field], f"$.delegation.proposal.{field}")
    if not isinstance(proposal["objective"], str) or not proposal["objective"]:
        raise EvidenceError("string_invalid", "$.delegation.proposal.objective")
    if not isinstance(proposal["reason"], str) or not proposal["reason"]:
        raise EvidenceError("string_invalid", "$.delegation.proposal.reason")
    if _boolean(proposal["launch_requested"], "$.delegation.proposal.launch_requested"):
        raise EvidenceError("model_launch_authority_forbidden", "$.delegation.proposal.launch_requested")
    _bound_digests(proposal, bindings, "$.delegation.proposal")
    requested_limits = _limits(proposal["requested_limits"], "$.delegation.proposal.requested_limits")

    lineage_fields = {"run_id", "root_run_id", "parent_run_id", "workspace_id", "depth", "ancestor_run_ids", "authority", "limits"}
    parent = _closed(delegation["parent"], lineage_fields, "$.delegation.parent")
    child = _closed(delegation["child"], lineage_fields, "$.delegation.child")
    for label, row in (("parent", parent), ("child", child)):
        for field in ("run_id", "root_run_id", "workspace_id"):
            _identifier(row[field], f"$.delegation.{label}.{field}")
        if row["parent_run_id"] is not None:
            _identifier(row["parent_run_id"], f"$.delegation.{label}.parent_run_id")
        _integer(row["depth"], f"$.delegation.{label}.depth")
        _strings(row["ancestor_run_ids"], f"$.delegation.{label}.ancestor_run_ids")
        _authority(row["authority"], f"$.delegation.{label}.authority")
        _limits(row["limits"], f"$.delegation.{label}.limits")
        authority_refs = set(row["authority"]["disclosure_refs"])
        if authority_refs & recalled_artifact_refs:
            raise EvidenceError(
                "recalled_artifact_disclosed",
                f"$.delegation.{label}.authority.disclosure_refs",
            )
        if not authority_refs <= eligible_artifact_refs:
            raise EvidenceError(
                "delegation_disclosure_scope_mismatch",
                f"$.delegation.{label}.authority.disclosure_refs",
            )
    if parent["run_id"] != bindings["run_id"] or parent["workspace_id"] != bindings["workspace_id"]:
        raise EvidenceError("delegation_parent_binding_mismatch", "$.delegation.parent")
    if parent["root_run_id"] != bindings["root_run_id"]:
        raise EvidenceError("delegation_parent_binding_mismatch", "$.delegation.parent.root_run_id")
    if child["parent_run_id"] != parent["run_id"] or child["root_run_id"] != parent["root_run_id"]:
        raise EvidenceError("delegation_lineage_mismatch", "$.delegation.child")
    if child["workspace_id"] != parent["workspace_id"] or child["depth"] != parent["depth"] + 1:
        raise EvidenceError("delegation_lineage_mismatch", "$.delegation.child")
    if child["ancestor_run_ids"] != [*parent["ancestor_run_ids"], parent["run_id"]]:
        raise EvidenceError("delegation_lineage_mismatch", "$.delegation.child.ancestor_run_ids")
    if child["depth"] > 1 or child["run_id"] in {parent["run_id"], parent["root_run_id"], *parent["ancestor_run_ids"]}:
        raise EvidenceError("delegation_cycle_or_depth", "$.delegation.child")
    _subset(child["authority"], parent["authority"], "$.delegation.child.authority")
    for field in LIMIT_FIELDS:
        if child["limits"][field] > parent["limits"][field]:
            raise EvidenceError("child_limit_widened", f"$.delegation.child.limits.{field}")
    if requested_limits != child["limits"]:
        raise EvidenceError("delegation_limit_binding_mismatch", "$.delegation.proposal.requested_limits")
    admission = _closed(delegation["admission"], {
        "admitted", "admitted_by", "independent_preflight_sha256", "lease_sha256",
        "fanout_after", "concurrency_after", "lineage_budget_after",
        "assignment_sha256", "authority_sha256", "source_sha256", "policy_sha256",
        "route_sha256", "adapter_sha256", "admitted_limits",
    }, "$.delegation.admission")
    _boolean(admission["admitted"], "$.delegation.admission.admitted")
    if admission["admitted_by"] != "runtime_admission":
        raise EvidenceError("delegation_admitter_invalid", "$.delegation.admission.admitted_by")
    for field in ("independent_preflight_sha256", "lease_sha256"):
        _digest(admission[field], f"$.delegation.admission.{field}")
    if admission["lease_sha256"] != bindings["lease_sha256"]:
        raise EvidenceError("delegation_lease_binding_mismatch", "$.delegation.admission.lease_sha256")
    _bound_digests(admission, bindings, "$.delegation.admission")
    fanout = _integer(admission["fanout_after"], "$.delegation.admission.fanout_after")
    concurrency = _integer(admission["concurrency_after"], "$.delegation.admission.concurrency_after")
    budget_after = _limits(admission["lineage_budget_after"], "$.delegation.admission.lineage_budget_after")
    admitted_limits = _limits(admission["admitted_limits"], "$.delegation.admission.admitted_limits")
    if admission["admitted"] and (fanout > parent["limits"]["fanout"] or concurrency > parent["limits"]["concurrency"]):
        raise EvidenceError("delegation_structural_limit_exceeded", "$.delegation.admission")
    for field in LIMIT_FIELDS:
        if budget_after[field] > parent["limits"][field]:
            raise EvidenceError("lineage_budget_widened", f"$.delegation.admission.lineage_budget_after.{field}")
    if admitted_limits != child["limits"] or budget_after != child["limits"]:
        raise EvidenceError("delegation_limit_binding_mismatch", "$.delegation.admission.admitted_limits")
    return {
        "proposal_status": "untrusted_proposal",
        "admission_status": "admitted" if admission["admitted"] else "denied",
        "authority_attenuated": True,
        "independent_admission": True,
        "child_launched_by_model": False,
        "child": copy.deepcopy(child),
        "lineage_budget_after": copy.deepcopy(budget_after),
    }


def validate_journal(
    value: Any,
    bindings: Mapping[str, Any],
    child_run_id: str | None,
    parent_limits: Mapping[str, int],
    child_limits: Mapping[str, int],
    evaluated_at: datetime,
    artifact_locators: set[str],
    recovery_run_ids: set[str],
) -> dict[str, Any]:
    journal = _closed(value, {
        "journal_id", "workspace_id", "goal_id", "task_id", "root_run_id",
        "current_run_id", "workgraph_subtree_id", "adapter_id", "adapter_sha256",
        "disclosure_refs", "channel_open", "messages", "recalls",
    }, "$.journal")
    for field in (
        "journal_id", "workspace_id", "goal_id", "task_id", "root_run_id",
        "current_run_id", "workgraph_subtree_id", "adapter_id",
    ):
        _identifier(journal[field], f"$.journal.{field}")
    _digest(journal["adapter_sha256"], "$.journal.adapter_sha256")
    disclosure_refs = _strings(journal["disclosure_refs"], "$.journal.disclosure_refs", identifiers=False)
    for field in (
        "workspace_id", "goal_id", "task_id", "root_run_id", "current_run_id",
        "workgraph_subtree_id", "adapter_id", "adapter_sha256",
    ):
        if journal[field] != bindings[field]:
            raise EvidenceError("journal_scope_mismatch", f"$.journal.{field}")
    if disclosure_refs != bindings["disclosure_refs"]:
        raise EvidenceError("journal_scope_mismatch", "$.journal")
    channel_open = _boolean(journal["channel_open"], "$.journal.channel_open")
    if not isinstance(journal["messages"], list) or not isinstance(journal["recalls"], list):
        raise EvidenceError("array_required", "$.journal")
    previous_id: str | None = None
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    sender_counts: dict[str, int] = {}
    for index, raw in enumerate(journal["messages"]):
        path = f"$.journal.messages[{index}]"
        message = _closed(raw, {
            "message_id", "sequence", "predecessor_id", "reply_to_id", "message_type",
            "sender_run_id", "sender_route_id", "sender_adapter_id", "authority_sha256", "created_at",
            "ttl_seconds", "redaction_class", "content", "artifact_refs", "executable",
        }, path)
        message_id = _identifier(message["message_id"], f"{path}.message_id")
        if message_id in seen:
            raise EvidenceError("journal_message_duplicate", f"{path}.message_id")
        seen.add(message_id)
        if _integer(message["sequence"], f"{path}.sequence", 1) != index + 1 or message["predecessor_id"] != previous_id:
            raise EvidenceError("journal_append_chain_invalid", path)
        if message["reply_to_id"] is not None and message["reply_to_id"] not in seen:
            raise EvidenceError("journal_reply_invalid", f"{path}.reply_to_id")
        if message["message_type"] not in JOURNAL_TYPES:
            raise EvidenceError("journal_type_invalid", f"{path}.message_type")
        sender = _identifier(message["sender_run_id"], f"{path}.sender_run_id")
        allowed_senders = {bindings["run_id"]}
        if child_run_id is not None:
            allowed_senders.add(child_run_id)
        if sender not in allowed_senders:
            raise EvidenceError("journal_cross_lineage_forbidden", f"{path}.sender_run_id")
        sender_limits = child_limits if child_run_id is not None and sender == child_run_id else parent_limits
        sender_counts[sender] = sender_counts.get(sender, 0) + 1
        if sender_counts[sender] > sender_limits["journal_messages"]:
            raise EvidenceError("journal_count_exceeded", path)
        sender_route = _identifier(message["sender_route_id"], f"{path}.sender_route_id")
        sender_adapter = _identifier(message["sender_adapter_id"], f"{path}.sender_adapter_id")
        allowed_routes = {bindings["route_id"]} if sender == bindings["run_id"] else set(bindings["child_route_ids"])
        if sender_route not in allowed_routes or sender_adapter != bindings["adapter_id"]:
            raise EvidenceError("journal_sender_binding_mismatch", path)
        _digest(message["authority_sha256"], f"{path}.authority_sha256")
        if message["authority_sha256"] != bindings["authority_sha256"]:
            raise EvidenceError("journal_authority_mismatch", f"{path}.authority_sha256")
        created_at = _time(message["created_at"], f"{path}.created_at")
        ttl = _integer(message["ttl_seconds"], f"{path}.ttl_seconds", 1)
        if ttl > sender_limits["ttl_seconds"]:
            raise EvidenceError("journal_ttl_exceeded", f"{path}.ttl_seconds")
        if created_at > evaluated_at:
            raise EvidenceError("journal_message_from_future", f"{path}.created_at")
        if created_at + timedelta(seconds=ttl) <= evaluated_at:
            raise EvidenceError("journal_message_expired", f"{path}.ttl_seconds")
        if message["redaction_class"] not in {"public", "internal", "redacted"}:
            raise EvidenceError("journal_redaction_class_invalid", f"{path}.redaction_class")
        if not isinstance(message["content"], dict) or set(message["content"]) != {"summary", "claim", "instruction"}:
            raise EvidenceError("journal_content_schema_invalid", f"{path}.content")
        if message["content"]["instruction"] is not None or _boolean(message["executable"], f"{path}.executable"):
            raise EvidenceError("journal_instruction_forbidden", path)
        if not isinstance(message["content"]["summary"], str) or not isinstance(message["content"]["claim"], str):
            raise EvidenceError("journal_content_schema_invalid", f"{path}.content")
        if len(canonical_json(message["content"])) > sender_limits["message_bytes"]:
            raise EvidenceError("journal_message_size_exceeded", f"{path}.content")
        if _contains_credential(message) or any(key.lower() in {"chain_of_thought", "reasoning", "hidden_prompt"} for key in message["content"]):
            raise EvidenceError("journal_sensitive_content_forbidden", path)
        refs = _strings(message["artifact_refs"], f"{path}.artifact_refs", identifiers=False)
        if not set(refs) <= set(disclosure_refs) or not set(refs) <= artifact_locators:
            raise EvidenceError("journal_disclosure_scope_mismatch", f"{path}.artifact_refs")
        if _contains_credential(refs):
            raise EvidenceError("credential_reference_forbidden", f"{path}.artifact_refs")
        body = copy.deepcopy(message)
        body["content_sha256"] = canonical_digest("runtime-evidence-journal-content-v1", message["content"])
        body["record_sha256"] = canonical_digest("runtime-evidence-journal-record-v1", body)
        normalized.append(body)
        previous_id = message_id
    recall_subjects: set[str] = set()
    allowed_subjects = {
        "journal": {journal["journal_id"]},
        "message": seen,
        "run": {bindings["root_run_id"], bindings["run_id"], *recovery_run_ids},
        "route": {bindings["route_id"], *bindings["child_route_ids"]},
    }
    if child_run_id is not None:
        allowed_subjects["run"].add(child_run_id)
    for index, raw in enumerate(journal["recalls"]):
        path = f"$.journal.recalls[{index}]"
        recall = _closed(raw, {"recall_id", "subject_type", "subject_id", "authority_sha256", "created_at", "reason"}, path)
        _identifier(recall["recall_id"], f"{path}.recall_id")
        if recall["subject_type"] not in {"journal", "message", "run", "route"}:
            raise EvidenceError("recall_subject_type_invalid", f"{path}.subject_type")
        _identifier(recall["subject_id"], f"{path}.subject_id")
        _digest(recall["authority_sha256"], f"{path}.authority_sha256")
        if recall["authority_sha256"] != bindings["authority_sha256"]:
            raise EvidenceError("journal_authority_mismatch", f"{path}.authority_sha256")
        if recall["subject_id"] not in allowed_subjects[recall["subject_type"]]:
            raise EvidenceError("recall_subject_unknown", f"{path}.subject_id")
        if _time(recall["created_at"], f"{path}.created_at") > evaluated_at:
            raise EvidenceError("journal_recall_from_future", f"{path}.created_at")
        if not isinstance(recall["reason"], str) or not recall["reason"]:
            raise EvidenceError("string_invalid", f"{path}.reason")
        recall_subjects.add(recall["subject_id"])
    if journal["journal_id"] in recall_subjects and channel_open:
        raise EvidenceError("recalled_journal_reopened", "$.journal.channel_open")
    return {
        "journal_id": journal["journal_id"],
        "scope": "current_workgraph_subtree",
        "storage": "append_only_task_journal",
        "messages": normalized,
        "recalls": copy.deepcopy(journal["recalls"]),
        "channel_open": channel_open,
        "executable": False,
        "authoritative": False,
        "global": False,
        "mutable": False,
    }


def detect_progress(value: Any, limits: Mapping[str, int]) -> dict[str, Any]:
    detector = _closed(value, {
        "actions", "error_classes", "hypotheses", "progress_kinds", "lineage_edges",
        "fanout", "concurrency", "tokens_used", "external_cost_microunits_used",
        "thresholds",
    }, "$.detectors")
    actions = _strings(detector["actions"], "$.detectors.actions", unique=False)
    errors = _strings(detector["error_classes"], "$.detectors.error_classes", unique=False)
    hypotheses = _strings(detector["hypotheses"], "$.detectors.hypotheses", unique=False)
    progress = _strings(detector["progress_kinds"], "$.detectors.progress_kinds", unique=False)
    if not set(progress) <= PROGRESS_KINDS:
        raise EvidenceError("progress_kind_invalid", "$.detectors.progress_kinds")
    if not isinstance(detector["lineage_edges"], list):
        raise EvidenceError("array_required", "$.detectors.lineage_edges")
    edges: list[tuple[str, str]] = []
    for index, raw in enumerate(detector["lineage_edges"]):
        edge = _closed(raw, {"parent", "child"}, f"$.detectors.lineage_edges[{index}]")
        edges.append((_identifier(edge["parent"], "parent"), _identifier(edge["child"], "child")))
    fanout = _integer(detector["fanout"], "$.detectors.fanout")
    concurrency = _integer(detector["concurrency"], "$.detectors.concurrency")
    tokens = _integer(detector["tokens_used"], "$.detectors.tokens_used")
    cost = _integer(detector["external_cost_microunits_used"], "$.detectors.external_cost_microunits_used")
    thresholds = _closed(detector["thresholds"], {"repeat", "error", "no_progress"}, "$.detectors.thresholds")
    repeat_n = _integer(thresholds["repeat"], "$.detectors.thresholds.repeat", 2)
    error_n = _integer(thresholds["error"], "$.detectors.thresholds.error", 2)
    no_progress_n = _integer(thresholds["no_progress"], "$.detectors.thresholds.no_progress", 2)

    def tail_same(items: list[str], size: int) -> bool:
        return len(items) >= size and len(set(items[-size:])) == 1

    def has_cycle() -> bool:
        graph: dict[str, list[str]] = {}
        for parent, child in edges:
            graph.setdefault(parent, []).append(child)
        visiting: set[str] = set()
        visited: set[str] = set()
        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            if any(visit(child) for child in graph.get(node, [])):
                return True
            visiting.remove(node)
            visited.add(node)
            return False
        return any(visit(node) for node in sorted(graph))

    ping_pong = len(actions) >= 4 and actions[-4] == actions[-2] and actions[-3] == actions[-1] and actions[-2] != actions[-1]
    rewrite_retest = len(actions) >= 4 and actions[-4:] == ["rewrite", "retest", "rewrite", "retest"]
    flags = {
        "repeat": tail_same(actions, repeat_n),
        "repeated_error": tail_same(errors, error_n),
        "ping_pong": ping_pong,
        "rewrite_retest": rewrite_retest,
        "no_progress": len(progress) >= no_progress_n and all(item == "none" for item in progress[-no_progress_n:]),
        "cycle": has_cycle(),
        "fanout": fanout > limits["fanout"],
        "concurrency": concurrency > limits["concurrency"],
        "budget": tokens > limits["tokens"] or cost > limits["external_cost_microunits"],
    }
    # A changed hypothesis prevents a repeat/error signature from being treated as
    # an equivalent failed attempt.
    if len(hypotheses) >= 2 and hypotheses[-1] != hypotheses[-2]:
        flags["repeat"] = False
        flags["repeated_error"] = False
    if flags["cycle"] or flags["fanout"] or flags["concurrency"] or flags["budget"]:
        outcome = "stop"
    elif flags["repeated_error"] or flags["no_progress"]:
        outcome = "handoff"
    elif flags["ping_pong"] or flags["rewrite_retest"] or flags["repeat"]:
        outcome = "switch"
    else:
        outcome = "continue"
    return {"detectors": flags, "outcome": outcome, "deterministic": True, "authority_granted": False}


def normalize_packet(value: Any) -> dict[str, Any]:
    fields = {
        "evidence_version", "artifact_type", "evaluated_at", "bindings", "artifacts",
        "quality", "usage", "trajectory", "lineage", "recovery", "checkpoint",
        "handoff", "delegation", "journal", "detectors", "closeout",
    }
    packet = _closed(value, fields, "$")
    if packet["evidence_version"] != VERSION or packet["artifact_type"] != PACKET_TYPE:
        raise EvidenceError("version_or_type_unsupported", "$")
    evaluated_at = _time(packet["evaluated_at"], "$.evaluated_at")
    bindings = _closed(packet["bindings"], {
        "workspace_id", "goal_id", "task_id", "run_id", "root_run_id", "route_id",
        "adapter_id", "workgraph_subtree_id", "disclosure_refs", *BINDING_DIGEST_FIELDS,
    }, "$.bindings")
    for field in (
        "workspace_id", "goal_id", "task_id", "run_id", "root_run_id", "route_id",
        "adapter_id", "workgraph_subtree_id",
    ):
        _identifier(bindings[field], f"$.bindings.{field}")
    for field in BINDING_DIGEST_FIELDS:
        _digest(bindings[field], f"$.bindings.{field}")
    disclosure_refs = _strings(bindings["disclosure_refs"], "$.bindings.disclosure_refs", identifiers=False)
    if _contains_credential(disclosure_refs):
        raise EvidenceError("credential_reference_forbidden", "$.bindings.disclosure_refs")

    if not isinstance(packet["artifacts"], list):
        raise EvidenceError("array_required", "$.artifacts")
    artifact_ids: set[str] = set()
    artifact_locators: set[str] = set()
    eligible_artifact_ids: set[str] = set()
    eligible_artifact_locators: set[str] = set()
    recalled_artifact_refs: set[str] = set()
    for index, raw in enumerate(packet["artifacts"]):
        path = f"$.artifacts[{index}]"
        artifact = _closed(raw, {"artifact_id", "locator", "sha256", "media_type", "bytes", "lineage_run_id", "recalled"}, path)
        artifact_id = _identifier(artifact["artifact_id"], f"{path}.artifact_id")
        if artifact_id in artifact_ids:
            raise EvidenceError("artifact_duplicate", f"{path}.artifact_id")
        artifact_ids.add(artifact_id)
        if not isinstance(artifact["locator"], str) or _contains_credential(artifact["locator"]):
            raise EvidenceError("artifact_locator_invalid", f"{path}.locator")
        artifact_locators.add(artifact["locator"])
        _digest(artifact["sha256"], f"{path}.sha256")
        _identifier(artifact["media_type"], f"{path}.media_type")
        _integer(artifact["bytes"], f"{path}.bytes")
        _identifier(artifact["lineage_run_id"], f"{path}.lineage_run_id")
        if _boolean(artifact["recalled"], f"{path}.recalled"):
            recalled_artifact_refs.update((artifact_id, artifact["locator"]))
        else:
            eligible_artifact_ids.add(artifact_id)
            eligible_artifact_locators.add(artifact["locator"])

    quality = _closed(packet["quality"], {"status", "evidence_sha256", "acceptance_claimed", "provenance"}, "$.quality")
    if quality["status"] not in {"passed", "failed", "unknown"}:
        raise EvidenceError("quality_status_invalid", "$.quality.status")
    _digest(quality["evidence_sha256"], "$.quality.evidence_sha256")
    if _boolean(quality["acceptance_claimed"], "$.quality.acceptance_claimed"):
        raise EvidenceError("acceptance_authority_forbidden", "$.quality.acceptance_claimed")
    usage = normalize_usage(packet["usage"])

    if not isinstance(packet["trajectory"], list):
        raise EvidenceError("array_required", "$.trajectory")
    for index, raw in enumerate(packet["trajectory"]):
        path = f"$.trajectory[{index}]"
        row = _closed(raw, {"event_id", "event_type", "outcome", "evidence_sha256", "artifact_ids", "provenance"}, path)
        for field in ("event_id", "event_type", "outcome"):
            _identifier(row[field], f"{path}.{field}")
        _digest(row["evidence_sha256"], f"{path}.evidence_sha256")
        refs = _strings(row["artifact_ids"], f"{path}.artifact_ids")
        if not set(refs) <= artifact_ids:
            raise EvidenceError("trajectory_artifact_unknown", path)
        if not set(refs) <= eligible_artifact_ids:
            raise EvidenceError("recalled_artifact_accepted", f"{path}.artifact_ids")

    lineage = _closed(packet["lineage"], {"root_run_id", "current_run_id", "parent_run_id", "depth", "ancestor_run_ids"}, "$.lineage")
    for field in ("root_run_id", "current_run_id"):
        _identifier(lineage[field], f"$.lineage.{field}")
    if lineage["parent_run_id"] is not None:
        _identifier(lineage["parent_run_id"], "$.lineage.parent_run_id")
    _integer(lineage["depth"], "$.lineage.depth")
    ancestors = _strings(lineage["ancestor_run_ids"], "$.lineage.ancestor_run_ids")
    if (
        lineage["root_run_id"] != bindings["root_run_id"]
        or lineage["current_run_id"] != bindings["run_id"]
        or lineage["current_run_id"] in ancestors
    ):
        raise EvidenceError("lineage_cycle_or_binding", "$.lineage")

    recovery = _closed(packet["recovery"], {"predecessor_run_id", "successor_run_id", "state", "evidence_sha256", "history_rewritten", "provenance"}, "$.recovery")
    for field in ("predecessor_run_id", "successor_run_id"):
        _identifier(recovery[field], f"$.recovery.{field}")
    if recovery["predecessor_run_id"] == recovery["successor_run_id"] or recovery["state"] not in {"not_required", "recovered_to_successor", "unreconciled"}:
        raise EvidenceError("recovery_invalid", "$.recovery")
    if recovery["successor_run_id"] != bindings["run_id"]:
        raise EvidenceError("recovery_successor_binding_mismatch", "$.recovery.successor_run_id")
    _digest(recovery["evidence_sha256"], "$.recovery.evidence_sha256")
    if _boolean(recovery["history_rewritten"], "$.recovery.history_rewritten"):
        raise EvidenceError("recovery_history_rewrite_forbidden", "$.recovery.history_rewritten")

    checkpoint = _closed(packet["checkpoint"], {
        "checkpoint_id", "run_id", "assignment_sha256", "authority_sha256", "source_sha256",
        "policy_sha256", "route_sha256", "lease_sha256", "adapter_sha256", "event_sequence",
        "journal_cursor", "remaining_limits", "accepted_artifact_ids", "attempted_hypotheses",
        "failures", "next_action", "stop_conditions",
    }, "$.checkpoint")
    for field in ("checkpoint_id", "run_id", "next_action"):
        _identifier(checkpoint[field], f"$.checkpoint.{field}")
    if checkpoint["run_id"] != bindings["run_id"]:
        raise EvidenceError("checkpoint_binding_mismatch", "$.checkpoint")
    try:
        _bound_digests(checkpoint, bindings, "$.checkpoint")
    except EvidenceError as exc:
        if exc.code == "evidence_binding_mismatch":
            raise EvidenceError("checkpoint_binding_mismatch", exc.path) from exc
        raise
    _integer(checkpoint["event_sequence"], "$.checkpoint.event_sequence")
    _integer(checkpoint["journal_cursor"], "$.checkpoint.journal_cursor")
    remaining = _limits(checkpoint["remaining_limits"], "$.checkpoint.remaining_limits")
    accepted_ids = _strings(checkpoint["accepted_artifact_ids"], "$.checkpoint.accepted_artifact_ids")
    if not set(accepted_ids) <= artifact_ids:
        raise EvidenceError("checkpoint_artifact_unknown", "$.checkpoint.accepted_artifact_ids")
    if not set(accepted_ids) <= eligible_artifact_ids:
        raise EvidenceError("recalled_artifact_accepted", "$.checkpoint.accepted_artifact_ids")
    _provenance(quality["provenance"], "$.quality.provenance", bindings, accepted_ids, artifact_ids, eligible_artifact_ids)
    for index, row in enumerate(packet["trajectory"]):
        _provenance(row["provenance"], f"$.trajectory[{index}].provenance", bindings, accepted_ids, artifact_ids, eligible_artifact_ids)
    _provenance(recovery["provenance"], "$.recovery.provenance", bindings, accepted_ids, artifact_ids, eligible_artifact_ids)
    for field in ("attempted_hypotheses", "failures", "stop_conditions"):
        _strings(checkpoint[field], f"$.checkpoint.{field}")

    handoff = _closed(packet["handoff"], {
        "handoff_id", "checkpoint_id", "assignment_sha256", "authority_sha256", "source_sha256",
        "policy_sha256", "route_sha256", "lease_sha256", "adapter_sha256", "objective", "allowed_paths",
        "allowed_tools", "allowed_effects", "denied_effects", "validation_commands",
        "journal_cursor", "next_action", "excludes_chain_of_thought", "excludes_credentials",
    }, "$.handoff")
    for field in ("handoff_id", "checkpoint_id", "next_action"):
        _identifier(handoff[field], f"$.handoff.{field}")
    if handoff["checkpoint_id"] != checkpoint["checkpoint_id"] or handoff["journal_cursor"] != checkpoint["journal_cursor"]:
        raise EvidenceError("handoff_binding_mismatch", "$.handoff")
    try:
        _bound_digests(handoff, bindings, "$.handoff")
    except EvidenceError as exc:
        if exc.code == "evidence_binding_mismatch":
            raise EvidenceError("handoff_binding_mismatch", exc.path) from exc
        raise
    if not isinstance(handoff["objective"], str) or not handoff["objective"]:
        raise EvidenceError("string_invalid", "$.handoff.objective")
    _portable_paths(handoff["allowed_paths"], "$.handoff.allowed_paths")
    for field in ("allowed_tools", "allowed_effects", "denied_effects"):
        _strings(handoff[field], f"$.handoff.{field}")
    _strings(handoff["validation_commands"], "$.handoff.validation_commands", identifiers=False)
    if not _boolean(handoff["excludes_chain_of_thought"], "$.handoff.excludes_chain_of_thought") or not _boolean(handoff["excludes_credentials"], "$.handoff.excludes_credentials"):
        raise EvidenceError("handoff_sensitive_content_forbidden", "$.handoff")
    if _contains_credential(handoff):
        raise EvidenceError("credential_reference_forbidden", "$.handoff")

    eligible_artifact_refs = eligible_artifact_ids | eligible_artifact_locators
    delegation = evaluate_delegation(
        packet["delegation"],
        bindings,
        eligible_artifact_refs,
        recalled_artifact_refs,
    )
    delegation_parent = packet["delegation"]["parent"]
    expected_lineage = {
        "root_run_id": delegation_parent["root_run_id"],
        "current_run_id": delegation_parent["run_id"],
        "parent_run_id": delegation_parent["parent_run_id"],
        "depth": delegation_parent["depth"],
        "ancestor_run_ids": delegation_parent["ancestor_run_ids"],
    }
    if lineage != expected_lineage:
        raise EvidenceError("lineage_binding_mismatch", "$.lineage")
    if lineage["depth"] != len(ancestors):
        raise EvidenceError("lineage_binding_mismatch", "$.lineage.depth")
    if lineage["depth"] == 0:
        if lineage["current_run_id"] != lineage["root_run_id"]:
            raise EvidenceError("lineage_binding_mismatch", "$.lineage.current_run_id")
    elif ancestors[0] != lineage["root_run_id"] or ancestors[-1] != lineage["parent_run_id"]:
        raise EvidenceError("lineage_binding_mismatch", "$.lineage.ancestor_run_ids")

    child_admitted = delegation["admission_status"] == "admitted"
    child_run_id = delegation["child"]["run_id"] if child_admitted else None
    allowed_run_ids = {bindings["run_id"]}
    if child_run_id is not None:
        allowed_run_ids.add(child_run_id)
    for index, artifact in enumerate(packet["artifacts"]):
        if artifact["lineage_run_id"] not in allowed_run_ids:
            code = "delegation_child_not_admitted" if artifact["lineage_run_id"] == delegation["child"]["run_id"] else "artifact_lineage_foreign"
            raise EvidenceError(code, f"$.artifacts[{index}].lineage_run_id")
    for index, row in enumerate(usage["receipts"]):
        if row["run_id"] not in allowed_run_ids or row["lineage_run_id"] not in allowed_run_ids:
            child_identity = delegation["child"]["run_id"] in {row["run_id"], row["lineage_run_id"]}
            code = "delegation_child_not_admitted" if child_identity and not child_admitted else "usage_lineage_foreign"
            raise EvidenceError(code, f"$.usage[{index}]")
        if row["run_id"] != row["lineage_run_id"]:
            raise EvidenceError("usage_lineage_mismatch", f"$.usage[{index}]")
    journal_bindings = dict(bindings)
    journal_bindings["current_run_id"] = bindings["run_id"]
    journal_bindings["child_route_ids"] = delegation["child"]["authority"]["route_ids"] if child_admitted else []
    if set(disclosure_refs) & recalled_artifact_refs:
        raise EvidenceError("recalled_artifact_disclosed", "$.bindings.disclosure_refs")
    known_lineage_run_ids = {lineage["root_run_id"], lineage["current_run_id"], *ancestors}
    if child_run_id is not None:
        known_lineage_run_ids.add(child_run_id)
    proven_recovery_run_ids = {
        run_id
        for run_id in (recovery["predecessor_run_id"], recovery["successor_run_id"])
        if run_id in known_lineage_run_ids
    }
    journal = validate_journal(
        packet["journal"],
        journal_bindings,
        child_run_id,
        packet["delegation"]["parent"]["limits"],
        delegation["child"]["limits"],
        evaluated_at,
        eligible_artifact_locators,
        proven_recovery_run_ids,
    )
    detectors = detect_progress(packet["detectors"], remaining)
    closeout = _closed(packet["closeout"], {"status", "execution_success_claimed", "quality_accepted", "parent_accepted", "proof_boundary", "provenance"}, "$.closeout")
    if closeout["status"] not in {"candidate", "failed", "blocked", "unknown"}:
        raise EvidenceError("closeout_status_invalid", "$.closeout.status")
    for field in ("execution_success_claimed", "quality_accepted", "parent_accepted"):
        _boolean(closeout[field], f"$.closeout.{field}")
    if closeout["parent_accepted"]:
        raise EvidenceError("acceptance_authority_forbidden", "$.closeout.parent_accepted")
    if closeout["proof_boundary"] != "synthetic_local":
        raise EvidenceError("proof_boundary_invalid", "$.closeout.proof_boundary")
    _provenance(closeout["provenance"], "$.closeout.provenance", bindings, accepted_ids, artifact_ids, eligible_artifact_ids)

    normalized = {
        "evidence_version": VERSION,
        "artifact_type": RECEIPT_TYPE,
        "bindings": copy.deepcopy(bindings),
        "artifacts": copy.deepcopy(packet["artifacts"]),
        "quality": copy.deepcopy(quality),
        "usage": usage,
        "trajectory": copy.deepcopy(packet["trajectory"]),
        "lineage": copy.deepcopy(lineage),
        "recovery": copy.deepcopy(recovery),
        "checkpoint": copy.deepcopy(checkpoint),
        "handoff": copy.deepcopy(handoff),
        "delegation": delegation,
        "journal": journal,
        "progress": detectors,
        "closeout": copy.deepcopy(closeout),
        "proof_boundary": "synthetic_local",
        "side_effect_free": True,
        "runtime_effects": False,
        "provider_called": False,
        "network_used": False,
        "filesystem_mutated": False,
        "authority_granted": False,
        "acceptance_granted": False,
    }
    normalized["receipt_sha256"] = canonical_digest("runtime-evidence-receipt-v1", normalized)
    return normalized


def _set_path(document: dict[str, Any], path: list[Any], value: Any) -> None:
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


def run_cases(document: Any, source: Path | None = None) -> dict[str, Any]:
    cases = _closed(document, {"evidence_version", "artifact_type", "valid", "adversarial"}, "$")
    if cases["evidence_version"] != VERSION or cases["artifact_type"] != CASES_TYPE:
        raise EvidenceError("version_or_type_unsupported", "$")
    valid_receipt = normalize_packet(cases["valid"])
    if not isinstance(cases["adversarial"], list):
        raise EvidenceError("array_required", "$.adversarial")
    results: list[dict[str, Any]] = []
    for index, raw in enumerate(cases["adversarial"]):
        path = f"$.adversarial[{index}]"
        if not isinstance(raw, dict):
            raise EvidenceError("object_required", path)
        extra = sorted(set(raw) - {"name", "path", "value", "mutations", "expected_code"})
        if extra:
            raise EvidenceError("unknown_field", f"{path}.{extra[0]}")
        if not {"name", "expected_code"} <= set(raw):
            raise EvidenceError("missing_field", path)
        single_mutation = "path" in raw or "value" in raw
        multiple_mutations = "mutations" in raw
        if single_mutation == multiple_mutations or (single_mutation and not {"path", "value"} <= set(raw)):
            raise EvidenceError("mutation_path_invalid", path)
        case = raw
        _identifier(case["name"], f"$.adversarial[{index}].name")
        _identifier(case["expected_code"], f"$.adversarial[{index}].expected_code")
        mutations = [{"path": case["path"], "value": case["value"]}] if single_mutation else case["mutations"]
        if not isinstance(mutations, list) or not mutations:
            raise EvidenceError("mutation_path_invalid", f"{path}.mutations")
        mutated = copy.deepcopy(cases["valid"])
        try:
            for mutation_index, raw_mutation in enumerate(mutations):
                mutation_path = f"{path}.mutations[{mutation_index}]"
                mutation = _closed(raw_mutation, {"path", "value"}, mutation_path)
                if not isinstance(mutation["path"], list) or not mutation["path"]:
                    raise EvidenceError("mutation_path_invalid", f"{mutation_path}.path")
                _set_path(mutated, mutation["path"], mutation["value"])
            normalize_packet(mutated)
        except (KeyError, IndexError, TypeError) as exc:
            raise EvidenceError("mutation_path_invalid", f"$.adversarial[{index}].path") from exc
        except EvidenceError as exc:
            if exc.code != case["expected_code"]:
                raise EvidenceError("unexpected_failure_code", f"{case['name']}:{exc.code}") from exc
            results.append({"name": case["name"], "status": "pass", "failure_code": exc.code})
        else:
            raise EvidenceError("adversarial_case_accepted", case["name"])
    return {
        "evidence_version": VERSION,
        "artifact_type": "runtime_evidence_case_receipt_v1",
        "valid": True,
        "valid_receipt_sha256": valid_receipt["receipt_sha256"],
        "adversarial": results,
        "case_count": 1 + len(results),
        "source": source.as_posix() if source else None,
        "side_effect_free": True,
    }


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("input_invalid", str(path)) from exc


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate_json_key", key)
        result[key] = value
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        document = load_json(args.input)
        receipt = run_cases(document, args.input) if isinstance(document, dict) and document.get("artifact_type") == CASES_TYPE else normalize_packet(document)
    except EvidenceError as exc:
        print(json.dumps({"valid": False, "error": {"code": exc.code, "path": exc.path}}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
