#!/usr/bin/env python3
"""Pure structural catalog and selection ledger with unavailable sources."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping

from package_host_supported_host_fact_sources_v1 import UnavailableFact


OPERATIONS = (
    "read_operator_preset_bundle",
    "read_operator_selection_head",
    "read_operator_selection_mutation",
    "commit_operator_selection",
)
OPERATION_SET = frozenset(OPERATIONS)
VARIANTS = {
    "read_operator_preset_bundle": "catalog_candidate",
    "read_operator_selection_head": "selection_head_candidate",
    "read_operator_selection_mutation": "mutation_query_authorization_candidate",
    "commit_operator_selection": "commit_authorization_candidate",
}
SOURCE_IDS = {
    "read_operator_preset_bundle": "operator-catalog-publisher",
    "read_operator_selection_head": "operator-selection-ledger",
    "read_operator_selection_mutation": "operator-selection-mutation-history",
    "commit_operator_selection": "operator-selection-commit-authority",
}
VARIANT_SET = frozenset(VARIANTS.values())
SOURCE_ID_SET = frozenset(SOURCE_IDS.values())
EVENT_TYPES = frozenset({"issue", "revoke"})
LEDGER_TYPE = "supported_host_catalog_selection_ledger_v1"
EVENT_TYPE = "supported_host_catalog_selection_event_v1"
DECISION_TYPE = "supported_host_catalog_selection_structural_decision_v1"
UNAVAILABLE_TYPE = "supported_host_catalog_selection_source_result_v1"
LEDGER_FIELDS = frozenset({"schema_version", "artifact_type", "ledger_id", "events", "head_sha256", "state_sha256"})
EVENT_FIELDS = frozenset({
    "schema_version", "artifact_type", "ledger_id", "sequence", "previous_event_sha256",
    "expected_head_sha256", "event_type", "occurred_at", "operation", "decision_id",
    "decision_sha256", "decision", "reason", "event_sha256",
})
DECISION_FIELDS = frozenset({
    "schema_version", "artifact_type", "decision_id", "decision_source_id", "ledger_id",
    "operation", "variant", "identity_sha256", "operation_body_sha256",
    "dependency_receipts_sha256", "source_sha256", "candidate_sha256", "manifest_sha256",
    "generation", "payload", "observed_at", "expires_at", "decision_sha256",
})
CATALOG_FIELDS = frozenset({
    "catalog_id", "generation", "previous_catalog_sha256", "presets", "history",
    "qualification_set_sha256",
})
PRESET_FIELDS = frozenset({"preset_id", "family_id", "definition_sha256", "qualification_input_sha256"})
HISTORY_FIELDS = frozenset({"generation", "catalog_sha256", "previous_catalog_sha256"})
HEAD_FIELDS = frozenset({
    "catalog_sha256", "bundle_sha256", "catalog_generation", "binding_sha256",
    "selection_sha256", "selection_version",
})
QUERY_FIELDS = frozenset({"submission_id", "submission_sha256"})
COMMIT_FIELDS = frozenset({
    "submission_id", "submission_sha256", "expected_selection_version",
    "current_selection_sha256", "requested_selection_sha256",
})
REVOKE_REASONS = frozenset({"binding_invalidated", "request_withdrawn", "operator_revoked"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset({
    "private_key", "private_key_path", "credential", "certificate", "endpoint", "path", "env",
    "environment", "provider", "provider_result", "live", "live_status", "fixture", "default",
    "fallback", "caller_route", "mutable_overlay", "result", "mutation", "head", "qualified",
    "qualification_status", "receiver_index", "historical_receipt", "self_digest", "absent",
    "exact", "collision",
})


class CatalogSelectionError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise CatalogSelectionError("canonical_value_invalid", "$") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise CatalogSelectionError(code, path)
    return deepcopy(dict(value))


def _version(value: Any, code: str, path: str) -> int:
    if type(value) is not int or value != 1:
        raise CatalogSelectionError(code, path)
    return value


def _positive_int(value: Any, code: str, path: str) -> int:
    if type(value) is not int or value < 1:
        raise CatalogSelectionError(code, path)
    return value


def _id(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise CatalogSelectionError("identifier_invalid", path)
    return value


def _operation(value: Any, path: str) -> str:
    if not isinstance(value, str) or value not in OPERATION_SET:
        raise CatalogSelectionError("canonical_operation_invalid", path)
    return value


def _variant(value: Any, path: str, *, operation: str | None = None) -> str:
    if not isinstance(value, str) or value not in VARIANT_SET:
        raise CatalogSelectionError("decision_variant_invalid", path)
    if operation is not None:
        operation = _operation(operation, path.rsplit(".", 1)[0] + ".operation")
        if value != VARIANTS[operation]:
            raise CatalogSelectionError("decision_variant_invalid", path)
    return value


def _source_id(value: Any, path: str, *, operation: str) -> str:
    operation = _operation(operation, path.rsplit(".", 1)[0] + ".operation")
    if not isinstance(value, str) or value not in SOURCE_ID_SET or value != SOURCE_IDS[operation]:
        raise CatalogSelectionError("decision_source_invalid", path)
    return value


def _event_type(value: Any, path: str) -> str:
    if not isinstance(value, str) or value not in EVENT_TYPES:
        raise CatalogSelectionError("ledger_event_type_invalid", path)
    return value


def _revoke_reason(value: Any, path: str) -> str:
    if not isinstance(value, str) or value not in REVOKE_REASONS:
        raise CatalogSelectionError("ledger_revoke_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise CatalogSelectionError("digest_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CatalogSelectionError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CatalogSelectionError("timestamp_invalid", path) from exc
    if parsed.utcoffset() != timedelta(0) or parsed.microsecond != 0:
        raise CatalogSelectionError("timestamp_invalid", path)
    return parsed


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CatalogSelectionError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _reject_forbidden(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise CatalogSelectionError("authority_field_forbidden", path + "." + str(key))
            _reject_forbidden(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")


def _validate_catalog(value: Any, path: str) -> dict[str, Any]:
    row = _closed(value, CATALOG_FIELDS, "catalog_candidate_shape_invalid", path)
    _id(row["catalog_id"], path + ".catalog_id")
    generation = _positive_int(row["generation"], "catalog_generation_invalid", path + ".generation")
    if not isinstance(row["presets"], list) or len(row["presets"]) < 2:
        raise CatalogSelectionError("catalog_presets_invalid", path + ".presets")
    preset_ids: set[str] = set()
    qualification_inputs: list[str] = []
    for index, raw in enumerate(row["presets"]):
        item_path = f"{path}.presets[{index}]"
        preset = _closed(raw, PRESET_FIELDS, "catalog_preset_invalid", item_path)
        preset_id = _id(preset["preset_id"], item_path + ".preset_id")
        _id(preset["family_id"], item_path + ".family_id")
        _sha(preset["definition_sha256"], item_path + ".definition_sha256")
        qualification_inputs.append(_sha(preset["qualification_input_sha256"], item_path + ".qualification_input_sha256"))
        if preset_id in preset_ids:
            raise CatalogSelectionError("catalog_preset_duplicate", item_path + ".preset_id")
        preset_ids.add(preset_id)
    if row["qualification_set_sha256"] != canonical_digest(sorted(qualification_inputs)):
        raise CatalogSelectionError("catalog_qualification_set_mismatch", path + ".qualification_set_sha256")
    if not isinstance(row["history"], list) or len(row["history"]) != generation - 1:
        raise CatalogSelectionError("catalog_history_invalid", path + ".history")
    previous: str | None = None
    for index, raw in enumerate(row["history"]):
        item_path = f"{path}.history[{index}]"
        item = _closed(raw, HISTORY_FIELDS, "catalog_history_invalid", item_path)
        if type(item["generation"]) is not int or item["generation"] != index + 1:
            raise CatalogSelectionError("catalog_history_invalid", item_path + ".generation")
        current = _sha(item["catalog_sha256"], item_path + ".catalog_sha256")
        if item["previous_catalog_sha256"] != previous:
            raise CatalogSelectionError("catalog_lineage_mismatch", item_path + ".previous_catalog_sha256")
        previous = current
    if generation == 1:
        if row["previous_catalog_sha256"] is not None:
            raise CatalogSelectionError("catalog_root_invalid", path + ".previous_catalog_sha256")
    elif row["previous_catalog_sha256"] != previous:
        raise CatalogSelectionError("catalog_lineage_mismatch", path + ".previous_catalog_sha256")
    return row


def _validate_payload(variant: str, value: Any, path: str = "$.decision.payload") -> dict[str, Any]:
    variant = _variant(variant, path.rsplit(".", 1)[0] + ".variant")
    if variant == "catalog_candidate":
        return _validate_catalog(value, path)
    if variant == "selection_head_candidate":
        row = _closed(value, HEAD_FIELDS, "selection_head_candidate_shape_invalid", path)
        for field in ("catalog_sha256", "bundle_sha256", "binding_sha256", "selection_sha256"):
            _sha(row[field], path + "." + field)
        _positive_int(row["catalog_generation"], "selection_head_generation_invalid", path + ".catalog_generation")
        _positive_int(row["selection_version"], "selection_head_version_invalid", path + ".selection_version")
        return row
    if variant == "mutation_query_authorization_candidate":
        row = _closed(value, QUERY_FIELDS, "mutation_query_shape_invalid", path)
        _id(row["submission_id"], path + ".submission_id")
        _sha(row["submission_sha256"], path + ".submission_sha256")
        return row
    if variant == "commit_authorization_candidate":
        row = _closed(value, COMMIT_FIELDS, "commit_authorization_shape_invalid", path)
        _id(row["submission_id"], path + ".submission_id")
        for field in ("submission_sha256", "current_selection_sha256", "requested_selection_sha256"):
            _sha(row[field], path + "." + field)
        _positive_int(row["expected_selection_version"], "commit_cas_invalid", path + ".expected_selection_version")
        return row
    raise CatalogSelectionError("decision_variant_invalid", path.rsplit(".", 1)[0] + ".variant")


def validate_structural_decision(
    value: Any, *, expected_ledger_id: str, expected_operation: str, expected_identity_sha256: str,
    expected_operation_body_sha256: str, expected_dependency_receipts_sha256: str,
    expected_source_sha256: str, expected_candidate_sha256: str, expected_manifest_sha256: str,
    expected_generation: int, now: datetime,
) -> dict[str, Any]:
    row = _closed(value, DECISION_FIELDS, "decision_shape_invalid", "$.decision")
    _reject_forbidden(row, "$.decision")
    _version(row["schema_version"], "decision_version_invalid", "$.decision.schema_version")
    if row["artifact_type"] != DECISION_TYPE:
        raise CatalogSelectionError("decision_version_invalid", "$.decision.artifact_type")
    _id(row["decision_id"], "$.decision.decision_id")
    expected_operation = _operation(expected_operation, "$.expected_operation")
    decision_operation = _operation(row["operation"], "$.decision.operation")
    if decision_operation != expected_operation:
        raise CatalogSelectionError("decision_operation_mismatch", "$.decision.operation")
    _variant(row["variant"], "$.decision.variant", operation=expected_operation)
    _source_id(row["decision_source_id"], "$.decision.decision_source_id", operation=expected_operation)
    if row["ledger_id"] != expected_ledger_id:
        raise CatalogSelectionError("decision_ledger_mismatch", "$.decision.ledger_id")
    expected = {
        "identity_sha256": expected_identity_sha256,
        "operation_body_sha256": expected_operation_body_sha256,
        "dependency_receipts_sha256": expected_dependency_receipts_sha256,
        "source_sha256": expected_source_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "manifest_sha256": expected_manifest_sha256,
    }
    for field, wanted in expected.items():
        _sha(wanted, "$.expected." + field)
        if row[field] != wanted:
            raise CatalogSelectionError("decision_binding_mismatch", "$.decision." + field)
    _positive_int(expected_generation, "decision_generation_invalid", "$.expected_generation")
    if type(row["generation"]) is not int or row["generation"] != expected_generation:
        raise CatalogSelectionError("decision_generation_invalid", "$.decision.generation")
    payload = _validate_payload(row["variant"], row["payload"])
    if row["variant"] == "catalog_candidate" and payload["generation"] != row["generation"]:
        raise CatalogSelectionError("catalog_generation_invalid", "$.decision.payload.generation")
    if row["variant"] == "selection_head_candidate" and payload["catalog_generation"] != row["generation"]:
        raise CatalogSelectionError("selection_head_generation_invalid", "$.decision.payload.catalog_generation")
    current = _utc(now, "$.now")
    observed = _time(row["observed_at"], "$.decision.observed_at")
    expires = _time(row["expires_at"], "$.decision.expires_at")
    if observed > current or expires <= current or expires <= observed or expires - observed > timedelta(minutes=5):
        raise CatalogSelectionError("decision_freshness_invalid", "$.decision.expires_at")
    if row["decision_sha256"] != canonical_digest({key: item for key, item in row.items() if key != "decision_sha256"}):
        raise CatalogSelectionError("decision_digest_mismatch", "$.decision.decision_sha256")
    return row


def _genesis(ledger_id: str) -> str:
    return canonical_digest({"schema_version": 1, "artifact_type": "supported_host_catalog_selection_genesis_v1", "ledger_id": ledger_id})


def _state_digest(state: Mapping[str, Any]) -> str:
    return canonical_digest({key: item for key, item in state.items() if key != "state_sha256"})


def new_ledger(ledger_id: str) -> dict[str, Any]:
    _id(ledger_id, "$.ledger_id")
    state = {"schema_version": 1, "artifact_type": LEDGER_TYPE, "ledger_id": ledger_id, "events": [], "head_sha256": _genesis(ledger_id), "state_sha256": ""}
    state["state_sha256"] = _state_digest(state)
    return state


def validate_ledger(value: Any) -> dict[str, Any]:
    state = _closed(value, LEDGER_FIELDS, "ledger_shape_invalid", "$.ledger")
    _reject_forbidden(state, "$.ledger")
    _version(state["schema_version"], "ledger_version_invalid", "$.ledger.schema_version")
    if state["artifact_type"] != LEDGER_TYPE:
        raise CatalogSelectionError("ledger_version_invalid", "$.ledger.artifact_type")
    ledger_id = _id(state["ledger_id"], "$.ledger.ledger_id")
    if not isinstance(state["events"], list):
        raise CatalogSelectionError("ledger_events_invalid", "$.ledger.events")
    previous = _genesis(ledger_id)
    identities: dict[str, str] = {}
    digests: set[str] = set()
    revoked: set[str] = set()
    last_time: datetime | None = None
    for index, raw in enumerate(state["events"]):
        path = f"$.ledger.events[{index}]"
        event = _closed(raw, EVENT_FIELDS, "ledger_event_shape_invalid", path)
        _version(event["schema_version"], "ledger_event_version_invalid", path + ".schema_version")
        if event["artifact_type"] != EVENT_TYPE or event["ledger_id"] != ledger_id:
            raise CatalogSelectionError("ledger_event_binding_mismatch", path)
        if type(event["sequence"]) is not int or event["sequence"] != index + 1:
            raise CatalogSelectionError("ledger_sequence_invalid", path + ".sequence")
        if event["previous_event_sha256"] != previous or event["expected_head_sha256"] != previous:
            raise CatalogSelectionError("ledger_chain_broken", path + ".previous_event_sha256")
        occurred = _time(event["occurred_at"], path + ".occurred_at")
        if last_time is not None and occurred < last_time:
            raise CatalogSelectionError("ledger_time_regression", path + ".occurred_at")
        last_time = occurred
        operation = _operation(event["operation"], path + ".operation")
        decision_id = _id(event["decision_id"], path + ".decision_id")
        decision_sha = _sha(event["decision_sha256"], path + ".decision_sha256")
        event_type = _event_type(event["event_type"], path + ".event_type")
        if event_type == "issue":
            decision = _closed(event["decision"], DECISION_FIELDS, "decision_shape_invalid", path + ".decision")
            _version(decision["schema_version"], "decision_version_invalid", path + ".decision.schema_version")
            if decision["artifact_type"] != DECISION_TYPE or decision["decision_id"] != decision_id or decision["decision_sha256"] != decision_sha or decision["operation"] != operation or decision["ledger_id"] != ledger_id:
                raise CatalogSelectionError("ledger_decision_binding_mismatch", path + ".decision")
            _variant(decision["variant"], path + ".decision.variant", operation=operation)
            _source_id(decision["decision_source_id"], path + ".decision.decision_source_id", operation=operation)
            _positive_int(decision["generation"], "decision_generation_invalid", path + ".decision.generation")
            for field in ("identity_sha256", "operation_body_sha256", "dependency_receipts_sha256", "source_sha256", "candidate_sha256", "manifest_sha256"):
                _sha(decision[field], path + ".decision." + field)
            _validate_payload(decision["variant"], decision["payload"], path + ".decision.payload")
            if decision["variant"] == "catalog_candidate" and decision["payload"]["generation"] != decision["generation"]:
                raise CatalogSelectionError("catalog_generation_invalid", path + ".decision.payload.generation")
            if decision["variant"] == "selection_head_candidate" and decision["payload"]["catalog_generation"] != decision["generation"]:
                raise CatalogSelectionError("selection_head_generation_invalid", path + ".decision.payload.catalog_generation")
            if decision_sha != canonical_digest({key: item for key, item in decision.items() if key != "decision_sha256"}):
                raise CatalogSelectionError("decision_digest_mismatch", path + ".decision.decision_sha256")
            observed = _time(decision["observed_at"], path + ".decision.observed_at")
            expires = _time(decision["expires_at"], path + ".decision.expires_at")
            if expires <= observed or expires - observed > timedelta(minutes=5) or event["occurred_at"] != decision["observed_at"] or event["reason"] is not None:
                raise CatalogSelectionError("ledger_decision_binding_mismatch", path)
            if decision_id in identities:
                raise CatalogSelectionError("ledger_issue_duplicate" if identities[decision_id] == decision_sha else "ledger_decision_collision", path + ".decision_id")
            if decision_sha in digests:
                raise CatalogSelectionError("ledger_issue_replay", path + ".decision_sha256")
            identities[decision_id] = decision_sha
            digests.add(decision_sha)
        elif event_type == "revoke":
            if event["decision"] is not None:
                raise CatalogSelectionError("ledger_revoke_invalid", path)
            _revoke_reason(event["reason"], path + ".reason")
            if identities.get(decision_id) != decision_sha:
                raise CatalogSelectionError("ledger_revoke_target_missing", path + ".decision_sha256")
            if decision_sha in revoked:
                raise CatalogSelectionError("ledger_revoke_duplicate", path + ".decision_sha256")
            revoked.add(decision_sha)
        expected_event = canonical_digest({key: item for key, item in event.items() if key != "event_sha256"})
        if event["event_sha256"] != expected_event:
            raise CatalogSelectionError("ledger_event_digest_mismatch", path + ".event_sha256")
        previous = expected_event
    if state["head_sha256"] != previous:
        raise CatalogSelectionError("ledger_head_mismatch", "$.ledger.head_sha256")
    if state["state_sha256"] != _state_digest(state):
        raise CatalogSelectionError("ledger_state_digest_mismatch", "$.ledger.state_sha256")
    return state


def _append(state: Mapping[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    candidate = deepcopy(dict(state))
    event["event_sha256"] = canonical_digest({key: item for key, item in event.items() if key != "event_sha256"})
    candidate["events"].append(event)
    candidate["head_sha256"] = event["event_sha256"]
    candidate["state_sha256"] = _state_digest(candidate)
    return validate_ledger(candidate)


def issue_decision(
    state: Any,
    decision: Any,
    *,
    expected_head_sha256: str,
    expected_ledger_id: str,
    expected_operation: str,
    expected_identity_sha256: str,
    expected_operation_body_sha256: str,
    expected_dependency_receipts_sha256: str,
    expected_source_sha256: str,
    expected_candidate_sha256: str,
    expected_manifest_sha256: str,
    expected_generation: int,
    now: datetime,
) -> dict[str, Any]:
    ledger = validate_ledger(state)
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise CatalogSelectionError("ledger_stale_head", "$.expected_head_sha256")
    if ledger["ledger_id"] != expected_ledger_id:
        raise CatalogSelectionError("decision_ledger_mismatch", "$.expected_ledger_id")
    row = validate_structural_decision(
        decision,
        expected_ledger_id=expected_ledger_id,
        expected_operation=expected_operation,
        expected_identity_sha256=expected_identity_sha256,
        expected_operation_body_sha256=expected_operation_body_sha256,
        expected_dependency_receipts_sha256=expected_dependency_receipts_sha256,
        expected_source_sha256=expected_source_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_generation=expected_generation,
        now=now,
    )
    event = {
        "schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": ledger["ledger_id"],
        "sequence": len(ledger["events"]) + 1, "previous_event_sha256": ledger["head_sha256"],
        "expected_head_sha256": expected_head_sha256, "event_type": "issue", "occurred_at": row["observed_at"],
        "operation": row["operation"], "decision_id": row["decision_id"], "decision_sha256": row["decision_sha256"],
        "decision": row, "reason": None, "event_sha256": "",
    }
    return _append(ledger, event)


def revoke_decision(state: Any, *, decision_sha256: str, reason: str, expected_head_sha256: str, occurred_at: datetime) -> dict[str, Any]:
    ledger = validate_ledger(state)
    _sha(decision_sha256, "$.decision_sha256")
    _sha(expected_head_sha256, "$.expected_head_sha256")
    if ledger["head_sha256"] != expected_head_sha256:
        raise CatalogSelectionError("ledger_stale_head", "$.expected_head_sha256")
    reason = _revoke_reason(reason, "$.reason")
    issue = next((item for item in ledger["events"] if item["event_type"] == "issue" and item["decision_sha256"] == decision_sha256), None)
    if issue is None:
        raise CatalogSelectionError("ledger_revoke_target_missing", "$.decision_sha256")
    event = {
        "schema_version": 1, "artifact_type": EVENT_TYPE, "ledger_id": ledger["ledger_id"],
        "sequence": len(ledger["events"]) + 1, "previous_event_sha256": ledger["head_sha256"],
        "expected_head_sha256": expected_head_sha256, "event_type": "revoke", "occurred_at": _format(_utc(occurred_at, "$.occurred_at")),
        "operation": issue["operation"], "decision_id": issue["decision_id"], "decision_sha256": decision_sha256,
        "decision": None, "reason": reason, "event_sha256": "",
    }
    return _append(ledger, event)


def recover_ledger(value: Any, *, trusted_sequence: int, trusted_head_sha256: str) -> dict[str, Any]:
    if type(trusted_sequence) is not int or trusted_sequence < 0:
        raise CatalogSelectionError("ledger_anchor_sequence_invalid", "$.trusted_sequence")
    _sha(trusted_head_sha256, "$.trusted_head_sha256")
    ledger = validate_ledger(value)
    if len(ledger["events"]) < trusted_sequence:
        raise CatalogSelectionError("ledger_rollback_detected", "$.ledger.events")
    if len(ledger["events"]) != trusted_sequence or ledger["head_sha256"] != trusted_head_sha256:
        raise CatalogSelectionError("ledger_anchor_head_mismatch", "$.ledger.head_sha256")
    return ledger


class _UnavailableSource:
    __slots__ = ("_operation",)

    def __init__(self, operation: str) -> None:
        self._operation = _operation(operation, "$.operation")

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime) -> UnavailableFact:
        del exact_identity, dependency_receipts, now
        operation = _operation(operation, "$.operation")
        if operation != self._operation:
            raise CatalogSelectionError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(
            operation=operation,
            reason="canonical_source_not_implemented",
            canonical_source_id=SOURCE_IDS[operation],
        )


class CatalogSource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("read_operator_preset_bundle")


class SelectionHeadSource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("read_operator_selection_head")


class SelectionMutationSource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("read_operator_selection_mutation")


class SelectionCommitSource(_UnavailableSource):
    def __init__(self) -> None:
        super().__init__("commit_operator_selection")
