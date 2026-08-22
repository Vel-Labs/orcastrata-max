#!/usr/bin/env python3
"""Pure structural native-supervision candidate and unavailable source."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Mapping

from package_host_supported_host_fact_sources_v1 import UnavailableFact


OPERATION = "read_operator_supervision"
SOURCE_ID = "native-desktop-inventory-authority"
CANDIDATE_TYPE = "supported_host_native_supervision_candidate_v1"
CANDIDATE_FIELDS = frozenset({
    "schema_version", "artifact_type", "candidate_id", "native_host", "children", "parent_edges",
    "observation_cursor", "previous_candidate_sha256", "bindings", "observed_at", "expires_at",
    "candidate_sha256",
})
NATIVE_HOST_FIELDS = frozenset({
    "native_host_id", "host_instance_id", "identity_receipt_sha256",
    "authentication_receipt_sha256", "lifecycle_state",
})
CHILD_FIELDS = frozenset({
    "child_id", "native_identity_sha256", "authentication_receipt_sha256", "lifecycle_state",
})
EDGE_FIELDS = frozenset({"parent_id", "child_id", "edge_sha256"})
CURSOR_FIELDS = frozenset({"cursor_id", "sequence", "event_sha256", "previous_event_sha256"})
BINDING_FIELDS = frozenset({
    "source_sha256", "candidate_sha256", "manifest_sha256", "generation", "service_start_id",
    "identity_sha256", "operation_body_sha256", "dependency_receipts_sha256",
})
LIFECYCLE_STATES = frozenset({"starting", "running", "stopping", "stopped"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_NATIVE_ID_FORBIDDEN = ("fixture", "synthetic", "test", "default", "collaboration", "thread", "task", "agent", "caller")
_FORBIDDEN_KEYS = frozenset({
    "thread_id", "thread", "task_id", "task", "agent_id", "agent", "collaboration_id", "collaboration",
    "synthetic", "test", "fixture", "process_state", "caller_native_id", "caller_selected_id",
    "environment", "env", "path", "endpoint", "private_key", "private_key_path", "credential",
    "credentials", "live", "live_status", "provider", "provider_result",
})


class SupervisionError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise SupervisionError("canonical_value_invalid", "$") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise SupervisionError(code, path)
    return deepcopy(dict(value))


def _id(value: Any, path: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SupervisionError("identifier_invalid", path)
    return value


def _native_id(value: Any, path: str) -> str:
    result = _id(value, path)
    lowered = result.lower()
    if any(token in lowered for token in _NATIVE_ID_FORBIDDEN):
        raise SupervisionError("native_identity_ineligible", path)
    return result


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise SupervisionError("digest_invalid", path)
    return value


def _positive_int(value: Any, code: str, path: str) -> int:
    if type(value) is not int or value < 1:
        raise SupervisionError(code, path)
    return value


def _lifecycle(value: Any, path: str) -> str:
    if not isinstance(value, str) or value not in LIFECYCLE_STATES:
        raise SupervisionError("lifecycle_state_invalid", path)
    return value


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SupervisionError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SupervisionError("timestamp_invalid", path) from exc
    if parsed.utcoffset() != timedelta(0) or parsed.microsecond != 0:
        raise SupervisionError("timestamp_invalid", path)
    return parsed


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise SupervisionError("utc_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _temporal(
    value: Mapping[str, Any],
    *,
    path: str,
    now: datetime,
    historical: bool,
) -> tuple[datetime, datetime]:
    """Parse once and apply the canonical current or historical time rules."""

    observed = _time(value["observed_at"], path + ".observed_at")
    expires = _time(value["expires_at"], path + ".expires_at")
    if expires <= observed or expires - observed > timedelta(minutes=5):
        code = "supervision_previous_time_invalid" if historical else "supervision_time_invalid"
        raise SupervisionError(code, path + ".expires_at")
    if observed > now:
        code = "supervision_previous_future" if historical else "supervision_observed_future"
        raise SupervisionError(code, path + ".observed_at")
    if not historical and expires <= now:
        raise SupervisionError("supervision_expired", path + ".expires_at")
    return observed, expires


def _reject_forbidden(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
                raise SupervisionError("supervision_field_forbidden", path + "." + str(key))
            _reject_forbidden(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_forbidden(item, f"{path}[{index}]")


def _validate_bindings(value: Any, *, expected: Mapping[str, Any], path: str = "$.candidate.bindings") -> dict[str, Any]:
    row = _closed(value, BINDING_FIELDS, "supervision_bindings_invalid", path)
    wanted = _closed(expected, BINDING_FIELDS, "supervision_expected_bindings_invalid", "$.expected_bindings")
    for field in BINDING_FIELDS - {"generation", "service_start_id"}:
        _sha(row[field], path + "." + field)
        _sha(wanted[field], "$.expected_bindings." + field)
    _positive_int(row["generation"], "supervision_generation_invalid", path + ".generation")
    _positive_int(wanted["generation"], "supervision_generation_invalid", "$.expected_bindings.generation")
    _id(row["service_start_id"], path + ".service_start_id")
    _id(wanted["service_start_id"], "$.expected_bindings.service_start_id")
    for field in BINDING_FIELDS:
        if row[field] != wanted[field]:
            raise SupervisionError("supervision_binding_mismatch", path + "." + field)
    return row


def _validate_predecessor_record(
    value: Any,
    *,
    expected_native_host_id: str,
    expected_bindings: Mapping[str, Any],
    now: datetime,
) -> tuple[dict[str, Any], datetime]:
    """Validate one complete historical record without following its predecessor."""

    path = "$.previous"
    _reject_forbidden(value, path)
    row = _closed(value, CANDIDATE_FIELDS, "supervision_previous_invalid", path)
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != CANDIDATE_TYPE:
        raise SupervisionError("supervision_previous_version_invalid", path)
    _id(row["candidate_id"], path + ".candidate_id")
    native = _closed(row["native_host"], NATIVE_HOST_FIELDS, "native_host_invalid", path + ".native_host")
    native_host_id = _native_id(native["native_host_id"], path + ".native_host.native_host_id")
    if native_host_id != _native_id(expected_native_host_id, "$.expected_native_host_id"):
        raise SupervisionError("native_host_mismatch", path + ".native_host.native_host_id")
    _native_id(native["host_instance_id"], path + ".native_host.host_instance_id")
    _sha(native["identity_receipt_sha256"], path + ".native_host.identity_receipt_sha256")
    _sha(native["authentication_receipt_sha256"], path + ".native_host.authentication_receipt_sha256")
    _lifecycle(native["lifecycle_state"], path + ".native_host.lifecycle_state")
    if not isinstance(row["children"], list) or not row["children"]:
        raise SupervisionError("supervision_children_invalid", path + ".children")
    child_ids: set[str] = set()
    for index, raw in enumerate(row["children"]):
        child_path = f"{path}.children[{index}]"
        child = _closed(raw, CHILD_FIELDS, "supervision_child_invalid", child_path)
        child_id = _native_id(child["child_id"], child_path + ".child_id")
        if child_id == native_host_id or child_id in child_ids:
            raise SupervisionError("supervision_child_duplicate", child_path + ".child_id")
        child_ids.add(child_id)
        _sha(child["native_identity_sha256"], child_path + ".native_identity_sha256")
        _sha(child["authentication_receipt_sha256"], child_path + ".authentication_receipt_sha256")
        _lifecycle(child["lifecycle_state"], child_path + ".lifecycle_state")
    if not isinstance(row["parent_edges"], list) or len(row["parent_edges"]) != len(child_ids):
        raise SupervisionError("supervision_topology_invalid", path + ".parent_edges")
    parents: dict[str, str] = {}
    nodes = child_ids | {native_host_id}
    for index, raw in enumerate(row["parent_edges"]):
        edge_path = f"{path}.parent_edges[{index}]"
        edge = _closed(raw, EDGE_FIELDS, "supervision_edge_invalid", edge_path)
        parent_id = _native_id(edge["parent_id"], edge_path + ".parent_id")
        child_id = _native_id(edge["child_id"], edge_path + ".child_id")
        if parent_id not in nodes or child_id not in child_ids or child_id in parents:
            raise SupervisionError("supervision_topology_invalid", edge_path)
        if edge["edge_sha256"] != canonical_digest({"parent_id": parent_id, "child_id": child_id}):
            raise SupervisionError("supervision_edge_digest_mismatch", edge_path + ".edge_sha256")
        parents[child_id] = parent_id
    if set(parents) != child_ids:
        raise SupervisionError("supervision_topology_invalid", path + ".parent_edges")
    for child_id in child_ids:
        seen = {child_id}
        current = child_id
        while current != native_host_id:
            current = parents.get(current, "")
            if current not in nodes or current in seen:
                raise SupervisionError("supervision_topology_cycle", path + ".parent_edges")
            seen.add(current)
    cursor = _closed(row["observation_cursor"], CURSOR_FIELDS, "supervision_cursor_invalid", path + ".observation_cursor")
    _id(cursor["cursor_id"], path + ".observation_cursor.cursor_id")
    sequence = _positive_int(cursor["sequence"], "supervision_cursor_invalid", path + ".observation_cursor.sequence")
    _sha(cursor["event_sha256"], path + ".observation_cursor.event_sha256")
    _validate_bindings(row["bindings"], expected=expected_bindings, path=path + ".bindings")
    if sequence == 1:
        if row["previous_candidate_sha256"] is not None:
            raise SupervisionError("supervision_previous_root_invalid", path + ".previous_candidate_sha256")
        if cursor["previous_event_sha256"] is not None:
            raise SupervisionError("supervision_previous_root_invalid", path + ".observation_cursor.previous_event_sha256")
    else:
        _sha(row["previous_candidate_sha256"], path + ".previous_candidate_sha256")
        _sha(cursor["previous_event_sha256"], path + ".observation_cursor.previous_event_sha256")
    observed, _ = _temporal(row, path=path, now=now, historical=True)
    if row["candidate_sha256"] != canonical_digest({key: item for key, item in row.items() if key != "candidate_sha256"}):
        raise SupervisionError("supervision_previous_digest_mismatch", path + ".candidate_sha256")
    return row, observed


def validate_candidate(
    value: Any,
    *,
    expected_native_host_id: str,
    expected_bindings: Mapping[str, Any],
    now: datetime,
    previous: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate one structural candidate without granting evidence authority."""

    _reject_forbidden(value, "$.candidate")
    row = _closed(value, CANDIDATE_FIELDS, "supervision_candidate_shape_invalid", "$.candidate")
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != CANDIDATE_TYPE:
        raise SupervisionError("supervision_candidate_version_invalid", "$.candidate")
    _id(row["candidate_id"], "$.candidate.candidate_id")
    native = _closed(row["native_host"], NATIVE_HOST_FIELDS, "native_host_invalid", "$.candidate.native_host")
    native_host_id = _native_id(native["native_host_id"], "$.candidate.native_host.native_host_id")
    if native_host_id != _native_id(expected_native_host_id, "$.expected_native_host_id"):
        raise SupervisionError("native_host_mismatch", "$.candidate.native_host.native_host_id")
    _native_id(native["host_instance_id"], "$.candidate.native_host.host_instance_id")
    _sha(native["identity_receipt_sha256"], "$.candidate.native_host.identity_receipt_sha256")
    _sha(native["authentication_receipt_sha256"], "$.candidate.native_host.authentication_receipt_sha256")
    _lifecycle(native["lifecycle_state"], "$.candidate.native_host.lifecycle_state")
    if not isinstance(row["children"], list) or not row["children"]:
        raise SupervisionError("supervision_children_invalid", "$.candidate.children")
    child_ids: set[str] = set()
    for index, raw in enumerate(row["children"]):
        path = f"$.candidate.children[{index}]"
        child = _closed(raw, CHILD_FIELDS, "supervision_child_invalid", path)
        child_id = _native_id(child["child_id"], path + ".child_id")
        if child_id == native_host_id or child_id in child_ids:
            raise SupervisionError("supervision_child_duplicate", path + ".child_id")
        child_ids.add(child_id)
        _sha(child["native_identity_sha256"], path + ".native_identity_sha256")
        _sha(child["authentication_receipt_sha256"], path + ".authentication_receipt_sha256")
        _lifecycle(child["lifecycle_state"], path + ".lifecycle_state")
    if not isinstance(row["parent_edges"], list) or len(row["parent_edges"]) != len(child_ids):
        raise SupervisionError("supervision_topology_invalid", "$.candidate.parent_edges")
    parents: dict[str, str] = {}
    nodes = child_ids | {native_host_id}
    for index, raw in enumerate(row["parent_edges"]):
        path = f"$.candidate.parent_edges[{index}]"
        edge = _closed(raw, EDGE_FIELDS, "supervision_edge_invalid", path)
        parent_id = _native_id(edge["parent_id"], path + ".parent_id")
        child_id = _native_id(edge["child_id"], path + ".child_id")
        if parent_id not in nodes or child_id not in child_ids or child_id in parents:
            raise SupervisionError("supervision_topology_invalid", path)
        if edge["edge_sha256"] != canonical_digest({"parent_id": parent_id, "child_id": child_id}):
            raise SupervisionError("supervision_edge_digest_mismatch", path + ".edge_sha256")
        parents[child_id] = parent_id
    if set(parents) != child_ids:
        raise SupervisionError("supervision_topology_invalid", "$.candidate.parent_edges")
    for child_id in child_ids:
        seen = {child_id}
        current = child_id
        while current != native_host_id:
            current = parents.get(current, "")
            if current not in nodes or current in seen:
                raise SupervisionError("supervision_topology_cycle", "$.candidate.parent_edges")
            seen.add(current)
    cursor = _closed(row["observation_cursor"], CURSOR_FIELDS, "supervision_cursor_invalid", "$.candidate.observation_cursor")
    _id(cursor["cursor_id"], "$.candidate.observation_cursor.cursor_id")
    _positive_int(cursor["sequence"], "supervision_cursor_invalid", "$.candidate.observation_cursor.sequence")
    _sha(cursor["event_sha256"], "$.candidate.observation_cursor.event_sha256")
    if cursor["previous_event_sha256"] is not None:
        _sha(cursor["previous_event_sha256"], "$.candidate.observation_cursor.previous_event_sha256")
    _validate_bindings(row["bindings"], expected=expected_bindings)
    current = _utc(now, "$.now")
    observed, _ = _temporal(row, path="$.candidate", now=current, historical=False)
    if previous is None:
        if row["previous_candidate_sha256"] is not None or cursor["sequence"] != 1 or cursor["previous_event_sha256"] is not None:
            raise SupervisionError("supervision_continuity_invalid", "$.candidate.observation_cursor")
    else:
        prior, prior_observed = _validate_predecessor_record(
            previous,
            expected_native_host_id=expected_native_host_id,
            expected_bindings=expected_bindings,
            now=current,
        )
        if prior_observed > observed:
            raise SupervisionError("supervision_time_regression", "$.candidate.observed_at")
        if row["previous_candidate_sha256"] != prior["candidate_sha256"]:
            raise SupervisionError("supervision_predecessor_mismatch", "$.candidate.previous_candidate_sha256")
        prior_cursor = _closed(prior["observation_cursor"], CURSOR_FIELDS, "supervision_previous_invalid", "$.previous.observation_cursor")
        if cursor["cursor_id"] != prior_cursor["cursor_id"]:
            raise SupervisionError("supervision_cursor_fork", "$.candidate.observation_cursor.cursor_id")
        if type(prior_cursor["sequence"]) is not int or cursor["sequence"] != prior_cursor["sequence"] + 1:
            raise SupervisionError("supervision_cursor_nonmonotonic", "$.candidate.observation_cursor.sequence")
        if cursor["previous_event_sha256"] != prior_cursor["event_sha256"]:
            raise SupervisionError("supervision_cursor_fork", "$.candidate.observation_cursor.previous_event_sha256")
        stable_native_fields = NATIVE_HOST_FIELDS - {"lifecycle_state"}
        if (
            any(prior["native_host"][field] != row["native_host"][field] for field in stable_native_fields)
            or prior["bindings"] != row["bindings"]
        ):
            raise SupervisionError("supervision_continuity_invalid", "$.candidate")
    if row["candidate_sha256"] != canonical_digest({key: item for key, item in row.items() if key != "candidate_sha256"}):
        raise SupervisionError("supervision_digest_mismatch", "$.candidate.candidate_sha256")
    return row


class SupervisionSource:
    __slots__ = ()

    def read_fact(self, operation: str, exact_identity: Any, dependency_receipts: Mapping[str, str], now: datetime) -> UnavailableFact:
        del exact_identity, dependency_receipts, now
        if not isinstance(operation, str) or operation != OPERATION:
            raise SupervisionError("canonical_operation_invalid", "$.operation")
        return UnavailableFact(operation, "canonical_source_not_implemented", SOURCE_ID)
