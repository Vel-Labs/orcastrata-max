#!/usr/bin/env python3
"""Durable, fixed-channel cross-owner artifacts for the supported host.

The public surface is role and edge specific.  It never accepts an edge,
producer role, consumer role, ledger, artifact bytes, source, or promotion
state.  All artifacts produced by this module are source-local quarantine
evidence.  They cannot become T082 authority.
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
from typing import Any, Mapping

import supported_host_catalog_selection_v1 as t067
import supported_host_effect_authority_v1 as t064
import supported_host_registered_action_v1 as t072
import supported_host_responses_seals_v1 as t066
import supported_host_supervision_v1 as t068
import supported_host_family_catalog_selection_v1 as catalog_family
import supported_host_family_effect_action_v1 as effect_action_family
import supported_host_family_native_recovery_v1 as native_recovery_family
import supported_host_family_responses_seals_v1 as responses_family


PROTOCOL_VERSION = "supported_host_cross_owner_artifacts_v1"
PROOF_BOUNDARY = "source_local_quarantine_non_production"
ARTIFACT_TYPE = "supported_host_cross_owner_artifact_v1"
EVENT_TYPE = "supported_host_cross_owner_journal_event_v1"
CURSOR_TYPE = "supported_host_cross_owner_cursor_v1"
ANCHOR_TYPE = "supported_host_cross_owner_anchor_v1"
REQUEST_TYPE = "supported_host_cross_owner_request_v1"
RESPONSE_TYPE = "supported_host_cross_owner_response_v1"
PENDING_TYPE = "supported_host_cross_owner_pending_v1"
FAMILY_ANCHOR_TYPE = "supported_host_cross_owner_family_anchor_v1"

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class CrossOwnerArtifactError(ValueError):
    """Stable, non-echoing artifact rejection."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True, slots=True)
class EdgeSpec:
    edge_id: str
    producer_role: str
    consumer_role: str
    mechanism: str
    operations: frozenset[str]


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    role: str
    service_id: str
    build_sha256: str
    root_identity_sha256: str
    start_id: str
    session_id: str
    session_expires_at: str
    expected_uid: int
    expected_gid: int
    supplemental_groups: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ImportedArtifactProjection:
    edge_id: str
    artifact_sha256: str
    import_head_sha256: str
    accepted_mechanism: str
    operation: str
    event_kind: str
    semantic_subject: dict[str, Any]
    predecessor_bytes: bytes
    successor_bytes: bytes
    transition_bytes: bytes
    producer_anchor: dict[str, Any]
    dependency_import_heads: dict[str, str]
    effective_expires_at: str
    authority_state: str
    proof_boundary: str


EDGE_SPECS: tuple[EdgeSpec, ...] = (
    EdgeSpec("catalog_selection_to_responses_selection_v1", "catalog-selection", "responses-seals", "T067", frozenset({"read_operator_preset_bundle", "read_operator_selection_head", "read_operator_selection_mutation", "commit_operator_selection"})),
    EdgeSpec("native_supervision_to_responses_context_v1", "native-supervision", "responses-seals", "T068", frozenset({"read_operator_supervision"})),
    EdgeSpec("responses_context_to_effect_authority_v1", "responses-seals", "effect-authority", "T066", frozenset({"issue_responses_context"})),
    EdgeSpec("effect_authority_to_registered_action_v1", "effect-authority", "registered-action", "T064", frozenset({"verify_effect_authority", "revoke_effect_authority"})),
    EdgeSpec("registered_action_to_responses_bridge_v1", "registered-action", "responses-seals", "T072", frozenset({"admit_registered_action", "invoke_registered_action", "revoke_registered_action"})),
    EdgeSpec("responses_projection_to_recovery_v1", "responses-seals", "recovery", "T066", frozenset({"seal_or_verify_projection"})),
    EdgeSpec("native_supervision_to_recovery_v1", "native-supervision", "recovery", "T068", frozenset({"read_operator_supervision"})),
    EdgeSpec("effect_authority_to_recovery_v1", "effect-authority", "recovery", "T064", frozenset({"verify_effect_authority", "revoke_effect_authority"})),
)
_EDGES = {row.edge_id: row for row in EDGE_SPECS}


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise CrossOwnerArtifactError("artifact_canonical_value_invalid") from exc


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return _digest_bytes(_canonical(value))


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise CrossOwnerArtifactError("artifact_digest_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise CrossOwnerArtifactError("artifact_identifier_invalid", path)
    return value


def _parse_time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CrossOwnerArtifactError("artifact_time_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CrossOwnerArtifactError("artifact_time_invalid", path) from exc
    if parsed.utcoffset() != timedelta(0) or parsed.microsecond:
        raise CrossOwnerArtifactError("artifact_time_invalid", path)
    return parsed


def _utc(value: datetime, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CrossOwnerArtifactError("artifact_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _identity(value: ServiceIdentity, role: str, path: str) -> dict[str, Any]:
    if not isinstance(value, ServiceIdentity) or value.role != role:
        raise CrossOwnerArtifactError("artifact_role_identity_invalid", path)
    row = {name: getattr(value, name) for name in ServiceIdentity.__dataclass_fields__}
    for field in ("role", "service_id", "start_id", "session_id"):
        _identifier(row[field], path + "." + field)
    _sha(row["build_sha256"], path + ".build_sha256")
    _sha(row["root_identity_sha256"], path + ".root_identity_sha256")
    _parse_time(row["session_expires_at"], path + ".session_expires_at")
    if type(row["expected_uid"]) is not int or row["expected_uid"] < 0:
        raise CrossOwnerArtifactError("artifact_service_uid_invalid", path + ".expected_uid")
    if type(row["expected_gid"]) is not int or row["expected_gid"] < 0:
        raise CrossOwnerArtifactError("artifact_service_gid_invalid", path + ".expected_gid")
    if not isinstance(row["supplemental_groups"], (list, tuple)):
        raise CrossOwnerArtifactError("artifact_service_groups_invalid", path + ".supplemental_groups")
    if (any(type(item) is not int or item < 0 for item in row["supplemental_groups"])
            or list(row["supplemental_groups"]) != sorted(set(row["supplemental_groups"]))
            or row["expected_gid"] in row["supplemental_groups"]):
        raise CrossOwnerArtifactError("artifact_service_groups_invalid", path + ".supplemental_groups")
    row["supplemental_groups"] = list(row["supplemental_groups"])
    return row


def _descriptor_witness(descriptor: int) -> tuple[tuple[int, ...], int, tuple[int, ...]]:
    sock = socket.socket(fileno=os.dup(descriptor))
    try:
        if sock.family != socket.AF_UNIX or sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
            raise CrossOwnerArtifactError("artifact_transport_descriptor_invalid")
        info = os.fstat(sock.fileno())
        local_peercred = getattr(socket, "LOCAL_PEERCRED", None)
        sol_local = getattr(socket, "SOL_LOCAL", None)
        if local_peercred is not None and sol_local is not None:
            raw = sock.getsockopt(sol_local, local_peercred, 256)
            if len(raw) < 12:
                raise CrossOwnerArtifactError("artifact_peer_credentials_malformed")
            version, uid, count = struct.unpack_from("=IIh2x", raw, 0)
            if version == 0 or count < 0 or count > 16 or len(raw) < 12 + 4 * count:
                raise CrossOwnerArtifactError("artifact_peer_credentials_malformed")
            groups = struct.unpack_from(f"={count}I", raw, 12) if count else ()
        elif hasattr(socket, "SO_PEERCRED"):
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _, uid, gid = struct.unpack("3i", raw)
            groups = (gid,)
        else:
            raise CrossOwnerArtifactError("artifact_peer_credentials_unavailable")
        fingerprint = (info.st_dev, info.st_ino, info.st_mode, info.st_rdev, int(sock.type), int(sock.proto))
        return fingerprint, uid, tuple(sorted(set(groups)))
    except OSError as exc:
        raise CrossOwnerArtifactError("artifact_peer_credentials_unavailable") from exc
    finally:
        sock.close()


def _assert_peer(witness: tuple[tuple[int, ...], int, tuple[int, ...]], identity: Mapping[str, Any]) -> None:
    expected_groups = tuple(sorted({identity["expected_gid"], *identity["supplemental_groups"]}))
    if witness[1] != identity["expected_uid"] or witness[2] != expected_groups:
        raise CrossOwnerArtifactError("artifact_peer_identity_mismatch")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any, digest_value: Any, path: str) -> bytes:
    if not isinstance(value, str):
        raise CrossOwnerArtifactError("artifact_bytes_invalid", path)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise CrossOwnerArtifactError("artifact_bytes_invalid", path) from exc
    if _b64(raw) != value or _digest_bytes(raw) != _sha(digest_value, path + "_sha256"):
        raise CrossOwnerArtifactError("artifact_bytes_digest_mismatch", path)
    return raw


def _json_bytes(raw: bytes, path: str) -> Any:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CrossOwnerArtifactError("artifact_embedded_json_invalid", path) from exc
    if _canonical(value) != raw:
        raise CrossOwnerArtifactError("artifact_embedded_json_noncanonical", path)
    return value


def _embedded_json(raw: bytes, path: str) -> Any:
    """Accept either accepted family's exact canonical JSON convention."""
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CrossOwnerArtifactError("artifact_embedded_json_invalid", path) from exc
    compact = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    if raw not in {compact, compact + b"\n"}:
        raise CrossOwnerArtifactError("artifact_embedded_json_noncanonical", path)
    return value


def _event_from_material(spec: EdgeSpec, predecessor: bytes, successor: bytes, transition: bytes) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    before = _embedded_json(predecessor, "$.predecessor_ledger_b64")
    after = _embedded_json(successor, "$.successor_ledger_b64")
    exact = _embedded_json(transition, "$.transition_b64")
    if spec.mechanism == "T068":
        if not isinstance(before, list) or not isinstance(after, list) or len(after) != len(before) + 1 or after[:-1] != before:
            raise CrossOwnerArtifactError("artifact_mechanism_chain_invalid")
        candidate = after[-1]
        if not isinstance(exact, Mapping):
            raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
        try:
            accepted_transition = native_recovery_family.validate_native_split_transition(
                exact, before=before, after=after,
            ) if exact.get("artifact_type") == native_recovery_family.SPLIT_TRANSITION_TYPE else None
        except native_recovery_family.NativeRecoveryFamilyError as exc:
            raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid") from exc
        if accepted_transition is None and after[-1] != exact:
            raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
        operation = "read_operator_supervision"
        event_kind = "issue"
        subject = {"candidate_sha256": candidate.get("candidate_sha256")}
        predecessor_head = None if not before else before[-1].get("candidate_sha256")
        successor_head = candidate.get("candidate_sha256")
        _sha(successor_head, "$.candidate_sha256")
        current: list[dict[str, Any]] = []
        try:
            for item in after:
                current.append(t068.validate_candidate(
                    item,
                    expected_native_host_id=item["native_host"]["native_host_id"],
                    expected_bindings=item["bindings"],
                    now=t068._time(item["observed_at"], "$.candidate.observed_at"),
                    previous=None if not current else current[-1],
                ))
        except (KeyError, TypeError, t068.SupervisionError) as exc:
            raise CrossOwnerArtifactError("artifact_accepted_mechanism_invalid") from exc
        return {"sequence": len(before), "head": predecessor_head}, {"sequence": len(after), "head": successor_head}, {"operation": operation, "event_kind": event_kind, "subject": subject}
    if not isinstance(before, Mapping) or not isinstance(after, Mapping) or not isinstance(before.get("events"), list) or not isinstance(after.get("events"), list):
        raise CrossOwnerArtifactError("artifact_mechanism_ledger_invalid")
    if len(after["events"]) != len(before["events"]) + 1 or after["events"][:-1] != before["events"]:
        raise CrossOwnerArtifactError("artifact_mechanism_chain_invalid")
    try:
        validator = {"T064": t064.validate_ledger, "T066": t066.validate_ledger,
                     "T067": t067.validate_ledger, "T072": t072.validate_ledger}[spec.mechanism]
        validated_before = validator(before)
        validated_after = validator(after)
    except (KeyError, t064.EffectAuthorityError, t066.ResponsesSealsError,
            t067.CatalogSelectionError, t072.RegisteredActionError) as exc:
        raise CrossOwnerArtifactError("artifact_accepted_mechanism_invalid") from exc
    if validated_before != before or validated_after != after:
        raise CrossOwnerArtifactError("artifact_accepted_mechanism_invalid")
    event = after["events"][-1]
    if not isinstance(event, Mapping):
        raise CrossOwnerArtifactError("artifact_mechanism_event_invalid")
    operation = event.get("operation") or (exact.get("operation") if isinstance(exact, Mapping) else None)
    raw_event_kind = event.get("event_type")
    event_kind = {
        "execution_admission": "admission",
        "registration": "admission",
        "observation": "observation",
    }.get(raw_event_kind, raw_event_kind)
    if operation not in spec.operations or event_kind not in {"issue", "revoke", "consume", "observation", "admission"}:
        raise CrossOwnerArtifactError("artifact_mechanism_operation_invalid")
    try:
        if spec.mechanism == "T066":
            accepted_transition = responses_family._validate_transition(exact)
            if accepted_transition["predecessor_ledger_json"].encode() != predecessor or accepted_transition["successor_ledger_json"].encode() != successor:
                raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
        elif spec.mechanism in {"T064", "T072"}:
            if exact.get("artifact_type") == effect_action_family.TRANSITION_TYPE:
                accepted_transition = effect_action_family._validate_transition(exact, "$.transition")
                ledger_field = "effect" if spec.mechanism == "T064" else "action"
                if accepted_transition["kind"] != ledger_field or accepted_transition["predecessor_ledger_json"].encode() != predecessor or accepted_transition["successor_ledger_json"].encode() != successor:
                    raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
            else:
                owner_id = effect_action_family.EFFECT_OWNER_ID if spec.mechanism == "T064" else effect_action_family.ACTION_OWNER_ID
                accepted_transition = effect_action_family.validate_split_transition(exact, owner_id=owner_id, before=before)
                if accepted_transition["successor_ledger_json"].encode() != successor:
                    raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
        elif spec.mechanism == "T067":
            if exact != event:
                raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
        else:
            raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid")
    except (responses_family.ResponsesSealsFamilyError, effect_action_family.EffectActionFamilyError) as exc:
        raise CrossOwnerArtifactError("artifact_mechanism_transition_invalid") from exc
    if spec.mechanism == "T072":
        subject = {"effect_request_sha256": event.get("effect_request_sha256")}
    else:
        subject = {"decision_sha256": event.get("decision_sha256")}
    return {"sequence": len(before["events"]), "head": before.get("head_sha256")}, {"sequence": len(after["events"]), "head": after.get("head_sha256")}, {"operation": operation, "event_kind": event_kind, "subject": subject}


def _family_anchor(spec: EdgeSpec, raw_anchor: Mapping[str, Any], before: bytes, after: bytes, transition: bytes, dependency_heads: Mapping[str, str]) -> dict[str, Any]:
    predecessor, successor, _event = _event_from_material(spec, before, after, transition)
    row = {
        "schema_version": 1, "artifact_type": FAMILY_ANCHOR_TYPE,
        "accepted_mechanism": spec.mechanism, "producer_role": spec.producer_role,
        "successor_sequence": successor["sequence"], "successor_head_sha256": successor["head"],
        "successor_ledger_bytes_sha256": _digest_bytes(after),
        "transition_bytes_sha256": _digest_bytes(transition),
        "dependency_import_heads": deepcopy(dict(dependency_heads)),
        "retained_family_anchor": deepcopy(dict(raw_anchor)), "anchor_sha256": "",
    }
    row["anchor_sha256"] = _digest({key: item for key, item in row.items() if key != "anchor_sha256"})
    _validate_family_anchor(row, spec, before, after, transition, dependency_heads)
    return row


def _validate_family_anchor(value: Any, spec: EdgeSpec, before: bytes, after: bytes, transition: bytes, dependency_heads: Mapping[str, str]) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "accepted_mechanism", "producer_role", "successor_sequence", "successor_head_sha256", "successor_ledger_bytes_sha256", "transition_bytes_sha256", "dependency_import_heads", "retained_family_anchor", "anchor_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CrossOwnerArtifactError("artifact_family_anchor_shape_invalid")
    row = deepcopy(dict(value)); predecessor, successor, _event = _event_from_material(spec, before, after, transition)
    transition_row = _embedded_json(transition, "$.transition")
    if "dependency_import_heads" in transition_row:
        expected_dependency_heads = transition_row["dependency_import_heads"]
    else:
        expected_dependency_heads = {}
    if dict(dependency_heads) != expected_dependency_heads:
        raise CrossOwnerArtifactError("artifact_dependency_heads_mismatch")
    if (row["schema_version"] != 1 or row["artifact_type"] != FAMILY_ANCHOR_TYPE
            or row["accepted_mechanism"] != spec.mechanism or row["producer_role"] != spec.producer_role
            or row["successor_sequence"] != successor["sequence"] or row["successor_head_sha256"] != successor["head"]
            or row["successor_ledger_bytes_sha256"] != _digest_bytes(after)
            or row["transition_bytes_sha256"] != _digest_bytes(transition)
            or row["dependency_import_heads"] != dict(dependency_heads)):
        raise CrossOwnerArtifactError("artifact_family_anchor_mismatch")
    raw = row["retained_family_anchor"]
    try:
        if spec.mechanism == "T067":
            accepted_after = _embedded_json(after, "$.successor")
            catalog_family._validate_anchor(raw, accepted_after, catalog_family._json_bytes(accepted_after))
        elif spec.mechanism == "T066":
            accepted = responses_family._validate_anchor(raw)
            if accepted != responses_family._anchor(_embedded_json(after, "$.successor")):
                raise CrossOwnerArtifactError("artifact_family_anchor_mismatch")
        elif spec.mechanism in {"T064", "T072"}:
            owner_id = effect_action_family.EFFECT_OWNER_ID if spec.mechanism == "T064" else effect_action_family.ACTION_OWNER_ID
            if raw.get("artifact_type") == effect_action_family.SPLIT_ANCHOR_TYPE:
                effect_action_family.validate_split_anchor(raw, owner_id=owner_id, successor=_embedded_json(after, "$.successor"), transition=_embedded_json(transition, "$.transition"))
            else:
                fields = {"schema_version", "artifact_type", "family_sequence", "snapshot_sha256", "effect_sequence", "effect_head_sha256", "effect_ledger_bytes_sha256", "action_sequence", "action_head_sha256", "action_ledger_bytes_sha256", "anchor_sha256"}
                successor_ledger = _embedded_json(after, "$.successor")
                sequence_field = "effect_sequence" if spec.mechanism == "T064" else "action_sequence"
                head_field = "effect_head_sha256" if spec.mechanism == "T064" else "action_head_sha256"
                bytes_field = "effect_ledger_bytes_sha256" if spec.mechanism == "T064" else "action_ledger_bytes_sha256"
                if (not isinstance(raw, Mapping) or set(raw) != fields or raw.get("schema_version") != 1
                        or raw.get("artifact_type") != effect_action_family.ANCHOR_TYPE
                        or raw.get(sequence_field) != len(successor_ledger["events"])
                        or raw.get(head_field) != successor_ledger["head_sha256"]
                        or raw.get(bytes_field) != _digest_bytes(after)
                        or raw.get("anchor_sha256") != effect_action_family.digest({key: item for key, item in raw.items() if key != "anchor_sha256"})):
                    raise CrossOwnerArtifactError("artifact_family_anchor_mismatch")
        elif spec.mechanism == "T068":
            if raw.get("artifact_type") == native_recovery_family.SPLIT_ANCHOR_TYPE:
                native_recovery_family.validate_native_split_anchor(raw, successor=_embedded_json(after, "$.successor"), transition=_embedded_json(transition, "$.transition"))
            else:
                fields = {"schema_version", "artifact_type", "protocol_version", "native_sequence", "native_head_sha256", "native_chain_bytes_sha256", "recovery_sequence", "recovery_head_sha256", "recovery_ledger_bytes_sha256", "consumption_sequence", "consumptions_bytes_sha256", "anchor_sha256"}
                successor_chain = _embedded_json(after, "$.successor")
                if (not isinstance(raw, Mapping) or set(raw) != fields or raw.get("schema_version") != 1
                        or raw.get("artifact_type") != native_recovery_family.ANCHOR_TYPE
                        or raw.get("protocol_version") != native_recovery_family.PROTOCOL_VERSION
                        or raw.get("native_sequence") != len(successor_chain)
                        or raw.get("native_head_sha256") != successor_chain[-1]["candidate_sha256"]
                        or raw.get("native_chain_bytes_sha256") != _digest_bytes(after)
                        or raw.get("anchor_sha256") != native_recovery_family._digest({key: item for key, item in raw.items() if key != "anchor_sha256"})):
                    raise CrossOwnerArtifactError("artifact_family_anchor_mismatch")
    except (catalog_family.CatalogFamilyError, responses_family.ResponsesSealsFamilyError,
            effect_action_family.EffectActionFamilyError, native_recovery_family.NativeRecoveryFamilyError) as exc:
        raise CrossOwnerArtifactError("artifact_family_anchor_mismatch") from exc
    if row["anchor_sha256"] != _digest({key: item for key, item in row.items() if key != "anchor_sha256"}):
        raise CrossOwnerArtifactError("artifact_family_anchor_digest_mismatch")
    return row


def _mechanism_expiry(spec: EdgeSpec, successor: bytes) -> datetime | None:
    value = _embedded_json(successor, "$.successor_ledger_b64")
    if spec.mechanism == "T068":
        raw = value[-1].get("expires_at") if value else None
    else:
        event = value["events"][-1]
        decision = event.get("decision")
        raw = decision.get("expires_at") if isinstance(decision, Mapping) else None
        if raw is None and isinstance(event.get("authority"), Mapping):
            raw = event["authority"].get("expires_at")
        if raw is None and isinstance(event.get("observation"), Mapping):
            raw = event["observation"].get("expires_at")
    return None if raw is None else _parse_time(raw, "$.mechanism.expires_at")


_ARTIFACT_FIELDS = frozenset({
    "schema_version", "artifact_type", "protocol_version", "edge_id", "joint_authority_sha256",
    "producer", "consumer", "export_sequence", "predecessor_export_head_sha256",
    "accepted_mechanism", "operation", "semantic_subject", "predecessor_sequence",
    "predecessor_head_sha256", "predecessor_ledger_b64", "predecessor_ledger_bytes_sha256",
    "successor_sequence", "successor_head_sha256", "successor_ledger_b64",
    "successor_ledger_bytes_sha256", "transition_b64", "transition_bytes_sha256",
    "producer_family_anchor", "producer_dependency_import_heads", "observed_at", "expires_at",
    "event_kind", "target_revoke_artifact_sha256", "proof_boundary", "artifact_sha256",
})


def validate_artifact(value: Any, expected: EdgeSpec | None = None, *, expected_producer_identity: ServiceIdentity | None = None, expected_consumer_identity: ServiceIdentity | None = None) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    if not isinstance(value, Mapping) or set(value) != _ARTIFACT_FIELDS:
        raise CrossOwnerArtifactError("artifact_shape_invalid")
    row = deepcopy(dict(value))
    spec = _EDGES.get(row.get("edge_id"))
    if spec is None or (expected is not None and spec != expected):
        raise CrossOwnerArtifactError("artifact_edge_invalid", "$.edge_id")
    if row["schema_version"] != 1 or row["artifact_type"] != ARTIFACT_TYPE or row["protocol_version"] != PROTOCOL_VERSION or row["proof_boundary"] != PROOF_BOUNDARY:
        raise CrossOwnerArtifactError("artifact_identity_invalid")
    _sha(row["joint_authority_sha256"], "$.joint_authority_sha256")
    _identity(ServiceIdentity(**row["producer"]), spec.producer_role, "$.producer")
    _identity(ServiceIdentity(**row["consumer"]), spec.consumer_role, "$.consumer")
    if expected_producer_identity is not None and row["producer"] != _identity(expected_producer_identity, spec.producer_role, "$.expected_producer"):
        raise CrossOwnerArtifactError("artifact_producer_identity_mismatch")
    if expected_consumer_identity is not None and row["consumer"] != _identity(expected_consumer_identity, spec.consumer_role, "$.expected_consumer"):
        raise CrossOwnerArtifactError("artifact_consumer_identity_mismatch")
    if type(row["export_sequence"]) is not int or row["export_sequence"] < 1:
        raise CrossOwnerArtifactError("artifact_sequence_invalid")
    if row["predecessor_export_head_sha256"] is not None:
        _sha(row["predecessor_export_head_sha256"], "$.predecessor_export_head_sha256")
    if row["accepted_mechanism"] != spec.mechanism or row["operation"] not in spec.operations:
        raise CrossOwnerArtifactError("artifact_mechanism_invalid")
    if not isinstance(row["semantic_subject"], Mapping) or not isinstance(row["producer_family_anchor"], Mapping):
        raise CrossOwnerArtifactError("artifact_authority_material_invalid")
    if not isinstance(row["producer_dependency_import_heads"], Mapping):
        raise CrossOwnerArtifactError("artifact_dependency_heads_invalid")
    for key, item in row["producer_dependency_import_heads"].items():
        _identifier(key, "$.producer_dependency_import_heads")
        _sha(item, "$.producer_dependency_import_heads." + key)
    before = _unb64(row["predecessor_ledger_b64"], row["predecessor_ledger_bytes_sha256"], "$.predecessor_ledger_b64")
    after = _unb64(row["successor_ledger_b64"], row["successor_ledger_bytes_sha256"], "$.successor_ledger_b64")
    transition = _unb64(row["transition_b64"], row["transition_bytes_sha256"], "$.transition_b64")
    predecessor, successor, event = _event_from_material(spec, before, after, transition)
    if row["predecessor_sequence"] != predecessor["sequence"] or row["predecessor_head_sha256"] != predecessor["head"]:
        raise CrossOwnerArtifactError("artifact_predecessor_mismatch")
    if row["successor_sequence"] != successor["sequence"] or row["successor_head_sha256"] != successor["head"]:
        raise CrossOwnerArtifactError("artifact_successor_mismatch")
    if row["operation"] != event["operation"] or row["event_kind"] != event["event_kind"]:
        raise CrossOwnerArtifactError("artifact_event_mismatch")
    _validate_family_anchor(row["producer_family_anchor"], spec, before, after, transition, row["producer_dependency_import_heads"])
    if not set(event["subject"].items()).issubset(set(row["semantic_subject"].items())):
        raise CrossOwnerArtifactError("artifact_subject_mismatch")
    observed = _parse_time(row["observed_at"], "$.observed_at")
    expires = _parse_time(row["expires_at"], "$.expires_at")
    if expires <= observed or expires > observed + timedelta(minutes=5):
        raise CrossOwnerArtifactError("artifact_freshness_invalid")
    mechanism_expiry = _mechanism_expiry(spec, after)
    if mechanism_expiry is not None and expires > mechanism_expiry:
        raise CrossOwnerArtifactError("artifact_mechanism_expiry_exceeded")
    if row["target_revoke_artifact_sha256"] is not None:
        _sha(row["target_revoke_artifact_sha256"], "$.target_revoke_artifact_sha256")
    _sha(row["artifact_sha256"], "$.artifact_sha256")
    if row["artifact_sha256"] != _digest({key: item for key, item in row.items() if key != "artifact_sha256"}):
        raise CrossOwnerArtifactError("artifact_digest_mismatch")
    return row, before, after, transition


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_dir(path.parent)


def _replace(path: Path, data: bytes) -> None:
    pending = path.with_name("." + path.name + ".pending")
    if pending.exists() or pending.is_symlink():
        raise CrossOwnerArtifactError("artifact_pending_residue", str(pending))
    _write_new(pending, data)
    os.replace(pending, path)
    _fsync_dir(path.parent)


def _read(path: Path) -> tuple[bytes, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
            raise CrossOwnerArtifactError("artifact_file_invalid", str(path))
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            data = b""
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(descriptor)
        value = json.loads(data)
    except CrossOwnerArtifactError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CrossOwnerArtifactError("artifact_file_invalid", str(path)) from exc
    if data != _canonical(value):
        raise CrossOwnerArtifactError("artifact_file_noncanonical", str(path))
    return data, value


def _cursor(spec: EdgeSpec, direction: str, sequence: int, head: str | None) -> dict[str, Any]:
    row = {"schema_version": 1, "artifact_type": CURSOR_TYPE, "edge_id": spec.edge_id, "direction": direction, "sequence": sequence, "head_sha256": head, "cursor_sha256": ""}
    row["cursor_sha256"] = _digest({key: item for key, item in row.items() if key != "cursor_sha256"})
    return row


def _anchor(role: str, cursors: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    row = {"schema_version": 1, "artifact_type": ANCHOR_TYPE, "role": role, "cursor_heads": {key: value["cursor_sha256"] for key, value in sorted(cursors.items())}, "anchor_sha256": ""}
    row["anchor_sha256"] = _digest({key: item for key, item in row.items() if key != "anchor_sha256"})
    return row


class _RoleJournal:
    def __init__(self, root: Path, identity: ServiceIdentity, joint_authority_sha256: str) -> None:
        self.root = Path(root)
        self.identity = identity
        self.joint_authority_sha256 = _sha(joint_authority_sha256, "$.joint_authority_sha256")
        self.role = identity.role
        self.lock_path = self.root / "role.lock"
        self.anchor_path = self.root / "cross-owner-anchor.json"
        self.pending_path = self.root / "cross-owner-pending.json"
        self._thread_lock = threading.RLock()
        is_new = not self.root.exists()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if is_new:
            self.lock_path.touch(mode=0o600, exist_ok=False)
        elif not self.lock_path.exists() or not self.anchor_path.exists():
            raise CrossOwnerArtifactError("artifact_role_store_truncated")
        if not is_new:
            return
        descriptor = self._lock()
        try:
            cursors: dict[str, dict[str, Any]] = {}
            for spec in EDGE_SPECS:
                if spec.producer_role == self.role:
                    path = self._edge_dir(spec, "export", initialize=True)
                    cursors["export:" + spec.edge_id] = _read(path / "cursor.json")[1]
                if spec.consumer_role == self.role:
                    path = self._edge_dir(spec, "import", initialize=True)
                    cursors["import:" + spec.edge_id] = _read(path / "cursor.json")[1]
            expected_anchor = _anchor(self.role, cursors)
            _write_new(self.anchor_path, _canonical(expected_anchor))
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _lock(self) -> int:
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    def _edge_dir(self, spec: EdgeSpec, direction: str, *, initialize: bool = False) -> Path:
        path = self.root / ("exports" if direction == "export" else "imports") / spec.edge_id
        if initialize:
            (path / "artifacts").mkdir(mode=0o700, parents=True, exist_ok=False)
            (path / "events").mkdir(mode=0o700, parents=True, exist_ok=False)
        cursor = path / "cursor.json"
        if initialize:
            _write_new(cursor, _canonical(_cursor(spec, direction, 0, None)))
        elif not path.is_dir() or not (path / "artifacts").is_dir() or not (path / "events").is_dir() or not cursor.exists():
            raise CrossOwnerArtifactError("artifact_journal_truncation")
        return path

    def _recover_edge(self, spec: EdgeSpec, direction: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        path = self._edge_dir(spec, direction)
        _, raw_cursor = _read(path / "cursor.json")
        expected_cursor = _cursor(spec, direction, raw_cursor.get("sequence"), raw_cursor.get("head_sha256"))
        if raw_cursor != expected_cursor:
            raise CrossOwnerArtifactError("artifact_cursor_invalid")
        artifacts = sorted((path / "artifacts").iterdir())
        events = sorted((path / "events").iterdir())
        if len(artifacts) != len(events) or len(events) != raw_cursor["sequence"]:
            raise CrossOwnerArtifactError("artifact_journal_truncation")
        previous = None
        rows: list[dict[str, Any]] = []
        for sequence, (artifact_path, event_path) in enumerate(zip(artifacts, events), 1):
            expected_name = f"{sequence:020d}.json"
            if artifact_path.name != expected_name or event_path.name != expected_name:
                raise CrossOwnerArtifactError("artifact_journal_gap")
            artifact_bytes, raw_artifact = _read(artifact_path)
            artifact, _, _, _ = validate_artifact(raw_artifact, spec)
            _, event = _read(event_path)
            fields = {"schema_version", "artifact_type", "edge_id", "direction", "sequence", "previous_event_sha256", "artifact_sha256", "artifact_bytes_sha256", "event_sha256"}
            if not isinstance(event, Mapping) or set(event) != fields or event.get("schema_version") != 1 or event.get("artifact_type") != EVENT_TYPE or event.get("edge_id") != spec.edge_id or event.get("direction") != direction or event.get("sequence") != sequence or event.get("previous_event_sha256") != previous or event.get("artifact_sha256") != artifact["artifact_sha256"] or event.get("artifact_bytes_sha256") != _digest_bytes(artifact_bytes):
                raise CrossOwnerArtifactError("artifact_journal_event_invalid")
            expected_event = _digest({key: item for key, item in event.items() if key != "event_sha256"})
            if event.get("event_sha256") != expected_event:
                raise CrossOwnerArtifactError("artifact_journal_fork")
            previous = artifact["artifact_sha256"]
            rows.append(artifact)
        if raw_cursor["head_sha256"] != previous:
            raise CrossOwnerArtifactError("artifact_cursor_rollback")
        return raw_cursor, rows

    def _recover_pending_locked(self) -> bool:
        if not self.pending_path.exists() and not self.pending_path.is_symlink():
            return False
        _, pending = _read(self.pending_path)
        fields = {"schema_version", "artifact_type", "edge_id", "direction", "sequence",
                  "predecessor_cursor", "artifact", "event", "successor_cursor", "pending_sha256"}
        if not isinstance(pending, Mapping) or set(pending) != fields or pending.get("schema_version") != 1 or pending.get("artifact_type") != PENDING_TYPE:
            raise CrossOwnerArtifactError("artifact_pending_invalid")
        if pending.get("pending_sha256") != _digest({key: item for key, item in pending.items() if key != "pending_sha256"}):
            raise CrossOwnerArtifactError("artifact_pending_invalid")
        spec = _EDGES.get(pending.get("edge_id"))
        direction = pending.get("direction")
        if spec is None or direction not in {"export", "import"}:
            raise CrossOwnerArtifactError("artifact_pending_invalid")
        artifact, _, _, _ = validate_artifact(pending["artifact"], spec)
        predecessor = pending["predecessor_cursor"]
        successor = pending["successor_cursor"]
        path = self._edge_dir(spec, direction)
        _, current = _read(path / "cursor.json")
        artifact_path = path / "artifacts" / f"{pending['sequence']:020d}.json"
        event_path = path / "events" / f"{pending['sequence']:020d}.json"
        if not artifact_path.exists() and not event_path.exists() and current == predecessor:
            self.pending_path.unlink()
            _fsync_dir(self.root)
            return True
        if not artifact_path.exists() and event_path.exists():
            raise CrossOwnerArtifactError("artifact_pending_partial_invalid")
        if not artifact_path.exists():
            _write_new(artifact_path, _canonical(artifact))
        elif _read(artifact_path)[1] != artifact:
            raise CrossOwnerArtifactError("artifact_pending_collision")
        if not event_path.exists():
            _write_new(event_path, _canonical(pending["event"]))
        elif _read(event_path)[1] != pending["event"]:
            raise CrossOwnerArtifactError("artifact_pending_collision")
        if current == predecessor:
            _replace(path / "cursor.json", _canonical(successor))
        elif current != successor:
            raise CrossOwnerArtifactError("artifact_pending_cursor_collision")
        self.pending_path.unlink()
        _fsync_dir(self.root)
        return True

    def recover(self) -> dict[str, Any]:
        descriptor = self._lock()
        try:
            recovered_pending = self._recover_pending_locked()
            cursors: dict[str, dict[str, Any]] = {}
            for direction in ("export", "import"):
                base = self.root / (direction + "s")
                if base.exists():
                    for child in sorted(base.iterdir()):
                        spec = _EDGES.get(child.name)
                        if spec is None or self.role not in {spec.producer_role, spec.consumer_role}:
                            raise CrossOwnerArtifactError("artifact_unknown_edge_residue")
                        cursor, _ = self._recover_edge(spec, direction)
                        cursors[direction + ":" + spec.edge_id] = cursor
            _, actual_anchor = _read(self.anchor_path)
            expected_anchor = _anchor(self.role, cursors)
            if recovered_pending:
                _replace(self.anchor_path, _canonical(expected_anchor))
            elif actual_anchor != expected_anchor:
                raise CrossOwnerArtifactError("artifact_role_anchor_mismatch")
            return deepcopy(expected_anchor)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _commit(self, spec: EdgeSpec, direction: str, artifact: Mapping[str, Any], expected_head: str | None) -> dict[str, Any]:
        descriptor = self._lock()
        try:
            if self.pending_path.exists() or self.pending_path.is_symlink():
                raise CrossOwnerArtifactError("artifact_pending_residue")
            cursor, rows = self._recover_edge(spec, direction)
            for retained in rows:
                if retained["artifact_sha256"] == artifact["artifact_sha256"]:
                    return cursor
                if retained["export_sequence"] == artifact["export_sequence"]:
                    raise CrossOwnerArtifactError("artifact_sequence_collision")
            if cursor["head_sha256"] != expected_head:
                raise CrossOwnerArtifactError("artifact_expected_head_mismatch")
            sequence = cursor["sequence"] + 1
            if artifact["export_sequence"] != sequence:
                raise CrossOwnerArtifactError("artifact_export_gap")
            path = self._edge_dir(spec, direction)
            artifact_bytes = _canonical(artifact)
            event = {"schema_version": 1, "artifact_type": EVENT_TYPE, "edge_id": spec.edge_id, "direction": direction, "sequence": sequence, "previous_event_sha256": cursor["head_sha256"], "artifact_sha256": artifact["artifact_sha256"], "artifact_bytes_sha256": _digest_bytes(artifact_bytes), "event_sha256": ""}
            event["event_sha256"] = _digest({key: item for key, item in event.items() if key != "event_sha256"})
            successor = _cursor(spec, direction, sequence, artifact["artifact_sha256"])
            pending = {"schema_version": 1, "artifact_type": PENDING_TYPE, "edge_id": spec.edge_id,
                       "direction": direction, "sequence": sequence, "predecessor_cursor": cursor,
                       "artifact": deepcopy(dict(artifact)), "event": event,
                       "successor_cursor": successor, "pending_sha256": ""}
            pending["pending_sha256"] = _digest({key: item for key, item in pending.items() if key != "pending_sha256"})
            _write_new(self.pending_path, _canonical(pending))
            _write_new(path / "artifacts" / f"{sequence:020d}.json", artifact_bytes)
            _write_new(path / "events" / f"{sequence:020d}.json", _canonical(event))
            _replace(path / "cursor.json", _canonical(successor))
            self.pending_path.unlink()
            _fsync_dir(self.root)
            cursors: dict[str, dict[str, Any]] = {}
            for direction_name in ("export", "import"):
                base = self.root / (direction_name + "s")
                if base.exists():
                    for child in base.iterdir():
                        edge = _EDGES[child.name]
                        item, _ = self._recover_edge(edge, direction_name)
                        cursors[direction_name + ":" + edge.edge_id] = item
            _replace(self.anchor_path, _canonical(_anchor(self.role, cursors)))
            self._recover_edge(spec, direction)
            return successor
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _latest(self, spec: EdgeSpec, direction: str) -> dict[str, Any] | None:
        _, rows = self._recover_edge(spec, direction)
        return None if not rows else rows[-1]


def _family_material(spec: EdgeSpec, family_store: Any) -> tuple[bytes, bytes, bytes, dict[str, Any], dict[str, Any], dict[str, str]]:
    """Select the latest fixed operation from an owner-recovered family store."""
    if spec.mechanism == "T068":
        if hasattr(family_store, "current_export_material"):
            material = family_store.current_export_material()
            return (material["predecessor_bytes"], material["successor_bytes"], material["transition_bytes"],
                    deepcopy(dict(material["anchor"])), deepcopy(dict(material["semantic_subject"])),
                    deepcopy(dict(material["dependency_import_heads"])))
        recovered = family_store.recover()
        state = recovered.get("state", {}) if isinstance(recovered, Mapping) else {}
        chain = recovered[0] if isinstance(recovered, tuple) else state.get("chain", recovered.get("chain"))
        if not isinstance(chain, list) or not chain:
            raise CrossOwnerArtifactError("artifact_family_transition_unavailable")
        before, after, transition = chain[:-1], chain, chain[-1]
        anchor = family_store.current_anchor()
        subject = {"candidate_sha256": chain[-1].get("candidate_sha256")}
        return _canonical(before), _canonical(after), _canonical(transition), anchor, subject, {}
    recovered = family_store.recover()
    if spec.mechanism == "T067":
        ledger = recovered
        events = ledger.get("events", [])
        if not events:
            raise CrossOwnerArtifactError("artifact_family_transition_unavailable")
        before = {**ledger, "events": events[:-1]}
        # Recompute the valid predecessor by using the store's immutable prior snapshot.
        snapshot = family_store.snapshots / f"{len(events) - 1:020d}.json"
        before_bytes = snapshot.read_bytes()
        before = _embedded_json(before_bytes, "$.family_snapshot")
        after_bytes = _canonical(ledger)
        event = events[-1]
        if event.get("operation") not in spec.operations:
            raise CrossOwnerArtifactError("artifact_family_operation_unavailable")
        return before_bytes, after_bytes, _canonical(event), family_store.current_anchor(), {"decision_sha256": event.get("decision_sha256")}, {}
    transitions = family_store.transitions() if hasattr(family_store, "transitions") else recovered.get("transitions", [])
    selected = next((row for row in reversed(transitions) if row.get("operation") in spec.operations), None)
    if selected is None:
        raise CrossOwnerArtifactError("artifact_family_transition_unavailable")
    before = selected.get("predecessor_ledger_json")
    after = selected.get("successor_ledger_json")
    if not isinstance(before, str) or not isinstance(after, str):
        raise CrossOwnerArtifactError("artifact_family_transition_invalid")
    anchor = recovered.get("anchor")
    if not isinstance(anchor, Mapping):
        raise CrossOwnerArtifactError("artifact_family_anchor_invalid")
    if spec.mechanism == "T066":
        anchor = responses_family._anchor(_embedded_json(after.encode(), "$.family_successor"))
    subject = {"decision_sha256": selected.get("decision_sha256") or json.loads(after)["events"][-1].get("decision_sha256")}
    if spec.mechanism == "T066" and selected.get("operation") == "issue_responses_context":
        owner_artifact = selected.get("owner_artifact")
        if not isinstance(owner_artifact, Mapping):
            raise CrossOwnerArtifactError("artifact_family_transition_invalid")
        subject["identity_sha256"] = owner_artifact.get("identity_sha256")
    imports = selected.get("dependency_import_heads", {})
    return before.encode(), after.encode(), _canonical(selected), deepcopy(dict(anchor)), subject, deepcopy(dict(imports))


def _make_artifact(journal: _RoleJournal, spec: EdgeSpec, family_store: Any, consumer: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
    with journal._thread_lock:
        return _make_artifact_locked(journal, spec, family_store, consumer, observed_at, expires_at)


def _make_artifact_locked(journal: _RoleJournal, spec: EdgeSpec, family_store: Any, consumer: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
    producer = _identity(journal.identity, spec.producer_role, "$.producer")
    consumer_row = _identity(consumer, spec.consumer_role, "$.consumer")
    joint = journal.joint_authority_sha256
    observed = _utc(observed_at, "$.observed_at")
    expires = _utc(expires_at, "$.expires_at")
    if expires <= observed or expires > observed + timedelta(minutes=5) or expires > _parse_time(producer["session_expires_at"], "$.producer.session_expires_at") or expires > _parse_time(consumer_row["session_expires_at"], "$.consumer.session_expires_at"):
        raise CrossOwnerArtifactError("artifact_freshness_invalid")
    cursor, _ = journal._recover_edge(spec, "export")
    before, after, transition, anchor, subject, import_heads = _family_material(spec, family_store)
    predecessor, successor, event = _event_from_material(spec, before, after, transition)
    if event["operation"] not in spec.operations:
        raise CrossOwnerArtifactError("artifact_operation_invalid")
    semantic_subject = {**subject, **event["subject"]}
    latest = journal._latest(spec, "export")
    if (latest is not None
            and latest["successor_ledger_bytes_sha256"] == _digest_bytes(after)
            and latest["transition_bytes_sha256"] == _digest_bytes(transition)
            and latest["producer"] == producer
            and latest["consumer"] == consumer_row
            and latest["joint_authority_sha256"] == joint):
        return latest
    revoke_target = None
    if event["event_kind"] in {"revoke", "consume"}:
        _, retained = journal._recover_edge(spec, "export")
        for candidate in reversed(retained):
            if candidate["event_kind"] == "issue" and candidate["semantic_subject"] == semantic_subject:
                revoke_target = candidate["artifact_sha256"]
                break
        if revoke_target is None:
            raise CrossOwnerArtifactError("artifact_revoke_target_missing")
    row = {
        "schema_version": 1, "artifact_type": ARTIFACT_TYPE, "protocol_version": PROTOCOL_VERSION,
        "edge_id": spec.edge_id, "joint_authority_sha256": joint, "producer": producer, "consumer": consumer_row,
        "export_sequence": cursor["sequence"] + 1, "predecessor_export_head_sha256": cursor["head_sha256"],
        "accepted_mechanism": spec.mechanism, "operation": event["operation"], "semantic_subject": semantic_subject,
        "predecessor_sequence": predecessor["sequence"], "predecessor_head_sha256": predecessor["head"],
        "predecessor_ledger_b64": _b64(before), "predecessor_ledger_bytes_sha256": _digest_bytes(before),
        "successor_sequence": successor["sequence"], "successor_head_sha256": successor["head"],
        "successor_ledger_b64": _b64(after), "successor_ledger_bytes_sha256": _digest_bytes(after),
        "transition_b64": _b64(transition), "transition_bytes_sha256": _digest_bytes(transition),
        "producer_family_anchor": _family_anchor(spec, anchor, before, after, transition, import_heads),
        "producer_dependency_import_heads": import_heads,
        "observed_at": _format(observed), "expires_at": _format(expires), "event_kind": event["event_kind"],
        "target_revoke_artifact_sha256": revoke_target, "proof_boundary": PROOF_BOUNDARY, "artifact_sha256": "",
    }
    row["artifact_sha256"] = _digest({key: item for key, item in row.items() if key != "artifact_sha256"})
    validate_artifact(row, spec)
    journal._commit(spec, "export", row, cursor["head_sha256"])
    return row


def _request(spec: EdgeSpec, cursor: Mapping[str, Any], challenge: str) -> dict[str, Any]:
    _identifier(challenge, "$.challenge")
    row = {"schema_version": 1, "artifact_type": REQUEST_TYPE, "protocol_version": PROTOCOL_VERSION, "edge_id": spec.edge_id, "cursor_sequence": cursor["sequence"], "cursor_head_sha256": cursor["head_sha256"], "challenge": challenge, "request_sha256": ""}
    row["request_sha256"] = _digest({key: item for key, item in row.items() if key != "request_sha256"})
    return row


def _send(descriptor: int, value: Any) -> None:
    payload = _canonical(value)
    if len(payload) > 16_777_216:
        raise CrossOwnerArtifactError("artifact_transport_oversize")
    sock = socket.socket(fileno=os.dup(descriptor))
    try:
        if sock.family != socket.AF_UNIX or sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
            raise CrossOwnerArtifactError("artifact_transport_descriptor_invalid")
        sock.sendall(len(payload).to_bytes(4, "big") + payload)
    finally:
        sock.close()


def _recv(descriptor: int) -> Any:
    sock = socket.socket(fileno=os.dup(descriptor))
    try:
        if sock.family != socket.AF_UNIX or sock.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
            raise CrossOwnerArtifactError("artifact_transport_descriptor_invalid")
        header = b""
        while len(header) < 4:
            part = sock.recv(4 - len(header))
            if not part:
                raise CrossOwnerArtifactError("artifact_transport_closed")
            header += part
        length = int.from_bytes(header, "big")
        if length < 2 or length > 16_777_216:
            raise CrossOwnerArtifactError("artifact_transport_size_invalid")
        payload = b""
        while len(payload) < length:
            part = sock.recv(length - len(payload))
            if not part:
                raise CrossOwnerArtifactError("artifact_transport_closed")
            payload += part
    finally:
        sock.close()
    return _json_bytes(payload, "$.transport")


def _serve(journal: _RoleJournal, spec: EdgeSpec, descriptor: int) -> None:
    before_witness = _descriptor_witness(descriptor)
    request = _recv(descriptor)
    fields = {"schema_version", "artifact_type", "protocol_version", "edge_id", "cursor_sequence", "cursor_head_sha256", "challenge", "request_sha256"}
    if not isinstance(request, Mapping) or set(request) != fields or request.get("schema_version") != 1 or request.get("artifact_type") != REQUEST_TYPE or request.get("protocol_version") != PROTOCOL_VERSION or request.get("edge_id") != spec.edge_id:
        raise CrossOwnerArtifactError("artifact_request_invalid")
    expected = _digest({key: item for key, item in request.items() if key != "request_sha256"})
    if request.get("request_sha256") != expected:
        raise CrossOwnerArtifactError("artifact_request_digest_mismatch")
    cursor, rows = journal._recover_edge(spec, "export")
    sequence = request.get("cursor_sequence")
    if type(sequence) is not int or sequence < 0 or sequence >= len(rows) + 1:
        raise CrossOwnerArtifactError("artifact_request_cursor_invalid")
    if sequence == len(rows) and request.get("cursor_head_sha256") != cursor["head_sha256"]:
        raise CrossOwnerArtifactError("artifact_request_cursor_invalid")
    artifact = None if sequence == len(rows) else rows[sequence]
    if artifact is not None:
        _assert_peer(before_witness, artifact["consumer"])
    response = {"schema_version": 1, "artifact_type": RESPONSE_TYPE, "protocol_version": PROTOCOL_VERSION, "edge_id": spec.edge_id, "challenge": request["challenge"], "request_sha256": request["request_sha256"], "artifact": artifact, "response_sha256": ""}
    response["response_sha256"] = _digest({key: item for key, item in response.items() if key != "response_sha256"})
    _send(descriptor, response)
    if _descriptor_witness(descriptor) != before_witness:
        raise CrossOwnerArtifactError("artifact_channel_witness_changed")


def _import(journal: _RoleJournal, spec: EdgeSpec, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
    if journal.role != spec.consumer_role:
        raise CrossOwnerArtifactError("artifact_role_identity_invalid")
    cursor, _ = journal._recover_edge(spec, "import")
    if cursor["head_sha256"] != expected_import_head_sha256:
        raise CrossOwnerArtifactError("artifact_expected_head_mismatch")
    request = _request(spec, cursor, challenge)
    before_witness = _descriptor_witness(descriptor)
    _send(descriptor, request)
    response = _recv(descriptor)
    if _descriptor_witness(descriptor) != before_witness:
        raise CrossOwnerArtifactError("artifact_channel_witness_changed")
    fields = {"schema_version", "artifact_type", "protocol_version", "edge_id", "challenge", "request_sha256", "artifact", "response_sha256"}
    if not isinstance(response, Mapping) or set(response) != fields or response.get("schema_version") != 1 or response.get("artifact_type") != RESPONSE_TYPE or response.get("protocol_version") != PROTOCOL_VERSION or response.get("edge_id") != spec.edge_id or response.get("challenge") != challenge or response.get("request_sha256") != request["request_sha256"]:
        raise CrossOwnerArtifactError("artifact_response_invalid")
    if response.get("response_sha256") != _digest({key: item for key, item in response.items() if key != "response_sha256"}):
        raise CrossOwnerArtifactError("artifact_response_digest_mismatch")
    if response["artifact"] is None:
        return None
    artifact, before, after, transition = validate_artifact(
        response["artifact"], spec,
        expected_producer_identity=expected_producer_identity,
        expected_consumer_identity=expected_consumer_identity,
    )
    _assert_peer(before_witness, artifact["producer"])
    expected_producer = _identity(expected_producer_identity, spec.producer_role, "$.expected_producer")
    expected_consumer = _identity(expected_consumer_identity, spec.consumer_role, "$.expected_consumer")
    if artifact["producer"] != expected_producer:
        raise CrossOwnerArtifactError("artifact_producer_identity_mismatch")
    if artifact["consumer"] != expected_consumer or artifact["consumer"] != _identity(journal.identity, spec.consumer_role, "$.consumer"):
        raise CrossOwnerArtifactError("artifact_consumer_identity_mismatch")
    if artifact["joint_authority_sha256"] != journal.joint_authority_sha256:
        raise CrossOwnerArtifactError("artifact_joint_authority_mismatch")
    if artifact["export_sequence"] != cursor["sequence"] + 1 or artifact["predecessor_export_head_sha256"] != cursor["head_sha256"]:
        raise CrossOwnerArtifactError("artifact_import_gap")
    if _parse_time(artifact["expires_at"], "$.expires_at") <= _utc(now, "$.now"):
        raise CrossOwnerArtifactError("artifact_expired")
    successor = journal._commit(spec, "import", artifact, cursor["head_sha256"])
    return ImportedArtifactProjection(spec.edge_id, artifact["artifact_sha256"], successor["head_sha256"], spec.mechanism, artifact["operation"], artifact["event_kind"], deepcopy(dict(artifact["semantic_subject"])), before, after, transition, deepcopy(dict(artifact["producer_family_anchor"])), deepcopy(dict(artifact["producer_dependency_import_heads"])), artifact["expires_at"], "quarantine", PROOF_BOUNDARY)


def _current(journal: _RoleJournal, spec: EdgeSpec) -> ImportedArtifactProjection | None:
    artifact = journal._latest(spec, "import")
    if artifact is None:
        return None
    _, before, after, transition = validate_artifact(artifact, spec)
    cursor, _ = journal._recover_edge(spec, "import")
    return ImportedArtifactProjection(spec.edge_id, artifact["artifact_sha256"], cursor["head_sha256"], spec.mechanism, artifact["operation"], artifact["event_kind"], deepcopy(dict(artifact["semantic_subject"])), before, after, transition, deepcopy(dict(artifact["producer_family_anchor"])), deepcopy(dict(artifact["producer_dependency_import_heads"])), artifact["expires_at"], "quarantine", PROOF_BOUNDARY)


class _RoleStore:
    ROLE = ""
    def __init__(self, root: Path, identity: ServiceIdentity, *, joint_authority_sha256: str) -> None:
        _identity(identity, self.ROLE, "$.identity")
        self._journal = _RoleJournal(root, identity, joint_authority_sha256)
    def recover(self) -> dict[str, Any]:
        return self._journal.recover()
    def promote(self, *_args: Any, **_kwargs: Any) -> None:
        raise CrossOwnerArtifactError("artifact_promotion_forbidden")


_SOURCE_LOCAL_EXPORTS = {
    "catalog_selection_to_responses_selection_v1": "export_catalog_selection_to_responses_selection",
    "native_supervision_to_responses_context_v1": "export_native_supervision_to_responses_context",
    "responses_context_to_effect_authority_v1": "export_responses_context_to_effect_authority",
    "effect_authority_to_registered_action_v1": "export_effect_authority_to_registered_action",
    "registered_action_to_responses_bridge_v1": "export_registered_action_to_responses_bridge",
    "responses_projection_to_recovery_v1": "export_responses_projection_to_recovery",
    "native_supervision_to_recovery_v1": "export_native_supervision_to_recovery",
    "effect_authority_to_recovery_v1": "export_effect_authority_to_recovery",
}


def transfer_source_local_artifact(
    *, edge_id: str, producer_store: _RoleStore, consumer_store: _RoleStore,
    family_store: Any, producer_identity: ServiceIdentity,
    consumer_identity: ServiceIdentity, joint_authority_sha256: str,
    observed_at: datetime, expires_at: datetime,
) -> ImportedArtifactProjection:
    """Persist one exact T092 artifact without claiming a live OS channel.

    This helper exists only for temp-root quarantine execution. The live owner
    entry points continue to require the fixed authenticated descriptor path.
    """
    spec = _EDGES.get(edge_id)
    if spec is None or _SOURCE_LOCAL_EXPORTS.get(edge_id) is None:
        raise CrossOwnerArtifactError("artifact_edge_invalid", "$.edge_id")
    if type(producer_store) is not _ROLE_TYPES[spec.producer_role] or type(consumer_store) is not _ROLE_TYPES[spec.consumer_role]:
        raise CrossOwnerArtifactError("artifact_role_identity_invalid")
    _identity(producer_identity, spec.producer_role, "$.producer")
    _identity(consumer_identity, spec.consumer_role, "$.consumer")
    _sha(joint_authority_sha256, "$.joint_authority_sha256")
    if producer_store._journal.identity != producer_identity or consumer_store._journal.identity != consumer_identity:
        raise CrossOwnerArtifactError("artifact_role_identity_invalid")
    if (producer_store._journal.joint_authority_sha256 != joint_authority_sha256
            or consumer_store._journal.joint_authority_sha256 != joint_authority_sha256):
        raise CrossOwnerArtifactError("artifact_joint_authority_mismatch")
    artifact = getattr(producer_store, _SOURCE_LOCAL_EXPORTS[edge_id])(
        family_store=family_store, consumer_identity=consumer_identity,
        observed_at=observed_at, expires_at=expires_at,
    )
    accepted, before, after, transition = validate_artifact(
        artifact, spec, expected_producer_identity=producer_identity,
        expected_consumer_identity=consumer_identity,
    )
    cursor, _ = consumer_store._journal._recover_edge(spec, "import")
    if (accepted["export_sequence"] != cursor["sequence"] + 1
            or accepted["predecessor_export_head_sha256"] != cursor["head_sha256"]):
        raise CrossOwnerArtifactError("artifact_import_gap")
    if _parse_time(accepted["expires_at"], "$.expires_at") <= _utc(observed_at, "$.observed_at"):
        raise CrossOwnerArtifactError("artifact_expired")
    successor = consumer_store._journal._commit(spec, "import", accepted, cursor["head_sha256"])
    return ImportedArtifactProjection(
        spec.edge_id, accepted["artifact_sha256"], successor["head_sha256"],
        spec.mechanism, accepted["operation"], accepted["event_kind"],
        deepcopy(dict(accepted["semantic_subject"])), before, after, transition,
        deepcopy(dict(accepted["producer_family_anchor"])),
        deepcopy(dict(accepted["producer_dependency_import_heads"])),
        accepted["expires_at"], "quarantine", PROOF_BOUNDARY,
    )


def _spec(edge: str) -> EdgeSpec:
    return _EDGES[edge]


class CatalogSelectionCrossOwnerStore(_RoleStore):
    ROLE = "catalog-selection"
    def export_catalog_selection_to_responses_selection(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("catalog_selection_to_responses_selection_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_catalog_selection_to_responses_selection(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("catalog_selection_to_responses_selection_v1"), descriptor)


class NativeSupervisionCrossOwnerStore(_RoleStore):
    ROLE = "native-supervision"
    def export_native_supervision_to_responses_context(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("native_supervision_to_responses_context_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_native_supervision_to_responses_context(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("native_supervision_to_responses_context_v1"), descriptor)
    def export_native_supervision_to_recovery(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("native_supervision_to_recovery_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_native_supervision_to_recovery(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("native_supervision_to_recovery_v1"), descriptor)


class ResponsesSealsCrossOwnerStore(_RoleStore):
    ROLE = "responses-seals"
    def import_catalog_selection_from_catalog_selection(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("catalog_selection_to_responses_selection_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_catalog_selection_from_catalog_selection(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("catalog_selection_to_responses_selection_v1"))
    def import_native_supervision_from_native_supervision(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("native_supervision_to_responses_context_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_native_supervision_from_native_supervision(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("native_supervision_to_responses_context_v1"))
    def export_responses_context_to_effect_authority(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("responses_context_to_effect_authority_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_responses_context_to_effect_authority(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("responses_context_to_effect_authority_v1"), descriptor)
    def import_registered_action_from_registered_action(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("registered_action_to_responses_bridge_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_registered_action_from_registered_action(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("registered_action_to_responses_bridge_v1"))
    def export_responses_projection_to_recovery(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("responses_projection_to_recovery_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_responses_projection_to_recovery(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("responses_projection_to_recovery_v1"), descriptor)


class EffectAuthorityCrossOwnerStore(_RoleStore):
    ROLE = "effect-authority"
    def import_responses_context_from_responses_seals(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("responses_context_to_effect_authority_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_responses_context_from_responses_seals(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("responses_context_to_effect_authority_v1"))
    def export_effect_authority_to_registered_action(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("effect_authority_to_registered_action_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_effect_authority_to_registered_action(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("effect_authority_to_registered_action_v1"), descriptor)
    def export_effect_authority_to_recovery(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("effect_authority_to_recovery_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_effect_authority_to_recovery(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("effect_authority_to_recovery_v1"), descriptor)


class RegisteredActionCrossOwnerStore(_RoleStore):
    ROLE = "registered-action"
    def import_effect_authority_from_effect_authority(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("effect_authority_to_registered_action_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_effect_authority_from_effect_authority(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("effect_authority_to_registered_action_v1"))
    def export_registered_action_to_responses_bridge(self, *, family_store: Any, consumer_identity: ServiceIdentity, observed_at: datetime, expires_at: datetime) -> dict[str, Any]:
        return _make_artifact(self._journal, _spec("registered_action_to_responses_bridge_v1"), family_store, consumer_identity, observed_at, expires_at)
    def serve_registered_action_to_responses_bridge(self, *, descriptor: int) -> None:
        _serve(self._journal, _spec("registered_action_to_responses_bridge_v1"), descriptor)


class RecoveryCrossOwnerStore(_RoleStore):
    ROLE = "recovery"
    def import_responses_projection_from_responses_seals(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("responses_projection_to_recovery_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_responses_projection_from_responses_seals(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("responses_projection_to_recovery_v1"))
    def import_native_supervision_from_native_supervision(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("native_supervision_to_recovery_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_native_supervision_from_native_supervision(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("native_supervision_to_recovery_v1"))
    def import_effect_authority_from_effect_authority(self, *, descriptor: int, expected_import_head_sha256: str | None, challenge: str, now: datetime, expected_producer_identity: ServiceIdentity, expected_consumer_identity: ServiceIdentity) -> ImportedArtifactProjection | None:
        return _import(self._journal, _spec("effect_authority_to_recovery_v1"), descriptor, expected_import_head_sha256, challenge, now, expected_producer_identity, expected_consumer_identity)
    def current_effect_authority_from_effect_authority(self) -> ImportedArtifactProjection | None:
        return _current(self._journal, _spec("effect_authority_to_recovery_v1"))


_ROLE_TYPES = {
    "catalog-selection": CatalogSelectionCrossOwnerStore,
    "native-supervision": NativeSupervisionCrossOwnerStore,
    "responses-seals": ResponsesSealsCrossOwnerStore,
    "effect-authority": EffectAuthorityCrossOwnerStore,
    "registered-action": RegisteredActionCrossOwnerStore,
    "recovery": RecoveryCrossOwnerStore,
}


__all__ = [
    "ARTIFACT_TYPE", "EDGE_SPECS", "PROOF_BOUNDARY", "PROTOCOL_VERSION",
    "CatalogSelectionCrossOwnerStore", "CrossOwnerArtifactError", "EffectAuthorityCrossOwnerStore",
    "ImportedArtifactProjection", "NativeSupervisionCrossOwnerStore", "RecoveryCrossOwnerStore",
    "RegisteredActionCrossOwnerStore", "ResponsesSealsCrossOwnerStore", "ServiceIdentity",
    "transfer_source_local_artifact", "validate_artifact",
]
