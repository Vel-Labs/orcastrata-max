#!/usr/bin/env python3
"""Protected durable-writer protocol and an explicitly untrusted test backend."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Protocol


NAMESPACES = (
    "authority", "registered_action", "responses", "catalog", "selection",
    "native_inventory", "recovery",
)
NAMESPACE_SET = frozenset(NAMESPACES)
OPERATIONS = (
    "commit_operator_selection", "commit_or_verify_record", "invoke_registered_action",
    "issue_responses_context", "read_operator_preset_bundle",
    "read_operator_recovery_lease_grant", "read_operator_selection_head",
    "read_operator_selection_mutation", "read_operator_supervision",
    "seal_or_verify_projection", "verify_effect_authority", "verify_responses_bridge",
)
OPERATION_SET = frozenset(OPERATIONS)
REQUEST_TYPE = "protected_durable_append_request_v1"
RECEIPT_TYPE = "protected_durable_append_receipt_v1"
ANCHOR_RECEIPT_TYPE = "protected_anchor_receipt_v1"
PENDING_TYPE = "protected_writer_pending_v1"
TEST_BACKEND_TYPE = "test_only_untrusted_local_backend_v1"
TEST_RECEIPT_STATE = "test_only_untrusted_local_backend"
PROTECTED_RECEIPT_STATE = "protected_writer_receipt"
EMPTY_SHA256 = "sha256:" + hashlib.sha256(b"").hexdigest()
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_REQUEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "store_id", "namespace", "canonical_source_id",
    "producer_principal_id", "operation", "candidate_sha256", "profile_sha256",
    "expected_sequence", "expected_head_sha256", "expected_generation", "event_kind",
    "record_id", "occurred_at", "nonce", "payload", "payload_sha256",
    "target_event_sha256", "consumer_sha256", "request_sha256",
})
_RECEIPT_FIELDS = frozenset({
    "schema_version", "artifact_type", "state", "request_sha256", "store_id", "namespace",
    "canonical_source_id", "producer_principal_id", "operation", "candidate_sha256",
    "profile_sha256", "nonce", "prior_sequence", "successor_sequence", "prior_head_sha256",
    "successor_head_sha256", "prior_generation", "successor_generation", "event_sha256",
    "anchor_sha256", "previous_receipt_sha256", "writer_id", "writer_build_sha256",
    "protected_session_id", "protected_session_binding_sha256", "witnessed_at", "expires_at",
    "anchor_authority_id", "anchor_authority_build_sha256", "anchor_receipt_sha256",
    "writer_receipt_sha256", "receipt_sha256",
})
_ANCHOR_RECEIPT_FIELDS = frozenset({
    "schema_version", "artifact_type", "anchor_authority_id", "anchor_authority_build_sha256",
    "anchor_receipt_id", "request_sha256", "nonce", "prior_sequence", "successor_sequence",
    "prior_head_sha256", "successor_head_sha256", "prior_generation", "successor_generation",
    "event_sha256", "writer_receipt_sha256", "anchor_sha256",
    "previous_anchor_receipt_sha256", "retained_at", "expires_at", "receipt_sha256",
})
_PROVENANCE_FIELDS = frozenset({
    "writer_id", "writer_build_sha256", "protected_session_id",
    "protected_session_binding_sha256",
})
_LOCAL_MANIFEST_FIELDS = frozenset({
    "schema_version", "artifact_type", "classification", "store_id", "created_at", "owners",
})
_LOCAL_HEAD_FIELDS = frozenset({
    "schema_version", "artifact_type", "store_id", "namespace", "sequence", "generation",
    "head_sha256", "anchor_sha256", "last_receipt_sha256",
    "last_anchor_receipt_sha256",
})
_LOCAL_RECORD_FIELDS = frozenset({"request", "writer_receipt", "anchor_receipt"})


class DurableStoreError(ValueError):
    """Stable rejection without echoing caller data."""

    def __init__(self, code: str, location: str = "$") -> None:
        self.code = code
        self.location = location
        super().__init__(f"{code}: {location}")


class ProtectedDurableWriter(Protocol):
    """Separate protected boundary. Python structural conformance is not trust."""

    def append(self, request: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]: ...


@dataclass(frozen=True)
class ProtectedWriterPending:
    reason: str
    request_sha256: str
    receipt_sha256: str | None

    def as_mapping(self) -> Mapping[str, Any]:
        return {
            "schema_version": 1,
            "artifact_type": PENDING_TYPE,
            "state": "protected_writer_pending",
            "reason": self.reason,
            "request_sha256": self.request_sha256,
            "receipt_sha256": self.receipt_sha256,
            "production_ready": False,
        }


def _json_value(value: Any, location: str) -> None:
    if value is None or isinstance(value, (str, bool)) or type(value) is int:
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_value(item, f"{location}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise DurableStoreError("json_key_invalid", location)
            _json_value(item, f"{location}.{key}")
        return
    raise DurableStoreError("json_value_invalid", location)


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    _json_value(value, "$")
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = dict(value)
    row[field] = ""
    row[field] = _digest(canonical_bytes(row))
    return row


def _mapping(value: Any, fields: frozenset[str], code: str, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise DurableStoreError(code, location)
    return dict(value)


def _integer(value: Any, code: str, location: str) -> int:
    if type(value) is not int or value < 0:
        raise DurableStoreError(code, location)
    return value


def _identifier(value: Any, code: str, location: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise DurableStoreError(code, location)
    return value


def _sha(value: Any, code: str, location: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise DurableStoreError(code, location)
    return value


def _time(value: Any, code: str, location: str) -> str:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise DurableStoreError(code, location)
    return value


def _validate_request(value: Any) -> dict[str, Any]:
    row = _mapping(value, _REQUEST_FIELDS, "append_request_shape_invalid", "$.request")
    if _integer(row["schema_version"], "append_request_version_invalid", "$.request.schema_version") != 1:
        raise DurableStoreError("append_request_version_invalid", "$.request.schema_version")
    if row["artifact_type"] != REQUEST_TYPE:
        raise DurableStoreError("append_request_type_invalid", "$.request.artifact_type")
    _identifier(row["store_id"], "store_id_invalid", "$.request.store_id")
    if row["namespace"] not in NAMESPACE_SET:
        raise DurableStoreError("namespace_invalid", "$.request.namespace")
    _identifier(row["canonical_source_id"], "canonical_source_id_invalid", "$.request.canonical_source_id")
    _identifier(row["producer_principal_id"], "producer_principal_id_invalid", "$.request.producer_principal_id")
    if row["operation"] not in OPERATION_SET:
        raise DurableStoreError("operation_invalid", "$.request.operation")
    _sha(row["candidate_sha256"], "candidate_digest_invalid", "$.request.candidate_sha256")
    _sha(row["profile_sha256"], "profile_digest_invalid", "$.request.profile_sha256")
    _integer(row["expected_sequence"], "expected_sequence_invalid", "$.request.expected_sequence")
    _integer(row["expected_generation"], "expected_generation_invalid", "$.request.expected_generation")
    _sha(row["expected_head_sha256"], "expected_head_invalid", "$.request.expected_head_sha256")
    if row["event_kind"] not in {"fact", "revoke", "consume"}:
        raise DurableStoreError("event_kind_invalid", "$.request.event_kind")
    _identifier(row["record_id"], "record_id_invalid", "$.request.record_id")
    _time(row["occurred_at"], "occurred_at_invalid", "$.request.occurred_at")
    if not isinstance(row["nonce"], str) or _NONCE.fullmatch(row["nonce"]) is None:
        raise DurableStoreError("nonce_invalid", "$.request.nonce")
    if not isinstance(row["payload"], Mapping):
        raise DurableStoreError("payload_invalid", "$.request.payload")
    _json_value(row["payload"], "$.request.payload")
    if _sha(row["payload_sha256"], "payload_digest_invalid", "$.request.payload_sha256") != _digest(canonical_bytes(row["payload"])):
        raise DurableStoreError("payload_digest_mismatch", "$.request.payload_sha256")
    kind = row["event_kind"]
    if kind == "fact":
        if row["target_event_sha256"] is not None or row["consumer_sha256"] is not None:
            raise DurableStoreError("fact_transition_fields_invalid", "$.request")
    else:
        _sha(row["target_event_sha256"], "target_event_invalid", "$.request.target_event_sha256")
        if kind == "consume":
            if row["namespace"] != "recovery":
                raise DurableStoreError("consumption_namespace_invalid", "$.request.namespace")
            _sha(row["consumer_sha256"], "consumer_digest_invalid", "$.request.consumer_sha256")
        elif row["consumer_sha256"] is not None:
            raise DurableStoreError("revocation_consumer_invalid", "$.request.consumer_sha256")
    request_sha = _sha(row["request_sha256"], "request_digest_invalid", "$.request.request_sha256")
    if _seal(row, "request_sha256")["request_sha256"] != request_sha:
        raise DurableStoreError("request_digest_mismatch", "$.request.request_sha256")
    return row


def prepare_append_request(
    *, store_id: str, namespace: str, canonical_source_id: str, producer_principal_id: str,
    operation: str, candidate_sha256: str, profile_sha256: str, expected_sequence: int,
    expected_head_sha256: str, expected_generation: int, event_kind: str, record_id: str,
    occurred_at: str, nonce: str, payload: Mapping[str, Any],
    target_event_sha256: str | None = None, consumer_sha256: str | None = None,
) -> Mapping[str, Any]:
    row = _seal({
        "schema_version": 1, "artifact_type": REQUEST_TYPE, "store_id": store_id,
        "namespace": namespace, "canonical_source_id": canonical_source_id,
        "producer_principal_id": producer_principal_id, "operation": operation,
        "candidate_sha256": candidate_sha256, "profile_sha256": profile_sha256,
        "expected_sequence": expected_sequence, "expected_head_sha256": expected_head_sha256,
        "expected_generation": expected_generation, "event_kind": event_kind,
        "record_id": record_id, "occurred_at": occurred_at, "nonce": nonce,
        "payload": dict(payload), "payload_sha256": _digest(canonical_bytes(payload)),
        "target_event_sha256": target_event_sha256, "consumer_sha256": consumer_sha256,
        "request_sha256": "",
    }, "request_sha256")
    return _validate_request(row)


def _event_digest(request: Mapping[str, Any], successor_sequence: int, successor_generation: int) -> str:
    return _digest(canonical_bytes({
        "request_sha256": request["request_sha256"], "successor_sequence": successor_sequence,
        "successor_generation": successor_generation,
    }))


def _anchor_digest(request: Mapping[str, Any], event_sha256: str, previous_receipt_sha256: str) -> str:
    return _digest(canonical_bytes({
        "store_id": request["store_id"], "namespace": request["namespace"],
        "event_sha256": event_sha256, "previous_receipt_sha256": previous_receipt_sha256,
    }))


def _writer_statement_digest(receipt: Mapping[str, Any]) -> str:
    statement = dict(receipt)
    statement["anchor_receipt_sha256"] = ""
    statement["writer_receipt_sha256"] = ""
    statement["receipt_sha256"] = ""
    return _digest(canonical_bytes(statement))


def _validate_receipt(value: Any, request: Mapping[str, Any]) -> dict[str, Any]:
    row = _mapping(value, _RECEIPT_FIELDS, "protected_receipt_shape_invalid", "$.receipt")
    if _integer(row["schema_version"], "protected_receipt_version_invalid", "$.receipt.schema_version") != 1 or row["artifact_type"] != RECEIPT_TYPE:
        raise DurableStoreError("protected_receipt_identity_invalid", "$.receipt")
    if row["state"] not in {TEST_RECEIPT_STATE, PROTECTED_RECEIPT_STATE}:
        raise DurableStoreError("protected_receipt_state_invalid", "$.receipt.state")
    for field in (
        "request_sha256", "store_id", "namespace", "canonical_source_id", "producer_principal_id",
        "operation", "candidate_sha256", "profile_sha256", "nonce",
    ):
        if row[field] != request[field]:
            raise DurableStoreError("protected_receipt_request_binding_mismatch", "$.receipt." + field)
    prior_sequence = _integer(row["prior_sequence"], "receipt_sequence_invalid", "$.receipt.prior_sequence")
    successor_sequence = _integer(row["successor_sequence"], "receipt_sequence_invalid", "$.receipt.successor_sequence")
    prior_generation = _integer(row["prior_generation"], "receipt_generation_invalid", "$.receipt.prior_generation")
    successor_generation = _integer(row["successor_generation"], "receipt_generation_invalid", "$.receipt.successor_generation")
    if prior_sequence != request["expected_sequence"] or successor_sequence != prior_sequence + 1:
        raise DurableStoreError("receipt_sequence_cas_invalid", "$.receipt.successor_sequence")
    if prior_generation != request["expected_generation"] or successor_generation != prior_generation + 1:
        raise DurableStoreError("receipt_generation_cas_invalid", "$.receipt.successor_generation")
    if row["prior_head_sha256"] != request["expected_head_sha256"]:
        raise DurableStoreError("receipt_head_cas_invalid", "$.receipt.prior_head_sha256")
    event_sha = _sha(row["event_sha256"], "receipt_event_digest_invalid", "$.receipt.event_sha256")
    if event_sha != _event_digest(request, successor_sequence, successor_generation) or row["successor_head_sha256"] != event_sha:
        raise DurableStoreError("receipt_event_digest_mismatch", "$.receipt.event_sha256")
    previous_receipt = _sha(row["previous_receipt_sha256"], "previous_receipt_invalid", "$.receipt.previous_receipt_sha256")
    if _sha(row["anchor_sha256"], "anchor_digest_invalid", "$.receipt.anchor_sha256") != _anchor_digest(request, event_sha, previous_receipt):
        raise DurableStoreError("anchor_parity_mismatch", "$.receipt.anchor_sha256")
    _identifier(row["writer_id"], "writer_id_invalid", "$.receipt.writer_id")
    _sha(row["writer_build_sha256"], "writer_build_invalid", "$.receipt.writer_build_sha256")
    _identifier(row["protected_session_id"], "protected_session_id_invalid", "$.receipt.protected_session_id")
    _sha(row["protected_session_binding_sha256"], "protected_session_binding_invalid", "$.receipt.protected_session_binding_sha256")
    witnessed = _time(row["witnessed_at"], "witnessed_at_invalid", "$.receipt.witnessed_at")
    expires = _time(row["expires_at"], "expires_at_invalid", "$.receipt.expires_at")
    if expires <= witnessed:
        raise DurableStoreError("receipt_expiry_invalid", "$.receipt.expires_at")
    _identifier(row["anchor_authority_id"], "anchor_authority_id_invalid", "$.receipt.anchor_authority_id")
    _sha(row["anchor_authority_build_sha256"], "anchor_authority_build_invalid", "$.receipt.anchor_authority_build_sha256")
    _sha(row["anchor_receipt_sha256"], "anchor_receipt_digest_invalid", "$.receipt.anchor_receipt_sha256")
    writer_receipt_sha = _sha(row["writer_receipt_sha256"], "writer_receipt_digest_invalid", "$.receipt.writer_receipt_sha256")
    if writer_receipt_sha != _writer_statement_digest(row):
        raise DurableStoreError("writer_receipt_digest_mismatch", "$.receipt.writer_receipt_sha256")
    receipt_sha = _sha(row["receipt_sha256"], "receipt_digest_invalid", "$.receipt.receipt_sha256")
    if _seal(row, "receipt_sha256")["receipt_sha256"] != receipt_sha:
        raise DurableStoreError("receipt_digest_mismatch", "$.receipt.receipt_sha256")
    return row


def _validate_anchor_receipt(value: Any, request: Mapping[str, Any], writer_receipt: Mapping[str, Any]) -> dict[str, Any]:
    row = _mapping(value, _ANCHOR_RECEIPT_FIELDS, "anchor_receipt_shape_invalid", "$.anchor_receipt")
    if _integer(row["schema_version"], "anchor_receipt_version_invalid", "$.anchor_receipt.schema_version") != 1 or row["artifact_type"] != ANCHOR_RECEIPT_TYPE:
        raise DurableStoreError("anchor_receipt_identity_invalid", "$.anchor_receipt")
    _identifier(row["anchor_authority_id"], "anchor_authority_id_invalid", "$.anchor_receipt.anchor_authority_id")
    _sha(row["anchor_authority_build_sha256"], "anchor_authority_build_invalid", "$.anchor_receipt.anchor_authority_build_sha256")
    _identifier(row["anchor_receipt_id"], "anchor_receipt_id_invalid", "$.anchor_receipt.anchor_receipt_id")
    if row["request_sha256"] != request["request_sha256"] or row["nonce"] != request["nonce"]:
        raise DurableStoreError("anchor_receipt_request_binding_mismatch", "$.anchor_receipt")
    bindings = (
        ("prior_sequence", "prior_sequence"), ("successor_sequence", "successor_sequence"),
        ("prior_head_sha256", "prior_head_sha256"), ("successor_head_sha256", "successor_head_sha256"),
        ("prior_generation", "prior_generation"), ("successor_generation", "successor_generation"),
        ("event_sha256", "event_sha256"), ("writer_receipt_sha256", "writer_receipt_sha256"),
        ("anchor_sha256", "anchor_sha256"),
    )
    for anchor_field, writer_field in bindings:
        if row[anchor_field] != writer_receipt[writer_field]:
            raise DurableStoreError("anchor_receipt_writer_binding_mismatch", "$.anchor_receipt." + anchor_field)
    if row["anchor_authority_id"] != writer_receipt["anchor_authority_id"] or row["anchor_authority_build_sha256"] != writer_receipt["anchor_authority_build_sha256"]:
        raise DurableStoreError("anchor_authority_binding_mismatch", "$.anchor_receipt")
    prior_sequence = _integer(row["prior_sequence"], "anchor_receipt_sequence_invalid", "$.anchor_receipt.prior_sequence")
    successor_sequence = _integer(row["successor_sequence"], "anchor_receipt_sequence_invalid", "$.anchor_receipt.successor_sequence")
    prior_generation = _integer(row["prior_generation"], "anchor_receipt_generation_invalid", "$.anchor_receipt.prior_generation")
    successor_generation = _integer(row["successor_generation"], "anchor_receipt_generation_invalid", "$.anchor_receipt.successor_generation")
    if successor_sequence != prior_sequence + 1 or successor_generation != prior_generation + 1:
        raise DurableStoreError("anchor_receipt_cas_invalid", "$.anchor_receipt")
    for field in ("prior_head_sha256", "successor_head_sha256", "event_sha256", "writer_receipt_sha256", "anchor_sha256", "previous_anchor_receipt_sha256"):
        _sha(row[field], "anchor_receipt_digest_invalid", "$.anchor_receipt." + field)
    retained = _time(row["retained_at"], "anchor_retained_at_invalid", "$.anchor_receipt.retained_at")
    expires = _time(row["expires_at"], "anchor_expires_at_invalid", "$.anchor_receipt.expires_at")
    if expires <= retained:
        raise DurableStoreError("anchor_receipt_expiry_invalid", "$.anchor_receipt.expires_at")
    if retained < writer_receipt["witnessed_at"] or expires > writer_receipt["expires_at"]:
        raise DurableStoreError("anchor_receipt_time_binding_invalid", "$.anchor_receipt")
    receipt_sha = _sha(row["receipt_sha256"], "anchor_receipt_digest_invalid", "$.anchor_receipt.receipt_sha256")
    if _seal(row, "receipt_sha256")["receipt_sha256"] != receipt_sha:
        raise DurableStoreError("anchor_receipt_digest_mismatch", "$.anchor_receipt.receipt_sha256")
    if writer_receipt["anchor_receipt_sha256"] != receipt_sha:
        raise DurableStoreError("writer_anchor_receipt_mismatch", "$.receipt.anchor_receipt_sha256")
    return row


def evaluate_protected_receipt(
    request: Mapping[str, Any], receipt: Mapping[str, Any], anchor_receipt: Mapping[str, Any],
    protected_session_provenance: Mapping[str, Any],
) -> ProtectedWriterPending:
    request_row = _validate_request(request)
    receipt_row = _validate_receipt(receipt, request_row)
    _validate_anchor_receipt(anchor_receipt, request_row, receipt_row)
    provenance = _mapping(protected_session_provenance, _PROVENANCE_FIELDS, "protected_session_provenance_shape_invalid", "$.protected_session_provenance")
    for field in _PROVENANCE_FIELDS:
        if provenance[field] != receipt_row[field]:
            raise DurableStoreError("protected_session_provenance_mismatch", "$.protected_session_provenance." + field)
    if receipt_row["state"] == TEST_RECEIPT_STATE:
        reason = "test_only_untrusted_local_backend"
    else:
        reason = "protected_session_provenance_not_verifiable_source_locally"
    return ProtectedWriterPending(reason, request_row["request_sha256"], receipt_row["receipt_sha256"])


def validate_protected_record(
    request: Mapping[str, Any], receipt: Mapping[str, Any],
    anchor_receipt: Mapping[str, Any],
) -> Mapping[str, Mapping[str, Any]]:
    """Validate and detach one exact T082 authority triple.

    This function does not promote the triple to live authority. The caller must
    independently prove the protected writer and anchor service identities.
    """

    request_row = _validate_request(request)
    receipt_row = _validate_receipt(receipt, request_row)
    anchor_row = _validate_anchor_receipt(anchor_receipt, request_row, receipt_row)
    return {
        "request": request_row,
        "writer_receipt": receipt_row,
        "anchor_receipt": anchor_row,
    }


def submit_protected_append(
    writer: ProtectedDurableWriter, request: Mapping[str, Any], protected_session_provenance: Mapping[str, Any],
) -> tuple[Mapping[str, Mapping[str, Any]], ProtectedWriterPending]:
    request_row = _validate_request(request)
    evidence = writer.append(request_row)
    if not isinstance(evidence, Mapping) or set(evidence) != {"writer_receipt", "anchor_receipt"}:
        raise DurableStoreError("protected_append_evidence_shape_invalid", "$.evidence")
    return evidence, evaluate_protected_receipt(
        request_row, evidence["writer_receipt"], evidence["anchor_receipt"], protected_session_provenance,
    )


def _secure(path: Path, *, directory: bool, location: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DurableStoreError("local_component_missing", location) from exc
    good_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    expected_mode = 0o700 if directory else 0o600
    if not good_type or stat.S_ISLNK(info.st_mode):
        raise DurableStoreError("local_component_type_invalid", location)
    if stat.S_IMODE(info.st_mode) != expected_mode or info.st_uid != os.geteuid():
        raise DurableStoreError("local_component_permissions_invalid", location)
    if not directory and info.st_nlink != 1:
        raise DurableStoreError("local_component_link_invalid", location)
    return info


def _read(path: Path) -> dict[str, Any]:
    _secure(path, directory=False, location="$.local")
    try:
        data = path.read_bytes()
        value = json.loads(data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DurableStoreError("local_json_invalid", "$.local") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != data:
        raise DurableStoreError("local_json_not_canonical", "$.local")
    return value


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.parent / (".pending-" + secrets.token_hex(16))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        data = canonical_bytes(value)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise DurableStoreError("local_write_incomplete", "$.local")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if path.exists() or path.is_symlink():
        raise DurableStoreError("local_publication_collision", "$.local")
    os.rename(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _replace(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.parent / (".pending-" + secrets.token_hex(16))
    _write_new(temporary, value)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


class TestOnlyUntrustedLocalBackend:
    """Temp-root test backend. It cannot create production-ready evidence."""

    classification = TEST_RECEIPT_STATE

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise DurableStoreError("local_root_invalid", "$.root")
        self.root = root
        self.manifest = _mapping(_read(root / "manifest.json"), _LOCAL_MANIFEST_FIELDS, "local_manifest_invalid", "$.manifest")
        if self.manifest["classification"] != TEST_RECEIPT_STATE:
            raise DurableStoreError("local_backend_classification_invalid", "$.manifest.classification")
        self.recover_all()

    @classmethod
    def create(cls, root: Path, owners: Mapping[str, Mapping[str, str]], *, store_id: str, created_at: str) -> "TestOnlyUntrustedLocalBackend":
        if not isinstance(root, Path) or not root.is_absolute() or root.exists() or root.is_symlink():
            raise DurableStoreError("local_root_invalid", "$.root")
        _identifier(store_id, "store_id_invalid", "$.store_id")
        _time(created_at, "created_at_invalid", "$.created_at")
        if not isinstance(owners, Mapping) or set(owners) != NAMESPACE_SET:
            raise DurableStoreError("local_owners_invalid", "$.owners")
        normalized = {}
        for namespace in NAMESPACES:
            owner = owners[namespace]
            if not isinstance(owner, Mapping) or set(owner) != {"canonical_source_id", "producer_principal_id"}:
                raise DurableStoreError("local_owner_invalid", "$.owners." + namespace)
            normalized[namespace] = {
                "canonical_source_id": _identifier(owner["canonical_source_id"], "canonical_source_id_invalid", "$.owners"),
                "producer_principal_id": _identifier(owner["producer_principal_id"], "producer_principal_id_invalid", "$.owners"),
            }
        root.mkdir(mode=0o700)
        _write_new(root / "manifest.json", {
            "schema_version": 1, "artifact_type": TEST_BACKEND_TYPE,
            "classification": TEST_RECEIPT_STATE, "store_id": store_id,
            "created_at": created_at, "owners": normalized,
        })
        for namespace in NAMESPACES:
            namespace_root = root / namespace
            namespace_root.mkdir(mode=0o700)
            (namespace_root / "events").mkdir(mode=0o700)
            _write_new(namespace_root / "head.json", {
                "schema_version": 1, "artifact_type": "test_only_local_head_v1",
                "store_id": store_id, "namespace": namespace, "sequence": 0, "generation": 0,
                "head_sha256": EMPTY_SHA256, "anchor_sha256": EMPTY_SHA256,
                "last_receipt_sha256": EMPTY_SHA256,
                "last_anchor_receipt_sha256": EMPTY_SHA256,
            })
        return cls(root)

    @property
    def store_id(self) -> str:
        return self.manifest["store_id"]

    def _recover(self, namespace: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if namespace not in NAMESPACE_SET:
            raise DurableStoreError("namespace_invalid", "$.namespace")
        namespace_root = self.root / namespace
        _secure(self.root, directory=True, location="$.root")
        _secure(namespace_root, directory=True, location="$.namespace")
        _secure(namespace_root / "events", directory=True, location="$.events")
        head = _mapping(_read(namespace_root / "head.json"), _LOCAL_HEAD_FIELDS, "local_head_invalid", "$.head")
        sequence = _integer(head["sequence"], "local_sequence_invalid", "$.head.sequence")
        generation = _integer(head["generation"], "local_generation_invalid", "$.head.generation")
        if sequence != generation or head["store_id"] != self.store_id or head["namespace"] != namespace:
            raise DurableStoreError("local_head_identity_invalid", "$.head")
        names = sorted(path.name for path in (namespace_root / "events").iterdir())
        expected = [f"{index:020d}.json" for index in range(1, sequence + 1)]
        if names != expected:
            raise DurableStoreError("local_sequence_or_residue_invalid", "$.events")
        prior_head = EMPTY_SHA256
        prior_anchor = EMPTY_SHA256
        prior_receipt = EMPTY_SHA256
        prior_anchor_receipt = EMPTY_SHA256
        records: list[dict[str, Any]] = []
        nonces: set[str] = set()
        ids: dict[str, str] = {}
        revoked: set[str] = set()
        consumed: set[str] = set()
        for index, name in enumerate(names, 1):
            record = _mapping(_read(namespace_root / "events" / name), _LOCAL_RECORD_FIELDS, "local_record_invalid", "$.record")
            request = _validate_request(record["request"])
            receipt = _validate_receipt(record["writer_receipt"], request)
            anchor_receipt = _validate_anchor_receipt(record["anchor_receipt"], request, receipt)
            owner = self.manifest["owners"][namespace]
            if request["store_id"] != self.store_id or request["namespace"] != namespace or request["canonical_source_id"] != owner["canonical_source_id"] or request["producer_principal_id"] != owner["producer_principal_id"]:
                raise DurableStoreError("local_request_owner_mismatch", "$.request")
            if request["expected_sequence"] != index - 1 or request["expected_generation"] != index - 1 or request["expected_head_sha256"] != prior_head:
                raise DurableStoreError("local_chain_fork", "$.request")
            if receipt["previous_receipt_sha256"] != prior_receipt or receipt["anchor_sha256"] != _anchor_digest(request, receipt["event_sha256"], prior_receipt):
                raise DurableStoreError("local_anchor_fork", "$.receipt")
            if anchor_receipt["previous_anchor_receipt_sha256"] != prior_anchor_receipt:
                raise DurableStoreError("local_anchor_receipt_fork", "$.anchor_receipt")
            if request["nonce"] in nonces:
                raise DurableStoreError("local_nonce_replay", "$.request.nonce")
            if request["record_id"] in ids:
                raise DurableStoreError("local_record_replay" if ids[request["record_id"]] == request["payload_sha256"] else "local_record_collision", "$.request.record_id")
            if request["event_kind"] != "fact":
                target = request["target_event_sha256"]
                if not any(item["writer_receipt"]["event_sha256"] == target and item["request"]["event_kind"] == "fact" for item in records):
                    raise DurableStoreError("local_transition_target_missing", "$.request.target_event_sha256")
                if target in revoked or target in consumed:
                    raise DurableStoreError("local_transition_replay", "$.request.target_event_sha256")
                (revoked if request["event_kind"] == "revoke" else consumed).add(target)
            nonces.add(request["nonce"])
            ids[request["record_id"]] = request["payload_sha256"]
            records.append({"request": request, "writer_receipt": receipt, "anchor_receipt": anchor_receipt})
            prior_head = receipt["successor_head_sha256"]
            prior_anchor = receipt["anchor_sha256"]
            prior_receipt = receipt["receipt_sha256"]
            prior_anchor_receipt = anchor_receipt["receipt_sha256"]
        if head["head_sha256"] != prior_head or head["anchor_sha256"] != prior_anchor or head["last_receipt_sha256"] != prior_receipt or head["last_anchor_receipt_sha256"] != prior_anchor_receipt:
            raise DurableStoreError("local_head_chain_mismatch", "$.head")
        return head, records

    def recover_all(self) -> Mapping[str, Mapping[str, Any]]:
        return {namespace: self._recover(namespace)[0] for namespace in NAMESPACES}

    def head(self, namespace: str) -> Mapping[str, Any]:
        return self._recover(namespace)[0]

    def append(self, request: Mapping[str, Any], *, fault: Any = None) -> Mapping[str, Mapping[str, Any]]:
        request = _validate_request(request)
        namespace = request["namespace"]
        head, records = self._recover(namespace)
        owner = self.manifest["owners"][namespace]
        if request["store_id"] != self.store_id or request["canonical_source_id"] != owner["canonical_source_id"] or request["producer_principal_id"] != owner["producer_principal_id"]:
            raise DurableStoreError("local_request_owner_mismatch", "$.request")
        if request["expected_sequence"] != head["sequence"] or request["expected_generation"] != head["generation"]:
            raise DurableStoreError("local_stale_sequence_generation", "$.request")
        if request["expected_head_sha256"] != head["head_sha256"]:
            raise DurableStoreError("local_stale_head", "$.request.expected_head_sha256")
        if any(item["request"]["nonce"] == request["nonce"] for item in records):
            raise DurableStoreError("local_nonce_replay", "$.request.nonce")
        same = next((item for item in records if item["request"]["record_id"] == request["record_id"]), None)
        if same is not None:
            raise DurableStoreError("local_record_replay" if same["request"]["payload_sha256"] == request["payload_sha256"] else "local_record_collision", "$.request.record_id")
        if request["event_kind"] != "fact":
            target = request["target_event_sha256"]
            target_record = next((item for item in records if item["writer_receipt"]["event_sha256"] == target and item["request"]["event_kind"] == "fact"), None)
            transitions = [item for item in records if item["request"]["target_event_sha256"] == target]
            if target_record is None:
                raise DurableStoreError("local_transition_target_missing", "$.request.target_event_sha256")
            if transitions:
                raise DurableStoreError("local_transition_replay", "$.request.target_event_sha256")
        successor = head["sequence"] + 1
        event_sha = _event_digest(request, successor, successor)
        anchor_sha = _anchor_digest(request, event_sha, head["last_receipt_sha256"])
        receipt = {
            "schema_version": 1, "artifact_type": RECEIPT_TYPE, "state": TEST_RECEIPT_STATE,
            "request_sha256": request["request_sha256"], "store_id": self.store_id,
            "namespace": namespace, "canonical_source_id": request["canonical_source_id"],
            "producer_principal_id": request["producer_principal_id"], "operation": request["operation"],
            "candidate_sha256": request["candidate_sha256"], "profile_sha256": request["profile_sha256"],
            "nonce": request["nonce"], "prior_sequence": head["sequence"],
            "successor_sequence": successor, "prior_head_sha256": head["head_sha256"],
            "successor_head_sha256": event_sha, "prior_generation": head["generation"],
            "successor_generation": successor, "event_sha256": event_sha, "anchor_sha256": anchor_sha,
            "previous_receipt_sha256": head["last_receipt_sha256"],
            "writer_id": "test-only.untrusted-local-writer",
            "writer_build_sha256": _digest(b"test-only-untrusted-local-writer-v1"),
            "protected_session_id": "test-only.local-session",
            "protected_session_binding_sha256": _digest(b"test-only-local-session-not-protected"),
            "witnessed_at": request["occurred_at"], "expires_at": "9999-12-31T23:59:59Z",
            "anchor_authority_id": "test-only.untrusted-local-anchor",
            "anchor_authority_build_sha256": _digest(b"test-only-untrusted-local-anchor-v1"),
            "anchor_receipt_sha256": "", "writer_receipt_sha256": "", "receipt_sha256": "",
        }
        receipt["writer_receipt_sha256"] = _writer_statement_digest(receipt)
        anchor_receipt = _seal({
            "schema_version": 1, "artifact_type": ANCHOR_RECEIPT_TYPE,
            "anchor_authority_id": receipt["anchor_authority_id"],
            "anchor_authority_build_sha256": receipt["anchor_authority_build_sha256"],
            "anchor_receipt_id": f"test-only.anchor-{successor:020d}",
            "request_sha256": request["request_sha256"], "nonce": request["nonce"],
            "prior_sequence": head["sequence"], "successor_sequence": successor,
            "prior_head_sha256": head["head_sha256"], "successor_head_sha256": event_sha,
            "prior_generation": head["generation"], "successor_generation": successor,
            "event_sha256": event_sha, "writer_receipt_sha256": receipt["writer_receipt_sha256"],
            "anchor_sha256": anchor_sha,
            "previous_anchor_receipt_sha256": head["last_anchor_receipt_sha256"],
            "retained_at": request["occurred_at"], "expires_at": "9999-12-31T23:59:59Z",
            "receipt_sha256": "",
        }, "receipt_sha256")
        receipt["anchor_receipt_sha256"] = anchor_receipt["receipt_sha256"]
        receipt = _seal(receipt, "receipt_sha256")
        record_path = self.root / namespace / "events" / f"{successor:020d}.json"
        if fault is not None:
            fault("before_event_publish")
        _write_new(record_path, {"request": request, "writer_receipt": receipt, "anchor_receipt": anchor_receipt})
        if fault is not None:
            fault("after_event_publish")
        _replace(self.root / namespace / "head.json", {
            "schema_version": 1, "artifact_type": "test_only_local_head_v1",
            "store_id": self.store_id, "namespace": namespace, "sequence": successor,
            "generation": successor, "head_sha256": event_sha, "anchor_sha256": anchor_sha,
            "last_receipt_sha256": receipt["receipt_sha256"],
            "last_anchor_receipt_sha256": anchor_receipt["receipt_sha256"],
        })
        if fault is not None:
            fault("after_head_publish")
        self._recover(namespace)
        return {"writer_receipt": receipt, "anchor_receipt": anchor_receipt}


__all__ = [
    "ANCHOR_RECEIPT_TYPE", "DurableStoreError", "EMPTY_SHA256", "NAMESPACES", "OPERATIONS",
    "PROTECTED_RECEIPT_STATE", "ProtectedDurableWriter", "ProtectedWriterPending",
    "REQUEST_TYPE", "RECEIPT_TYPE", "TEST_RECEIPT_STATE",
    "TestOnlyUntrustedLocalBackend", "canonical_bytes", "evaluate_protected_receipt",
    "prepare_append_request", "submit_protected_append", "validate_protected_record",
]
