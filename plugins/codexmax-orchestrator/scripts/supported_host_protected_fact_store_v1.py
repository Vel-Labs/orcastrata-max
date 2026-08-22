#!/usr/bin/env python3
"""Protected fact authority for the first-party supported-host producer.

The service owns validation and chain recovery.  Persistence and anchoring are
injected devices.  The test devices are deliberately a different class from
the production sessions and can never produce a production-classified read.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping


RECORD_TYPE = "supported_host_protected_fact_record_v1"
TRANSITION_TYPE = "supported_host_protected_fact_transition_v1"
WRITER_RECEIPT_TYPE = "supported_host_protected_fact_writer_receipt_v1"
ANCHOR_RECEIPT_TYPE = "supported_host_protected_fact_anchor_receipt_v1"
PRODUCTION_CLASSIFICATION = "protected_production_device_session_v1"
TEST_CLASSIFICATION = "test_only_protected_device_v1"
EMPTY_SHA256 = "sha256:" + hashlib.sha256(b"").hexdigest()
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

IDENTITY_FIELDS = frozenset({
    "workspace_id", "source_sha256", "candidate_sha256", "manifest_sha256",
    "generation", "host_id", "service_instance_id", "service_start_id",
})
RECORD_FIELDS = frozenset({
    "schema_version", "artifact_type", "record_id", "operation",
    "canonical_source_id", "producer_principal_id", "namespace", "identity",
    "profile_sha256", "service_start_id", "operation_body_sha256",
    "dependency_receipts_sha256", "fact_key", "fact_value", "fact_sha256",
    "source_digest", "issued_at", "observed_at", "expires_at", "revoked",
    "consumed", "append_request", "writer_receipt", "anchor_receipt",
    "sequence", "generation", "prior_head_sha256", "successor_head_sha256",
    "record_sha256",
})
TRANSITION_FIELDS = frozenset({
    "schema_version", "artifact_type", "transition_id", "kind", "operation",
    "namespace", "target_record_sha256", "consumer_sha256", "occurred_at",
    "sequence", "generation", "prior_head_sha256", "successor_head_sha256",
    "writer_receipt", "anchor_receipt", "transition_sha256",
})
HEAD_FIELDS = frozenset({"sequence", "generation", "head_sha256", "last_anchor_sha256"})


class ProtectedFactStoreError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise ProtectedFactStoreError("protected_fact_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _closed(value: Any, fields: frozenset[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ProtectedFactStoreError(code, path)
    return deepcopy(dict(value))


def _sha(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ProtectedFactStoreError(code, path)
    return value


def _identifier(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ProtectedFactStoreError(code, path)
    return value


def _parse_time(value: Any, code: str, path: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise ProtectedFactStoreError(code, path)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _format_time(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ProtectedFactStoreError("protected_fact_clock_invalid", "$.clock")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seal(row: Mapping[str, Any], field: str) -> dict[str, Any]:
    result = deepcopy(dict(row))
    result[field] = ""
    result[field] = digest(result)
    return result


def _event_digest(row: Mapping[str, Any], digest_field: str) -> str:
    return digest({key: value for key, value in row.items() if key not in {digest_field, "successor_head_sha256"}})


class ProductionProtectedPersistenceDeviceV1:
    """Removed callback boundary retained only for a stable rejection."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise ProtectedFactStoreError("protected_os_service_channel_required", "$.persistence")


class ProductionIndependentAnchorDeviceV1:
    """Removed callback boundary retained only for a stable rejection."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise ProtectedFactStoreError("protected_os_service_channel_required", "$.anchor")


class TestOnlyInMemoryPersistenceDeviceV1:
    classification = TEST_CLASSIFICATION

    def __init__(self, events: list[Mapping[str, Any]] | None = None) -> None:
        self._events = deepcopy(events or [])

    def recover(self) -> list[Mapping[str, Any]]:
        return deepcopy(self._events)

    def publish(self, event: Mapping[str, Any], expected_head_sha256: str) -> None:
        current = EMPTY_SHA256 if not self._events else self._events[-1]["successor_head_sha256"]
        if current != expected_head_sha256:
            raise ProtectedFactStoreError("protected_fact_expected_head_mismatch", "$.expected_head_sha256")
        self._events.append(deepcopy(dict(event)))


class TestOnlyInMemoryAnchorDeviceV1:
    classification = TEST_CLASSIFICATION

    def __init__(self, anchor: Mapping[str, Any] | None = None) -> None:
        self._anchor = deepcopy(dict(anchor)) if anchor is not None else {
            "sequence": 0, "generation": 0, "head_sha256": EMPTY_SHA256,
            "last_anchor_sha256": EMPTY_SHA256,
        }

    def recover(self) -> Mapping[str, Any]:
        return deepcopy(self._anchor)

    def publish(self, anchor: Mapping[str, Any], expected_head_sha256: str) -> None:
        if self._anchor["head_sha256"] != expected_head_sha256:
            raise ProtectedFactStoreError("protected_anchor_expected_head_mismatch", "$.expected_head_sha256")
        self._anchor = deepcopy(dict(anchor))


@dataclass(frozen=True, slots=True)
class ProtectedFactRead:
    state: str
    reason: str | None
    record: Mapping[str, Any] | None
    classification: str


class StoreDerivedAvailableFact:
    """Explicit test-only result. Production never accepts this object."""

    __slots__ = ("operation", "key", "value", "observed_at", "expires_at", "canonical_source_id", "source_digest", "_classification")

    def __init__(self, record: Mapping[str, Any], classification: str) -> None:
        if classification != TEST_CLASSIFICATION:
            raise ProtectedFactStoreError("store_derived_result_test_only", "$.result")
        self.operation = record["operation"]
        self.key = record["fact_key"]
        self.value = MappingProxyType(deepcopy(dict(record["fact_value"])))
        self.observed_at = _parse_time(record["observed_at"], "protected_fact_time_invalid", "$.record.observed_at")
        self.expires_at = _parse_time(record["expires_at"], "protected_fact_time_invalid", "$.record.expires_at")
        self.canonical_source_id = record["canonical_source_id"]
        self.source_digest = record["source_digest"]
        self._classification = classification

class FirstPartyProtectedWriterServiceV1:
    """Append-only writer and restart-safe fact reader."""

    def __init__(self, persistence: Any, anchor: Any, *, utc_clock: Callable[[], datetime], test_only: bool = False) -> None:
        if not test_only:
            raise ProtectedFactStoreError("protected_os_service_channel_required", "$.devices")
        expected_type = TestOnlyInMemoryPersistenceDeviceV1
        expected_anchor = TestOnlyInMemoryAnchorDeviceV1
        if type(persistence) is not expected_type or type(anchor) is not expected_anchor:
            raise ProtectedFactStoreError("protected_device_classification_invalid", "$.devices")
        if not callable(utc_clock):
            raise ProtectedFactStoreError("protected_fact_clock_invalid", "$.clock")
        self._persistence = persistence
        self._anchor = anchor
        self._clock = utc_clock
        self.classification = TEST_CLASSIFICATION
        self.recover()

    @classmethod
    def test_only(cls, persistence: TestOnlyInMemoryPersistenceDeviceV1, anchor: TestOnlyInMemoryAnchorDeviceV1, *, utc_clock: Callable[[], datetime]) -> "FirstPartyProtectedWriterServiceV1":
        return cls(persistence, anchor, utc_clock=utc_clock, test_only=True)

    def _now(self) -> datetime:
        value = self._clock()
        _format_time(value)
        return value.astimezone(timezone.utc).replace(microsecond=0)

    def recover(self) -> Mapping[str, Any]:
        events = self._persistence.recover()
        if not isinstance(events, list):
            raise ProtectedFactStoreError("protected_fact_log_invalid", "$.events")
        prior = EMPTY_SHA256
        generation = 0
        record_ids: dict[str, str] = {}
        revoked: set[str] = set()
        consumed: set[str] = set()
        facts: dict[str, dict[str, Any]] = {}
        for sequence, raw in enumerate(events, 1):
            kind = raw.get("artifact_type") if isinstance(raw, Mapping) else None
            fields = RECORD_FIELDS if kind == RECORD_TYPE else TRANSITION_FIELDS if kind == TRANSITION_TYPE else frozenset()
            row = _closed(raw, fields, "protected_fact_event_shape_invalid", "$.events")
            digest_field = "record_sha256" if kind == RECORD_TYPE else "transition_sha256"
            if row["sequence"] != sequence or row["generation"] != generation + 1 or row["prior_head_sha256"] != prior:
                raise ProtectedFactStoreError("protected_fact_chain_fork", "$.events")
            if _event_digest(row, digest_field) != row[digest_field] or row["successor_head_sha256"] != row[digest_field]:
                raise ProtectedFactStoreError("protected_fact_event_digest_mismatch", "$.events")
            if kind == RECORD_TYPE:
                self._validate_record(row)
                prior_record = record_ids.get(row["record_id"])
                if prior_record is not None:
                    code = "protected_fact_record_replay" if prior_record == row["record_sha256"] else "protected_fact_record_collision"
                    raise ProtectedFactStoreError(code, "$.record.record_id")
                record_ids[row["record_id"]] = row["record_sha256"]
                facts[row["record_sha256"]] = row
            else:
                target = row["target_record_sha256"]
                if target not in facts:
                    raise ProtectedFactStoreError("protected_fact_transition_target_missing", "$.transition.target_record_sha256")
                target_set = revoked if row["kind"] == "revoke" else consumed
                if target in revoked or target in consumed:
                    raise ProtectedFactStoreError("protected_fact_transition_replay", "$.transition.target_record_sha256")
                target_set.add(target)
            prior = row["successor_head_sha256"]
            generation = row["generation"]
        expected = {"sequence": len(events), "generation": generation, "head_sha256": prior,
                    "last_anchor_sha256": EMPTY_SHA256 if not events else events[-1]["anchor_receipt"]["receipt_sha256"]}
        anchor = _closed(self._anchor.recover(), HEAD_FIELDS, "protected_anchor_shape_invalid", "$.anchor")
        if anchor != expected:
            raise ProtectedFactStoreError("protected_anchor_parity_mismatch", "$.anchor")
        return MappingProxyType({"events": events, "facts": facts, "revoked": revoked, "consumed": consumed, "head": expected})

    def _validate_record(self, row: Mapping[str, Any]) -> None:
        if row["schema_version"] != 1 or row["artifact_type"] != RECORD_TYPE:
            raise ProtectedFactStoreError("protected_fact_record_identity_invalid", "$.record")
        for field in ("record_id", "operation", "canonical_source_id", "producer_principal_id", "namespace"):
            _identifier(row[field], "protected_fact_identifier_invalid", "$.record." + field)
        identity = _closed(row["identity"], IDENTITY_FIELDS, "protected_fact_identity_shape_invalid", "$.record.identity")
        if row["service_start_id"] != identity["service_start_id"] or row["generation"] < 1 or identity["generation"] < 1:
            raise ProtectedFactStoreError("protected_fact_identity_mismatch", "$.record.identity")
        for field in ("source_sha256", "candidate_sha256", "manifest_sha256"):
            _sha(identity[field], "protected_fact_identity_digest_invalid", "$.record.identity." + field)
        for field in ("profile_sha256", "operation_body_sha256", "dependency_receipts_sha256", "fact_sha256", "source_digest", "prior_head_sha256", "successor_head_sha256", "record_sha256"):
            _sha(row[field], "protected_fact_digest_invalid", "$.record." + field)
        if not isinstance(row["fact_value"], Mapping) or row["fact_sha256"] != digest({"key": row["fact_key"], "value": row["fact_value"]}):
            raise ProtectedFactStoreError("protected_fact_payload_digest_mismatch", "$.record.fact_sha256")
        issued = _parse_time(row["issued_at"], "protected_fact_time_invalid", "$.record.issued_at")
        observed = _parse_time(row["observed_at"], "protected_fact_time_invalid", "$.record.observed_at")
        expires = _parse_time(row["expires_at"], "protected_fact_time_invalid", "$.record.expires_at")
        if issued > observed or expires <= observed or row["revoked"] is not False or row["consumed"] is not False:
            raise ProtectedFactStoreError("protected_fact_time_or_state_invalid", "$.record")
        for name, receipt_type in (("writer_receipt", WRITER_RECEIPT_TYPE), ("anchor_receipt", ANCHOR_RECEIPT_TYPE)):
            receipt = row[name]
            if not isinstance(receipt, Mapping) or receipt.get("artifact_type") != receipt_type or receipt.get("receipt_sha256") != _seal(receipt, "receipt_sha256")["receipt_sha256"]:
                raise ProtectedFactStoreError("protected_fact_receipt_invalid", "$.record." + name)

    def append_fact(self, *, record_id: str, operation: str, canonical_source_id: str,
                    producer_principal_id: str, namespace: str, identity: Mapping[str, Any],
                    profile_sha256: str, operation_body: Mapping[str, Any],
                    dependency_receipts: Mapping[str, str], fact_key: str,
                    fact_value: Mapping[str, Any], source_digest: str, issued_at: str,
                    observed_at: str, expires_at: str, expected_sequence: int,
                    expected_generation: int, expected_head_sha256: str,
                    append_request: Mapping[str, Any]) -> Mapping[str, Any]:
        state = self.recover()
        head = state["head"]
        if (expected_sequence, expected_generation, expected_head_sha256) != (head["sequence"], head["generation"], head["head_sha256"]):
            raise ProtectedFactStoreError("protected_fact_expected_head_mismatch", "$.expected_head")
        same_id = [item for item in state["facts"].values() if item["record_id"] == record_id]
        if same_id:
            raise ProtectedFactStoreError("protected_fact_record_collision", "$.record_id")
        if not isinstance(dependency_receipts, Mapping) or any(not isinstance(k, str) or _SHA.fullmatch(v or "") is None for k, v in dependency_receipts.items()):
            raise ProtectedFactStoreError("protected_fact_dependencies_invalid", "$.dependency_receipts")
        sequence = expected_sequence + 1
        generation = expected_generation + 1
        writer = _seal({"schema_version": 1, "artifact_type": WRITER_RECEIPT_TYPE,
                        "sequence": sequence, "generation": generation,
                        "prior_head_sha256": expected_head_sha256,
                        "request_sha256": digest(append_request), "receipt_sha256": ""}, "receipt_sha256")
        anchor_receipt = _seal({"schema_version": 1, "artifact_type": ANCHOR_RECEIPT_TYPE,
                                "sequence": sequence, "generation": generation,
                                "prior_head_sha256": expected_head_sha256,
                                "writer_receipt_sha256": writer["receipt_sha256"],
                                "receipt_sha256": ""}, "receipt_sha256")
        row = {
            "schema_version": 1, "artifact_type": RECORD_TYPE, "record_id": record_id,
            "operation": operation, "canonical_source_id": canonical_source_id,
            "producer_principal_id": producer_principal_id, "namespace": namespace,
            "identity": deepcopy(dict(identity)), "profile_sha256": profile_sha256,
            "service_start_id": identity.get("service_start_id"),
            "operation_body_sha256": digest(operation_body),
            "dependency_receipts_sha256": digest(dict(sorted(dependency_receipts.items()))),
            "fact_key": fact_key, "fact_value": deepcopy(dict(fact_value)),
            "fact_sha256": digest({"key": fact_key, "value": fact_value}),
            "source_digest": source_digest, "issued_at": issued_at, "observed_at": observed_at,
            "expires_at": expires_at, "revoked": False, "consumed": False,
            "append_request": deepcopy(dict(append_request)), "writer_receipt": writer,
            "anchor_receipt": anchor_receipt, "sequence": sequence, "generation": generation,
            "prior_head_sha256": expected_head_sha256, "successor_head_sha256": "",
            "record_sha256": "",
        }
        row["record_sha256"] = _event_digest(row, "record_sha256")
        row["successor_head_sha256"] = row["record_sha256"]
        self._validate_record(row)
        self._publish(row, head)
        return MappingProxyType(deepcopy(row))

    def _publish(self, row: Mapping[str, Any], prior_head: Mapping[str, Any]) -> None:
        # Each device must provide atomic compare-and-publish.  Cross-device
        # interruption fails recovery closed until the deployment reconciles it.
        self._persistence.publish(row, prior_head["head_sha256"])
        anchor = {"sequence": row["sequence"], "generation": row["generation"],
                  "head_sha256": row["successor_head_sha256"],
                  "last_anchor_sha256": row["anchor_receipt"]["receipt_sha256"]}
        self._anchor.publish(anchor, prior_head["head_sha256"])
        self.recover()

    def transition(self, *, kind: str, transition_id: str, operation: str, namespace: str,
                   target_record_sha256: str, occurred_at: str, expected_sequence: int,
                   expected_generation: int, expected_head_sha256: str,
                   consumer_sha256: str | None = None) -> Mapping[str, Any]:
        if kind not in {"revoke", "consume"} or (kind == "consume") != (consumer_sha256 is not None):
            raise ProtectedFactStoreError("protected_fact_transition_invalid", "$.transition")
        state = self.recover(); head = state["head"]
        if (expected_sequence, expected_generation, expected_head_sha256) != (head["sequence"], head["generation"], head["head_sha256"]):
            raise ProtectedFactStoreError("protected_fact_expected_head_mismatch", "$.expected_head")
        if target_record_sha256 not in state["facts"]:
            raise ProtectedFactStoreError("protected_fact_transition_target_missing", "$.target")
        if target_record_sha256 in state["revoked"] or target_record_sha256 in state["consumed"]:
            raise ProtectedFactStoreError("protected_fact_transition_replay", "$.target")
        if kind == "consume" and state["facts"][target_record_sha256]["namespace"] != "recovery":
            raise ProtectedFactStoreError("protected_fact_consumption_namespace_invalid", "$.target")
        sequence = expected_sequence + 1; generation = expected_generation + 1
        writer = _seal({"schema_version": 1, "artifact_type": WRITER_RECEIPT_TYPE, "sequence": sequence,
                        "generation": generation, "prior_head_sha256": expected_head_sha256,
                        "request_sha256": digest({"kind": kind, "target": target_record_sha256}), "receipt_sha256": ""}, "receipt_sha256")
        anchor_receipt = _seal({"schema_version": 1, "artifact_type": ANCHOR_RECEIPT_TYPE, "sequence": sequence,
                                "generation": generation, "prior_head_sha256": expected_head_sha256,
                                "writer_receipt_sha256": writer["receipt_sha256"], "receipt_sha256": ""}, "receipt_sha256")
        core = {"schema_version": 1, "artifact_type": TRANSITION_TYPE, "transition_id": transition_id,
                "kind": kind, "operation": operation, "namespace": namespace,
                "target_record_sha256": target_record_sha256, "consumer_sha256": consumer_sha256,
                "occurred_at": occurred_at, "sequence": sequence, "generation": generation,
                "prior_head_sha256": expected_head_sha256, "writer_receipt": writer,
                "anchor_receipt": anchor_receipt}
        head_digest = digest(core)
        row = {**core, "successor_head_sha256": head_digest, "transition_sha256": head_digest}
        self._publish(row, head)
        return MappingProxyType(deepcopy(row))

    def read_fact(self, *, operation: str, canonical_source_id: str, producer_principal_id: str,
                  namespace: str, identity: Mapping[str, Any], profile_sha256: str,
                  operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str],
                  now: datetime) -> ProtectedFactRead:
        try:
            state = self.recover()
            current = _format_time(now)
        except ProtectedFactStoreError as exc:
            return ProtectedFactRead("unavailable", exc.code, None, self.classification)
        matches = []
        for record_sha, row in state["facts"].items():
            if row["operation"] != operation:
                continue
            expected = (
                row["canonical_source_id"] == canonical_source_id,
                row["producer_principal_id"] == producer_principal_id,
                row["namespace"] == namespace,
                row["identity"] == dict(identity),
                row["profile_sha256"] == profile_sha256,
                row["service_start_id"] == identity.get("service_start_id"),
                row["operation_body_sha256"] == digest(operation_body),
                row["dependency_receipts_sha256"] == digest(dict(sorted(dependency_receipts.items()))),
            )
            if all(expected):
                matches.append((record_sha, row))
        if len(matches) != 1:
            return ProtectedFactRead("unavailable", "protected_fact_absent" if not matches else "protected_fact_collision", None, self.classification)
        record_sha, row = matches[0]
        if record_sha in state["revoked"]:
            return ProtectedFactRead("unavailable", "protected_fact_revoked", None, self.classification)
        if record_sha in state["consumed"]:
            return ProtectedFactRead("unavailable", "protected_fact_consumed", None, self.classification)
        observed = _parse_time(row["observed_at"], "protected_fact_time_invalid", "$.record.observed_at")
        expires = _parse_time(row["expires_at"], "protected_fact_time_invalid", "$.record.expires_at")
        if observed > now or expires <= now or current < row["issued_at"]:
            return ProtectedFactRead("unavailable", "protected_fact_time_invalid", None, self.classification)
        return ProtectedFactRead("available", None, MappingProxyType(deepcopy(row)), self.classification)


class ProtectedFactStoreClientV1:
    __slots__ = ("_service", "classification")

    def __init__(self, service: FirstPartyProtectedWriterServiceV1) -> None:
        if type(service) is not FirstPartyProtectedWriterServiceV1:
            raise ProtectedFactStoreError("protected_fact_service_invalid", "$.service")
        self._service = service
        self.classification = service.classification

    def read_fact(self, **query: Any) -> ProtectedFactRead:
        return self._service.read_fact(**query)

    def promote(self, read: ProtectedFactRead) -> StoreDerivedAvailableFact:
        if not isinstance(read, ProtectedFactRead) or read.state != "available" or read.record is None or read.classification != self.classification:
            raise ProtectedFactStoreError("protected_fact_promotion_invalid", "$.read")
        return StoreDerivedAvailableFact(read.record, self.classification)


__all__ = [
    "ANCHOR_RECEIPT_TYPE", "EMPTY_SHA256", "FirstPartyProtectedWriterServiceV1",
    "PRODUCTION_CLASSIFICATION", "ProductionIndependentAnchorDeviceV1",
    "ProductionProtectedPersistenceDeviceV1", "ProtectedFactRead",
    "ProtectedFactStoreClientV1", "ProtectedFactStoreError", "RECORD_TYPE",
    "StoreDerivedAvailableFact", "TEST_CLASSIFICATION", "TRANSITION_TYPE",
    "TestOnlyInMemoryAnchorDeviceV1", "TestOnlyInMemoryPersistenceDeviceV1",
    "WRITER_RECEIPT_TYPE", "digest",
]
