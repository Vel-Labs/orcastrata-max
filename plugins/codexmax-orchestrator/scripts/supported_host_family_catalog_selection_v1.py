#!/usr/bin/env python3
"""Durable first-party owner for the complete accepted T067 ledger.

The public methods accept operation-specific source observations.  They do not
accept a T067 decision, ledger, head, source identity, principal, callback, or
promotion flag.  The owner constructs every accepted T067 byte itself.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

import supported_host_catalog_selection_v1 as t067


PROTOCOL_VERSION = "supported_host_family_catalog_selection_v1"
LEDGER_ID = "first-party-catalog-selection-ledger-v1"
OWNER_ID = "catalog_selection"
PRINCIPAL_ID = "first-party-catalog-selection-producer-v1"
MANIFEST_TYPE = "supported_host_family_catalog_selection_manifest_v1"
ANCHOR_TYPE = "supported_host_family_catalog_selection_anchor_v1"
ARTIFACT_TYPE = "supported_host_family_catalog_selection_successor_v1"
EXECUTION_SCOPE = "source_local_quarantine_non_production"
SOURCE_BUILD_SHA256 = "sha256:" + hashlib.sha256(b"supported_host_family_catalog_selection_v1").hexdigest()
DEPENDENCIES = {
    "read_operator_preset_bundle": frozenset({"open_operator_listener"}),
    "read_operator_selection_head": frozenset({"read_operator_preset_bundle"}),
    "read_operator_selection_mutation": frozenset({"read_operator_selection_head"}),
    "commit_operator_selection": frozenset({"read_operator_selection_mutation"}),
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class CatalogFamilyError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True, slots=True)
class LedgerSuccessor:
    operation: str
    acquisition_id: str
    ledger_sequence: int
    predecessor_head_sha256: str
    predecessor_ledger_sha256: str
    predecessor_ledger_bytes: bytes
    successor_head_sha256: str
    ledger_sha256: str
    ledger_bytes: bytes
    decision_sha256: str
    execution_scope: str = EXECUTION_SCOPE


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CatalogFamilyError("family_json_invalid") from exc


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return _digest_bytes(_json_bytes(value))


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise CatalogFamilyError("family_identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise CatalogFamilyError("family_digest_invalid", path)
    return value


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise CatalogFamilyError("family_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _format(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _replace(path: Path, data: bytes) -> None:
    temporary = path.with_name("." + path.name + ".pending")
    if temporary.exists():
        raise CatalogFamilyError("family_pending_residue", str(temporary))
    _write_new(temporary, data)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _read_exact(path: Path) -> tuple[bytes, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise CatalogFamilyError("family_file_invalid", str(path))
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read()
        finally:
            os.close(descriptor)
        value = json.loads(data)
    except CatalogFamilyError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogFamilyError("family_file_invalid", str(path)) from exc
    if _json_bytes(value) != data:
        raise CatalogFamilyError("family_noncanonical_bytes", str(path))
    return data, value


def _manifest() -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": MANIFEST_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "owner_id": OWNER_ID,
        "producer_principal_id": PRINCIPAL_ID,
        "ledger_id": LEDGER_ID,
        "source_build_sha256": SOURCE_BUILD_SHA256,
        "execution_scope": EXECUTION_SCOPE,
        "operations": list(t067.OPERATIONS),
        "manifest_sha256": "",
    }
    row["manifest_sha256"] = _digest({key: value for key, value in row.items() if key != "manifest_sha256"})
    return row


def _anchor(ledger: Mapping[str, Any], ledger_bytes: bytes) -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": ANCHOR_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "owner_id": OWNER_ID,
        "ledger_id": LEDGER_ID,
        "ledger_sequence": len(ledger["events"]),
        "ledger_head_sha256": ledger["head_sha256"],
        "ledger_sha256": _digest_bytes(ledger_bytes),
        "anchor_sha256": "",
    }
    row["anchor_sha256"] = _digest({key: value for key, value in row.items() if key != "anchor_sha256"})
    return row


def _validate_anchor(value: Any, ledger: Mapping[str, Any], data: bytes) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "protocol_version", "owner_id", "ledger_id", "ledger_sequence", "ledger_head_sha256", "ledger_sha256", "anchor_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CatalogFamilyError("family_anchor_invalid", "$.anchor")
    row = dict(value)
    if row["schema_version"] != 1 or row["artifact_type"] != ANCHOR_TYPE or row["protocol_version"] != PROTOCOL_VERSION or row["owner_id"] != OWNER_ID or row["ledger_id"] != LEDGER_ID:
        raise CatalogFamilyError("family_anchor_invalid", "$.anchor")
    if type(row["ledger_sequence"]) is not int or row["ledger_sequence"] != len(ledger["events"]):
        raise CatalogFamilyError("family_truncation_detected", "$.anchor.ledger_sequence")
    if row["ledger_head_sha256"] != ledger["head_sha256"] or row["ledger_sha256"] != _digest_bytes(data):
        raise CatalogFamilyError("family_anchor_mismatch", "$.anchor")
    if row["anchor_sha256"] != _digest({key: item for key, item in row.items() if key != "anchor_sha256"}):
        raise CatalogFamilyError("family_anchor_invalid", "$.anchor.anchor_sha256")
    return row


class CatalogSelectionFamilyStore:
    """Retain complete canonical T067 ledger snapshots under owner-local CAS."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.snapshots = root / "snapshots"
        self.lock_path = root / "owner.lock"
        self.manifest_path = root / "manifest.json"
        self.anchor_path = root / "anchor.json"
        self.recover()

    @classmethod
    def create_source_local(cls, root: Path) -> "CatalogSelectionFamilyStore":
        if not root.is_absolute() or root.exists() or root.is_symlink():
            raise CatalogFamilyError("family_root_invalid", "$.root")
        root.mkdir(mode=0o700)
        (root / "snapshots").mkdir(mode=0o700)
        _write_new(root / "manifest.json", _json_bytes(_manifest()))
        ledger = t067.new_ledger(LEDGER_ID)
        ledger_bytes = _json_bytes(ledger)
        _write_new(root / "snapshots" / "00000000000000000000.json", ledger_bytes)
        _write_new(root / "anchor.json", _json_bytes(_anchor(ledger, ledger_bytes)))
        _write_new(root / "owner.lock", b"")
        return cls(root)

    def _lock(self):
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    def _snapshot_paths(self) -> list[Path]:
        paths = sorted(self.snapshots.iterdir())
        if any(path.is_symlink() or not path.is_file() or not re.fullmatch(r"\d{20}\.json", path.name) for path in paths):
            raise CatalogFamilyError("family_snapshot_inventory_invalid", "$.snapshots")
        return paths

    def recover(self) -> dict[str, Any]:
        manifest_bytes, manifest = _read_exact(self.manifest_path)
        if manifest_bytes != _json_bytes(_manifest()):
            raise CatalogFamilyError("family_manifest_invalid", "$.manifest")
        paths = self._snapshot_paths()
        if not paths:
            raise CatalogFamilyError("family_truncation_detected", "$.snapshots")
        previous: dict[str, Any] | None = None
        for sequence, path in enumerate(paths):
            if path.name != f"{sequence:020d}.json":
                raise CatalogFamilyError("family_snapshot_gap", str(path))
            data, raw = _read_exact(path)
            try:
                ledger = t067.validate_ledger(raw)
            except t067.CatalogSelectionError as exc:
                raise CatalogFamilyError("family_t067_invalid", str(path)) from exc
            if len(ledger["events"]) != sequence:
                raise CatalogFamilyError("family_snapshot_sequence_invalid", str(path))
            if previous is not None and ledger["events"][:-1] != previous["events"]:
                raise CatalogFamilyError("family_fork_detected", str(path))
            previous = ledger
        assert previous is not None
        latest_data = data
        _, raw_anchor = _read_exact(self.anchor_path)
        _validate_anchor(raw_anchor, previous, latest_data)
        return deepcopy(previous)

    def current_anchor(self) -> dict[str, Any]:
        ledger = self.recover()
        data, _ = _read_exact(self.snapshots / f"{len(ledger['events']):020d}.json")
        return _anchor(ledger, data)

    def _latest_issue(self, ledger: Mapping[str, Any], operation: str) -> Mapping[str, Any] | None:
        revoked = {event["decision_sha256"] for event in ledger["events"] if event["event_type"] == "revoke"}
        for event in reversed(ledger["events"]):
            if event["event_type"] == "issue" and event["operation"] == operation and event["decision_sha256"] not in revoked:
                return event["decision"]
        return None

    def _existing(self, ledger: Mapping[str, Any], acquisition_id: str, request_sha256: str) -> LedgerSuccessor | None:
        revoked = {event["decision_sha256"] for event in ledger["events"] if event["event_type"] == "revoke"}
        for index, event in enumerate(ledger["events"], 1):
            if event["event_type"] != "issue" or event["decision_id"] != acquisition_id:
                continue
            decision = event["decision"]
            actual = _digest({"operation": decision["operation"], "payload": decision["payload"], "identity_sha256": decision["identity_sha256"], "operation_body_sha256": decision["operation_body_sha256"], "dependency_receipts_sha256": decision["dependency_receipts_sha256"]})
            if actual != request_sha256:
                raise CatalogFamilyError("family_acquisition_collision", "$.acquisition_id")
            if decision["decision_sha256"] in revoked:
                raise CatalogFamilyError("family_acquisition_revoked", "$.acquisition_id")
            snapshot = self.snapshots / f"{index:020d}.json"
            data, stored_raw = _read_exact(snapshot)
            stored = t067.validate_ledger(stored_raw)
            predecessor_data, predecessor_raw = _read_exact(self.snapshots / f"{index - 1:020d}.json")
            predecessor_ledger = t067.validate_ledger(predecessor_raw)
            return LedgerSuccessor(decision["operation"], acquisition_id, index,
                predecessor_ledger["head_sha256"], _digest_bytes(predecessor_data), predecessor_data,
                stored["head_sha256"], _digest_bytes(data), data, decision["decision_sha256"])
        return None

    def _retry_for_raw(self, ledger: Mapping[str, Any], acquisition_id: str, operation: str,
                       raw_request: Mapping[str, Any], identity: Mapping[str, Any],
                       operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str]) -> LedgerSuccessor | None:
        revoked = {event["decision_sha256"] for event in ledger["events"] if event["event_type"] == "revoke"}
        for index, event in enumerate(ledger["events"], 1):
            if event["event_type"] != "issue" or event["decision_id"] != acquisition_id:
                continue
            decision = event["decision"]
            payload = decision["payload"]
            if operation == "read_operator_preset_bundle":
                stored_raw = {"catalog_id": payload["catalog_id"], "presets": payload["presets"]}
            elif operation == "read_operator_selection_head":
                stored_raw = {key: payload[key] for key in ("bundle_sha256", "binding_sha256", "selection_sha256", "selection_version")}
            elif operation == "read_operator_selection_mutation":
                stored_raw = deepcopy(payload)
            else:
                stored_raw = {key: payload[key] for key in ("submission_id", "submission_sha256", "requested_selection_sha256")}
            bindings_match = (
                decision["operation"] == operation
                and decision["identity_sha256"] == t067.canonical_digest(identity)
                and decision["operation_body_sha256"] == t067.canonical_digest(operation_body)
                and decision["dependency_receipts_sha256"] == t067.canonical_digest(dict(sorted(dependency_receipts.items())))
            )
            if not bindings_match or stored_raw != raw_request:
                raise CatalogFamilyError("family_acquisition_collision", "$.acquisition_id")
            if decision["decision_sha256"] in revoked:
                raise CatalogFamilyError("family_acquisition_revoked", "$.acquisition_id")
            data, stored_raw = _read_exact(self.snapshots / f"{index:020d}.json")
            stored = t067.validate_ledger(stored_raw)
            predecessor_data, predecessor_raw = _read_exact(self.snapshots / f"{index - 1:020d}.json")
            predecessor_ledger = t067.validate_ledger(predecessor_raw)
            return LedgerSuccessor(operation, acquisition_id, index,
                predecessor_ledger["head_sha256"], _digest_bytes(predecessor_data), predecessor_data,
                stored["head_sha256"], _digest_bytes(data), data, decision["decision_sha256"])
        return None

    def _commit(self, operation: str, acquisition_id: str, payload: Mapping[str, Any], *, expected_family_head_sha256: str, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], owner_now: datetime) -> LedgerSuccessor:
        _identifier(acquisition_id, "$.acquisition_id")
        if not isinstance(identity, Mapping) or not isinstance(operation_body, Mapping) or not isinstance(dependency_receipts, Mapping):
            raise CatalogFamilyError("family_query_invalid", "$.query")
        if set(dependency_receipts) != set(DEPENDENCIES[operation]):
            raise CatalogFamilyError("family_dependencies_invalid", "$.dependency_receipts")
        for name, receipt in dependency_receipts.items():
            _identifier(name, "$.dependency_receipts")
            _sha(receipt, "$.dependency_receipts." + name)
        now = _utc(owner_now, "$.owner_now")
        identity_sha = t067.canonical_digest(identity)
        body_sha = t067.canonical_digest(operation_body)
        dependencies_sha = t067.canonical_digest(dict(sorted(dependency_receipts.items())))
        request_sha = _digest({"operation": operation, "payload": payload, "identity_sha256": identity_sha, "operation_body_sha256": body_sha, "dependency_receipts_sha256": dependencies_sha})
        descriptor = self._lock()
        try:
            ledger = self.recover()
            retried = self._existing(ledger, acquisition_id, request_sha)
            if retried is not None:
                return retried
            if ledger["head_sha256"] != expected_family_head_sha256:
                raise CatalogFamilyError("family_stale_owner_state", "$.ledger")
            generation = payload.get("generation", payload.get("catalog_generation", 1))
            decision = {
                "schema_version": 1, "artifact_type": t067.DECISION_TYPE,
                "decision_id": acquisition_id, "decision_source_id": t067.SOURCE_IDS[operation],
                "ledger_id": LEDGER_ID, "operation": operation, "variant": t067.VARIANTS[operation],
                "identity_sha256": identity_sha, "operation_body_sha256": body_sha,
                "dependency_receipts_sha256": dependencies_sha,
                "source_sha256": _digest({"owner": OWNER_ID, "operation": operation, "acquisition_id": acquisition_id, "payload_sha256": _digest(payload)}),
                "candidate_sha256": _digest(payload), "manifest_sha256": _manifest()["manifest_sha256"],
                "generation": generation, "payload": deepcopy(dict(payload)),
                "observed_at": _format(now), "expires_at": _format(now + timedelta(seconds=60)),
                "decision_sha256": "",
            }
            decision["decision_sha256"] = t067.canonical_digest({key: item for key, item in decision.items() if key != "decision_sha256"})
            successor = t067.issue_decision(
                ledger, decision, expected_head_sha256=ledger["head_sha256"], expected_ledger_id=LEDGER_ID,
                expected_operation=operation, expected_identity_sha256=identity_sha,
                expected_operation_body_sha256=body_sha, expected_dependency_receipts_sha256=dependencies_sha,
                expected_source_sha256=decision["source_sha256"], expected_candidate_sha256=decision["candidate_sha256"],
                expected_manifest_sha256=decision["manifest_sha256"], expected_generation=generation, now=now,
            )
            data = _json_bytes(successor)
            sequence = len(successor["events"])
            _write_new(self.snapshots / f"{sequence:020d}.json", data)
            _replace(self.anchor_path, _json_bytes(_anchor(successor, data)))
            self.recover()
            predecessor_data = _json_bytes(ledger)
            return LedgerSuccessor(operation, acquisition_id, sequence,
                ledger["head_sha256"], _digest_bytes(predecessor_data), predecessor_data,
                successor["head_sha256"], _digest_bytes(data), data, decision["decision_sha256"])
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def publish_catalog(self, *, acquisition_id: str, catalog_id: str, presets: list[Mapping[str, Any]], identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], owner_now: datetime) -> LedgerSuccessor:
        ledger = self.recover()
        normalized = [deepcopy(dict(item)) for item in presets]
        retried = self._retry_for_raw(ledger, acquisition_id, "read_operator_preset_bundle",
            {"catalog_id": catalog_id, "presets": normalized}, identity, operation_body, dependency_receipts)
        if retried is not None:
            return retried
        prior = self._latest_issue(ledger, "read_operator_preset_bundle")
        generation = 1 if prior is None else prior["payload"]["generation"] + 1
        history = [] if prior is None else deepcopy(prior["payload"]["history"]) + [{"generation": prior["payload"]["generation"], "catalog_sha256": t067.canonical_digest(prior["payload"]), "previous_catalog_sha256": prior["payload"]["previous_catalog_sha256"]}]
        payload = {"catalog_id": catalog_id, "generation": generation,
            "previous_catalog_sha256": None if prior is None else t067.canonical_digest(prior["payload"]),
            "presets": normalized, "history": history,
            "qualification_set_sha256": t067.canonical_digest(sorted(item["qualification_input_sha256"] for item in normalized))}
        return self._commit("read_operator_preset_bundle", acquisition_id, payload, expected_family_head_sha256=ledger["head_sha256"], identity=identity, operation_body=operation_body, dependency_receipts=dependency_receipts, owner_now=owner_now)

    def observe_selection_head(self, *, acquisition_id: str, bundle_sha256: str, binding_sha256: str, selection_sha256: str, selection_version: int, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], owner_now: datetime) -> LedgerSuccessor:
        ledger = self.recover()
        raw_request = {"bundle_sha256": bundle_sha256, "binding_sha256": binding_sha256,
            "selection_sha256": selection_sha256, "selection_version": selection_version}
        retried = self._retry_for_raw(ledger, acquisition_id, "read_operator_selection_head",
            raw_request, identity, operation_body, dependency_receipts)
        if retried is not None:
            return retried
        catalog = self._latest_issue(ledger, "read_operator_preset_bundle")
        if catalog is None:
            raise CatalogFamilyError("family_catalog_missing", "$.catalog")
        payload = {"catalog_sha256": t067.canonical_digest(catalog["payload"]), "bundle_sha256": bundle_sha256,
            "catalog_generation": catalog["payload"]["generation"], "binding_sha256": binding_sha256,
            "selection_sha256": selection_sha256, "selection_version": selection_version}
        return self._commit("read_operator_selection_head", acquisition_id, payload, expected_family_head_sha256=ledger["head_sha256"], identity=identity, operation_body=operation_body, dependency_receipts=dependency_receipts, owner_now=owner_now)

    def observe_mutation_query(self, *, acquisition_id: str, submission_id: str, submission_sha256: str, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], owner_now: datetime) -> LedgerSuccessor:
        ledger = self.recover()
        raw_request = {"submission_id": submission_id, "submission_sha256": submission_sha256}
        retried = self._retry_for_raw(ledger, acquisition_id, "read_operator_selection_mutation",
            raw_request, identity, operation_body, dependency_receipts)
        if retried is not None:
            return retried
        if self._latest_issue(ledger, "read_operator_selection_head") is None:
            raise CatalogFamilyError("family_selection_head_missing", "$.selection_head")
        return self._commit("read_operator_selection_mutation", acquisition_id, raw_request, expected_family_head_sha256=ledger["head_sha256"], identity=identity, operation_body=operation_body, dependency_receipts=dependency_receipts, owner_now=owner_now)

    def authorize_commit(self, *, acquisition_id: str, submission_id: str, submission_sha256: str, requested_selection_sha256: str, identity: Mapping[str, Any], operation_body: Mapping[str, Any], dependency_receipts: Mapping[str, str], owner_now: datetime) -> LedgerSuccessor:
        ledger = self.recover()
        raw_request = {"submission_id": submission_id, "submission_sha256": submission_sha256,
            "requested_selection_sha256": requested_selection_sha256}
        retried = self._retry_for_raw(ledger, acquisition_id, "commit_operator_selection",
            raw_request, identity, operation_body, dependency_receipts)
        if retried is not None:
            return retried
        mutation = self._latest_issue(ledger, "read_operator_selection_mutation")
        head = self._latest_issue(ledger, "read_operator_selection_head")
        if mutation is None or head is None or mutation["payload"] != {"submission_id": submission_id, "submission_sha256": submission_sha256}:
            raise CatalogFamilyError("family_mutation_observation_mismatch", "$.submission_id")
        payload = {"submission_id": submission_id, "submission_sha256": submission_sha256,
            "expected_selection_version": head["payload"]["selection_version"],
            "current_selection_sha256": head["payload"]["selection_sha256"],
            "requested_selection_sha256": requested_selection_sha256}
        return self._commit("commit_operator_selection", acquisition_id, payload, expected_family_head_sha256=ledger["head_sha256"], identity=identity, operation_body=operation_body, dependency_receipts=dependency_receipts, owner_now=owner_now)

    def revoke(self, *, decision_sha256: str, reason: str, owner_now: datetime) -> LedgerSuccessor:
        descriptor = self._lock()
        try:
            ledger = self.recover()
            issue = next((event for event in ledger["events"] if event["event_type"] == "issue" and event["decision_sha256"] == decision_sha256), None)
            if issue is None:
                raise CatalogFamilyError("family_revoke_target_missing", "$.decision_sha256")
            successor = t067.revoke_decision(ledger, decision_sha256=decision_sha256, reason=reason,
                expected_head_sha256=ledger["head_sha256"], occurred_at=_utc(owner_now, "$.owner_now"))
            data = _json_bytes(successor)
            sequence = len(successor["events"])
            _write_new(self.snapshots / f"{sequence:020d}.json", data)
            _replace(self.anchor_path, _json_bytes(_anchor(successor, data)))
            self.recover()
            predecessor_data = _json_bytes(ledger)
            return LedgerSuccessor(issue["operation"], issue["decision_id"], sequence,
                ledger["head_sha256"], _digest_bytes(predecessor_data), predecessor_data,
                successor["head_sha256"], _digest_bytes(data), data, decision_sha256)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def revalidate_successor(artifact: LedgerSuccessor) -> dict[str, Any]:
        if not isinstance(artifact, LedgerSuccessor) or artifact.execution_scope != EXECUTION_SCOPE:
            raise CatalogFamilyError("family_successor_invalid", "$.artifact")
        if _digest_bytes(artifact.predecessor_ledger_bytes) != artifact.predecessor_ledger_sha256:
            raise CatalogFamilyError("family_predecessor_bytes_mismatch", "$.artifact.predecessor_ledger_bytes")
        if _digest_bytes(artifact.ledger_bytes) != artifact.ledger_sha256:
            raise CatalogFamilyError("family_successor_bytes_mismatch", "$.artifact.ledger_bytes")
        try:
            predecessor_raw = json.loads(artifact.predecessor_ledger_bytes)
            raw = json.loads(artifact.ledger_bytes)
        except json.JSONDecodeError as exc:
            raise CatalogFamilyError("family_successor_invalid", "$.artifact.ledger_bytes") from exc
        if _json_bytes(predecessor_raw) != artifact.predecessor_ledger_bytes or _json_bytes(raw) != artifact.ledger_bytes:
            raise CatalogFamilyError("family_noncanonical_bytes", "$.artifact.ledger_bytes")
        predecessor = t067.validate_ledger(predecessor_raw)
        ledger = t067.validate_ledger(raw)
        if (len(predecessor["events"]) + 1 != artifact.ledger_sequence
                or predecessor["head_sha256"] != artifact.predecessor_head_sha256
                or ledger["events"][:-1] != predecessor["events"]
                or len(ledger["events"]) != artifact.ledger_sequence
                or ledger["head_sha256"] != artifact.successor_head_sha256):
            raise CatalogFamilyError("family_successor_binding_mismatch", "$.artifact")
        event = ledger["events"][-1]
        if event["operation"] != artifact.operation or event["decision_sha256"] != artifact.decision_sha256:
            raise CatalogFamilyError("family_successor_binding_mismatch", "$.artifact")
        return ledger


__all__ = ["CatalogFamilyError", "CatalogSelectionFamilyStore", "LedgerSuccessor", "EXECUTION_SCOPE", "LEDGER_ID", "OWNER_ID", "PRINCIPAL_ID", "PROTOCOL_VERSION"]
