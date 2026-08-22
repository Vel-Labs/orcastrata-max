#!/usr/bin/env python3
"""Durable first-party owner for the accepted T068 and T069 mechanisms."""

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
from typing import Any, Mapping, Sequence

import supported_host_recovery_v1 as t069
import supported_host_supervision_v1 as t068
import supported_host_effect_authority_v1 as t064
import supported_host_family_responses_seals_v1 as responses_family


PROTOCOL_VERSION = "supported_host_family_native_recovery_v1"
OWNER_ID = "native_recovery"
PRINCIPAL_ID = "first-party-native-recovery-producer-v1"
NATIVE_OPERATION = t068.OPERATION
RECOVERY_OPERATION = t069.OPERATION
NATIVE_SOURCE_ID = t068.SOURCE_ID
RECOVERY_SOURCE_ID = t069.SOURCE_ID
RECOVERY_LEDGER_ID = "first-party-recovery-ledger-v1"
EXECUTION_SCOPE = "source_local_quarantine_non_production"
MANIFEST_TYPE = "supported_host_family_native_recovery_manifest_v1"
ANCHOR_TYPE = "supported_host_family_native_recovery_anchor_v1"
INVENTORY_TYPE = "supported_host_family_native_inventory_v1"
CONSUMPTION_TYPE = "supported_host_family_recovery_consumption_v1"
SOURCE_BUILD_SHA256 = "sha256:" + hashlib.sha256(PROTOCOL_VERSION.encode()).hexdigest()
NATIVE_OWNER_ID = "native-supervision"
RECOVERY_OWNER_ID = "recovery"
NATIVE_SPLIT_PROTOCOL = "supported_host_native_supervision_family_v1"
RECOVERY_SPLIT_PROTOCOL = "supported_host_recovery_family_v1"
SPLIT_MANIFEST_TYPE = "supported_host_native_recovery_split_manifest_v1"
SPLIT_SNAPSHOT_TYPE = "supported_host_native_recovery_split_snapshot_v1"
SPLIT_ANCHOR_TYPE = "supported_host_native_recovery_split_anchor_v1"
SPLIT_TRANSITION_TYPE = "supported_host_native_recovery_split_transition_v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class NativeRecoveryFamilyError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


@dataclass(frozen=True, slots=True)
class NativeSuccessor:
    operation: str
    acquisition_id: str
    predecessor_candidate_sha256: str | None
    predecessor_chain_bytes: bytes
    successor_candidate_sha256: str
    successor_chain_bytes: bytes
    candidate_bytes: bytes
    inventory_bytes: bytes
    execution_scope: str = EXECUTION_SCOPE


@dataclass(frozen=True, slots=True)
class RecoverySuccessor:
    operation: str
    acquisition_id: str
    predecessor_head_sha256: str
    predecessor_ledger_bytes: bytes
    reservation_sha256: str
    grant_sha256: str
    successor_head_sha256: str
    successor_ledger_bytes: bytes
    execution_scope: str = EXECUTION_SCOPE


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise NativeRecoveryFamilyError("family_canonical_value_invalid") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise NativeRecoveryFamilyError("family_identifier_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise NativeRecoveryFamilyError("family_digest_invalid", path)
    return value


def _positive(value: Any, path: str, *, zero: bool = False) -> int:
    if type(value) is not int or value < (0 if zero else 1):
        raise NativeRecoveryFamilyError("family_integer_invalid", path)
    return value


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise NativeRecoveryFamilyError("family_clock_invalid", path)
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
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _replace(path: Path, data: bytes) -> None:
    temporary = path.with_name("." + path.name + ".pending")
    if temporary.exists() or temporary.is_symlink():
        raise NativeRecoveryFamilyError("family_pending_residue", str(temporary))
    _write_new(temporary, data)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _read_exact(path: Path) -> tuple[bytes, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
            raise NativeRecoveryFamilyError("family_file_invalid", str(path))
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            data = b""
            while True:
                part = os.read(descriptor, 65536)
                if not part:
                    break
                data += part
        finally:
            os.close(descriptor)
        value = json.loads(data)
    except NativeRecoveryFamilyError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NativeRecoveryFamilyError("family_file_invalid", str(path)) from exc
    if data != _canonical_bytes(value):
        raise NativeRecoveryFamilyError("family_noncanonical_bytes", str(path))
    return data, value


def _manifest() -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": MANIFEST_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "owner_id": OWNER_ID,
        "producer_principal_id": PRINCIPAL_ID,
        "operations": [NATIVE_OPERATION, RECOVERY_OPERATION],
        "native_source_id": NATIVE_SOURCE_ID,
        "recovery_source_id": RECOVERY_SOURCE_ID,
        "recovery_ledger_id": RECOVERY_LEDGER_ID,
        "source_build_sha256": SOURCE_BUILD_SHA256,
        "execution_scope": EXECUTION_SCOPE,
        "manifest_sha256": "",
    }
    row["manifest_sha256"] = _digest({key: item for key, item in row.items() if key != "manifest_sha256"})
    return row


def _anchor(native_chain: Sequence[Mapping[str, Any]], recovery_ledger: Mapping[str, Any], consumptions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": ANCHOR_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "native_sequence": len(native_chain),
        "native_head_sha256": None if not native_chain else native_chain[-1]["candidate_sha256"],
        "native_chain_bytes_sha256": _bytes_digest(_canonical_bytes(list(native_chain))),
        "recovery_sequence": len(recovery_ledger["events"]),
        "recovery_head_sha256": recovery_ledger["head_sha256"],
        "recovery_ledger_bytes_sha256": _bytes_digest(_canonical_bytes(recovery_ledger)),
        "consumption_sequence": len(consumptions),
        "consumptions_bytes_sha256": _bytes_digest(_canonical_bytes(list(consumptions))),
        "anchor_sha256": "",
    }
    row["anchor_sha256"] = _digest({key: item for key, item in row.items() if key != "anchor_sha256"})
    return row


def _validate_consumptions(value: Any, ledger: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise NativeRecoveryFamilyError("family_consumptions_invalid", "$.consumptions")
    issued = {event["decision_sha256"] for event in ledger["events"] if event["event_type"] == "issue" and event["decision"]["variant"] == "recovery_lease_grant_candidate"}
    revoked = {event["decision_sha256"] for event in ledger["events"] if event["event_type"] == "revoke"}
    seen: set[str] = set()
    previous: str | None = None
    rows: list[dict[str, Any]] = []
    fields = {"schema_version", "artifact_type", "sequence", "grant_sha256", "use_receipt_sha256", "observed_at", "previous_consumption_sha256", "consumption_sha256"}
    for index, raw in enumerate(value, 1):
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise NativeRecoveryFamilyError("family_consumption_shape_invalid", f"$.consumptions[{index - 1}]")
        row = deepcopy(dict(raw))
        if row["schema_version"] != 1 or row["artifact_type"] != CONSUMPTION_TYPE or row["sequence"] != index:
            raise NativeRecoveryFamilyError("family_consumption_sequence_invalid", f"$.consumptions[{index - 1}]")
        _sha(row["grant_sha256"], "$.consumptions.grant_sha256")
        _sha(row["use_receipt_sha256"], "$.consumptions.use_receipt_sha256")
        t069._time(row["observed_at"], "$.consumptions.observed_at")
        if row["grant_sha256"] not in issued or row["grant_sha256"] in revoked:
            raise NativeRecoveryFamilyError("family_consumption_grant_invalid", "$.consumptions.grant_sha256")
        if row["grant_sha256"] in seen:
            raise NativeRecoveryFamilyError("family_consumption_duplicate", "$.consumptions.grant_sha256")
        if row["previous_consumption_sha256"] != previous:
            raise NativeRecoveryFamilyError("family_consumption_chain_broken", "$.consumptions.previous_consumption_sha256")
        expected = _digest({key: item for key, item in row.items() if key != "consumption_sha256"})
        if row["consumption_sha256"] != expected:
            raise NativeRecoveryFamilyError("family_consumption_digest_mismatch", "$.consumptions.consumption_sha256")
        previous = expected
        seen.add(row["grant_sha256"])
        rows.append(row)
    return rows


class NativeRecoveryFamilyStore:
    """Retain full T068 candidates and full T069 ledger snapshots."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.native_dir = root / "native"
        self.recovery_dir = root / "recovery"
        self.manifest_path = root / "manifest.json"
        self.anchor_path = root / "anchor.json"
        self.consumptions_path = root / "consumptions.json"
        self.lock_path = root / "owner.lock"
        self.recover()

    @classmethod
    def create_source_local(cls, root: Path) -> "NativeRecoveryFamilyStore":
        if not root.is_absolute() or root.exists() or root.is_symlink():
            raise NativeRecoveryFamilyError("family_root_invalid", "$.root")
        root.mkdir(mode=0o700)
        (root / "native").mkdir(mode=0o700)
        (root / "recovery").mkdir(mode=0o700)
        manifest = _manifest()
        ledger = t069.new_ledger(RECOVERY_LEDGER_ID)
        _write_new(root / "manifest.json", _canonical_bytes(manifest))
        _write_new(root / "native" / "00000000000000000000.json", _canonical_bytes([]))
        _write_new(root / "recovery" / "00000000000000000000.json", _canonical_bytes(ledger))
        _write_new(root / "consumptions.json", _canonical_bytes([]))
        _write_new(root / "anchor.json", _canonical_bytes(_anchor([], ledger, [])))
        _write_new(root / "owner.lock", b"")
        return cls(root)

    def _lock(self) -> int:
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    @staticmethod
    def _inventory(paths: Sequence[Path], label: str) -> list[Path]:
        if any(path.is_symlink() or not path.is_file() or not re.fullmatch(r"\d{20}\.json", path.name) for path in paths):
            raise NativeRecoveryFamilyError("family_snapshot_inventory_invalid", label)
        return sorted(paths)

    def recover(self) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
        manifest_bytes, _ = _read_exact(self.manifest_path)
        if manifest_bytes != _canonical_bytes(_manifest()):
            raise NativeRecoveryFamilyError("family_manifest_invalid", "$.manifest")
        native_paths = self._inventory(list(self.native_dir.iterdir()), "$.native")
        recovery_paths = self._inventory(list(self.recovery_dir.iterdir()), "$.recovery")
        if not native_paths or not recovery_paths:
            raise NativeRecoveryFamilyError("family_truncation_detected")

        previous_chain: list[dict[str, Any]] = []
        for sequence, path in enumerate(native_paths):
            if path.name != f"{sequence:020d}.json":
                raise NativeRecoveryFamilyError("family_snapshot_gap", str(path))
            _, raw = _read_exact(path)
            if not isinstance(raw, list) or len(raw) != sequence or raw[:-1] != previous_chain:
                raise NativeRecoveryFamilyError("family_native_fork", str(path))
            current: list[dict[str, Any]] = []
            for index, candidate in enumerate(raw):
                try:
                    validated = t068.validate_candidate(
                        candidate,
                        expected_native_host_id=candidate["native_host"]["native_host_id"],
                        expected_bindings=candidate["bindings"],
                        now=t068._time(candidate["observed_at"], "$.candidate.observed_at"),
                        previous=None if index == 0 else current[-1],
                    )
                except (KeyError, TypeError, t068.SupervisionError) as exc:
                    raise NativeRecoveryFamilyError("family_t068_invalid", str(path)) from exc
                current.append(validated)
            previous_chain = current

        previous_ledger = t069.new_ledger(RECOVERY_LEDGER_ID)
        for sequence, path in enumerate(recovery_paths):
            if path.name != f"{sequence:020d}.json":
                raise NativeRecoveryFamilyError("family_snapshot_gap", str(path))
            _, raw = _read_exact(path)
            try:
                ledger = t069.validate_ledger(raw)
            except t069.RecoveryError as exc:
                raise NativeRecoveryFamilyError("family_t069_invalid", str(path)) from exc
            if len(ledger["events"]) != sequence or (sequence and ledger["events"][:-1] != previous_ledger["events"]):
                raise NativeRecoveryFamilyError("family_recovery_fork", str(path))
            previous_ledger = ledger

        _, raw_consumptions = _read_exact(self.consumptions_path)
        consumptions = _validate_consumptions(raw_consumptions, previous_ledger)
        _, retained_anchor = _read_exact(self.anchor_path)
        expected_anchor = _anchor(previous_chain, previous_ledger, consumptions)
        if retained_anchor != expected_anchor:
            raise NativeRecoveryFamilyError("family_anchor_mismatch", "$.anchor")
        return deepcopy(previous_chain), deepcopy(previous_ledger), deepcopy(consumptions)

    def current_anchor(self) -> dict[str, Any]:
        native, recovery, consumptions = self.recover()
        return _anchor(native, recovery, consumptions)

    def observe_supervision(
        self,
        *,
        acquisition_id: str,
        native_host_id: str,
        host_instance_id: str,
        identity_receipt_sha256: str,
        authentication_receipt_sha256: str,
        lifecycle_state: str,
        children: Sequence[tuple[str, str, str, str]],
        parent_edges: Sequence[tuple[str, str]],
        cursor_id: str,
        cursor_event_sha256: str,
        owner_now: datetime,
    ) -> NativeSuccessor:
        """Construct T068 from raw native topology. No candidate is accepted."""
        _identifier(acquisition_id, "$.acquisition_id")
        now = _utc(owner_now, "$.owner_now")
        request = {
            "native_host_id": native_host_id, "host_instance_id": host_instance_id,
            "identity_receipt_sha256": identity_receipt_sha256,
            "authentication_receipt_sha256": authentication_receipt_sha256,
            "lifecycle_state": lifecycle_state, "children": list(children),
            "parent_edges": list(parent_edges), "cursor_id": cursor_id,
            "cursor_event_sha256": cursor_event_sha256,
        }
        request_sha = _digest(request)
        descriptor = self._lock()
        try:
            chain, recovery, consumptions = self.recover()
            for index, retained in enumerate(chain, 1):
                if retained["candidate_id"] != acquisition_id:
                    continue
                retained_request = {
                    "native_host_id": retained["native_host"]["native_host_id"],
                    "host_instance_id": retained["native_host"]["host_instance_id"],
                    "identity_receipt_sha256": retained["native_host"]["identity_receipt_sha256"],
                    "authentication_receipt_sha256": retained["native_host"]["authentication_receipt_sha256"],
                    "lifecycle_state": retained["native_host"]["lifecycle_state"],
                    "children": [tuple(item[field] for field in ("child_id", "native_identity_sha256", "authentication_receipt_sha256", "lifecycle_state")) for item in retained["children"]],
                    "parent_edges": [tuple(item[field] for field in ("parent_id", "child_id")) for item in retained["parent_edges"]],
                    "cursor_id": retained["observation_cursor"]["cursor_id"],
                    "cursor_event_sha256": retained["observation_cursor"]["event_sha256"],
                }
                if retained_request != request:
                    raise NativeRecoveryFamilyError("family_acquisition_collision", "$.acquisition_id")
                return self._native_successor(acquisition_id, chain[:index])

            prior = None if not chain else chain[-1]
            sequence = len(chain) + 1
            child_rows = [
                {"child_id": child_id, "native_identity_sha256": identity_sha, "authentication_receipt_sha256": auth_sha, "lifecycle_state": state}
                for child_id, identity_sha, auth_sha, state in children
            ]
            edge_rows = [
                {"parent_id": parent, "child_id": child, "edge_sha256": t068.canonical_digest({"parent_id": parent, "child_id": child})}
                for parent, child in parent_edges
            ]
            bindings = {
                "source_sha256": SOURCE_BUILD_SHA256,
                "candidate_sha256": _manifest()["manifest_sha256"],
                "manifest_sha256": _manifest()["manifest_sha256"],
                "generation": 1,
                "service_start_id": "native-recovery-source-local-start-v1",
                "identity_sha256": t068.canonical_digest({"native_host_id": native_host_id, "host_instance_id": host_instance_id, "identity_receipt_sha256": identity_receipt_sha256, "authentication_receipt_sha256": authentication_receipt_sha256}),
                "operation_body_sha256": request_sha,
                "dependency_receipts_sha256": t068.canonical_digest({"source": "native-owner-observation"}),
            }
            if prior is not None:
                bindings = deepcopy(prior["bindings"])
                if bindings["identity_sha256"] != t068.canonical_digest({"native_host_id": native_host_id, "host_instance_id": host_instance_id, "identity_receipt_sha256": identity_receipt_sha256, "authentication_receipt_sha256": authentication_receipt_sha256}):
                    raise NativeRecoveryFamilyError("family_native_identity_drift", "$.native_host_id")
                bindings["operation_body_sha256"] = prior["bindings"]["operation_body_sha256"]
            candidate = {
                "schema_version": 1, "artifact_type": t068.CANDIDATE_TYPE,
                "candidate_id": acquisition_id,
                "native_host": {"native_host_id": native_host_id, "host_instance_id": host_instance_id, "identity_receipt_sha256": identity_receipt_sha256, "authentication_receipt_sha256": authentication_receipt_sha256, "lifecycle_state": lifecycle_state},
                "children": child_rows, "parent_edges": edge_rows,
                "observation_cursor": {"cursor_id": cursor_id, "sequence": sequence, "event_sha256": cursor_event_sha256, "previous_event_sha256": None if prior is None else prior["observation_cursor"]["event_sha256"]},
                "previous_candidate_sha256": None if prior is None else prior["candidate_sha256"],
                "bindings": bindings, "observed_at": _format(now), "expires_at": _format(now + timedelta(seconds=60)),
                "candidate_sha256": "",
            }
            candidate["candidate_sha256"] = t068.canonical_digest({key: item for key, item in candidate.items() if key != "candidate_sha256"})
            try:
                validated = t068.validate_candidate(candidate, expected_native_host_id=native_host_id, expected_bindings=bindings, now=now, previous=prior)
            except t068.SupervisionError as exc:
                raise NativeRecoveryFamilyError("family_t068_invalid", exc.path) from exc
            chain.append(validated)
            _write_new(self.native_dir / f"{sequence:020d}.json", _canonical_bytes(chain))
            _replace(self.anchor_path, _canonical_bytes(_anchor(chain, recovery, consumptions)))
            self.recover()
            return self._native_successor(acquisition_id, chain)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _native_successor(acquisition_id: str, chain: Sequence[Mapping[str, Any]]) -> NativeSuccessor:
        candidate = chain[-1]
        inventory = {
            "schema_version": 1, "artifact_type": INVENTORY_TYPE,
            "operation": NATIVE_OPERATION, "candidate_sha256": candidate["candidate_sha256"],
            "cursor_id": candidate["observation_cursor"]["cursor_id"],
            "cursor_sequence": candidate["observation_cursor"]["sequence"],
            "native_host_id": candidate["native_host"]["native_host_id"],
            "child_ids": sorted(child["child_id"] for child in candidate["children"]),
            "topology_sha256": _digest({"children": candidate["children"], "parent_edges": candidate["parent_edges"]}),
            "execution_scope": EXECUTION_SCOPE, "inventory_sha256": "",
        }
        inventory["inventory_sha256"] = _digest({key: item for key, item in inventory.items() if key != "inventory_sha256"})
        return NativeSuccessor(
            NATIVE_OPERATION, acquisition_id,
            None if len(chain) == 1 else chain[-2]["candidate_sha256"],
            _canonical_bytes(list(chain[:-1])), candidate["candidate_sha256"],
            _canonical_bytes(list(chain)), _canonical_bytes(candidate), _canonical_bytes(inventory),
        )

    def reconcile_and_issue_grant(
        self,
        *,
        acquisition_id: str,
        workspace_id: str,
        effect_id: str,
        run_id: str,
        thread_id: str,
        lease_id: str,
        predecessor_effect_state_sha256: str,
        predecessor_effect_receipt_sha256: str,
        reconciliation_decision_sha256: str,
        t064_identity_sha256: str,
        t066_identity_sha256: str,
        predecessor_fencing_token: int,
        predecessor_fencing_version: int,
        owner_now: datetime,
    ) -> RecoverySuccessor:
        """Derive an ordered T069 reservation and grant from reconciliation."""
        _identifier(acquisition_id, "$.acquisition_id")
        now = _utc(owner_now, "$.owner_now")
        scope = {"workspace_id": workspace_id, "effect_id": effect_id, "run_id": run_id, "thread_id": thread_id, "lease_id": lease_id}
        for field, value in scope.items():
            _identifier(value, "$." + field)
        for field, value in {
            "predecessor_effect_state_sha256": predecessor_effect_state_sha256,
            "predecessor_effect_receipt_sha256": predecessor_effect_receipt_sha256,
            "reconciliation_decision_sha256": reconciliation_decision_sha256,
            "t064_identity_sha256": t064_identity_sha256, "t066_identity_sha256": t066_identity_sha256,
        }.items():
            _sha(value, "$." + field)
        prior_token = _positive(predecessor_fencing_token, "$.predecessor_fencing_token", zero=True)
        prior_version = _positive(predecessor_fencing_version, "$.predecessor_fencing_version", zero=True)
        request = {**scope, "predecessor_effect_state_sha256": predecessor_effect_state_sha256, "predecessor_effect_receipt_sha256": predecessor_effect_receipt_sha256, "reconciliation_decision_sha256": reconciliation_decision_sha256, "t064_identity_sha256": t064_identity_sha256, "t066_identity_sha256": t066_identity_sha256, "predecessor_fencing_token": prior_token, "predecessor_fencing_version": prior_version}
        descriptor = self._lock()
        try:
            native, ledger, consumptions = self.recover()
            reservation_id = acquisition_id + ".reservation"
            grant_id = acquisition_id + ".grant"
            issues = [event for event in ledger["events"] if event["event_type"] == "issue"]
            existing = next((event for event in issues if event["decision_id"] == grant_id), None)
            if existing is not None:
                reservation = next(event for event in issues if event["decision_id"] == reservation_id)
                retained_request = self._recovery_request(reservation["decision"], existing["decision"])
                if retained_request != request:
                    raise NativeRecoveryFamilyError("family_acquisition_collision", "$.acquisition_id")
                return self._recovery_successor(acquisition_id, ledger, reservation["decision_sha256"], existing["decision_sha256"])

            active_same_scope = []
            for event in issues:
                decision = event["decision"]
                if decision["variant"] != "recovery_reservation_candidate":
                    continue
                payload = decision["payload"]
                if (decision["bindings"]["workspace_id"], payload["effect_id"], payload["run_id"], payload["thread_id"], payload["lease_id"]) == tuple(scope.values()):
                    active_same_scope.append(payload)
            if active_same_scope:
                last = active_same_scope[-1]
                if (prior_token, prior_version) != (last["fencing_token"], last["fencing_version"]):
                    raise NativeRecoveryFamilyError("family_recovery_predecessor_fence_mismatch", "$.predecessor_fencing_token")
            reservation_token = prior_token + 1
            reservation_version = prior_version + 1
            bindings = {
                "workspace_id": workspace_id, "source_sha256": SOURCE_BUILD_SHA256,
                "candidate_sha256": _manifest()["manifest_sha256"], "manifest_sha256": _manifest()["manifest_sha256"],
                "generation": 1, "service_start_id": "native-recovery-source-local-start-v1",
                "dependency_receipts_sha256": t069.canonical_digest({"t064": t064_identity_sha256, "t066": t066_identity_sha256, "reconciliation": reconciliation_decision_sha256}),
            }
            common = {"effect_id": effect_id, "run_id": run_id, "thread_id": thread_id, "lease_id": lease_id, "predecessor_effect_state_sha256": predecessor_effect_state_sha256, "predecessor_effect_receipt_sha256": predecessor_effect_receipt_sha256, "reconciliation_decision_sha256": reconciliation_decision_sha256, "t064_identity_sha256": t064_identity_sha256, "t066_identity_sha256": t066_identity_sha256}
            reservation_payload = {"reservation_id": reservation_id, **common, "fencing_token": reservation_token, "fencing_version": reservation_version}
            reservation = self._decision(reservation_id, "recovery_reservation_candidate", bindings, reservation_payload, now)
            first = t069.issue_decision(ledger, reservation, expected_head_sha256=ledger["head_sha256"], expected_bindings=bindings, now=now)
            grant_payload = {"grant_id": grant_id, "reservation_sha256": reservation["decision_sha256"], **common, "predecessor_fencing_token": reservation_token, "predecessor_fencing_version": reservation_version, "fencing_token": reservation_token + 1, "fencing_version": reservation_version + 1}
            grant = self._decision(grant_id, "recovery_lease_grant_candidate", bindings, grant_payload, now + timedelta(seconds=1))
            successor = t069.issue_decision(first, grant, expected_head_sha256=first["head_sha256"], expected_bindings=bindings, now=now + timedelta(seconds=1))
            first_sequence = len(first["events"])
            _write_new(self.recovery_dir / f"{first_sequence:020d}.json", _canonical_bytes(first))
            _write_new(self.recovery_dir / f"{len(successor['events']):020d}.json", _canonical_bytes(successor))
            _replace(self.anchor_path, _canonical_bytes(_anchor(native, successor, consumptions)))
            self.recover()
            return RecoverySuccessor(RECOVERY_OPERATION, acquisition_id, ledger["head_sha256"], _canonical_bytes(ledger), reservation["decision_sha256"], grant["decision_sha256"], successor["head_sha256"], _canonical_bytes(successor))
        except t069.RecoveryError as exc:
            raise NativeRecoveryFamilyError("family_t069_invalid", exc.path) from exc
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _decision(decision_id: str, variant: str, bindings: Mapping[str, Any], payload: Mapping[str, Any], now: datetime) -> dict[str, Any]:
        row = {"schema_version": 1, "artifact_type": t069.DECISION_TYPE, "decision_id": decision_id, "decision_source_id": RECOVERY_SOURCE_ID, "ledger_id": RECOVERY_LEDGER_ID, "operation": RECOVERY_OPERATION, "variant": variant, "bindings": deepcopy(dict(bindings)), "payload": deepcopy(dict(payload)), "observed_at": _format(now), "expires_at": _format(now + timedelta(seconds=60)), "decision_sha256": ""}
        row["decision_sha256"] = t069.canonical_digest({key: item for key, item in row.items() if key != "decision_sha256"})
        return row

    @staticmethod
    def _recovery_request(reservation: Mapping[str, Any], grant: Mapping[str, Any]) -> dict[str, Any]:
        payload = reservation["payload"]
        return {"workspace_id": reservation["bindings"]["workspace_id"], **{field: payload[field] for field in ("effect_id", "run_id", "thread_id", "lease_id", "predecessor_effect_state_sha256", "predecessor_effect_receipt_sha256", "reconciliation_decision_sha256", "t064_identity_sha256", "t066_identity_sha256")}, "predecessor_fencing_token": payload["fencing_token"] - 1, "predecessor_fencing_version": payload["fencing_version"] - 1}

    def _recovery_successor(self, acquisition_id: str, ledger: Mapping[str, Any], reservation_sha: str, grant_sha: str) -> RecoverySuccessor:
        grant_index = next(index for index, event in enumerate(ledger["events"], 1) if event["decision_sha256"] == grant_sha)
        _, before_raw = _read_exact(self.recovery_dir / f"{grant_index - 2:020d}.json")
        _, after_raw = _read_exact(self.recovery_dir / f"{grant_index:020d}.json")
        return RecoverySuccessor(RECOVERY_OPERATION, acquisition_id, before_raw["head_sha256"], _canonical_bytes(before_raw), reservation_sha, grant_sha, after_raw["head_sha256"], _canonical_bytes(after_raw))

    def revoke_recovery(self, *, decision_sha256: str, reason: str, owner_now: datetime) -> RecoverySuccessor:
        now = _utc(owner_now, "$.owner_now")
        descriptor = self._lock()
        try:
            native, ledger, consumptions = self.recover()
            issue = next((event for event in ledger["events"] if event["event_type"] == "issue" and event["decision_sha256"] == decision_sha256), None)
            if issue is None:
                raise NativeRecoveryFamilyError("family_revoke_missing", "$.decision_sha256")
            successor = t069.revoke_decision(ledger, decision_sha256=decision_sha256, reason=reason, expected_head_sha256=ledger["head_sha256"], occurred_at=now)
            _write_new(self.recovery_dir / f"{len(successor['events']):020d}.json", _canonical_bytes(successor))
            _replace(self.anchor_path, _canonical_bytes(_anchor(native, successor, consumptions)))
            self.recover()
            return RecoverySuccessor(RECOVERY_OPERATION, issue["decision_id"], ledger["head_sha256"], _canonical_bytes(ledger), decision_sha256, decision_sha256, successor["head_sha256"], _canonical_bytes(successor))
        except t069.RecoveryError as exc:
            raise NativeRecoveryFamilyError("family_t069_invalid", exc.path) from exc
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def consume_recovery_grant(self, *, grant_sha256: str, use_receipt_sha256: str, owner_now: datetime) -> dict[str, Any]:
        _sha(grant_sha256, "$.grant_sha256")
        _sha(use_receipt_sha256, "$.use_receipt_sha256")
        now = _utc(owner_now, "$.owner_now")
        descriptor = self._lock()
        try:
            native, ledger, consumptions = self.recover()
            existing = next((item for item in consumptions if item["grant_sha256"] == grant_sha256), None)
            if existing is not None:
                if existing["use_receipt_sha256"] != use_receipt_sha256:
                    raise NativeRecoveryFamilyError("family_consumption_collision", "$.grant_sha256")
                return existing
            row = {"schema_version": 1, "artifact_type": CONSUMPTION_TYPE, "sequence": len(consumptions) + 1, "grant_sha256": grant_sha256, "use_receipt_sha256": use_receipt_sha256, "observed_at": _format(now), "previous_consumption_sha256": None if not consumptions else consumptions[-1]["consumption_sha256"], "consumption_sha256": ""}
            row["consumption_sha256"] = _digest({key: item for key, item in row.items() if key != "consumption_sha256"})
            consumptions.append(row)
            _validate_consumptions(consumptions, ledger)
            _replace(self.consumptions_path, _canonical_bytes(consumptions))
            _replace(self.anchor_path, _canonical_bytes(_anchor(native, ledger, consumptions)))
            self.recover()
            return deepcopy(row)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def revalidate_native_successor(artifact: NativeSuccessor) -> list[dict[str, Any]]:
        if not isinstance(artifact, NativeSuccessor) or artifact.operation != NATIVE_OPERATION or artifact.execution_scope != EXECUTION_SCOPE:
            raise NativeRecoveryFamilyError("family_native_successor_invalid")
        try:
            chain = json.loads(artifact.successor_chain_bytes)
            candidate = json.loads(artifact.candidate_bytes)
            inventory = json.loads(artifact.inventory_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise NativeRecoveryFamilyError("family_native_successor_invalid") from exc
        if _canonical_bytes(chain) != artifact.successor_chain_bytes or _canonical_bytes(candidate) != artifact.candidate_bytes or candidate != chain[-1] or candidate["candidate_sha256"] != artifact.successor_candidate_sha256:
            raise NativeRecoveryFamilyError("family_native_successor_invalid")
        inventory_fields = {"schema_version", "artifact_type", "operation", "candidate_sha256", "cursor_id", "cursor_sequence", "native_host_id", "child_ids", "topology_sha256", "execution_scope", "inventory_sha256"}
        if (
            not isinstance(inventory, Mapping) or set(inventory) != inventory_fields
            or inventory["schema_version"] != 1 or inventory["artifact_type"] != INVENTORY_TYPE
            or inventory["operation"] != NATIVE_OPERATION
            or inventory["candidate_sha256"] != candidate["candidate_sha256"]
            or inventory["cursor_id"] != candidate["observation_cursor"]["cursor_id"]
            or inventory["cursor_sequence"] != candidate["observation_cursor"]["sequence"]
            or inventory["native_host_id"] != candidate["native_host"]["native_host_id"]
            or inventory["child_ids"] != sorted(child["child_id"] for child in candidate["children"])
            or inventory["topology_sha256"] != _digest({"children": candidate["children"], "parent_edges": candidate["parent_edges"]})
            or inventory["execution_scope"] != EXECUTION_SCOPE
            or inventory["inventory_sha256"] != _digest({key: item for key, item in inventory.items() if key != "inventory_sha256"})
        ):
            raise NativeRecoveryFamilyError("family_native_inventory_invalid")
        current: list[dict[str, Any]] = []
        for item in chain:
            current.append(t068.validate_candidate(item, expected_native_host_id=item["native_host"]["native_host_id"], expected_bindings=item["bindings"], now=t068._time(item["observed_at"], "$.observed_at"), previous=None if not current else current[-1]))
        return current

    @staticmethod
    def revalidate_recovery_successor(artifact: RecoverySuccessor) -> dict[str, Any]:
        if not isinstance(artifact, RecoverySuccessor) or artifact.operation != RECOVERY_OPERATION or artifact.execution_scope != EXECUTION_SCOPE:
            raise NativeRecoveryFamilyError("family_recovery_successor_invalid")
        try:
            before = json.loads(artifact.predecessor_ledger_bytes)
            after = json.loads(artifact.successor_ledger_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise NativeRecoveryFamilyError("family_recovery_successor_invalid") from exc
        if _canonical_bytes(before) != artifact.predecessor_ledger_bytes or _canonical_bytes(after) != artifact.successor_ledger_bytes:
            raise NativeRecoveryFamilyError("family_recovery_successor_noncanonical")
        before = t069.validate_ledger(before)
        after = t069.validate_ledger(after)
        if before["head_sha256"] != artifact.predecessor_head_sha256 or after["head_sha256"] != artifact.successor_head_sha256 or after["events"][:len(before["events"])] != before["events"]:
            raise NativeRecoveryFamilyError("family_recovery_successor_fork")
        return after


def _split_manifest(owner_id: str, protocol: str, operation: str) -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": SPLIT_MANIFEST_TYPE,
        "owner_id": owner_id,
        "protocol_version": protocol,
        "operation": operation,
        "proof_boundary": EXECUTION_SCOPE,
        "manifest_sha256": "",
    }
    row["manifest_sha256"] = _digest({key: item for key, item in row.items() if key != "manifest_sha256"})
    return row


def _split_snapshot(owner_id: str, sequence: int, previous: str, state: Mapping[str, Any]) -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": SPLIT_SNAPSHOT_TYPE,
        "owner_id": owner_id,
        "family_sequence": sequence,
        "previous_snapshot_sha256": previous,
        "state": deepcopy(dict(state)),
        "snapshot_sha256": "",
    }
    row["snapshot_sha256"] = _digest({key: item for key, item in row.items() if key != "snapshot_sha256"})
    return row


def _split_anchor(owner_id: str, snapshot: Mapping[str, Any]) -> dict[str, Any]:
    row = {
        "schema_version": 1,
        "artifact_type": SPLIT_ANCHOR_TYPE,
        "owner_id": owner_id,
        "family_sequence": snapshot["family_sequence"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "state_bytes_sha256": _bytes_digest(_canonical_bytes(snapshot["state"])),
        "anchor_sha256": "",
    }
    row["anchor_sha256"] = _digest({key: item for key, item in row.items() if key != "anchor_sha256"})
    return row


def validate_native_split_transition(value: Any, *, before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "owner_id", "operation", "sequence", "candidate_sha256", "predecessor_chain_bytes_sha256", "successor_chain_bytes_sha256", "dependency_import_heads", "proof_boundary", "transition_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeRecoveryFamilyError("family_transition_invalid", "$.transition")
    row = deepcopy(dict(value))
    if (row["schema_version"] != 1 or row["artifact_type"] != SPLIT_TRANSITION_TYPE
            or row["owner_id"] != NATIVE_OWNER_ID or row["operation"] != NATIVE_OPERATION
            or row["sequence"] != len(after) or len(after) != len(before) + 1
            or list(after[:-1]) != list(before) or row["candidate_sha256"] != after[-1]["candidate_sha256"]
            or row["predecessor_chain_bytes_sha256"] != _bytes_digest(_canonical_bytes(before))
            or row["successor_chain_bytes_sha256"] != _bytes_digest(_canonical_bytes(after))
            or row["dependency_import_heads"] != {} or row["proof_boundary"] != EXECUTION_SCOPE):
        raise NativeRecoveryFamilyError("family_transition_invalid", "$.transition")
    if row["transition_sha256"] != _digest({key: item for key, item in row.items() if key != "transition_sha256"}):
        raise NativeRecoveryFamilyError("family_transition_digest_mismatch", "$.transition")
    return row


def validate_native_split_anchor(value: Any, *, successor: Sequence[Mapping[str, Any]], transition: Mapping[str, Any]) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "owner_id", "family_sequence", "snapshot_sha256", "state_bytes_sha256", "anchor_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeRecoveryFamilyError("family_anchor_invalid", "$.anchor")
    row = deepcopy(dict(value))
    if (row["schema_version"] != 1 or row["artifact_type"] != SPLIT_ANCHOR_TYPE
            or row["owner_id"] != NATIVE_OWNER_ID or row["family_sequence"] != len(successor)
            or transition["sequence"] != row["family_sequence"]):
        raise NativeRecoveryFamilyError("family_anchor_mismatch", "$.anchor")
    _sha(row["snapshot_sha256"], "$.anchor.snapshot_sha256")
    _sha(row["state_bytes_sha256"], "$.anchor.state_bytes_sha256")
    if row["anchor_sha256"] != _digest({key: item for key, item in row.items() if key != "anchor_sha256"}):
        raise NativeRecoveryFamilyError("family_anchor_digest_mismatch", "$.anchor")
    return row


def _projection_field(projection: Any, field: str) -> Any:
    if projection is None:
        raise NativeRecoveryFamilyError("family_dependency_import_missing", "$.imports." + field)
    if isinstance(projection, Mapping):
        if field not in projection:
            raise NativeRecoveryFamilyError("family_dependency_import_invalid", "$.imports." + field)
        return projection[field]
    if not hasattr(projection, field):
        raise NativeRecoveryFamilyError("family_dependency_import_invalid", "$.imports." + field)
    return getattr(projection, field)


def _projection_json(projection: Any, field: str) -> Any:
    value = _projection_field(projection, field)
    if not isinstance(value, bytes):
        raise NativeRecoveryFamilyError("family_dependency_bytes_invalid", "$.imports." + field)
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NativeRecoveryFamilyError("family_dependency_bytes_invalid", "$.imports." + field) from exc
    if value != _canonical_bytes(decoded):
        raise NativeRecoveryFamilyError("family_dependency_bytes_noncanonical", "$.imports." + field)
    return decoded


def _current_projection(projection: Any, *, edge: str, mechanism: str, operations: set[str], now: datetime) -> tuple[Any, str]:
    if _projection_field(projection, "edge_id") != edge:
        raise NativeRecoveryFamilyError("family_dependency_edge_mismatch", "$.imports.edge_id")
    if _projection_field(projection, "accepted_mechanism") != mechanism:
        raise NativeRecoveryFamilyError("family_dependency_mechanism_mismatch", "$.imports.accepted_mechanism")
    if _projection_field(projection, "operation") not in operations:
        raise NativeRecoveryFamilyError("family_dependency_operation_mismatch", "$.imports.operation")
    if _projection_field(projection, "authority_state") != "quarantine" or _projection_field(projection, "proof_boundary") != EXECUTION_SCOPE:
        raise NativeRecoveryFamilyError("family_dependency_authority_invalid", "$.imports.authority_state")
    if t069._time(_projection_field(projection, "effective_expires_at"), "$.imports.effective_expires_at") <= now:
        raise NativeRecoveryFamilyError("family_dependency_expired", "$.imports.effective_expires_at")
    return deepcopy(_projection_field(projection, "semantic_subject")), _sha(
        _projection_field(projection, "import_head_sha256"), "$.imports.import_head_sha256"
    )


class _SplitFamilyStore:
    owner_id = ""
    protocol = ""
    operation = ""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.snapshots = self.root / "family-snapshots"
        self.manifest_path = self.root / "family-manifest.json"
        self.anchor_path = self.root / "family-anchor.json"
        self.lock_path = self.root / "role.lock"
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.snapshots.mkdir(mode=0o700, exist_ok=True)
        if not self.lock_path.exists():
            _write_new(self.lock_path, b"")
        if not self.manifest_path.exists():
            _write_new(self.manifest_path, _canonical_bytes(_split_manifest(self.owner_id, self.protocol, self.operation)))
            genesis = _split_snapshot(self.owner_id, 0, self._genesis_digest(), self._empty_state())
            _write_new(self.snapshots / "00000000000000000000.json", _canonical_bytes(genesis))
            _write_new(self.anchor_path, _canonical_bytes(_split_anchor(self.owner_id, genesis)))
        self.recover()

    def _genesis_digest(self) -> str:
        return _digest({"owner_id": self.owner_id, "protocol": self.protocol, "event": "genesis"})

    def _empty_state(self) -> dict[str, Any]:
        raise NotImplementedError

    def _validate_state(self, state: Any) -> dict[str, Any]:
        raise NotImplementedError

    def _lock(self) -> int:
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    def _recover_locked(self) -> dict[str, Any]:
        manifest_bytes, _ = _read_exact(self.manifest_path)
        if manifest_bytes != _canonical_bytes(_split_manifest(self.owner_id, self.protocol, self.operation)):
            raise NativeRecoveryFamilyError("family_manifest_invalid", "$.manifest")
        paths = sorted(self.snapshots.iterdir())
        if not paths:
            raise NativeRecoveryFamilyError("family_truncation_detected", "$.snapshots")
        previous = self._genesis_digest()
        latest: dict[str, Any] | None = None
        for sequence, path in enumerate(paths):
            if path.name != f"{sequence:020d}.json" or path.is_symlink():
                raise NativeRecoveryFamilyError("family_snapshot_gap", str(path))
            _, raw = _read_exact(path)
            fields = {"schema_version", "artifact_type", "owner_id", "family_sequence", "previous_snapshot_sha256", "state", "snapshot_sha256"}
            if not isinstance(raw, Mapping) or set(raw) != fields:
                raise NativeRecoveryFamilyError("family_snapshot_shape_invalid", str(path))
            expected = _split_snapshot(self.owner_id, sequence, previous, self._validate_state(raw["state"]))
            if raw != expected:
                raise NativeRecoveryFamilyError("family_snapshot_fork", str(path))
            latest = deepcopy(expected)
            previous = latest["snapshot_sha256"]
        assert latest is not None
        _, anchor = _read_exact(self.anchor_path)
        if anchor != _split_anchor(self.owner_id, latest):
            raise NativeRecoveryFamilyError("family_anchor_mismatch", "$.anchor")
        return latest

    def recover(self) -> dict[str, Any]:
        descriptor = self._lock()
        try:
            return deepcopy(self._recover_locked())
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def current_anchor(self) -> dict[str, Any]:
        snapshot = self.recover()
        return _split_anchor(self.owner_id, snapshot)

    def transitions(self) -> list[dict[str, Any]]:
        snapshot = self.recover()
        return deepcopy(snapshot["state"]["transitions"])

    def _commit(self, prior: Mapping[str, Any], state: Mapping[str, Any]) -> dict[str, Any]:
        sequence = prior["family_sequence"] + 1
        snapshot = _split_snapshot(self.owner_id, sequence, prior["snapshot_sha256"], self._validate_state(state))
        _write_new(self.snapshots / f"{sequence:020d}.json", _canonical_bytes(snapshot))
        _replace(self.anchor_path, _canonical_bytes(_split_anchor(self.owner_id, snapshot)))
        self._recover_locked()
        return snapshot


class NativeSupervisionFamilyStore(_SplitFamilyStore):
    """The supported native-supervision runtime. It owns only T068."""

    owner_id = NATIVE_OWNER_ID
    protocol = NATIVE_SPLIT_PROTOCOL
    operation = NATIVE_OPERATION

    def _empty_state(self) -> dict[str, Any]:
        return {"chain": [], "transitions": []}

    def _validate_state(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, Mapping) or set(state) != {"chain", "transitions"} or not isinstance(state["chain"], list) or not isinstance(state["transitions"], list):
            raise NativeRecoveryFamilyError("family_state_shape_invalid", "$.state")
        current: list[dict[str, Any]] = []
        for candidate in state["chain"]:
            try:
                current.append(t068.validate_candidate(candidate, expected_native_host_id=candidate["native_host"]["native_host_id"], expected_bindings=candidate["bindings"], now=t068._time(candidate["observed_at"], "$.candidate.observed_at"), previous=None if not current else current[-1]))
            except (KeyError, TypeError, t068.SupervisionError) as exc:
                raise NativeRecoveryFamilyError("family_t068_invalid", "$.state.chain") from exc
        if len(state["transitions"]) != len(current):
            raise NativeRecoveryFamilyError("family_transition_sequence_invalid", "$.state.transitions")
        for index, transition in enumerate(state["transitions"], 1):
            fields = {"schema_version", "artifact_type", "owner_id", "operation", "sequence", "candidate_sha256", "predecessor_chain_bytes_sha256", "successor_chain_bytes_sha256", "dependency_import_heads", "proof_boundary", "transition_sha256"}
            if not isinstance(transition, Mapping) or set(transition) != fields or transition["sequence"] != index or transition["candidate_sha256"] != current[index - 1]["candidate_sha256"] or transition["dependency_import_heads"] != {} or transition["proof_boundary"] != EXECUTION_SCOPE:
                raise NativeRecoveryFamilyError("family_transition_invalid", "$.state.transitions")
            expected = _digest({key: item for key, item in transition.items() if key != "transition_sha256"})
            if transition["transition_sha256"] != expected:
                raise NativeRecoveryFamilyError("family_transition_digest_mismatch", "$.state.transitions")
        return {"chain": current, "transitions": deepcopy(state["transitions"])}

    def observe_supervision(self, *, acquisition_id: str, native_host_id: str, host_instance_id: str,
                            identity_receipt_sha256: str, authentication_receipt_sha256: str,
                            lifecycle_state: str, children: Sequence[tuple[str, str, str, str]],
                            parent_edges: Sequence[tuple[str, str]], cursor_id: str,
                            cursor_event_sha256: str, owner_now: datetime) -> NativeSuccessor:
        _identifier(acquisition_id, "$.acquisition_id")
        now = _utc(owner_now, "$.owner_now")
        raw = {"native_host_id": native_host_id, "host_instance_id": host_instance_id, "identity_receipt_sha256": identity_receipt_sha256, "authentication_receipt_sha256": authentication_receipt_sha256, "lifecycle_state": lifecycle_state, "children": list(children), "parent_edges": list(parent_edges), "cursor_id": cursor_id, "cursor_event_sha256": cursor_event_sha256}
        descriptor = self._lock()
        try:
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); chain = state["chain"]
            for index, retained in enumerate(chain, 1):
                if retained["candidate_id"] == acquisition_id:
                    if retained["bindings"]["operation_body_sha256"] != _digest(raw):
                        raise NativeRecoveryFamilyError("family_acquisition_collision", "$.acquisition_id")
                    return self._successor(acquisition_id, chain[:index])
            prior = None if not chain else chain[-1]
            sequence = len(chain) + 1
            bindings = {
                "source_sha256": SOURCE_BUILD_SHA256, "candidate_sha256": _split_manifest(self.owner_id, self.protocol, self.operation)["manifest_sha256"], "manifest_sha256": _split_manifest(self.owner_id, self.protocol, self.operation)["manifest_sha256"], "generation": 1, "service_start_id": "native-supervision-source-local-start-v1", "identity_sha256": t068.canonical_digest({"native_host_id": native_host_id, "host_instance_id": host_instance_id, "identity_receipt_sha256": identity_receipt_sha256, "authentication_receipt_sha256": authentication_receipt_sha256}), "operation_body_sha256": _digest(raw), "dependency_receipts_sha256": t068.canonical_digest({"source": "native-supervision-owner"}),
            }
            candidate = {"schema_version": 1, "artifact_type": t068.CANDIDATE_TYPE, "candidate_id": acquisition_id, "native_host": {"native_host_id": native_host_id, "host_instance_id": host_instance_id, "identity_receipt_sha256": identity_receipt_sha256, "authentication_receipt_sha256": authentication_receipt_sha256, "lifecycle_state": lifecycle_state}, "children": [{"child_id": item[0], "native_identity_sha256": item[1], "authentication_receipt_sha256": item[2], "lifecycle_state": item[3]} for item in children], "parent_edges": [{"parent_id": item[0], "child_id": item[1], "edge_sha256": t068.canonical_digest({"parent_id": item[0], "child_id": item[1]})} for item in parent_edges], "observation_cursor": {"cursor_id": cursor_id, "sequence": sequence, "event_sha256": cursor_event_sha256, "previous_event_sha256": None if prior is None else prior["observation_cursor"]["event_sha256"]}, "previous_candidate_sha256": None if prior is None else prior["candidate_sha256"], "bindings": bindings, "observed_at": _format(now), "expires_at": _format(now + timedelta(seconds=60)), "candidate_sha256": ""}
            candidate["candidate_sha256"] = t068.canonical_digest({key: item for key, item in candidate.items() if key != "candidate_sha256"})
            try:
                candidate = t068.validate_candidate(candidate, expected_native_host_id=native_host_id, expected_bindings=bindings, now=now, previous=prior)
            except t068.SupervisionError as exc:
                raise NativeRecoveryFamilyError("family_t068_invalid", exc.path) from exc
            before = _canonical_bytes(chain); chain.append(candidate); after = _canonical_bytes(chain)
            transition = {"schema_version": 1, "artifact_type": SPLIT_TRANSITION_TYPE, "owner_id": self.owner_id, "operation": self.operation, "sequence": sequence, "candidate_sha256": candidate["candidate_sha256"], "predecessor_chain_bytes_sha256": _bytes_digest(before), "successor_chain_bytes_sha256": _bytes_digest(after), "dependency_import_heads": {}, "proof_boundary": EXECUTION_SCOPE, "transition_sha256": ""}
            transition["transition_sha256"] = _digest({key: item for key, item in transition.items() if key != "transition_sha256"})
            state["chain"] = chain; state["transitions"].append(transition); self._commit(snapshot, state)
            return self._successor(acquisition_id, chain)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)

    @staticmethod
    def _successor(acquisition_id: str, chain: Sequence[Mapping[str, Any]]) -> NativeSuccessor:
        candidate = chain[-1]
        inventory = {"schema_version": 1, "artifact_type": INVENTORY_TYPE, "operation": NATIVE_OPERATION, "candidate_sha256": candidate["candidate_sha256"], "cursor_id": candidate["observation_cursor"]["cursor_id"], "cursor_sequence": candidate["observation_cursor"]["sequence"], "native_host_id": candidate["native_host"]["native_host_id"], "child_ids": sorted(item["child_id"] for item in candidate["children"]), "topology_sha256": _digest({"children": candidate["children"], "parent_edges": candidate["parent_edges"]}), "execution_scope": EXECUTION_SCOPE, "inventory_sha256": ""}
        inventory["inventory_sha256"] = _digest({key: item for key, item in inventory.items() if key != "inventory_sha256"})
        return NativeSuccessor(NATIVE_OPERATION, acquisition_id, None if len(chain) == 1 else chain[-2]["candidate_sha256"], _canonical_bytes(list(chain[:-1])), candidate["candidate_sha256"], _canonical_bytes(list(chain)), _canonical_bytes(candidate), _canonical_bytes(inventory))

    def current_export_material(self) -> dict[str, Any]:
        snapshot = self.recover(); chain = snapshot["state"]["chain"]
        if not chain:
            raise NativeRecoveryFamilyError("family_export_unavailable", "$.chain")
        return {"operation": NATIVE_OPERATION, "event_kind": "issue", "semantic_subject": {"candidate_sha256": chain[-1]["candidate_sha256"]}, "predecessor_bytes": _canonical_bytes(chain[:-1]), "successor_bytes": _canonical_bytes(chain), "transition_bytes": _canonical_bytes(snapshot["state"]["transitions"][-1]), "anchor": _split_anchor(self.owner_id, snapshot), "dependency_import_heads": {}}


class RecoveryFamilyStore(_SplitFamilyStore):
    """The supported recovery runtime. It owns only T069 and consumption."""

    owner_id = RECOVERY_OWNER_ID
    protocol = RECOVERY_SPLIT_PROTOCOL
    operation = RECOVERY_OPERATION

    def __init__(self, root: Path | str, artifact_store: Any) -> None:
        self.artifact_store = artifact_store
        super().__init__(root)

    def _empty_state(self) -> dict[str, Any]:
        return {"ledger": t069.new_ledger(RECOVERY_LEDGER_ID), "consumptions": [], "transitions": []}

    def _validate_state(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, Mapping) or set(state) != {"ledger", "consumptions", "transitions"} or not isinstance(state["transitions"], list):
            raise NativeRecoveryFamilyError("family_state_shape_invalid", "$.state")
        try:
            ledger = t069.validate_ledger(state["ledger"])
        except t069.RecoveryError as exc:
            raise NativeRecoveryFamilyError("family_t069_invalid", "$.state.ledger") from exc
        consumptions = _validate_consumptions(state["consumptions"], ledger)
        for transition in state["transitions"]:
            fields = {"schema_version", "artifact_type", "owner_id", "operation", "acquisition_id", "request_sha256", "predecessor_head_sha256", "successor_head_sha256", "predecessor_ledger_bytes_sha256", "successor_ledger_bytes_sha256", "dependency_import_heads", "mechanism_event_sha256", "proof_boundary", "transition_sha256"}
            if not isinstance(transition, Mapping) or set(transition) != fields or transition["owner_id"] != self.owner_id or transition["proof_boundary"] != EXECUTION_SCOPE or not isinstance(transition["dependency_import_heads"], Mapping):
                raise NativeRecoveryFamilyError("family_transition_invalid", "$.state.transitions")
            for head in transition["dependency_import_heads"].values(): _sha(head, "$.state.transitions.dependency_import_heads")
            if transition["transition_sha256"] != _digest({key: item for key, item in transition.items() if key != "transition_sha256"}):
                raise NativeRecoveryFamilyError("family_transition_digest_mismatch", "$.state.transitions")
        return {"ledger": ledger, "consumptions": consumptions, "transitions": deepcopy(state["transitions"])}

    def _imports(self, now: datetime) -> tuple[dict[str, str], dict[str, Any]]:
        projection = self.artifact_store.current_responses_projection_from_responses_seals()
        native = self.artifact_store.current_native_supervision_from_native_supervision()
        effect = self.artifact_store.current_effect_authority_from_effect_authority()
        projection_subject, projection_head = _current_projection(projection, edge="responses_projection_to_recovery_v1", mechanism="T066", operations={"seal_or_verify_projection"}, now=now)
        native_subject, native_head = _current_projection(native, edge="native_supervision_to_recovery_v1", mechanism="T068", operations={NATIVE_OPERATION}, now=now)
        effect_subject, effect_head = _current_projection(effect, edge="effect_authority_to_recovery_v1", mechanism="T064", operations={"verify_effect_authority", "revoke_effect_authority"}, now=now)
        try:
            native_chain = _projection_json(native, "successor_bytes")
            current: list[dict[str, Any]] = []
            for candidate in native_chain:
                current.append(t068.validate_candidate(candidate, expected_native_host_id=candidate["native_host"]["native_host_id"], expected_bindings=candidate["bindings"], now=t068._time(candidate["observed_at"], "$.imports.native"), previous=None if not current else current[-1]))
            effect_ledger = t064.validate_ledger(_projection_json(effect, "successor_bytes"))
            responses_family._validate_transition(_projection_json(projection, "transition_bytes"), "$.imports.projection")
        except (KeyError, TypeError, t068.SupervisionError, t064.EffectAuthorityError, responses_family.ResponsesSealsFamilyError) as exc:
            raise NativeRecoveryFamilyError("family_dependency_mechanism_invalid", "$.imports") from exc
        if not native_chain or not effect_ledger["events"]:
            raise NativeRecoveryFamilyError("family_dependency_import_missing", "$.imports")
        heads = {"responses_projection_to_recovery_v1": projection_head, "native_supervision_to_recovery_v1": native_head, "effect_authority_to_recovery_v1": effect_head}
        subjects = {"projection": projection_subject, "native": native_subject, "effect": effect_subject, "native_candidate_sha256": native_chain[-1]["candidate_sha256"], "effect_head_sha256": effect_ledger["head_sha256"]}
        return heads, subjects

    def reconcile_and_issue_grant(self, *, acquisition_id: str, workspace_id: str, effect_id: str,
                                  run_id: str, thread_id: str, lease_id: str,
                                  predecessor_fencing_token: int, predecessor_fencing_version: int,
                                  owner_now: datetime) -> RecoverySuccessor:
        _identifier(acquisition_id, "$.acquisition_id"); now = _utc(owner_now, "$.owner_now")
        scope = {field: _identifier(value, "$." + field) for field, value in {"workspace_id": workspace_id, "effect_id": effect_id, "run_id": run_id, "thread_id": thread_id, "lease_id": lease_id}.items()}
        prior_token = _positive(predecessor_fencing_token, "$.predecessor_fencing_token", zero=True); prior_version = _positive(predecessor_fencing_version, "$.predecessor_fencing_version", zero=True)
        heads, subjects = self._imports(now)
        derived = {"predecessor_effect_state_sha256": subjects["effect_head_sha256"], "predecessor_effect_receipt_sha256": _digest(subjects["effect"]), "reconciliation_decision_sha256": _digest({"imports": heads, "scope": scope, "native_candidate_sha256": subjects["native_candidate_sha256"]}), "t064_identity_sha256": _digest(subjects["effect"]), "t066_identity_sha256": _digest(subjects["projection"])}
        request = {**scope, **derived, "predecessor_fencing_token": prior_token, "predecessor_fencing_version": prior_version, "dependency_import_heads": heads}
        descriptor = self._lock()
        try:
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); ledger = state["ledger"]
            existing = next((item for item in state["transitions"] if item["acquisition_id"] == acquisition_id), None)
            if existing is not None:
                if existing["request_sha256"] != _digest(request) or existing["dependency_import_heads"] != heads:
                    raise NativeRecoveryFamilyError("family_acquisition_collision", "$.acquisition_id")
                grant_event = next(event for event in ledger["events"] if event["event_sha256"] == existing["mechanism_event_sha256"])
                reservation_event = ledger["events"][ledger["events"].index(grant_event) - 1]
                return self._successor(acquisition_id, ledger, reservation_event["decision_sha256"], grant_event["decision_sha256"])
            same_scope = []
            for event in ledger["events"]:
                if event["event_type"] != "issue" or event["decision"]["variant"] != "recovery_reservation_candidate":
                    continue
                decision = event["decision"]; payload = decision["payload"]
                retained_scope = (decision["bindings"]["workspace_id"], payload["effect_id"], payload["run_id"], payload["thread_id"], payload["lease_id"])
                if retained_scope == (workspace_id, effect_id, run_id, thread_id, lease_id):
                    same_scope.append(payload)
            if same_scope:
                retained = same_scope[-1]
                if (prior_token, prior_version) != (retained["fencing_token"], retained["fencing_version"]):
                    raise NativeRecoveryFamilyError("family_recovery_predecessor_fence_mismatch", "$.predecessor_fencing_token")
            reservation_id = acquisition_id + ".reservation"; grant_id = acquisition_id + ".grant"
            bindings = {"workspace_id": workspace_id, "source_sha256": SOURCE_BUILD_SHA256, "candidate_sha256": _split_manifest(self.owner_id, self.protocol, self.operation)["manifest_sha256"], "manifest_sha256": _split_manifest(self.owner_id, self.protocol, self.operation)["manifest_sha256"], "generation": 1, "service_start_id": "recovery-source-local-start-v1", "dependency_receipts_sha256": t069.canonical_digest({"imports": heads})}
            common = {"effect_id": effect_id, "run_id": run_id, "thread_id": thread_id, "lease_id": lease_id, **derived}
            reservation = NativeRecoveryFamilyStore._decision(reservation_id, "recovery_reservation_candidate", bindings, {"reservation_id": reservation_id, **common, "fencing_token": prior_token + 1, "fencing_version": prior_version + 1}, now)
            first = t069.issue_decision(ledger, reservation, expected_head_sha256=ledger["head_sha256"], expected_bindings=bindings, now=now)
            grant = NativeRecoveryFamilyStore._decision(grant_id, "recovery_lease_grant_candidate", bindings, {"grant_id": grant_id, "reservation_sha256": reservation["decision_sha256"], **common, "predecessor_fencing_token": prior_token + 1, "predecessor_fencing_version": prior_version + 1, "fencing_token": prior_token + 2, "fencing_version": prior_version + 2}, now + timedelta(seconds=1))
            successor = t069.issue_decision(first, grant, expected_head_sha256=first["head_sha256"], expected_bindings=bindings, now=now + timedelta(seconds=1))
            transition = {"schema_version": 1, "artifact_type": SPLIT_TRANSITION_TYPE, "owner_id": self.owner_id, "operation": self.operation, "acquisition_id": acquisition_id, "request_sha256": _digest(request), "predecessor_head_sha256": ledger["head_sha256"], "successor_head_sha256": successor["head_sha256"], "predecessor_ledger_bytes_sha256": _bytes_digest(_canonical_bytes(ledger)), "successor_ledger_bytes_sha256": _bytes_digest(_canonical_bytes(successor)), "dependency_import_heads": heads, "mechanism_event_sha256": successor["events"][-1]["event_sha256"], "proof_boundary": EXECUTION_SCOPE, "transition_sha256": ""}
            transition["transition_sha256"] = _digest({key: item for key, item in transition.items() if key != "transition_sha256"})
            state["ledger"] = successor; state["transitions"].append(transition); self._commit(snapshot, state)
            return RecoverySuccessor(RECOVERY_OPERATION, acquisition_id, ledger["head_sha256"], _canonical_bytes(ledger), reservation["decision_sha256"], grant["decision_sha256"], successor["head_sha256"], _canonical_bytes(successor))
        except t069.RecoveryError as exc:
            raise NativeRecoveryFamilyError("family_t069_invalid", exc.path) from exc
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)

    def _successor(self, acquisition_id: str, ledger: Mapping[str, Any], reservation_sha: str, grant_sha: str) -> RecoverySuccessor:
        grant_index = next(index for index, event in enumerate(ledger["events"]) if event["decision_sha256"] == grant_sha)
        before = deepcopy(dict(ledger)); before["events"] = deepcopy(ledger["events"][:grant_index - 1]); before["head_sha256"] = t069.new_ledger(RECOVERY_LEDGER_ID)["head_sha256"] if not before["events"] else before["events"][-1]["event_sha256"]
        before["state_sha256"] = t069.validate_ledger(t069.new_ledger(RECOVERY_LEDGER_ID))["state_sha256"] if not before["events"] else t069._seal_state(before)
        return RecoverySuccessor(RECOVERY_OPERATION, acquisition_id, before["head_sha256"], _canonical_bytes(before), reservation_sha, grant_sha, ledger["head_sha256"], _canonical_bytes(ledger))

    def revoke_recovery(self, *, decision_sha256: str, reason: str, owner_now: datetime) -> RecoverySuccessor:
        descriptor = self._lock()
        try:
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); ledger = state["ledger"]
            retained = next((event for event in ledger["events"] if event["event_type"] == "revoke" and event["decision_sha256"] == decision_sha256), None)
            if retained is not None:
                prior_transition = next(item for item in state["transitions"] if item["mechanism_event_sha256"] == retained["event_sha256"])
                if prior_transition["request_sha256"] != _digest({"decision_sha256": decision_sha256, "reason": reason}):
                    raise NativeRecoveryFamilyError("family_revoke_collision", "$.decision_sha256")
                event_index = ledger["events"].index(retained)
                before = deepcopy(ledger); before["events"] = deepcopy(ledger["events"][:event_index])
                before["head_sha256"] = t069.new_ledger(RECOVERY_LEDGER_ID)["head_sha256"] if not before["events"] else before["events"][-1]["event_sha256"]
                before["state_sha256"] = t069._seal_state(before)
                return RecoverySuccessor(RECOVERY_OPERATION, "revoke", prior_transition["predecessor_head_sha256"], _canonical_bytes(before), decision_sha256, decision_sha256, ledger["head_sha256"], _canonical_bytes(ledger))
            successor = t069.revoke_decision(ledger, decision_sha256=decision_sha256, reason=reason, expected_head_sha256=ledger["head_sha256"], occurred_at=_utc(owner_now, "$.owner_now"))
            dependency_heads = deepcopy(state["transitions"][-1]["dependency_import_heads"])
            transition = {"schema_version": 1, "artifact_type": SPLIT_TRANSITION_TYPE, "owner_id": self.owner_id, "operation": "revoke_recovery", "acquisition_id": "revoke-" + decision_sha256.removeprefix("sha256:"), "request_sha256": _digest({"decision_sha256": decision_sha256, "reason": reason}), "predecessor_head_sha256": ledger["head_sha256"], "successor_head_sha256": successor["head_sha256"], "predecessor_ledger_bytes_sha256": _bytes_digest(_canonical_bytes(ledger)), "successor_ledger_bytes_sha256": _bytes_digest(_canonical_bytes(successor)), "dependency_import_heads": dependency_heads, "mechanism_event_sha256": successor["events"][-1]["event_sha256"], "proof_boundary": EXECUTION_SCOPE, "transition_sha256": ""}
            transition["transition_sha256"] = _digest({key: item for key, item in transition.items() if key != "transition_sha256"})
            state["ledger"] = successor; state["transitions"].append(transition); self._commit(snapshot, state)
            return RecoverySuccessor(RECOVERY_OPERATION, "revoke", ledger["head_sha256"], _canonical_bytes(ledger), decision_sha256, decision_sha256, successor["head_sha256"], _canonical_bytes(successor))
        except t069.RecoveryError as exc:
            raise NativeRecoveryFamilyError("family_t069_invalid", exc.path) from exc
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)

    def consume_recovery_grant(self, *, grant_sha256: str, use_receipt_sha256: str, owner_now: datetime) -> dict[str, Any]:
        _sha(grant_sha256, "$.grant_sha256"); _sha(use_receipt_sha256, "$.use_receipt_sha256"); now = _utc(owner_now, "$.owner_now")
        descriptor = self._lock()
        try:
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); existing = next((item for item in state["consumptions"] if item["grant_sha256"] == grant_sha256), None)
            if existing:
                if existing["use_receipt_sha256"] != use_receipt_sha256: raise NativeRecoveryFamilyError("family_consumption_collision", "$.grant_sha256")
                return deepcopy(existing)
            row = {"schema_version": 1, "artifact_type": CONSUMPTION_TYPE, "sequence": len(state["consumptions"]) + 1, "grant_sha256": grant_sha256, "use_receipt_sha256": use_receipt_sha256, "observed_at": _format(now), "previous_consumption_sha256": None if not state["consumptions"] else state["consumptions"][-1]["consumption_sha256"], "consumption_sha256": ""}
            row["consumption_sha256"] = _digest({key: item for key, item in row.items() if key != "consumption_sha256"}); state["consumptions"].append(row); self._commit(snapshot, state); return deepcopy(row)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN); os.close(descriptor)

    def current_export_material(self) -> dict[str, Any]:
        snapshot = self.recover(); transitions = snapshot["state"]["transitions"]
        if not transitions: raise NativeRecoveryFamilyError("family_export_unavailable", "$.transitions")
        transition = transitions[-1]
        latest_event = snapshot["state"]["ledger"]["events"][-1]
        subject_field = "grant_sha256" if latest_event["event_type"] == "issue" else "decision_sha256"
        predecessor = deepcopy(snapshot["state"]["ledger"])
        remove_count = 2 if transition["operation"] == RECOVERY_OPERATION else 1
        predecessor["events"] = deepcopy(predecessor["events"][:-remove_count])
        predecessor["head_sha256"] = t069.new_ledger(RECOVERY_LEDGER_ID)["head_sha256"] if not predecessor["events"] else predecessor["events"][-1]["event_sha256"]
        predecessor["state_sha256"] = t069._seal_state(predecessor)
        return {"operation": transition["operation"], "event_kind": latest_event["event_type"], "semantic_subject": {subject_field: latest_event["decision_sha256"]}, "predecessor_bytes": _canonical_bytes(predecessor), "successor_bytes": _canonical_bytes(snapshot["state"]["ledger"]), "transition_bytes": _canonical_bytes(transition), "anchor": _split_anchor(self.owner_id, snapshot), "dependency_import_heads": deepcopy(transition["dependency_import_heads"])}
