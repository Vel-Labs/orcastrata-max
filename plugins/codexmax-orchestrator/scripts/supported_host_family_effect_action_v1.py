#!/usr/bin/env python3
"""Separate durable first-party owners for accepted T064 and T072 ledgers.

The supported effect-authority store owns T064 and a typed imported T066
context. The supported registered-action store owns T072 and a typed imported
T064 transition. The combined T091 store remains a migration helper only.
Registered-action execution follows registry, admission, and observation order.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterator, Mapping

from codexmax_package_host.protocol_v1 import digest, format_time

import supported_host_effect_authority_v1 as t064
import supported_host_family_responses_seals_v1 as responses_family
import supported_host_registered_action_v1 as t072


PROTOCOL_VERSION = "supported_host_family_effect_action_v1"
OWNER_ID = "effect_action"
PRINCIPAL_ID = "first-party-effect-action-producer-v1"
EFFECT_LEDGER_ID = "first-party-effect-authority-ledger-v1"
ACTION_LEDGER_ID = "first-party-registered-action-ledger-v1"
PROOF_BOUNDARY = "source_local_quarantine_non_production"
MANIFEST_TYPE = "supported_host_family_effect_action_manifest_v1"
SNAPSHOT_TYPE = "supported_host_family_effect_action_snapshot_v1"
ANCHOR_TYPE = "supported_host_family_effect_action_anchor_v1"
CONTEXT_TYPE = "supported_host_family_effect_action_context_v1"
TRANSITION_TYPE = "supported_host_family_effect_action_transition_v1"
ISSUER_ACTOR = "first-party-effect-authority-owner"
ISSUER_GOAL_ID = "codexmax-standalone-product-completion-v1"
ISSUER_TASK_ID = "supported-host-runtime"
TRANSPORT = "admitted-local"

EFFECT_OWNER_ID = "effect-authority"
ACTION_OWNER_ID = "registered-action"
EFFECT_PROTOCOL_VERSION = "supported_host_effect_authority_family_v1"
ACTION_PROTOCOL_VERSION = "supported_host_registered_action_family_v1"
SPLIT_MANIFEST_TYPE = "supported_host_split_family_manifest_v1"
SPLIT_SNAPSHOT_TYPE = "supported_host_split_family_snapshot_v1"
SPLIT_ANCHOR_TYPE = "supported_host_split_family_anchor_v1"
SPLIT_TRANSITION_TYPE = "supported_host_split_family_transition_v1"

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class EffectActionFamilyError(ValueError):
    """Stable rejection that does not echo caller data."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _projection_field(projection: Any, name: str) -> Any:
    """Read one fixed field from a typed artifact-store projection."""

    if isinstance(projection, Mapping):
        if name not in projection:
            raise EffectActionFamilyError("family_import_projection_invalid", "$.import." + name)
        return projection[name]
    if not hasattr(projection, name):
        raise EffectActionFamilyError("family_import_projection_invalid", "$.import." + name)
    return getattr(projection, name)


def _projection_json(projection: Any, name: str) -> Any:
    value = _projection_field(projection, name)
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EffectActionFamilyError("family_import_bytes_invalid", "$.import." + name) from exc
    elif isinstance(value, str):
        decoded = value
    else:
        return deepcopy(value)
    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise EffectActionFamilyError("family_import_bytes_invalid", "$.import." + name) from exc
    if decoded.encode("utf-8") != _canonical_bytes(parsed):
        raise EffectActionFamilyError("family_import_bytes_noncanonical", "$.import." + name)
    return parsed


def _current_import(projection: Any, *, edge: str, operation: str, now: datetime) -> tuple[Any, str]:
    """Validate a current typed dependency projection without accepting bytes publicly."""

    if _projection_field(projection, "edge_id") != edge:
        raise EffectActionFamilyError("family_import_edge_mismatch", "$.import.edge_id")
    if _projection_field(projection, "operation") != operation:
        raise EffectActionFamilyError("family_import_operation_mismatch", "$.import.operation")
    if _projection_field(projection, "authority_state") != "quarantine":
        raise EffectActionFamilyError("family_import_authority_state_invalid", "$.import.authority_state")
    if _projection_field(projection, "proof_boundary") != PROOF_BOUNDARY:
        raise EffectActionFamilyError("family_import_proof_boundary_invalid", "$.import.proof_boundary")
    expiry = t064._time(_projection_field(projection, "effective_expires_at"), "$.import.effective_expires_at")
    if expiry <= now:
        raise EffectActionFamilyError("family_import_expired", "$.import.effective_expires_at")
    head = _sha(_projection_field(projection, "import_head_sha256"), "$.import.import_head_sha256")
    return deepcopy(_projection_field(projection, "semantic_subject")), head


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EffectActionFamilyError("family_canonical_value_invalid") from exc


def _bytes_sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise EffectActionFamilyError("family_digest_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise EffectActionFamilyError("family_identifier_invalid", path)
    return value


def _utc(value: Any, path: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise EffectActionFamilyError("family_clock_invalid", path)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = deepcopy(dict(value))
    row[field] = digest({key: item for key, item in row.items() if key != field})
    return row


def _validate_seal(value: Mapping[str, Any], field: str, code: str, path: str) -> None:
    _sha(value.get(field), path + "." + field)
    if value[field] != digest({key: item for key, item in value.items() if key != field}):
        raise EffectActionFamilyError(code, path + "." + field)


def _manifest() -> dict[str, Any]:
    return _seal({
        "schema_version": 1,
        "artifact_type": MANIFEST_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "owner_id": OWNER_ID,
        "producer_principal_id": PRINCIPAL_ID,
        "operations": ["verify_effect_authority", "invoke_registered_action"],
        "effect_ledger_id": EFFECT_LEDGER_ID,
        "action_ledger_id": ACTION_LEDGER_ID,
        "proof_boundary": PROOF_BOUNDARY,
        "manifest_sha256": "",
    }, "manifest_sha256")


def _empty_state() -> dict[str, Any]:
    return {
        "contexts": [],
        "effect_ledger": t064.new_ledger(EFFECT_LEDGER_ID),
        "action_ledger": t072.new_ledger(ACTION_LEDGER_ID),
        "transitions": [],
    }


def _anchor(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    state = snapshot["state"]
    effect_bytes = _canonical_bytes(state["effect_ledger"])
    action_bytes = _canonical_bytes(state["action_ledger"])
    return _seal({
        "schema_version": 1,
        "artifact_type": ANCHOR_TYPE,
        "family_sequence": snapshot["family_sequence"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "effect_sequence": len(state["effect_ledger"]["events"]),
        "effect_head_sha256": state["effect_ledger"]["head_sha256"],
        "effect_ledger_bytes_sha256": _bytes_sha(effect_bytes),
        "action_sequence": len(state["action_ledger"]["events"]),
        "action_head_sha256": state["action_ledger"]["head_sha256"],
        "action_ledger_bytes_sha256": _bytes_sha(action_bytes),
        "anchor_sha256": "",
    }, "anchor_sha256")


def _context_from_transition(transition: Any, identity: Any, retained_at: datetime) -> dict[str, Any]:
    try:
        accepted = responses_family._validate_transition(transition, "$.responses_context_transition")
    except responses_family.ResponsesSealsFamilyError as exc:
        raise EffectActionFamilyError("family_responses_context_invalid", "$.responses_context_transition") from exc
    if accepted["operation"] != "issue_responses_context" or accepted["event_type"] != "issue":
        raise EffectActionFamilyError("family_responses_context_invalid", "$.responses_context_transition.operation")
    try:
        context = t064._context(identity, "$.responses_context_identity")
    except t064.EffectAuthorityError as exc:
        raise EffectActionFamilyError("family_responses_identity_invalid", "$.responses_context_identity") from exc
    artifact = accepted["owner_artifact"]
    if artifact["identity_sha256"] != responses_family._digest(context):
        raise EffectActionFamilyError("family_responses_identity_mismatch", "$.responses_context_identity")
    if artifact["request_sha256"] != context["request_sha256"]:
        raise EffectActionFamilyError("family_responses_request_mismatch", "$.responses_context_identity.request_sha256")
    row = _seal({
        "schema_version": 1,
        "artifact_type": CONTEXT_TYPE,
        "context_decision_sha256": accepted["decision_sha256"],
        "responses_transition_sha256": accepted["transition_sha256"],
        "responses_successor_ledger_bytes_sha256": accepted["successor_ledger_bytes_sha256"],
        "identity": context,
        "retained_at": format_time(_utc(retained_at, "$.retained_at")),
        "context_record_sha256": "",
    }, "context_record_sha256")
    return row


def _validate_context(value: Any, path: str) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "context_decision_sha256", "responses_transition_sha256",
              "responses_successor_ledger_bytes_sha256", "identity", "retained_at", "context_record_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EffectActionFamilyError("family_context_shape_invalid", path)
    row = deepcopy(dict(value))
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != CONTEXT_TYPE:
        raise EffectActionFamilyError("family_context_identity_invalid", path)
    for field in ("context_decision_sha256", "responses_transition_sha256", "responses_successor_ledger_bytes_sha256"):
        _sha(row[field], path + "." + field)
    try:
        t064._context(row["identity"], path + ".identity")
        t064._time(row["retained_at"], path + ".retained_at")
    except t064.EffectAuthorityError as exc:
        raise EffectActionFamilyError("family_context_invalid", path) from exc
    _validate_seal(row, "context_record_sha256", "family_context_digest_mismatch", path)
    return row


def _transition(kind: str, operation: str, context_sha: str | None,
                before: Mapping[str, Any], after: Mapping[str, Any], mechanism_event_sha: str) -> dict[str, Any]:
    before_bytes = _canonical_bytes(before)
    after_bytes = _canonical_bytes(after)
    return _seal({
        "schema_version": 1,
        "artifact_type": TRANSITION_TYPE,
        "kind": kind,
        "operation": operation,
        "context_decision_sha256": context_sha,
        "predecessor_sequence": len(before["events"]),
        "predecessor_head_sha256": before["head_sha256"],
        "predecessor_ledger_json": before_bytes.decode("utf-8"),
        "predecessor_ledger_bytes_sha256": _bytes_sha(before_bytes),
        "successor_sequence": len(after["events"]),
        "successor_head_sha256": after["head_sha256"],
        "successor_ledger_json": after_bytes.decode("utf-8"),
        "successor_ledger_bytes_sha256": _bytes_sha(after_bytes),
        "mechanism_event_sha256": mechanism_event_sha,
        "proof_boundary": PROOF_BOUNDARY,
        "transition_sha256": "",
    }, "transition_sha256")


def _parse_ledger(text: Any, kind: str, path: str) -> dict[str, Any]:
    if not isinstance(text, str):
        raise EffectActionFamilyError("family_transition_ledger_invalid", path)
    raw = text.encode("utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EffectActionFamilyError("family_transition_ledger_invalid", path) from exc
    if raw != _canonical_bytes(value):
        raise EffectActionFamilyError("family_transition_ledger_noncanonical", path)
    try:
        return t064.validate_ledger(value) if kind == "effect" else t072.validate_ledger(value)
    except (t064.EffectAuthorityError, t072.RegisteredActionError) as exc:
        raise EffectActionFamilyError("family_transition_ledger_invalid", path) from exc


def _validate_transition(value: Any, path: str) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "kind", "operation", "context_decision_sha256",
              "predecessor_sequence", "predecessor_head_sha256", "predecessor_ledger_json",
              "predecessor_ledger_bytes_sha256", "successor_sequence", "successor_head_sha256",
              "successor_ledger_json", "successor_ledger_bytes_sha256", "mechanism_event_sha256",
              "proof_boundary", "transition_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EffectActionFamilyError("family_transition_shape_invalid", path)
    row = deepcopy(dict(value))
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != TRANSITION_TYPE or row["kind"] not in {"effect", "action"}:
        raise EffectActionFamilyError("family_transition_identity_invalid", path)
    allowed = {"verify_effect_authority", "revoke_effect_authority"} if row["kind"] == "effect" else {
        "retain_registered_action", "admit_registered_action", "invoke_registered_action", "revoke_registered_action"}
    if row["operation"] not in allowed or row["proof_boundary"] != PROOF_BOUNDARY:
        raise EffectActionFamilyError("family_transition_operation_invalid", path)
    if row["context_decision_sha256"] is not None:
        _sha(row["context_decision_sha256"], path + ".context_decision_sha256")
    before = _parse_ledger(row["predecessor_ledger_json"], row["kind"], path + ".predecessor_ledger_json")
    after = _parse_ledger(row["successor_ledger_json"], row["kind"], path + ".successor_ledger_json")
    if after["events"][:-1] != before["events"] or len(after["events"]) != len(before["events"]) + 1:
        raise EffectActionFamilyError("family_transition_chain_invalid", path)
    if row["predecessor_sequence"] != len(before["events"]) or row["successor_sequence"] != len(after["events"]):
        raise EffectActionFamilyError("family_transition_sequence_invalid", path)
    if row["predecessor_head_sha256"] != before["head_sha256"] or row["successor_head_sha256"] != after["head_sha256"]:
        raise EffectActionFamilyError("family_transition_head_invalid", path)
    if row["predecessor_ledger_bytes_sha256"] != _bytes_sha(row["predecessor_ledger_json"].encode()) or row["successor_ledger_bytes_sha256"] != _bytes_sha(row["successor_ledger_json"].encode()):
        raise EffectActionFamilyError("family_transition_bytes_invalid", path)
    if row["mechanism_event_sha256"] != after["events"][-1]["event_sha256"]:
        raise EffectActionFamilyError("family_transition_event_invalid", path)
    _validate_seal(row, "transition_sha256", "family_transition_digest_mismatch", path)
    return row


def _validate_state(value: Any) -> dict[str, Any]:
    fields = {"contexts", "effect_ledger", "action_ledger", "transitions"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EffectActionFamilyError("family_state_shape_invalid", "$.state")
    state = deepcopy(dict(value))
    if not isinstance(state["contexts"], list) or not isinstance(state["transitions"], list):
        raise EffectActionFamilyError("family_state_list_invalid", "$.state")
    try:
        effect = t064.validate_ledger(state["effect_ledger"])
        action = t072.validate_ledger(state["action_ledger"])
    except (t064.EffectAuthorityError, t072.RegisteredActionError) as exc:
        raise EffectActionFamilyError("family_accepted_ledger_invalid", "$.state") from exc
    contexts: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(state["contexts"]):
        context = _validate_context(raw, f"$.state.contexts[{index}]")
        key = context["context_decision_sha256"]
        if key in contexts:
            raise EffectActionFamilyError("family_context_replay", f"$.state.contexts[{index}]")
        contexts[key] = context
    expected_effect = t064.new_ledger(EFFECT_LEDGER_ID)
    expected_action = t072.new_ledger(ACTION_LEDGER_ID)
    transition_ids: set[str] = set()
    for index, raw in enumerate(state["transitions"]):
        transition = _validate_transition(raw, f"$.state.transitions[{index}]")
        if transition["transition_sha256"] in transition_ids:
            raise EffectActionFamilyError("family_transition_replay", f"$.state.transitions[{index}]")
        transition_ids.add(transition["transition_sha256"])
        before = _parse_ledger(transition["predecessor_ledger_json"], transition["kind"], "$.transition.before")
        after = _parse_ledger(transition["successor_ledger_json"], transition["kind"], "$.transition.after")
        if transition["kind"] == "effect":
            if before != expected_effect:
                raise EffectActionFamilyError("family_effect_fork_detected", f"$.state.transitions[{index}]")
            expected_effect = after
            context = contexts.get(transition["context_decision_sha256"])
            if context is None:
                raise EffectActionFamilyError("family_context_dependency_missing", f"$.state.transitions[{index}]")
            event = after["events"][-1]
            if event["event_type"] == "issue":
                identity = context["identity"]
                authority = event["authority"]
                bindings = {
                    "workspace_id": "workspace_id", "source_sha256": "source_sha256",
                    "candidate_sha256": "candidate_sha256", "thread_id": "thread_id",
                    "thread_generation": "thread_generation", "operation": "operation",
                    "request_intent_sha256": "request_intent_sha256",
                }
                if any(authority[target] != identity[source] for target, source in bindings.items()):
                    raise EffectActionFamilyError("family_effect_context_mismatch", f"$.state.transitions[{index}]")
                if event["request_sha256"] != identity["request_sha256"]:
                    raise EffectActionFamilyError("family_effect_context_mismatch", f"$.state.transitions[{index}]")
        else:
            if before != expected_action:
                raise EffectActionFamilyError("family_action_fork_detected", f"$.state.transitions[{index}]")
            expected_action = after
            operation = transition["operation"]
            if operation != "retain_registered_action":
                context = contexts.get(transition["context_decision_sha256"])
                if context is None:
                    raise EffectActionFamilyError("family_context_dependency_missing", f"$.state.transitions[{index}]")
                event = after["events"][-1]
                if operation == "admit_registered_action":
                    authority = event["observation"]["effect_request"]["authority_receipt"]
                    issue = next((item for item in expected_effect["events"] if item["event_type"] == "issue" and item["authority"] == authority), None)
                    linked = next((item for item in state["transitions"][:index] if item["kind"] == "effect" and issue is not None and item["mechanism_event_sha256"] == issue["event_sha256"]), None)
                    if linked is None or linked["context_decision_sha256"] != context["context_decision_sha256"]:
                        raise EffectActionFamilyError("family_effect_context_mismatch", f"$.state.transitions[{index}]")
                else:
                    request_sha = event["effect_request_sha256"]
                    admission = next((item for item in expected_action["events"] if item["event_type"] == "execution_admission" and item["effect_request_sha256"] == request_sha), None)
                    linked = next((item for item in state["transitions"][:index] if item["operation"] == "admit_registered_action" and admission is not None and item["mechanism_event_sha256"] == admission["event_sha256"]), None)
                    if linked is None or linked["context_decision_sha256"] != context["context_decision_sha256"]:
                        raise EffectActionFamilyError("family_effect_context_mismatch", f"$.state.transitions[{index}]")
    if effect != expected_effect or action != expected_action:
        raise EffectActionFamilyError("family_state_ledger_fork", "$.state")
    return state


def _snapshot(sequence: int, previous_sha: str, state: Mapping[str, Any]) -> dict[str, Any]:
    return _seal({
        "schema_version": 1,
        "artifact_type": SNAPSHOT_TYPE,
        "family_sequence": sequence,
        "previous_snapshot_sha256": previous_sha,
        "state": deepcopy(dict(state)),
        "snapshot_sha256": "",
    }, "snapshot_sha256")


def _validate_snapshot(value: Any, expected_sequence: int, expected_previous: str) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "family_sequence", "previous_snapshot_sha256", "state", "snapshot_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EffectActionFamilyError("family_snapshot_shape_invalid", "$.snapshot")
    row = deepcopy(dict(value))
    if type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["artifact_type"] != SNAPSHOT_TYPE or type(row["family_sequence"]) is not int or row["family_sequence"] != expected_sequence:
        raise EffectActionFamilyError("family_snapshot_sequence_invalid", "$.snapshot")
    if row["previous_snapshot_sha256"] != expected_previous:
        raise EffectActionFamilyError("family_snapshot_fork_detected", "$.snapshot.previous_snapshot_sha256")
    _validate_state(row["state"])
    _validate_seal(row, "snapshot_sha256", "family_snapshot_digest_mismatch", "$.snapshot")
    return row


class EffectActionFamilyStore:
    """Historical T091 combined store. Do not use it as a supported runtime."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.snapshots = self.root / "snapshots"
        self.manifest_path = self.root / "manifest.json"
        self.anchor_path = self.root / "anchor.json"
        self.lock_path = self.root / ".lock"
        self._initialize()

    def _initialize(self) -> None:
        if self.root.is_symlink():
            raise EffectActionFamilyError("family_root_symlink_forbidden", "$.root")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.snapshots.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        with self._lock():
            if not self.manifest_path.exists():
                initial = _snapshot(0, digest({"artifact_type": "supported_host_family_effect_action_genesis_v1"}), _empty_state())
                self._publish_new(self.manifest_path, _manifest())
                self._publish_new(self.snapshots / "00000000000000000000.json", initial)
                self._replace(self.anchor_path, _anchor(initial))
            self._recover_locked()

    @contextmanager
    def _lock(self) -> Iterator[None]:
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _write_temp(path: Path, value: Any) -> Path:
        descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=path.parent)
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        try:
            data = _canonical_bytes(value)
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return temporary

    @classmethod
    def _publish_new(cls, path: Path, value: Any) -> None:
        if path.exists() or path.is_symlink():
            raise EffectActionFamilyError("family_publication_collision", "$.store")
        temporary = cls._write_temp(path, value)
        try:
            os.link(temporary, path, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)
        cls._fsync(path.parent)

    @classmethod
    def _replace(cls, path: Path, value: Any) -> None:
        if path.is_symlink():
            raise EffectActionFamilyError("family_file_symlink_forbidden", "$.store")
        temporary = cls._write_temp(path, value)
        os.replace(temporary, path)
        cls._fsync(path.parent)

    @staticmethod
    def _fsync(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read(path: Path) -> Any:
        if path.is_symlink() or not path.is_file():
            raise EffectActionFamilyError("family_file_invalid", "$.store")
        try:
            data = path.read_bytes()
            value = json.loads(data)
        except (OSError, json.JSONDecodeError) as exc:
            raise EffectActionFamilyError("family_file_invalid", "$.store") from exc
        if data != _canonical_bytes(value):
            raise EffectActionFamilyError("family_file_noncanonical", "$.store")
        return value

    def _recover_locked(self) -> dict[str, Any]:
        manifest = self._read(self.manifest_path)
        if not isinstance(manifest, Mapping) or type(manifest.get("schema_version")) is not int or manifest != _manifest():
            raise EffectActionFamilyError("family_manifest_mismatch", "$.manifest")
        paths = sorted(self.snapshots.iterdir())
        if not paths:
            raise EffectActionFamilyError("family_truncation_detected", "$.snapshots")
        previous = digest({"artifact_type": "supported_host_family_effect_action_genesis_v1"})
        latest: dict[str, Any] | None = None
        for sequence, path in enumerate(paths):
            if path.is_symlink() or path.name != f"{sequence:020d}.json":
                raise EffectActionFamilyError("family_snapshot_gap", "$.snapshots")
            latest = _validate_snapshot(self._read(path), sequence, previous)
            previous = latest["snapshot_sha256"]
        assert latest is not None
        anchor = self._read(self.anchor_path)
        fields = {"schema_version", "artifact_type", "family_sequence", "snapshot_sha256", "effect_sequence",
                  "effect_head_sha256", "effect_ledger_bytes_sha256", "action_sequence", "action_head_sha256",
                  "action_ledger_bytes_sha256", "anchor_sha256"}
        if not isinstance(anchor, Mapping) or set(anchor) != fields:
            raise EffectActionFamilyError("family_anchor_invalid", "$.anchor")
        if (type(anchor["schema_version"]) is not int or anchor["schema_version"] != 1
                or anchor["artifact_type"] != ANCHOR_TYPE
                or any(type(anchor[field]) is not int or anchor[field] < 0 for field in (
                    "family_sequence", "effect_sequence", "action_sequence"))):
            raise EffectActionFamilyError("family_anchor_invalid", "$.anchor")
        for field in ("snapshot_sha256", "effect_head_sha256", "effect_ledger_bytes_sha256",
                      "action_head_sha256", "action_ledger_bytes_sha256"):
            _sha(anchor[field], "$.anchor." + field)
        _validate_seal(anchor, "anchor_sha256", "family_anchor_invalid", "$.anchor")
        if anchor["family_sequence"] > latest["family_sequence"]:
            raise EffectActionFamilyError("family_truncation_detected", "$.anchor.family_sequence")
        anchored = _validate_snapshot(self._read(self.snapshots / f"{anchor['family_sequence']:020d}.json"), anchor["family_sequence"],
                                      digest({"artifact_type": "supported_host_family_effect_action_genesis_v1"}) if anchor["family_sequence"] == 0 else self._read(self.snapshots / f"{anchor['family_sequence'] - 1:020d}.json")["snapshot_sha256"])
        if anchor != _anchor(anchored):
            raise EffectActionFamilyError("family_anchor_fork_detected", "$.anchor")
        if anchor["family_sequence"] < latest["family_sequence"]:
            self._replace(self.anchor_path, _anchor(latest))
        return latest

    def recover(self) -> dict[str, Any]:
        with self._lock():
            snapshot = self._recover_locked()
            state = snapshot["state"]
            return {
                "family_sequence": snapshot["family_sequence"],
                "effect_ledger": deepcopy(state["effect_ledger"]),
                "effect_ledger_json": _canonical_bytes(state["effect_ledger"]).decode(),
                "action_ledger": deepcopy(state["action_ledger"]),
                "action_ledger_json": _canonical_bytes(state["action_ledger"]).decode(),
                "contexts": deepcopy(state["contexts"]),
                "transitions": deepcopy(state["transitions"]),
                "anchor": _anchor(snapshot),
                "proof_boundary": PROOF_BOUNDARY,
            }

    def _commit(self, state: Mapping[str, Any], previous: Mapping[str, Any]) -> dict[str, Any]:
        sequence = previous["family_sequence"] + 1
        snapshot = _snapshot(sequence, previous["snapshot_sha256"], state)
        _validate_snapshot(snapshot, sequence, previous["snapshot_sha256"])
        self._publish_new(self.snapshots / f"{sequence:020d}.json", snapshot)
        self._replace(self.anchor_path, _anchor(snapshot))
        return snapshot

    @staticmethod
    def _find_context(state: Mapping[str, Any], context_sha: str) -> dict[str, Any]:
        _sha(context_sha, "$.context_decision_sha256")
        for item in state["contexts"]:
            if item["context_decision_sha256"] == context_sha:
                return item
        raise EffectActionFamilyError("family_context_dependency_missing", "$.context_decision_sha256")

    def verify_effect_authority(self, *, responses_context_transition: Mapping[str, Any],
                                responses_context_identity: Mapping[str, Any], owner_now: datetime) -> dict[str, Any]:
        """Retain one exact T066 context and derive one exact T064 authority."""

        context = _context_from_transition(responses_context_transition, responses_context_identity, owner_now)
        now = _utc(owner_now, "$.owner_now")
        with self._lock():
            snapshot = self._recover_locked()
            state = deepcopy(snapshot["state"])
            existing_context = next((item for item in state["contexts"] if item["context_decision_sha256"] == context["context_decision_sha256"]), None)
            if existing_context is not None and existing_context != context:
                raise EffectActionFamilyError("family_context_collision", "$.responses_context_transition")
            existing = next((item for item in state["transitions"] if item["operation"] == "verify_effect_authority" and item["context_decision_sha256"] == context["context_decision_sha256"]), None)
            if existing is not None:
                return deepcopy(existing)
            if existing_context is None:
                state["contexts"].append(context)
            identity = context["identity"]
            expires = t064._time(identity["expires_at"], "$.responses_context_identity.expires_at")
            if expires <= now:
                raise EffectActionFamilyError("family_context_expired", "$.responses_context_identity.expires_at")
            basis = {"context_decision_sha256": context["context_decision_sha256"], "context_record_sha256": context["context_record_sha256"]}
            authority_id = "authority-" + digest(basis).removeprefix("sha256:")
            receipt = {
                "schema_version": 1, "artifact_type": "effect_kernel_authority_receipt_v1",
                "authority_id": authority_id, "issuer_id": t064.ISSUER_DECISION_SOURCE_ID,
                "actor": ISSUER_ACTOR, "workspace_id": identity["workspace_id"],
                "goal_id": ISSUER_GOAL_ID, "task_id": ISSUER_TASK_ID,
                "source_sha256": identity["source_sha256"], "candidate_sha256": identity["candidate_sha256"],
                "thread_id": identity["thread_id"], "thread_generation": identity["thread_generation"],
                "operation": identity["operation"], "request_intent_sha256": identity["request_intent_sha256"],
                "issued_at": format_time(now), "expires_at": format_time(expires), "receipt_sha256": "",
            }
            receipt["receipt_sha256"] = digest({key: item for key, item in receipt.items() if key != "receipt_sha256"})
            decision = {
                "schema_version": 1, "artifact_type": t064.ISSUER_DECISION_TYPE,
                "decision_id": "decision-" + digest({**basis, "authority_receipt_sha256": receipt["receipt_sha256"]}).removeprefix("sha256:"),
                "decision_source_id": t064.ISSUER_DECISION_SOURCE_ID, "decision": "issue",
                "ledger_id": EFFECT_LEDGER_ID, "authority": receipt,
                "request_sha256": identity["request_sha256"], "decided_at": format_time(now),
                "expires_at": format_time(expires), "decision_sha256": "",
            }
            decision["decision_sha256"] = digest({key: item for key, item in decision.items() if key != "decision_sha256"})
            decision = t064.validate_issuer_decision(decision, expected_ledger_id=EFFECT_LEDGER_ID,
                                                     expected_context=identity, now=now)
            before = state["effect_ledger"]
            after = t064.issue_authority(before, decision, expected_head_sha256=before["head_sha256"])
            transition = _transition("effect", "verify_effect_authority", context["context_decision_sha256"], before, after, after["events"][-1]["event_sha256"])
            state["effect_ledger"] = after
            state["transitions"].append(transition)
            self._commit(state, snapshot)
            return deepcopy(transition)

    def retain_registered_action(self, *, action_id: str, tool_id: str,
                                 parameter_fields: list[str], owner_now: datetime) -> dict[str, Any]:
        """Retain a repository transport registry entry before admission."""

        registration = {"action_id": _identifier(action_id, "$.action_id"),
                        "tool_id": _identifier(tool_id, "$.tool_id"), "transport": TRANSPORT,
                        "parameter_fields": deepcopy(parameter_fields)}
        now = _utc(owner_now, "$.owner_now")
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); before = state["action_ledger"]
            try:
                after = t072.record_registration(before, registration, expected_head_sha256=before["head_sha256"], occurred_at=now)
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            if after == before:
                return deepcopy(next(item for item in state["transitions"] if item["operation"] == "retain_registered_action" and json.loads(item["successor_ledger_json"])["events"][-1]["action_id"] == action_id))
            transition = _transition("action", "retain_registered_action", None, before, after, after["events"][-1]["event_sha256"])
            state["action_ledger"] = after; state["transitions"].append(transition); self._commit(state, snapshot)
            return deepcopy(transition)

    def admit_registered_action(self, *, context_decision_sha256: str,
                                effect_request: Mapping[str, Any], admitted_at: datetime) -> dict[str, Any]:
        now = _utc(admitted_at, "$.admitted_at")
        if not isinstance(effect_request, Mapping):
            raise EffectActionFamilyError("family_effect_request_invalid", "$.effect_request")
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"])
            context = self._find_context(state, context_decision_sha256)
            issue = next((event for event in state["effect_ledger"]["events"] if event["event_type"] == "issue" and event["authority"] == effect_request.get("authority_receipt")), None)
            if issue is None:
                raise EffectActionFamilyError("family_effect_authority_unavailable", "$.effect_request.authority_receipt")
            linked = next((item for item in state["transitions"] if item["kind"] == "effect" and item["mechanism_event_sha256"] == issue["event_sha256"]), None)
            if linked is None or linked["context_decision_sha256"] != context["context_decision_sha256"]:
                raise EffectActionFamilyError("family_effect_context_mismatch", "$.effect_request.authority_receipt")
            identity = context["identity"]
            if any(effect_request.get(field) != identity[field] for field in ("workspace_id", "operation")):
                raise EffectActionFamilyError("family_effect_context_mismatch", "$.effect_request")
            before = state["action_ledger"]
            try:
                after = t072.record_execution_admission(before, effect_request, expected_head_sha256=before["head_sha256"], admitted_at=now)
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            if after == before:
                request_sha = effect_request.get("request_sha256")
                return deepcopy(next(item for item in state["transitions"] if item["operation"] == "admit_registered_action" and json.loads(item["successor_ledger_json"])["events"][-1].get("effect_request_sha256") == request_sha))
            transition = _transition("action", "admit_registered_action", context_decision_sha256, before, after, after["events"][-1]["event_sha256"])
            state["action_ledger"] = after; state["transitions"].append(transition); self._commit(state, snapshot)
            return deepcopy(transition)

    def invoke_registered_action(self, *, context_decision_sha256: str,
                                 executor_receipt: Mapping[str, Any], observed_at: datetime,
                                 expires_at: datetime) -> dict[str, Any]:
        now = _utc(observed_at, "$.observed_at"); expiry = _utc(expires_at, "$.expires_at")
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"])
            self._find_context(state, context_decision_sha256)
            if not isinstance(executor_receipt, Mapping):
                raise EffectActionFamilyError("family_executor_observation_unavailable", "$.executor_receipt")
            request_sha = executor_receipt.get("request_sha256")
            admission = next((event for event in state["action_ledger"]["events"] if event["event_type"] == "execution_admission" and event["effect_request_sha256"] == request_sha), None)
            if admission is None:
                raise EffectActionFamilyError("family_executor_admission_missing", "$.executor_receipt.request_sha256")
            linked = next((item for item in state["transitions"] if item["operation"] == "admit_registered_action" and item["mechanism_event_sha256"] == admission["event_sha256"]), None)
            if linked is None or linked["context_decision_sha256"] != context_decision_sha256:
                raise EffectActionFamilyError("family_effect_context_mismatch", "$.executor_receipt")
            before = state["action_ledger"]
            try:
                after = t072.record_observation(before, executor_receipt, expected_head_sha256=before["head_sha256"], observed_at=now, expires_at=expiry)
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            if after == before:
                return deepcopy(next(item for item in state["transitions"] if item["operation"] == "invoke_registered_action" and json.loads(item["successor_ledger_json"])["events"][-1].get("effect_request_sha256") == request_sha))
            transition = _transition("action", "invoke_registered_action", context_decision_sha256, before, after, after["events"][-1]["event_sha256"])
            state["action_ledger"] = after; state["transitions"].append(transition); self._commit(state, snapshot)
            return deepcopy(transition)

    def revoke_effect_authority(self, *, context_decision_sha256: str, reason: str,
                                owner_now: datetime) -> dict[str, Any]:
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"])
            self._find_context(state, context_decision_sha256)
            issue = next((event for event in state["effect_ledger"]["events"] if event["event_type"] == "issue" and any(item["mechanism_event_sha256"] == event["event_sha256"] and item["context_decision_sha256"] == context_decision_sha256 for item in state["transitions"])), None)
            if issue is None:
                raise EffectActionFamilyError("family_effect_authority_unavailable", "$.context_decision_sha256")
            before = state["effect_ledger"]
            try:
                after = t064.revoke_authority(before, authority_receipt_sha256=issue["authority_receipt_sha256"], reason=reason,
                                              expected_head_sha256=before["head_sha256"], occurred_at=_utc(owner_now, "$.owner_now"))
            except t064.EffectAuthorityError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            transition = _transition("effect", "revoke_effect_authority", context_decision_sha256, before, after, after["events"][-1]["event_sha256"])
            state["effect_ledger"] = after; state["transitions"].append(transition); self._commit(state, snapshot)
            return deepcopy(transition)

    def revoke_registered_action(self, *, context_decision_sha256: str,
                                 effect_request_sha256: str, reason: str,
                                 owner_now: datetime) -> dict[str, Any]:
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"])
            self._find_context(state, context_decision_sha256)
            before = state["action_ledger"]
            try:
                after = t072.revoke_observation(before, effect_request_sha256=effect_request_sha256, reason=reason,
                                                expected_head_sha256=before["head_sha256"], occurred_at=_utc(owner_now, "$.owner_now"))
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            if after == before:
                return deepcopy(next(item for item in state["transitions"] if item["operation"] == "revoke_registered_action" and json.loads(item["successor_ledger_json"])["events"][-1].get("effect_request_sha256") == effect_request_sha256))
            transition = _transition("action", "revoke_registered_action", context_decision_sha256, before, after, after["events"][-1]["event_sha256"])
            state["action_ledger"] = after; state["transitions"].append(transition); self._commit(state, snapshot)
            return deepcopy(transition)


def _split_manifest(owner_id: str, protocol: str, ledger_id: str) -> dict[str, Any]:
    return _seal({
        "schema_version": 1,
        "artifact_type": SPLIT_MANIFEST_TYPE,
        "protocol_version": protocol,
        "owner_id": owner_id,
        "ledger_id": ledger_id,
        "proof_boundary": PROOF_BOUNDARY,
        "manifest_sha256": "",
    }, "manifest_sha256")


def _split_transition(owner_id: str, operation: str, before: Mapping[str, Any],
                      after: Mapping[str, Any], dependency_heads: Mapping[str, str]) -> dict[str, Any]:
    before_bytes = _canonical_bytes(before)
    after_bytes = _canonical_bytes(after)
    return _seal({
        "schema_version": 1,
        "artifact_type": SPLIT_TRANSITION_TYPE,
        "owner_id": owner_id,
        "operation": operation,
        "predecessor_sequence": len(before["events"]),
        "predecessor_head_sha256": before["head_sha256"],
        "predecessor_ledger_json": before_bytes.decode("utf-8"),
        "predecessor_ledger_bytes_sha256": _bytes_sha(before_bytes),
        "successor_sequence": len(after["events"]),
        "successor_head_sha256": after["head_sha256"],
        "successor_ledger_json": after_bytes.decode("utf-8"),
        "successor_ledger_bytes_sha256": _bytes_sha(after_bytes),
        "mechanism_event_sha256": after["events"][-1]["event_sha256"],
        "dependency_import_heads": deepcopy(dict(dependency_heads)),
        "proof_boundary": PROOF_BOUNDARY,
        "transition_sha256": "",
    }, "transition_sha256")


def validate_split_transition(value: Any, *, owner_id: str, before: Mapping[str, Any], path: str = "$.transition") -> dict[str, Any]:
    """Validate one exact split T064 or T072 transition outside a store."""
    fields = {"schema_version", "artifact_type", "owner_id", "operation", "predecessor_sequence",
              "predecessor_head_sha256", "predecessor_ledger_json", "predecessor_ledger_bytes_sha256",
              "successor_sequence", "successor_head_sha256", "successor_ledger_json",
              "successor_ledger_bytes_sha256", "mechanism_event_sha256", "dependency_import_heads",
              "proof_boundary", "transition_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EffectActionFamilyError("family_transition_shape_invalid", path)
    if owner_id not in {EFFECT_OWNER_ID, ACTION_OWNER_ID}:
        raise EffectActionFamilyError("family_transition_identity_invalid", path)
    row = deepcopy(dict(value))
    if row["schema_version"] != 1 or row["artifact_type"] != SPLIT_TRANSITION_TYPE or row["owner_id"] != owner_id:
        raise EffectActionFamilyError("family_transition_identity_invalid", path)
    kind = "effect" if owner_id == EFFECT_OWNER_ID else "action"
    predecessor = _parse_ledger(row["predecessor_ledger_json"], kind, path)
    successor = _parse_ledger(row["successor_ledger_json"], kind, path)
    if predecessor != before or successor["events"][:-1] != predecessor["events"] or len(successor["events"]) != len(predecessor["events"]) + 1:
        raise EffectActionFamilyError("family_transition_fork_detected", path)
    if row["predecessor_sequence"] != len(predecessor["events"]) or row["successor_sequence"] != len(successor["events"]):
        raise EffectActionFamilyError("family_transition_sequence_invalid", path)
    if row["predecessor_head_sha256"] != predecessor["head_sha256"] or row["successor_head_sha256"] != successor["head_sha256"]:
        raise EffectActionFamilyError("family_transition_head_invalid", path)
    if row["predecessor_ledger_bytes_sha256"] != _bytes_sha(row["predecessor_ledger_json"].encode()) or row["successor_ledger_bytes_sha256"] != _bytes_sha(row["successor_ledger_json"].encode()):
        raise EffectActionFamilyError("family_transition_bytes_invalid", path)
    if row["mechanism_event_sha256"] != successor["events"][-1]["event_sha256"]:
        raise EffectActionFamilyError("family_transition_event_invalid", path)
    if not isinstance(row["dependency_import_heads"], Mapping):
        raise EffectActionFamilyError("family_dependency_heads_invalid", path)
    for edge, head in row["dependency_import_heads"].items():
        _identifier(edge, path + ".dependency_import_heads"); _sha(head, path + ".dependency_import_heads." + edge)
    if row["proof_boundary"] != PROOF_BOUNDARY:
        raise EffectActionFamilyError("family_proof_boundary_invalid", path)
    _validate_seal(row, "transition_sha256", "family_transition_digest_mismatch", path)
    return row


def validate_split_anchor(value: Any, *, owner_id: str, successor: Mapping[str, Any], transition: Mapping[str, Any]) -> dict[str, Any]:
    """Validate exact split anchor parity with the exported accepted ledger."""
    fields = {"schema_version", "artifact_type", "owner_id", "family_sequence", "snapshot_sha256", "ledger_sequence", "ledger_head_sha256", "ledger_bytes_sha256", "anchor_sha256"}
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EffectActionFamilyError("family_anchor_shape_invalid", "$.anchor")
    row = deepcopy(dict(value))
    if row["schema_version"] != 1 or row["artifact_type"] != SPLIT_ANCHOR_TYPE or row["owner_id"] != owner_id:
        raise EffectActionFamilyError("family_anchor_identity_invalid", "$.anchor")
    if row["family_sequence"] < 1 or row["ledger_sequence"] != len(successor["events"]) or row["ledger_head_sha256"] != successor["head_sha256"] or row["ledger_bytes_sha256"] != _bytes_sha(_canonical_bytes(successor)):
        raise EffectActionFamilyError("family_anchor_mismatch", "$.anchor")
    _sha(row["snapshot_sha256"], "$.anchor.snapshot_sha256")
    if transition["successor_head_sha256"] != row["ledger_head_sha256"]:
        raise EffectActionFamilyError("family_anchor_mismatch", "$.anchor")
    _validate_seal(row, "anchor_sha256", "family_anchor_digest_mismatch", "$.anchor")
    return row


class _SplitFamilyStore:
    """One-role append-only store. A subclass owns exactly one accepted ledger."""

    owner_id: str
    protocol: str
    ledger_id: str
    validator: Any
    new_ledger: Any

    def __init__(self, root: Path | str, artifact_store: Any) -> None:
        self.root = Path(root)
        self.artifact_store = artifact_store
        self.manifest_path = self.root / "manifest.json"
        self.snapshots = self.root / "snapshots"
        self.anchor_path = self.root / "anchor.json"
        self.lock_path = self.root / "family.lock"
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshots.mkdir(exist_ok=True)
        self.lock_path.touch(exist_ok=True)
        if not self.manifest_path.exists():
            self._publish_new(self.manifest_path, _split_manifest(self.owner_id, self.protocol, self.ledger_id))
            state = {"ledger": self.new_ledger(self.ledger_id), "transitions": []}
            genesis = self._snapshot(0, self._genesis(), state)
            self._publish_new(self.snapshots / "00000000000000000000.json", genesis)
            self._replace(self.anchor_path, self._anchor(genesis))
        self.recover()

    def _genesis(self) -> str:
        return digest({"artifact_type": self.protocol + "_genesis_v1", "owner_id": self.owner_id})

    @contextmanager
    def _lock(self) -> Iterator[None]:
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @classmethod
    def _write_temp(cls, path: Path, value: Any) -> Path:
        descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
        temporary = Path(name)
        data = _canonical_bytes(value)
        try:
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return temporary

    @classmethod
    def _publish_new(cls, path: Path, value: Any) -> None:
        if path.exists() or path.is_symlink():
            raise EffectActionFamilyError("family_publication_collision", "$.store")
        temporary = cls._write_temp(path, value)
        try:
            os.link(temporary, path, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)
        cls._fsync(path.parent)

    @classmethod
    def _replace(cls, path: Path, value: Any) -> None:
        if path.is_symlink():
            raise EffectActionFamilyError("family_file_symlink_forbidden", "$.store")
        temporary = cls._write_temp(path, value)
        os.replace(temporary, path)
        cls._fsync(path.parent)

    @staticmethod
    def _fsync(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _read(path: Path) -> Any:
        if path.is_symlink() or not path.is_file():
            raise EffectActionFamilyError("family_file_invalid", "$.store")
        data = path.read_bytes()
        try:
            value = json.loads(data)
        except json.JSONDecodeError as exc:
            raise EffectActionFamilyError("family_file_invalid", "$.store") from exc
        if data != _canonical_bytes(value):
            raise EffectActionFamilyError("family_file_noncanonical", "$.store")
        return value

    def _snapshot(self, sequence: int, previous: str, state: Mapping[str, Any]) -> dict[str, Any]:
        return _seal({
            "schema_version": 1,
            "artifact_type": SPLIT_SNAPSHOT_TYPE,
            "owner_id": self.owner_id,
            "family_sequence": sequence,
            "previous_snapshot_sha256": previous,
            "state": deepcopy(dict(state)),
            "snapshot_sha256": "",
        }, "snapshot_sha256")

    def _anchor(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        ledger = snapshot["state"]["ledger"]
        return _seal({
            "schema_version": 1,
            "artifact_type": SPLIT_ANCHOR_TYPE,
            "owner_id": self.owner_id,
            "family_sequence": snapshot["family_sequence"],
            "snapshot_sha256": snapshot["snapshot_sha256"],
            "ledger_sequence": len(ledger["events"]),
            "ledger_head_sha256": ledger["head_sha256"],
            "ledger_bytes_sha256": _bytes_sha(_canonical_bytes(ledger)),
            "anchor_sha256": "",
        }, "anchor_sha256")

    def _validate_transition(self, value: Any, before: Mapping[str, Any], path: str) -> dict[str, Any]:
        return validate_split_transition(value, owner_id=self.owner_id, before=before, path=path)

    def _validate_snapshot(self, value: Any, sequence: int, previous: str) -> dict[str, Any]:
        fields = {"schema_version", "artifact_type", "owner_id", "family_sequence",
                  "previous_snapshot_sha256", "state", "snapshot_sha256"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise EffectActionFamilyError("family_snapshot_shape_invalid", "$.snapshot")
        row = deepcopy(dict(value))
        if row["schema_version"] != 1 or row["artifact_type"] != SPLIT_SNAPSHOT_TYPE or row["owner_id"] != self.owner_id:
            raise EffectActionFamilyError("family_snapshot_identity_invalid", "$.snapshot")
        if row["family_sequence"] != sequence or row["previous_snapshot_sha256"] != previous:
            raise EffectActionFamilyError("family_snapshot_fork_detected", "$.snapshot")
        state = row["state"]
        if not isinstance(state, Mapping) or set(state) != {"ledger", "transitions"} or not isinstance(state["transitions"], list):
            raise EffectActionFamilyError("family_state_shape_invalid", "$.snapshot.state")
        expected = self.new_ledger(self.ledger_id)
        for index, transition in enumerate(state["transitions"]):
            accepted = self._validate_transition(transition, expected, f"$.snapshot.state.transitions[{index}]")
            expected = _parse_ledger(accepted["successor_ledger_json"], "effect" if self.owner_id == EFFECT_OWNER_ID else "action", "$.transition")
        try:
            ledger = self.validator(state["ledger"])
        except (t064.EffectAuthorityError, t072.RegisteredActionError) as exc:
            raise EffectActionFamilyError("family_accepted_ledger_invalid", "$.snapshot.state.ledger") from exc
        if ledger != expected:
            raise EffectActionFamilyError("family_state_ledger_fork", "$.snapshot.state.ledger")
        _validate_seal(row, "snapshot_sha256", "family_snapshot_digest_mismatch", "$.snapshot")
        return row

    def _recover_locked(self) -> dict[str, Any]:
        if self._read(self.manifest_path) != _split_manifest(self.owner_id, self.protocol, self.ledger_id):
            raise EffectActionFamilyError("family_manifest_mismatch", "$.manifest")
        paths = sorted(self.snapshots.iterdir())
        if not paths:
            raise EffectActionFamilyError("family_truncation_detected", "$.snapshots")
        previous = self._genesis()
        latest = None
        for sequence, path in enumerate(paths):
            if path.name != f"{sequence:020d}.json" or path.is_symlink():
                raise EffectActionFamilyError("family_snapshot_gap", "$.snapshots")
            latest = self._validate_snapshot(self._read(path), sequence, previous)
            previous = latest["snapshot_sha256"]
        assert latest is not None
        anchor = self._read(self.anchor_path)
        anchor_sequence = anchor.get("family_sequence") if isinstance(anchor, Mapping) else None
        if type(anchor_sequence) is not int or anchor_sequence < 0 or anchor_sequence > latest["family_sequence"]:
            raise EffectActionFamilyError("family_truncation_detected", "$.anchor.family_sequence")
        anchored = self._read(self.snapshots / f"{anchor_sequence:020d}.json")
        if anchor != self._anchor(anchored):
            raise EffectActionFamilyError("family_anchor_fork_detected", "$.anchor")
        if anchor_sequence < latest["family_sequence"]:
            self._replace(self.anchor_path, self._anchor(latest))
        return latest

    def recover(self) -> dict[str, Any]:
        with self._lock():
            snapshot = self._recover_locked()
            return {
                "owner_id": self.owner_id,
                "family_sequence": snapshot["family_sequence"],
                "ledger": deepcopy(snapshot["state"]["ledger"]),
                "ledger_json": _canonical_bytes(snapshot["state"]["ledger"]).decode(),
                "transitions": deepcopy(snapshot["state"]["transitions"]),
                "anchor": self._anchor(snapshot),
                "proof_boundary": PROOF_BOUNDARY,
            }

    def _commit(self, state: Mapping[str, Any], previous: Mapping[str, Any]) -> dict[str, Any]:
        sequence = previous["family_sequence"] + 1
        snapshot = self._snapshot(sequence, previous["snapshot_sha256"], state)
        self._validate_snapshot(snapshot, sequence, previous["snapshot_sha256"])
        self._publish_new(self.snapshots / f"{sequence:020d}.json", snapshot)
        self._replace(self.anchor_path, self._anchor(snapshot))
        return snapshot

    def _append(self, operation: str, after: Mapping[str, Any], dependency_heads: Mapping[str, str],
                snapshot: Mapping[str, Any], state: dict[str, Any]) -> dict[str, Any]:
        before = state["ledger"]
        if after == before:
            event_sha = after["events"][-1]["event_sha256"]
            found = next((item for item in state["transitions"] if item["mechanism_event_sha256"] == event_sha), None)
            if found is None:
                raise EffectActionFamilyError("family_retry_transition_missing", "$.state.transitions")
            if found["dependency_import_heads"] != dict(dependency_heads):
                raise EffectActionFamilyError("family_retry_dependency_collision", "$.dependency_import_heads")
            return deepcopy(found)
        transition = _split_transition(self.owner_id, operation, before, after, dependency_heads)
        state["ledger"] = deepcopy(dict(after))
        state["transitions"].append(transition)
        self._commit(state, snapshot)
        return deepcopy(transition)


class EffectAuthorityFamilyStore(_SplitFamilyStore):
    """Supported effect-authority runtime. It owns only T064."""

    owner_id = EFFECT_OWNER_ID
    protocol = EFFECT_PROTOCOL_VERSION
    ledger_id = EFFECT_LEDGER_ID
    validator = staticmethod(t064.validate_ledger)
    new_ledger = staticmethod(t064.new_ledger)

    def __init__(self, root: Path | str, artifact_store: Any, operation_state_store: Any) -> None:
        self.operation_state_store = operation_state_store
        super().__init__(root, artifact_store)

    def _context_import(self, now: datetime) -> tuple[dict[str, Any], str]:
        projection = self.artifact_store.current_responses_context_from_responses_seals()
        subject, head = _current_import(
            projection,
            edge="responses_context_to_effect_authority_v1",
            operation="issue_responses_context",
            now=now,
        )
        identity_sha256 = subject.get("identity_sha256") if isinstance(subject, Mapping) else subject
        _sha(identity_sha256, "$.import.semantic_subject.identity_sha256")
        identity = self.operation_state_store.current_responses_context_identity(identity_sha256)
        try:
            identity = t064._context(identity, "$.operation_state.responses_context_identity")
        except t064.EffectAuthorityError as exc:
            raise EffectActionFamilyError("family_responses_identity_invalid", "$.operation_state.responses_context_identity") from exc
        transition = _projection_json(projection, "transition_bytes")
        try:
            accepted = responses_family._validate_transition(transition, "$.import.transition_bytes")
        except responses_family.ResponsesSealsFamilyError as exc:
            raise EffectActionFamilyError("family_responses_context_invalid", "$.import.transition_bytes") from exc
        if (_projection_field(projection, "event_kind") != "issue"
                or accepted["operation"] != "issue_responses_context"
                or accepted["owner_artifact"]["identity_sha256"] != identity_sha256
                or responses_family._digest(identity) != identity_sha256):
            raise EffectActionFamilyError("family_responses_identity_mismatch", "$.operation_state.responses_context_identity")
        return identity, head

    def verify_effect_authority(self, *, owner_now: datetime) -> dict[str, Any]:
        now = _utc(owner_now, "$.owner_now")
        identity, import_head = self._context_import(now)
        with self._lock():
            snapshot = self._recover_locked()
            state = deepcopy(snapshot["state"])
            dependency_heads = {"responses_context_to_effect_authority_v1": import_head}
            existing = next((item for item in state["transitions"]
                             if item["operation"] == "verify_effect_authority"
                             and item["dependency_import_heads"] == dependency_heads), None)
            if existing is not None:
                return deepcopy(existing)
            expires = t064._time(identity["expires_at"], "$.import.semantic_subject.expires_at")
            basis = {"context_import_head_sha256": import_head, "request_sha256": identity["request_sha256"]}
            authority_id = "authority-" + digest(basis).removeprefix("sha256:")
            receipt = {
                "schema_version": 1, "artifact_type": "effect_kernel_authority_receipt_v1",
                "authority_id": authority_id, "issuer_id": t064.ISSUER_DECISION_SOURCE_ID,
                "actor": ISSUER_ACTOR, "workspace_id": identity["workspace_id"],
                "goal_id": ISSUER_GOAL_ID, "task_id": ISSUER_TASK_ID,
                "source_sha256": identity["source_sha256"], "candidate_sha256": identity["candidate_sha256"],
                "thread_id": identity["thread_id"], "thread_generation": identity["thread_generation"],
                "operation": identity["operation"], "request_intent_sha256": identity["request_intent_sha256"],
                "issued_at": format_time(now), "expires_at": format_time(expires), "receipt_sha256": "",
            }
            receipt["receipt_sha256"] = digest({key: value for key, value in receipt.items() if key != "receipt_sha256"})
            decision = {
                "schema_version": 1, "artifact_type": t064.ISSUER_DECISION_TYPE,
                "decision_id": "decision-" + digest({**basis, "authority_receipt_sha256": receipt["receipt_sha256"]}).removeprefix("sha256:"),
                "decision_source_id": t064.ISSUER_DECISION_SOURCE_ID, "decision": "issue",
                "ledger_id": self.ledger_id, "authority": receipt, "request_sha256": identity["request_sha256"],
                "decided_at": format_time(now), "expires_at": format_time(expires), "decision_sha256": "",
            }
            decision["decision_sha256"] = digest({key: value for key, value in decision.items() if key != "decision_sha256"})
            accepted = t064.validate_issuer_decision(decision, expected_ledger_id=self.ledger_id,
                                                     expected_context=identity, now=now)
            before = state["ledger"]
            after = t064.issue_authority(before, accepted, expected_head_sha256=before["head_sha256"])
            return self._append("verify_effect_authority", after, dependency_heads, snapshot, state)

    def revoke_effect_authority(self, *, authority_receipt_sha256: str, reason: str,
                                owner_now: datetime) -> dict[str, Any]:
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); before = state["ledger"]
            prior = next((event for event in before["events"] if event["event_type"] == "revoke"
                          and event["authority_receipt_sha256"] == authority_receipt_sha256), None)
            if prior is not None:
                return deepcopy(next(item for item in state["transitions"]
                                     if item["operation"] == "revoke_effect_authority"
                                     and item["mechanism_event_sha256"] == prior["event_sha256"]))
            try:
                after = t064.revoke_authority(before, authority_receipt_sha256=authority_receipt_sha256,
                                              reason=reason, expected_head_sha256=before["head_sha256"],
                                              occurred_at=_utc(owner_now, "$.owner_now"))
            except t064.EffectAuthorityError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            return self._append("revoke_effect_authority", after, {}, snapshot, state)


class RegisteredActionFamilyStore(_SplitFamilyStore):
    """Supported registered-action runtime. It owns only T072."""

    owner_id = ACTION_OWNER_ID
    protocol = ACTION_PROTOCOL_VERSION
    ledger_id = ACTION_LEDGER_ID
    validator = staticmethod(t072.validate_ledger)
    new_ledger = staticmethod(t072.new_ledger)

    def _effect_import(self, now: datetime) -> tuple[dict[str, Any], str]:
        projection = self.artifact_store.current_effect_authority_from_effect_authority()
        _, head = _current_import(
            projection,
            edge="effect_authority_to_registered_action_v1",
            operation=_projection_field(projection, "operation"),
            now=now,
        )
        operation = _projection_field(projection, "operation")
        if operation not in {"verify_effect_authority", "revoke_effect_authority"}:
            raise EffectActionFamilyError("family_import_operation_mismatch", "$.import.operation")
        event_kind = _projection_field(projection, "event_kind")
        if event_kind not in {"issue", "revoke"}:
            raise EffectActionFamilyError("family_import_event_kind_invalid", "$.import.event_kind")
        try:
            ledger = t064.validate_ledger(_projection_json(projection, "successor_bytes"))
        except t064.EffectAuthorityError as exc:
            raise EffectActionFamilyError("family_effect_import_invalid", "$.import.successor_bytes") from exc
        return ledger, head

    def retain_registered_action(self, *, action_id: str, tool_id: str,
                                 parameter_fields: list[str], owner_now: datetime) -> dict[str, Any]:
        registration = {"action_id": _identifier(action_id, "$.action_id"),
                        "tool_id": _identifier(tool_id, "$.tool_id"), "transport": TRANSPORT,
                        "parameter_fields": deepcopy(parameter_fields)}
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); before = state["ledger"]
            try:
                after = t072.record_registration(before, registration, expected_head_sha256=before["head_sha256"],
                                                 occurred_at=_utc(owner_now, "$.owner_now"))
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            if after == before:
                prior = next(event for event in before["events"] if event["event_type"] == "registration"
                             and event["action_id"] == registration["action_id"])
                return deepcopy(next(item for item in state["transitions"]
                                     if item["operation"] == "retain_registered_action"
                                     and item["mechanism_event_sha256"] == prior["event_sha256"]))
            return self._append("retain_registered_action", after, {}, snapshot, state)

    def admit_registered_action(self, *, effect_request: Mapping[str, Any], admitted_at: datetime) -> dict[str, Any]:
        now = _utc(admitted_at, "$.admitted_at")
        effect_ledger, import_head = self._effect_import(now)
        authority = effect_request.get("authority_receipt") if isinstance(effect_request, Mapping) else None
        issue = next((event for event in effect_ledger["events"] if event["event_type"] == "issue" and event["authority"] == authority), None)
        revoked = any(event["event_type"] == "revoke" and issue is not None and event["authority_receipt_sha256"] == issue["authority_receipt_sha256"] for event in effect_ledger["events"])
        if issue is None or revoked:
            raise EffectActionFamilyError("family_effect_authority_unavailable", "$.effect_request.authority_receipt")
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); before = state["ledger"]
            request_sha = effect_request.get("request_sha256") if isinstance(effect_request, Mapping) else None
            prior = next((event for event in before["events"] if event["event_type"] == "execution_admission"
                          and event["effect_request_sha256"] == request_sha), None)
            if prior is not None:
                transition = next(item for item in state["transitions"]
                                  if item["operation"] == "admit_registered_action"
                                  and item["mechanism_event_sha256"] == prior["event_sha256"])
                expected = {"effect_authority_to_registered_action_v1": import_head}
                if transition["dependency_import_heads"] != expected:
                    raise EffectActionFamilyError("family_retry_dependency_collision", "$.dependency_import_heads")
                return deepcopy(transition)
            try:
                after = t072.record_execution_admission(before, effect_request,
                                                        expected_head_sha256=before["head_sha256"], admitted_at=now)
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            return self._append("admit_registered_action", after,
                                {"effect_authority_to_registered_action_v1": import_head}, snapshot, state)

    def invoke_registered_action(self, *, executor_receipt: Mapping[str, Any], observed_at: datetime,
                                 expires_at: datetime) -> dict[str, Any]:
        if not isinstance(executor_receipt, Mapping):
            raise EffectActionFamilyError("family_executor_observation_unavailable", "$.executor_receipt")
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); before = state["ledger"]
            request_sha = executor_receipt.get("request_sha256")
            prior = next((event for event in before["events"] if event["event_type"] == "observation"
                          and event["effect_request_sha256"] == request_sha), None)
            if prior is not None:
                return deepcopy(next(item for item in state["transitions"]
                                     if item["operation"] == "invoke_registered_action"
                                     and item["mechanism_event_sha256"] == prior["event_sha256"]))
            try:
                after = t072.record_observation(before, executor_receipt, expected_head_sha256=before["head_sha256"],
                                                observed_at=_utc(observed_at, "$.observed_at"),
                                                expires_at=_utc(expires_at, "$.expires_at"))
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            return self._append("invoke_registered_action", after, {}, snapshot, state)

    def revoke_registered_action(self, *, effect_request_sha256: str, reason: str,
                                 owner_now: datetime) -> dict[str, Any]:
        with self._lock():
            snapshot = self._recover_locked(); state = deepcopy(snapshot["state"]); before = state["ledger"]
            prior = next((event for event in before["events"] if event["event_type"] == "revoke"
                          and event["effect_request_sha256"] == effect_request_sha256), None)
            if prior is not None:
                return deepcopy(next(item for item in state["transitions"]
                                     if item["operation"] == "revoke_registered_action"
                                     and item["mechanism_event_sha256"] == prior["event_sha256"]))
            try:
                after = t072.revoke_observation(before, effect_request_sha256=effect_request_sha256, reason=reason,
                                                expected_head_sha256=before["head_sha256"],
                                                occurred_at=_utc(owner_now, "$.owner_now"))
            except t072.RegisteredActionError as exc:
                raise EffectActionFamilyError(exc.code, exc.path) from exc
            return self._append("revoke_registered_action", after, {}, snapshot, state)
