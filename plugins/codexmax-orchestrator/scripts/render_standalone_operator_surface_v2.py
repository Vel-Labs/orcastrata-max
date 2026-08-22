#!/usr/bin/env python3
"""Validate and render a dynamic local operator V2 projection."""

from __future__ import annotations

import copy
import base64
import hashlib
import hmac
import html
import json
from datetime import datetime, timezone
from typing import Any


ARTIFACT_TYPE = "standalone_operator_local_projection_v2"
V3_ARTIFACT_TYPE = "standalone_operator_local_projection_v3"
SHA_FIELDS = {"source_sha256", "candidate_sha256", "binding_state_sha256", "projection_sha256"}
STATUS_DOMAIN = b"codexmax-operator-browser-status-v1\0"
TRANSPORT_DOMAIN = b"codexmax-operator-browser-transport-v1\0"
CANCEL_RECOVERY_PROVENANCE_FIELDS = {
    "grant_id", "grant_sha256", "issuer_id", "predecessor_run_id",
    "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256",
    "reconciliation_receipt_sha256", "expected_cas", "reserved_authority_id",
}
V3_CANCEL_RECOVERY_FIELDS = CANCEL_RECOVERY_PROVENANCE_FIELDS | {"predecessor_lease"}
V3_CANCEL_RECOVERY_FIELDS.add("predecessor_effect_receipt")
EFFECT_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "request_id", "request_sha256",
    "operation", "disposition", "run_id", "pre_state", "post_state",
    "state_version_before", "state_version_after", "action_receipt",
    "route_requested", "route_observed", "preset_snapshot", "lease",
    "event_ids", "proof_boundary", "unknowns", "receipt_sha256",
}
ACTION_RECEIPT_FIELDS = {
    "schema_version", "artifact_type", "action_receipt_id", "action_id",
    "effect_id", "operation", "outcome", "requested_at", "observed_at",
    "host_receipt_id", "observed_identity", "request_sha256",
    "output_sha256", "reconciled_outcome", "successor_run_id",
    "receipt_sha256",
}


class ProjectionError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code, self.path = code, path
        super().__init__(f"{code}: {path}")


def digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _b64decode(value: Any, path: str) -> bytes:
    if not isinstance(value, str) or not value or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in value):
        raise ProjectionError("browser_envelope_invalid", path)
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as exc:
        raise ProjectionError("browser_envelope_invalid", path) from exc


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProjectionError("browser_envelope_invalid", path)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise ProjectionError("browser_envelope_invalid", path) from exc


def _closed(value: Any, keys: set[str], path: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ProjectionError("projection_shape_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(c not in "0123456789abcdef" for c in value[7:]):
        raise ProjectionError("projection_digest_invalid", path)
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256 or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-" for character in value):
        raise ProjectionError("projection_identity_invalid", path)
    return value


def _validate_effect_receipt(value: Any, *, provenance: dict[str, Any], predecessor_lease: dict[str, Any], path: str) -> None:
    receipt = _closed(value, EFFECT_RECEIPT_FIELDS, path)
    if receipt["schema_version"] != 1 or receipt["artifact_type"] != "effect_kernel_receipt_v1":
        raise ProjectionError("recovery_authority_unavailable", path)
    for field in ("request_id", "run_id"):
        _identifier(receipt[field], f"{path}.{field}")
    for field in ("request_sha256", "receipt_sha256"):
        _sha(receipt[field], f"{path}.{field}")
    if receipt["receipt_sha256"] != digest({key: item for key, item in receipt.items() if key != "receipt_sha256"}):
        raise ProjectionError("recovery_authority_unavailable", path)
    if receipt["receipt_sha256"] != provenance["predecessor_effect_receipt_sha256"] or receipt["request_sha256"] != provenance["predecessor_effect_request_sha256"] or receipt["run_id"] != provenance["predecessor_run_id"] or receipt["lease"] != predecessor_lease or receipt["state_version_after"] != provenance["expected_cas"]["expected_state_version"]:
        raise ProjectionError("recovery_authority_unavailable", path)
    if receipt["action_receipt"] is not None:
        action = _closed(receipt["action_receipt"], ACTION_RECEIPT_FIELDS, f"{path}.action_receipt")
        for field in ("action_receipt_id", "action_id", "effect_id"):
            _identifier(action[field], f"{path}.action_receipt.{field}")
        for field in ("request_sha256", "output_sha256", "receipt_sha256"):
            _sha(action[field], f"{path}.action_receipt.{field}")
        if action["receipt_sha256"] != digest({key: item for key, item in action.items() if key != "receipt_sha256"}):
            raise ProjectionError("recovery_authority_unavailable", f"{path}.action_receipt")
    if receipt["operation"] not in {"run", "cancel"} or receipt["disposition"] != "execution_unknown" or receipt["post_state"] != "execution_unknown" or receipt["action_receipt"] is not None or receipt["route_observed"] != {"route_id": "unknown", "model": "unknown", "host": "unknown"} or receipt["proof_boundary"] != "source_local_registered_action":
        raise ProjectionError("recovery_authority_unavailable", path)
    if type(receipt["state_version_before"]) is not int or receipt["state_version_before"] < 0 or type(receipt["state_version_after"]) is not int or receipt["state_version_after"] != receipt["state_version_before"] + 1:
        raise ProjectionError("recovery_authority_unavailable", path)
    for field in ("route_requested", "route_observed"):
        route = _closed(receipt[field], {"route_id", "model", "host"}, f"{path}.{field}")
        for item in route.values():
            if not isinstance(item, str):
                raise ProjectionError("recovery_authority_unavailable", f"{path}.{field}")
    preset = _closed(receipt["preset_snapshot"], {"preset_id", "captured_at", "expires_at", "snapshot_sha256"}, f"{path}.preset_snapshot")
    _identifier(preset["preset_id"], f"{path}.preset_snapshot.preset_id"); _sha(preset["snapshot_sha256"], f"{path}.preset_snapshot.snapshot_sha256")
    lease = _closed(receipt["lease"], {"lease_id", "fencing_token", "issued_at", "expires_at", "lease_sha256"}, f"{path}.lease")
    if lease != predecessor_lease:
        raise ProjectionError("recovery_authority_unavailable", f"{path}.lease")
    _identifier(lease["lease_id"], f"{path}.lease.lease_id"); _sha(lease["lease_sha256"], f"{path}.lease.lease_sha256")
    if type(lease["fencing_token"]) is not int or lease["fencing_token"] < 1 or lease["lease_sha256"] != digest({key: item for key, item in lease.items() if key != "lease_sha256"}):
        raise ProjectionError("recovery_authority_unavailable", f"{path}.lease")
    if not isinstance(receipt["event_ids"], list) or not receipt["event_ids"] or any(not isinstance(item, str) for item in receipt["event_ids"]):
        raise ProjectionError("recovery_authority_unavailable", f"{path}.event_ids")
    if not isinstance(receipt["unknowns"], list) or any(not isinstance(item, str) for item in receipt["unknowns"]):
        raise ProjectionError("recovery_authority_unavailable", f"{path}.unknowns")
def _selection(value: Any, path: str) -> dict[str, Any]:
    row = _closed(value, {"bundle_sha256", "preset_id", "family_id", "expected_generation", "scope", "thread_id", "thread_generation", "current_preset_id", "current_family_id", "in_flight"}, path)
    _sha(row["bundle_sha256"], path + ".bundle_sha256")
    for field in ("preset_id", "family_id", "thread_id"):
        _identifier(row[field], path + "." + field)
    if type(row["expected_generation"]) is not int or row["expected_generation"] < 1 or type(row["thread_generation"]) is not int or row["thread_generation"] < 1 or row["scope"] not in {"new_thread", "next_turn"} or type(row["in_flight"]) is not bool:
        raise ProjectionError("selection_invalid", path)
    if (row["current_preset_id"] is None) != (row["current_family_id"] is None):
        raise ProjectionError("selection_invalid", path)
    for field in ("current_preset_id", "current_family_id"):
        if row[field] is not None:
            _identifier(row[field], path + "." + field)
    return row


def _validate_cancel_recovery_provenance(
    value: Any, *, run: dict[str, Any], refs: dict[str, Any], authority: dict[str, Any],
    active: dict[str, Any], supervision: dict[str, Any], path: str, grant: dict[str, Any] | None = None,
    v3: bool = False,
) -> None:
    """Close and bind successor provenance; V2 intentionally remains fail-closed."""
    row = _closed(value, V3_CANCEL_RECOVERY_FIELDS if v3 else CANCEL_RECOVERY_PROVENANCE_FIELDS, path)
    for field in ("grant_id", "issuer_id", "predecessor_run_id", "reserved_authority_id"):
        _identifier(row[field], f"{path}.{field}")
    for field in (
        "grant_sha256", "predecessor_effect_request_sha256",
        "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256",
    ):
        _sha(row[field], f"{path}.{field}")
    cas = _closed(row["expected_cas"], {"expected_state_version", "expected_thread_generation"}, f"{path}.expected_cas")
    if any(type(cas[field]) is not int or cas[field] < 0 for field in cas):
        raise ProjectionError("recovery_authority_unavailable", f"{path}.expected_cas")
    if not v3:
        raise ProjectionError("recovery_authority_unavailable", path)
    lease = _closed(row["predecessor_lease"], {"lease_id", "fencing_token", "issued_at", "expires_at", "lease_sha256"}, f"{path}.predecessor_lease")
    _identifier(lease["lease_id"], f"{path}.predecessor_lease.lease_id")
    _sha(lease["lease_sha256"], f"{path}.predecessor_lease.lease_sha256")
    if type(lease["fencing_token"]) is not int or lease["fencing_token"] < 1 or lease["lease_sha256"] != digest({key: item for key, item in lease.items() if key != "lease_sha256"}):
        raise ProjectionError("recovery_authority_unavailable", path)
    expected_cas = {
        "expected_state_version": authority["effect_state_version"] - 1,
        "expected_thread_generation": active["head"]["selection"]["thread_generation"],
    }
    accepted_reconciliation = supervision["receipt"]["recovery"]["reconciliation_receipt_sha256"]
    if (
        row["predecessor_run_id"] != run["predecessor_run_id"]
        or row["reconciliation_receipt_sha256"] != accepted_reconciliation
        or cas != expected_cas
        or run["lifecycle"] != "running"
        or grant is None
        or grant["effect_operation"] != "recover"
        or grant["run_id"] != run["run_id"]
        or grant["predecessor_run_id"] != run["predecessor_run_id"]
        or grant["successor_run_id"] is not None
        or grant["lease_id"] == lease["lease_id"]
        or grant["fencing_token"] <= lease["fencing_token"]
        or grant["effect_request_sha256"] != refs["effect_kernel_request_v1"]
        or grant["effect_receipt_sha256"] != refs["effect_kernel_receipt_v1"]
    ):
        raise ProjectionError("recovery_authority_unavailable", path)
    _validate_effect_receipt(
        row["predecessor_effect_receipt"], provenance=row,
        predecessor_lease=lease, path=f"{path}.predecessor_effect_receipt",
    )


def validate_projection(value: Any, *, now: datetime | None = None, projection_version: int = 2) -> dict[str, Any]:
    root = _closed(copy.deepcopy(value), {"schema_version", "artifact_type", "projection_id", "service_instance_id", "workspace_id", "source_sha256", "candidate_sha256", "binding_state_version", "binding_state_sha256", "selection", "run", "artifact_refs", "controls", "claims", "issued_at", "expires_at", "view_nonce", "projection_sha256", "projection_receipt", "supervision", "active_selection", "artifact_selection", "preset_catalog", "control_authority"}, "$")
    expected_artifact = ARTIFACT_TYPE if projection_version == 2 else V3_ARTIFACT_TYPE
    if root["schema_version"] != projection_version or root["artifact_type"] != expected_artifact:
        raise ProjectionError("projection_shape_invalid")
    for field in SHA_FIELDS:
        _sha(root[field], f"$.{field}")
    if type(root["binding_state_version"]) is not int or root["binding_state_version"] < 0:
        raise ProjectionError("projection_shape_invalid", "$.identity")
    for field in ("projection_id", "service_instance_id", "workspace_id", "view_nonce"):
        _identifier(root[field], f"$.{field}")
    observed = now or datetime.now(timezone.utc)
    issued, expires = _time(root["issued_at"], "$.issued_at"), _time(root["expires_at"], "$.expires_at")
    if issued > observed or expires <= observed or expires <= issued or (expires - issued).total_seconds() > 60:
        raise ProjectionError("projection_stale", "$.expires_at")
    if root["selection"] is not None:
        _selection(root["selection"], "$.selection")
    run = _closed(root["run"], {"run_id", "lifecycle", "fencing_token", "predecessor_run_id", "successor_run_id"}, "$.run")
    if run["lifecycle"] not in {"absent", "unavailable", "running", "cancel_requested", "cancelled", "completed", "failed", "execution_unknown"}:
        raise ProjectionError("run_state_invalid", "$.run.lifecycle")
    for field in ("run_id", "predecessor_run_id", "successor_run_id"):
        if run[field] is not None:
            _identifier(run[field], f"$.run.{field}")
    if run["lifecycle"] == "unavailable":
        if any(run[field] is not None for field in ("run_id", "fencing_token", "predecessor_run_id", "successor_run_id")):
            raise ProjectionError("run_state_invalid", "$.run")
    elif type(run["fencing_token"]) is not int or run["fencing_token"] < 1 or (run["lifecycle"] == "absent" and run["run_id"] is not None) or (run["lifecycle"] != "absent" and run["run_id"] is None):
        raise ProjectionError("run_state_invalid", "$.run")
    refs = _closed(root["artifact_refs"], {"standalone_responses_request_v1", "effect_kernel_request_v1", "effect_kernel_receipt_v1", "effect_kernel_action_receipt_v1", "standalone_responses_bridge_receipt_v1"}, "$.artifact_refs")
    for field, item in refs.items():
        if item is not None:
            _sha(item, f"$.artifact_refs.{field}")
    controls = _closed(root["controls"], {"run", "cancel", "recover", "select", "retry", "fallback", "replacement"}, "$.controls")
    for name, item in controls.items():
        row = _closed(item, {"enabled", "reason"}, f"$.controls.{name}")
        if type(row["enabled"]) is not bool or not isinstance(row["reason"], str) or not row["reason"]:
            raise ProjectionError("control_state_invalid", f"$.controls.{name}")
    if any(controls[name]["enabled"] for name in ("retry", "fallback", "replacement")):
        raise ProjectionError("control_state_not_authorized", "$.controls")
    claims = _closed(root["claims"], {"source_local", "capability_admitted", "installed", "live", "provider", "browser", "aol"}, "$.claims")
    if claims["source_local"] is not True or type(claims["capability_admitted"]) is not bool or any(claims[field] != "unknown" for field in ("installed", "live", "provider", "browser")) or claims["aol"] != "unavailable":
        raise ProjectionError("claims_invalid", "$.claims")
    supervision = _closed(root["supervision"], {"state", "reason", "receipt"}, "$.supervision")
    active = _closed(root["active_selection"], {"state", "reason", "head"}, "$.active_selection")
    artifact_selection = _closed(root["artifact_selection"], {"selection_sha256", "relation"}, "$.artifact_selection")
    catalog = _closed(root["preset_catalog"], {"state", "reason", "receipt_sha256", "bundle_sha256", "generation", "presets"}, "$.preset_catalog")
    if active["state"] not in {"verified", "unavailable"} or artifact_selection["relation"] not in {"current", "historical", "unavailable"}:
        raise ProjectionError("selection_head_invalid", "$.active_selection")
    if active["state"] == "unavailable":
        if not isinstance(active["reason"], str) or not active["reason"] or active["head"] is not None:
            raise ProjectionError("selection_head_invalid", "$.active_selection")
    else:
        head = _closed(active["head"], {"schema_version", "artifact_type", "head_id", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "selection_state_version", "selection", "selection_sha256", "catalog_receipt_sha256", "bundle_sha256", "bundle_generation", "issued_at", "expires_at", "receipt_sha256", "seal"}, "$.active_selection.head")
        if active["reason"] is not None or head["schema_version"] != 1 or head["artifact_type"] != "standalone_operator_selection_head_receipt_v1" or head["workspace_id"] != root["workspace_id"] or head["source_sha256"] != root["source_sha256"] or head["candidate_sha256"] != root["candidate_sha256"] or head["service_instance_id"] != root["service_instance_id"] or head["binding_state_version"] != root["binding_state_version"] or head["binding_state_sha256"] != root["binding_state_sha256"]:
            raise ProjectionError("selection_head_invalid", "$.active_selection.head")
        selected = _selection(head["selection"], "$.active_selection.head.selection")
        for field in ("head_id", "service_instance_id", "admission_id"):
            _identifier(head[field], f"$.active_selection.head.{field}")
        for field in ("source_sha256", "candidate_sha256", "binding_state_sha256", "selection_sha256", "catalog_receipt_sha256", "bundle_sha256", "receipt_sha256", "seal"):
            _sha(head[field], f"$.active_selection.head.{field}")
        head_issued, head_expires = _time(head["issued_at"], "$.active_selection.head.issued_at"), _time(head["expires_at"], "$.active_selection.head.expires_at")
        if head["selection_sha256"] != digest(selected) or type(head["selection_state_version"]) is not int or head["selection_state_version"] < 0 or type(head["bundle_generation"]) is not int or head["bundle_generation"] < 1 or head_issued > observed or head_expires <= observed or head["receipt_sha256"] != digest({key: item for key, item in head.items() if key not in {"receipt_sha256", "seal"}}):
            raise ProjectionError("selection_head_invalid", "$.active_selection.head")
    if catalog["state"] == "unavailable":
        if not isinstance(catalog["reason"], str) or catalog["receipt_sha256"] is not None or catalog["bundle_sha256"] is not None or catalog["generation"] is not None or catalog["presets"] != [] or controls["run"]["enabled"] or controls["select"]["enabled"]:
            raise ProjectionError("preset_catalog_invalid", "$.preset_catalog")
    elif catalog["state"] == "verified":
        _sha(catalog["receipt_sha256"], "$.preset_catalog.receipt_sha256"); _sha(catalog["bundle_sha256"], "$.preset_catalog.bundle_sha256")
        if catalog["reason"] is not None or type(catalog["generation"]) is not int or catalog["generation"] < 1 or not isinstance(catalog["presets"], list) or not 1 <= len(catalog["presets"]) <= 32:
            raise ProjectionError("preset_catalog_invalid", "$.preset_catalog")
        for index, item in enumerate(catalog["presets"]):
            row = _closed(item, {"preset_id", "family_id", "role"}, f"$.preset_catalog.presets[{index}]")
            if not all(isinstance(row[field], str) and row[field] for field in row):
                raise ProjectionError("preset_catalog_invalid", f"$.preset_catalog.presets[{index}]")
        preset_ids = [item["preset_id"] for item in catalog["presets"]]
        if len(set(preset_ids)) != len(preset_ids):
            raise ProjectionError("preset_catalog_invalid", "$.preset_catalog.presets")
        if len(catalog["presets"]) == 1 and controls["select"]["enabled"]:
            raise ProjectionError("preset_catalog_singleton", "$.controls.select")
        if active["state"] == "verified" and (active["head"]["catalog_receipt_sha256"] != catalog["receipt_sha256"] or active["head"]["bundle_sha256"] != catalog["bundle_sha256"] or active["head"]["bundle_generation"] != catalog["generation"]):
            raise ProjectionError("selection_catalog_mismatch", "$.active_selection.head")
        if active["state"] == "verified":
            selected = active["head"]["selection"]
            matching = [item for item in catalog["presets"] if item["preset_id"] == selected["preset_id"] and item["family_id"] == selected["family_id"]]
            if len(matching) != 1 or selected["bundle_sha256"] != catalog["bundle_sha256"] or selected["expected_generation"] != catalog["generation"]:
                raise ProjectionError("selection_catalog_mismatch", "$.active_selection.head.selection")
    else:
        raise ProjectionError("preset_catalog_invalid", "$.preset_catalog")
    if supervision["state"] == "unavailable":
        if not isinstance(supervision["reason"], str) or not supervision["reason"] or supervision["receipt"] is not None or any(controls[name]["enabled"] for name in ("run", "cancel", "recover", "select")):
            raise ProjectionError("supervision_veto_failed", "$.supervision")
    elif supervision["state"] == "verified":
        receipt_keys = {"schema_version", "artifact_type", "receipt_id", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "runtime_thread_id", "runtime_thread_generation", "selection_sha256", "native", "topology", "continuity", "recovery", "snapshot_sequence", "previous_snapshot_sha256", "issued_at", "expires_at", "snapshot_sha256", "receipt_sha256", "seal"}
        if supervision["reason"] is not None or not isinstance(supervision["receipt"], dict) or supervision["receipt"].get("artifact_type") != "standalone_operator_supervision_receipt_v1":
            raise ProjectionError("supervision_receipt_invalid", "$.supervision")
        receipt = _closed(supervision["receipt"], receipt_keys, "$.supervision.receipt")
        if receipt.get("workspace_id") != root["workspace_id"] or receipt.get("source_sha256") != root["source_sha256"] or receipt.get("candidate_sha256") != root["candidate_sha256"] or receipt.get("service_instance_id") != root["service_instance_id"] or receipt.get("binding_state_version") != root["binding_state_version"] or receipt.get("binding_state_sha256") != root["binding_state_sha256"]:
            raise ProjectionError("supervision_receipt_mismatch", "$.supervision")
        for field in ("receipt_id", "service_instance_id", "admission_id", "runtime_thread_id"):
            _identifier(receipt[field], f"$.supervision.receipt.{field}")
        for field in ("source_sha256", "candidate_sha256", "binding_state_sha256", "selection_sha256", "snapshot_sha256", "receipt_sha256", "seal"):
            _sha(receipt[field], f"$.supervision.receipt.{field}")
        if type(receipt["runtime_thread_generation"]) is not int or receipt["runtime_thread_generation"] < 1 or type(receipt["snapshot_sequence"]) is not int or receipt["snapshot_sequence"] < 1 or (receipt["snapshot_sequence"] == 1) != (receipt["previous_snapshot_sha256"] is None):
            raise ProjectionError("supervision_receipt_invalid", "$.supervision.receipt")
        if receipt["previous_snapshot_sha256"] is not None:
            _sha(receipt["previous_snapshot_sha256"], "$.supervision.receipt.previous_snapshot_sha256")
        native = _closed(receipt["native"], {"live_host", "native_available", "corroborated", "native_proved", "identity_receipt_sha256", "chain_tip_sha256", "event_sequence", "locator_kind", "parent_locator", "supervisor_locator", "model", "reasoning_effort", "route"}, "$.supervision.receipt.native")
        topology = _closed(receipt["topology"], {"inventory_event_sha256", "inventory_cursor", "presentation", "parent_count", "active_supervisor_count", "supervisor_checkpoint_sha256", "supervisor_checkpoint_count", "top_level_worker_count", "internal_worker_count", "activity_cursor"}, "$.supervision.receipt.topology")
        continuity = _closed(receipt["continuity"], {"host_read_event_sha256", "read_cursor", "subscription_state", "current_cursor_sequence"}, "$.supervision.receipt.continuity")
        recovery = _closed(receipt["recovery"], {"recovery_epoch", "reconciliation_receipt_sha256", "status"}, "$.supervision.receipt.recovery")
        if any(native[field] is not True for field in ("live_host", "native_available", "corroborated", "native_proved")) or native["locator_kind"] != "desktop_thread_id" or topology["presentation"] != "approved_containment" or topology["parent_count"] != 1 or topology["active_supervisor_count"] != 1 or topology["top_level_worker_count"] != 0 or continuity["subscription_state"] != "current" or recovery["status"] not in {"current", "reconciled"}:
            raise ProjectionError("supervision_receipt_invalid", "$.supervision.receipt")
        for field in ("identity_receipt_sha256", "chain_tip_sha256"):
            _sha(native[field], f"$.supervision.receipt.native.{field}")
        for field in ("parent_locator", "supervisor_locator"):
            _identifier(native[field], f"$.supervision.receipt.native.{field}")
        if type(native["event_sequence"]) is not int or not 1 <= native["event_sequence"] <= 1_000_000_000:
            raise ProjectionError("supervision_receipt_invalid", "$.supervision.receipt.native.event_sequence")
        for field in ("inventory_event_sha256", "supervisor_checkpoint_sha256"):
            _sha(topology[field], f"$.supervision.receipt.topology.{field}")
        for field in ("inventory_cursor", "activity_cursor"):
            _identifier(topology[field], f"$.supervision.receipt.topology.{field}")
        for field in ("supervisor_checkpoint_count", "internal_worker_count"):
            if type(topology[field]) is not int or not 0 <= topology[field] <= 10000:
                raise ProjectionError("supervision_receipt_invalid", f"$.supervision.receipt.topology.{field}")
        _sha(continuity["host_read_event_sha256"], "$.supervision.receipt.continuity.host_read_event_sha256")
        _identifier(continuity["read_cursor"], "$.supervision.receipt.continuity.read_cursor")
        if type(continuity["current_cursor_sequence"]) is not int or not 1 <= continuity["current_cursor_sequence"] <= 1_000_000_000:
            raise ProjectionError("supervision_receipt_invalid", "$.supervision.receipt.continuity.current_cursor_sequence")
        _sha(recovery["reconciliation_receipt_sha256"], "$.supervision.receipt.recovery.reconciliation_receipt_sha256")
        if type(recovery["recovery_epoch"]) is not int or not 0 <= recovery["recovery_epoch"] <= 1_000_000_000:
            raise ProjectionError("supervision_receipt_invalid", "$.supervision.receipt.recovery.recovery_epoch")
        supervision_issued, supervision_expires = _time(receipt["issued_at"], "$.supervision.receipt.issued_at"), _time(receipt["expires_at"], "$.supervision.receipt.expires_at")
        semantic = {key: item for key, item in receipt.items() if key not in {"issued_at", "expires_at", "snapshot_sha256", "receipt_sha256", "seal"}}
        if supervision_issued > observed or supervision_expires <= observed or receipt["snapshot_sha256"] != digest(semantic) or receipt["receipt_sha256"] != digest({key: item for key, item in receipt.items() if key not in {"receipt_sha256", "seal"}}):
            raise ProjectionError("supervision_receipt_invalid", "$.supervision.receipt")
        head = active["head"]
        if head is None or receipt["runtime_thread_id"] != head["selection"]["thread_id"] or receipt["runtime_thread_generation"] != head["selection"]["thread_generation"] or receipt["selection_sha256"] != head["selection_sha256"]:
            raise ProjectionError("supervision_receipt_mismatch", "$.supervision.receipt")
    else:
        raise ProjectionError("supervision_state_invalid", "$.supervision")
    if artifact_selection["selection_sha256"] is not None:
        _sha(artifact_selection["selection_sha256"], "$.artifact_selection.selection_sha256")
    active_sha = None if active["head"] is None else active["head"]["selection_sha256"]
    artifact_sha = None if root["selection"] is None else digest(root["selection"])
    expected_relation = "unavailable" if active_sha is None or artifact_sha is None else ("current" if active_sha == artifact_sha else "historical")
    if artifact_selection["selection_sha256"] != artifact_sha or artifact_selection["relation"] != expected_relation:
        raise ProjectionError("artifact_selection_invalid", "$.artifact_selection")
    control_authority = root["control_authority"]
    grant_fields = {"grant_id", "operation", "provenance", "run_id", "predecessor_run_id", "successor_run_id", "effect_operation", "lease_id", "fencing_token", "lease_expires_at", "cas_expected_state_version", "cas_expected_thread_generation", "authority_receipt_sha256", "effect_request_sha256", "effect_receipt_sha256", "action_receipt_sha256", "bridge_receipt_sha256", "cancel_observed", "recovery", "catalog_receipt_sha256", "bundle_sha256", "bundle_generation", "selection_head_receipt_sha256", "issued_at", "expires_at", "grant_sha256"}
    grants = None
    if control_authority is None:
        if any(controls[name]["enabled"] for name in ("run", "cancel", "recover", "select")):
            raise ProjectionError("control_authority_missing", "$.control_authority")
    else:
        authority = _closed(control_authority, {"schema_version", "artifact_type", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "admission_seal_sha256", "binding_state_version", "binding_state_sha256", "selection_sha256", "effect_state_version", "effect_state_sha256", "grants", "issued_at", "expires_at", "authority_sha256", "sealed_by"}, "$.control_authority")
        if authority["schema_version"] != 1 or authority["artifact_type"] != "standalone_operator_control_authority_v1" or authority["sealed_by"] != "projection_receipt_v1" or any(authority[field] != root[field] for field in ("workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "binding_state_version", "binding_state_sha256")):
            raise ProjectionError("control_authority_invalid", "$.control_authority")
        for field in ("admission_seal_sha256", "selection_sha256", "effect_state_sha256", "authority_sha256"):
            _sha(authority[field], f"$.control_authority.{field}")
        _identifier(authority["admission_id"], "$.control_authority.admission_id")
        head_admission = active["head"]["admission_id"]
        supervision_admission = supervision["receipt"]["admission_id"]
        projection_admission = None if root["projection_receipt"] is None else root["projection_receipt"]["admission_id"]
        if type(authority["effect_state_version"]) is not int or authority["effect_state_version"] < 0 or authority["effect_state_version"] != root["binding_state_version"] or authority["selection_sha256"] != active_sha or authority["admission_id"] != head_admission or authority["admission_id"] != supervision_admission or (projection_admission is not None and authority["admission_id"] != projection_admission) or authority["authority_sha256"] != digest({key: item for key, item in authority.items() if key != "authority_sha256"}):
            raise ProjectionError("control_authority_invalid", "$.control_authority")
        if _time(authority["issued_at"], "$.control_authority.issued_at") != issued or _time(authority["expires_at"], "$.control_authority.expires_at") > expires or _time(authority["expires_at"], "$.control_authority.expires_at") <= observed:
            raise ProjectionError("control_authority_stale", "$.control_authority")
        grants = _closed(authority["grants"], {"run", "cancel", "recover", "select"}, "$.control_authority.grants")
        grant_ids = set()
        for name, grant in grants.items():
            if controls[name]["enabled"] != (grant is not None):
                raise ProjectionError("control_state_not_authorized", f"$.controls.{name}")
            if grant is None:
                continue
            row = _closed(grant, grant_fields, f"$.control_authority.grants.{name}")
            if row["operation"] != name or row["grant_sha256"] != digest({key: item for key, item in row.items() if key != "grant_sha256"}) or row["catalog_receipt_sha256"] != catalog["receipt_sha256"] or row["bundle_sha256"] != catalog["bundle_sha256"] or row["bundle_generation"] != catalog["generation"] or row["selection_head_receipt_sha256"] != active["head"]["receipt_sha256"]:
                raise ProjectionError("control_grant_invalid", f"$.control_authority.grants.{name}")
            for field in ("grant_id", "operation", "provenance"):
                _identifier(row[field], f"$.control_authority.grants.{name}.{field}")
            if row["grant_id"] in grant_ids:
                raise ProjectionError("control_grant_invalid", "$.control_authority.grants")
            grant_ids.add(row["grant_id"])
            for field in ("catalog_receipt_sha256", "bundle_sha256", "selection_head_receipt_sha256", "grant_sha256"):
                _sha(row[field], f"$.control_authority.grants.{name}.{field}")
            if type(row["bundle_generation"]) is not int or row["bundle_generation"] < 1 or type(row["cancel_observed"]) is not bool or type(row["cas_expected_state_version"]) is not int or row["cas_expected_state_version"] < 0 or type(row["cas_expected_thread_generation"]) is not int or row["cas_expected_thread_generation"] < 1 or _time(row["issued_at"], f"$.control_authority.grants.{name}.issued_at") != issued or _time(row["expires_at"], f"$.control_authority.grants.{name}.expires_at") > _time(authority["expires_at"], "$.control_authority.expires_at") or _time(row["expires_at"], f"$.control_authority.grants.{name}.expires_at") <= observed:
                raise ProjectionError("control_grant_invalid", f"$.control_authority.grants.{name}")
            for field in ("run_id", "predecessor_run_id", "successor_run_id", "effect_operation", "lease_id"):
                if row[field] is not None:
                    _identifier(row[field], f"$.control_authority.grants.{name}.{field}")
            if row["fencing_token"] is not None and (type(row["fencing_token"]) is not int or row["fencing_token"] < 1):
                raise ProjectionError("control_grant_invalid", f"$.control_authority.grants.{name}.fencing_token")
            if row["lease_expires_at"] is not None and _time(row["lease_expires_at"], f"$.control_authority.grants.{name}.lease_expires_at") < _time(row["expires_at"], f"$.control_authority.grants.{name}.expires_at"):
                raise ProjectionError("control_grant_invalid", f"$.control_authority.grants.{name}.lease_expires_at")
            for field in ("authority_receipt_sha256", "effect_request_sha256", "effect_receipt_sha256", "action_receipt_sha256", "bridge_receipt_sha256"):
                if row[field] is not None:
                    _sha(row[field], f"$.control_authority.grants.{name}.{field}")
            null_receipts = all(row[field] is None for field in ("authority_receipt_sha256", "effect_request_sha256", "effect_receipt_sha256", "action_receipt_sha256", "bridge_receipt_sha256"))
            if name == "run" and (row["provenance"] != "authenticated_baseline" or run["lifecycle"] != "absent" or any(row[field] is not None for field in ("run_id", "predecessor_run_id", "successor_run_id", "effect_operation")) or row["lease_id"] is None or row["fencing_token"] != run["fencing_token"] or row["lease_expires_at"] is None or row["cas_expected_state_version"] != 0 or row["cas_expected_thread_generation"] != active["head"]["selection"]["thread_generation"] or not null_receipts or row["cancel_observed"] is not False or row["recovery"] is not None):
                raise ProjectionError("control_grant_invalid", "$.control_authority.grants.run")
            if name == "select" and (row["provenance"] != "host_selection_head" or any(row[field] is not None for field in ("run_id", "predecessor_run_id", "successor_run_id", "effect_operation", "lease_id", "fencing_token", "lease_expires_at")) or row["cas_expected_state_version"] != authority["effect_state_version"] or row["cas_expected_thread_generation"] != active["head"]["selection"]["thread_generation"] or not null_receipts or row["cancel_observed"] is not False or row["recovery"] is not None or len(catalog["presets"]) < 2):
                raise ProjectionError("control_grant_invalid", "$.control_authority.grants.select")
            if name == "cancel" and (row["provenance"] != "canonical_running_state" or run["lifecycle"] != "running" or row["run_id"] != run["run_id"] or row["predecessor_run_id"] != run["predecessor_run_id"] or row["successor_run_id"] is not None or row["effect_operation"] != ("recover" if projection_version == 3 and run["predecessor_run_id"] is not None else "run") or row["lease_id"] is None or row["lease_expires_at"] is None or row["fencing_token"] != run["fencing_token"] or row["cas_expected_state_version"] != (authority["effect_state_version"] - 1 if projection_version == 3 and run["predecessor_run_id"] is not None else authority["effect_state_version"]) or row["cas_expected_thread_generation"] != active["head"]["selection"]["thread_generation"] or row["authority_receipt_sha256"] is None or any(refs[field] is None for field in ("effect_kernel_request_v1", "effect_kernel_receipt_v1", "effect_kernel_action_receipt_v1", "standalone_responses_bridge_receipt_v1")) or row["effect_request_sha256"] != refs["effect_kernel_request_v1"] or row["effect_receipt_sha256"] != refs["effect_kernel_receipt_v1"] or row["action_receipt_sha256"] != refs["effect_kernel_action_receipt_v1"] or row["bridge_receipt_sha256"] != refs["standalone_responses_bridge_receipt_v1"] or row["cancel_observed"] is not False or (run["predecessor_run_id"] is None) != (row["recovery"] is None)):
                raise ProjectionError("control_grant_invalid", "$.control_authority.grants.cancel")
            if name == "cancel" and row["recovery"] is not None:
                _validate_cancel_recovery_provenance(
                    row["recovery"], run=run, refs=refs, authority=authority,
                    active=active, supervision=supervision,
                    path="$.control_authority.grants.cancel.recovery",
                    grant=row, v3=projection_version == 3,
                )
            if name == "recover" and (row["provenance"] != "host_recovery_lease_grant" or run["lifecycle"] != "execution_unknown" or row["run_id"] != run["run_id"] or row["predecessor_run_id"] != run["run_id"] or row["successor_run_id"] is not None or row["effect_operation"] != "recover" or row["lease_id"] is None or row["lease_expires_at"] is None or row["fencing_token"] <= run["fencing_token"] or row["cas_expected_state_version"] != authority["effect_state_version"] or row["cas_expected_thread_generation"] != active["head"]["selection"]["thread_generation"] or row["authority_receipt_sha256"] is not None or any(refs[field] is None for field in ("standalone_responses_request_v1", "effect_kernel_request_v1", "effect_kernel_receipt_v1")) or row["effect_request_sha256"] != refs["effect_kernel_request_v1"] or row["effect_receipt_sha256"] != refs["effect_kernel_receipt_v1"] or row["action_receipt_sha256"] is not None or row["bridge_receipt_sha256"] is not None or row["cancel_observed"] is not False or not isinstance(row["recovery"], dict)):
                raise ProjectionError("control_grant_invalid", "$.control_authority.grants.recover")
            if name == "recover":
                recovery_fields = {"schema_version", "artifact_type", "grant_id", "issuer_id", "workspace_id", "source_sha256", "candidate_sha256", "service_instance_id", "admission_id", "binding_state_version", "binding_state_sha256", "selection_sha256", "predecessor_run_id", "predecessor_effect_request_sha256", "predecessor_effect_receipt_sha256", "reconciliation_receipt_sha256", "no_successor", "fresh_lease", "expected_cas", "reserved_authority_id", "issued_at", "expires_at", "grant_sha256", "seal"}
                recovery_receipt = _closed(row["recovery"], recovery_fields, "$.control_authority.grants.recover.recovery")
                lease = _closed(recovery_receipt["fresh_lease"], {"lease_id", "fencing_token", "issued_at", "expires_at", "lease_sha256"}, "$.control_authority.grants.recover.recovery.fresh_lease")
                cas = _closed(recovery_receipt["expected_cas"], {"expected_state_version", "expected_thread_generation"}, "$.control_authority.grants.recover.recovery.expected_cas")
                recovery_issued, recovery_expires = _time(recovery_receipt["issued_at"], "$.control_authority.grants.recover.recovery.issued_at"), _time(recovery_receipt["expires_at"], "$.control_authority.grants.recover.recovery.expires_at")
                lease_issued, lease_expires = _time(lease["issued_at"], "$.control_authority.grants.recover.recovery.fresh_lease.issued_at"), _time(lease["expires_at"], "$.control_authority.grants.recover.recovery.fresh_lease.expires_at")
                if recovery_receipt["schema_version"] != 1 or recovery_receipt["artifact_type"] != "effect_kernel_recovery_lease_grant_v1" or recovery_receipt["workspace_id"] != root["workspace_id"] or recovery_receipt["source_sha256"] != root["source_sha256"] or recovery_receipt["candidate_sha256"] != root["candidate_sha256"] or recovery_receipt["service_instance_id"] != root["service_instance_id"] or recovery_receipt["admission_id"] != authority["admission_id"] or recovery_receipt["binding_state_version"] != authority["binding_state_version"] or recovery_receipt["binding_state_sha256"] != authority["binding_state_sha256"] or recovery_receipt["selection_sha256"] != authority["selection_sha256"] or recovery_receipt["predecessor_run_id"] != run["run_id"] or recovery_receipt["predecessor_effect_request_sha256"] != refs["effect_kernel_request_v1"] or recovery_receipt["predecessor_effect_receipt_sha256"] != refs["effect_kernel_receipt_v1"] or recovery_receipt["no_successor"] is not True or lease["lease_id"] != row["lease_id"] or lease["lease_id"] == run["run_id"] or lease["fencing_token"] != row["fencing_token"] or lease["expires_at"] != row["lease_expires_at"] or recovery_issued > issued or recovery_expires <= observed or recovery_expires < _time(row["expires_at"], "$.control_authority.grants.recover.expires_at") or lease_issued > recovery_issued or lease_expires <= observed or lease_expires < recovery_expires or cas != {"expected_state_version": row["cas_expected_state_version"], "expected_thread_generation": row["cas_expected_thread_generation"]} or recovery_receipt["grant_sha256"] != digest({key: item for key, item in recovery_receipt.items() if key not in {"grant_sha256", "seal"}}) or lease["lease_sha256"] != digest({key: item for key, item in lease.items() if key != "lease_sha256"}):
                    raise ProjectionError("control_grant_invalid", "$.control_authority.grants.recover.recovery")
                for field in ("grant_id", "issuer_id", "reserved_authority_id"):
                    _identifier(recovery_receipt[field], f"$.control_authority.grants.recover.recovery.{field}")
                for field in ("reconciliation_receipt_sha256", "grant_sha256", "seal"):
                    _sha(recovery_receipt[field], f"$.control_authority.grants.recover.recovery.{field}")
    if run["lifecycle"] == "absent" and run["fencing_token"] is not None:
        if grants is None or grants["run"] is None or not controls["run"]["enabled"] or grants["run"]["fencing_token"] != run["fencing_token"]:
            raise ProjectionError("run_state_invalid", "$.run.fencing_token")
    enabled = {name for name, control in controls.items() if control["enabled"]}
    enabled_reasons = {
        "run": {"authenticated baseline grant and current fence"},
        "cancel": {"canonical running receipt and current fence"},
        "recover": {"reconciled unknown with fresh successor fence"},
        "select": {"authenticated baseline selection is current", "selection generation current and no in-flight run"},
    }
    if any(controls[name]["reason"] not in enabled_reasons[name] for name in enabled_reasons if controls[name]["enabled"]):
        raise ProjectionError("control_state_not_authorized", "$.controls")
    if run["lifecycle"] == "execution_unknown" and enabled & {"run", "cancel", "select", "retry", "fallback", "replacement"}:
        raise ProjectionError("control_state_not_authorized", "$.controls")
    if controls["run"]["enabled"] and (run["lifecycle"] != "absent" or root["selection"] is None or artifact_sha != active_sha or any(refs[field] is not None for field in refs)):
        raise ProjectionError("control_state_not_authorized", "$.controls.run")
    if controls["cancel"]["enabled"] and (run["lifecycle"] != "running" or any(refs[field] is None for field in refs) or run["successor_run_id"] is not None):
        raise ProjectionError("control_state_not_authorized", "$.controls.cancel")
    if controls["recover"]["enabled"] and (run["lifecycle"] != "execution_unknown" or refs["effect_kernel_action_receipt_v1"] is not None or refs["standalone_responses_bridge_receipt_v1"] is not None or any(refs[field] is None for field in ("standalone_responses_request_v1", "effect_kernel_request_v1", "effect_kernel_receipt_v1")) or run["successor_run_id"] is not None):
        raise ProjectionError("control_state_not_authorized", "$.controls.recover")
    if controls["select"]["enabled"] and (run["lifecycle"] in {"running", "execution_unknown", "cancel_requested"} or active["state"] != "verified" or active["head"]["selection"]["in_flight"] is not False):
        raise ProjectionError("control_state_not_authorized", "$.controls.select")
    expected = digest({key: item for key, item in root.items() if key not in {"projection_sha256", "projection_receipt"}})
    if root["projection_sha256"] != expected:
        raise ProjectionError("projection_digest_mismatch", "$.projection_sha256")
    receipt = root["projection_receipt"]
    if receipt is not None:
        receipt = _closed(receipt, {"schema_version", "artifact_type", "projection_sha256", "admission_id", "workspace_id", "candidate_sha256", "expires_at", "seal"}, "$.projection_receipt")
        if receipt["schema_version"] != 1 or receipt["artifact_type"] != "standalone_operator_projection_receipt_v1" or receipt["projection_sha256"] != expected or receipt["workspace_id"] != root["workspace_id"] or receipt["candidate_sha256"] != root["candidate_sha256"] or receipt["expires_at"] != root["expires_at"] or _time(receipt["expires_at"], "$.projection_receipt.expires_at") <= observed:
            raise ProjectionError("projection_receipt_mismatch", "$.projection_receipt")
        _identifier(receipt["admission_id"], "$.projection_receipt.admission_id")
        _sha(receipt["seal"], "$.projection_receipt.seal")
    if claims["capability_admitted"] != (receipt is not None):
        raise ProjectionError("claims_invalid", "$.claims.capability_admitted")
    return root


def validate_browser_bootstrap(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    root = _closed(copy.deepcopy(value), {"schema_version", "artifact_type", "listener_id", "listener_nonce", "page_nonce", "hmac_key_b64", "issued_at", "expires_at"}, "$.bootstrap")
    observed = now or datetime.now(timezone.utc)
    issued, expires = _time(root["issued_at"], "$.bootstrap.issued_at"), _time(root["expires_at"], "$.bootstrap.expires_at")
    if root["schema_version"] != 1 or root["artifact_type"] != "standalone_operator_browser_bootstrap_v1" or not isinstance(root["listener_id"], str) or not root["listener_id"] or len(_b64decode(root["listener_nonce"], "$.bootstrap.listener_nonce")) != 32 or len(_b64decode(root["page_nonce"], "$.bootstrap.page_nonce")) != 32 or len(_b64decode(root["hmac_key_b64"], "$.bootstrap.hmac_key_b64")) != 32 or issued > observed or expires <= observed or (expires - issued).total_seconds() > 60:
        raise ProjectionError("browser_bootstrap_invalid", "$.bootstrap")
    return root


def _verify_envelope(value: Any, bootstrap: dict[str, Any], keys: set[str], artifact_type: str, domain: bytes, *, now: datetime) -> dict[str, Any]:
    root = _closed(copy.deepcopy(value), keys, "$.envelope")
    if root["schema_version"] != 1 or root["artifact_type"] != artifact_type or root["listener_id"] != bootstrap["listener_id"] or root["listener_nonce"] != bootstrap["listener_nonce"] or root["page_nonce"] != bootstrap["page_nonce"] or root["mac_algorithm"] != "HMAC-SHA-256":
        raise ProjectionError("browser_envelope_invalid", "$.envelope")
    issued, expires = _time(root["issued_at"], "$.envelope.issued_at"), _time(root["expires_at"], "$.envelope.expires_at")
    if issued > now or expires <= now or (expires - issued).total_seconds() > 5:
        raise ProjectionError("browser_envelope_expired", "$.envelope")
    expected_receipt = digest({key: item for key, item in root.items() if key not in {"receipt_sha256", "mac_b64"}})
    if root["receipt_sha256"] != expected_receipt:
        raise ProjectionError("browser_receipt_digest_mismatch", "$.envelope.receipt_sha256")
    key = _b64decode(bootstrap["hmac_key_b64"], "$.bootstrap.hmac_key_b64")
    expected_mac = base64.urlsafe_b64encode(hmac.new(key, domain + _canonical({key: item for key, item in root.items() if key != "mac_b64"}), hashlib.sha256).digest()).decode("ascii").rstrip("=")
    if not hmac.compare_digest(root["mac_b64"], expected_mac):
        raise ProjectionError("browser_mac_invalid", "$.envelope.mac_b64")
    return root


def validate_browser_status(value: Any, bootstrap: Any, *, previous_sequence: int = 0, previous_receipt_sha256: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    boot = validate_browser_bootstrap(bootstrap, now=now)
    keys = {"schema_version", "artifact_type", "listener_id", "listener_nonce", "page_nonce", "status_sequence", "previous_status_receipt_sha256", "projection_encoding", "projection_bytes_b64", "projection_sha256", "issued_at", "expires_at", "receipt_sha256", "mac_algorithm", "mac_b64"}
    root = _verify_envelope(value, boot, keys, "standalone_operator_browser_status_receipt_v1", STATUS_DOMAIN, now=now or datetime.now(timezone.utc))
    if type(root["status_sequence"]) is not int or root["status_sequence"] != previous_sequence + 1 or root["previous_status_receipt_sha256"] != (None if previous_sequence == 0 else previous_receipt_sha256) or root["projection_encoding"] != "base64url-canonical-json-v1":
        raise ProjectionError("browser_sequence_invalid", "$.envelope")
    raw = _b64decode(root["projection_bytes_b64"], "$.envelope.projection_bytes_b64")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != root["projection_sha256"]:
        raise ProjectionError("browser_payload_digest_mismatch", "$.envelope.projection_sha256")
    try:
        projection = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectionError("browser_payload_invalid", "$.envelope.projection_bytes_b64") from exc
    if _canonical(projection) != raw:
        raise ProjectionError("browser_payload_noncanonical", "$.envelope.projection_bytes_b64")
    return validate_projection(projection)


def validate_projection_v3(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    return validate_projection(value, now=now, projection_version=3)


def validate_browser_status_v3(value: Any, bootstrap: Any, *, previous_sequence: int = 0, previous_receipt_sha256: str | None = None, now: datetime | None = None) -> dict[str, Any]:
    boot = validate_browser_bootstrap(bootstrap, now=now)
    keys = {"schema_version", "artifact_type", "listener_id", "listener_nonce", "page_nonce", "status_sequence", "previous_status_receipt_sha256", "projection_encoding", "projection_bytes_b64", "projection_sha256", "issued_at", "expires_at", "receipt_sha256", "mac_algorithm", "mac_b64"}
    root = _verify_envelope(value, boot, keys, "standalone_operator_browser_status_receipt_v1", STATUS_DOMAIN, now=now or datetime.now(timezone.utc))
    if type(root["status_sequence"]) is not int or root["status_sequence"] != previous_sequence + 1 or root["previous_status_receipt_sha256"] != (None if previous_sequence == 0 else previous_receipt_sha256) or root["projection_encoding"] != "base64url-canonical-json-v1":
        raise ProjectionError("browser_sequence_invalid", "$.envelope")
    raw = _b64decode(root["projection_bytes_b64"], "$.envelope.projection_bytes_b64")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != root["projection_sha256"]:
        raise ProjectionError("browser_payload_digest_mismatch", "$.envelope.projection_sha256")
    try:
        projection = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectionError("browser_payload_invalid", "$.envelope.projection_bytes_b64") from exc
    if _canonical(projection) != raw:
        raise ProjectionError("browser_payload_noncanonical", "$.envelope.projection_bytes_b64")
    return validate_projection_v3(projection, now=now)


def validate_browser_transport(value: Any, bootstrap: Any, submission: Any, *, now: datetime | None = None) -> dict[str, Any]:
    boot = validate_browser_bootstrap(bootstrap, now=now)
    keys = {"schema_version", "artifact_type", "listener_id", "listener_nonce", "page_nonce", "submission_id", "submission_sha256", "payload_encoding", "payload_bytes_b64", "payload_sha256", "issued_at", "expires_at", "receipt_sha256", "mac_algorithm", "mac_b64"}
    root = _verify_envelope(value, boot, keys, "standalone_operator_browser_transport_receipt_v1", TRANSPORT_DOMAIN, now=now or datetime.now(timezone.utc))
    if root["submission_id"] != submission.get("submission_id") or root["submission_sha256"] != digest(submission) or root["payload_encoding"] != "base64url-canonical-json-v1":
        raise ProjectionError("browser_transport_binding_invalid", "$.envelope")
    raw = _b64decode(root["payload_bytes_b64"], "$.envelope.payload_bytes_b64")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != root["payload_sha256"]:
        raise ProjectionError("browser_payload_digest_mismatch", "$.envelope.payload_sha256")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProjectionError("browser_payload_invalid", "$.envelope.payload_bytes_b64") from exc
    if _canonical(payload) != raw or payload.get("optimistic_state_change") is not False or "unknown_until_status_refresh" not in {payload.get("effect_outcome"), payload.get("selection_outcome")}:
        raise ProjectionError("browser_transport_payload_invalid", "$.envelope.payload_bytes_b64")
    return payload


def render_snapshot(value: Any) -> str:
    root = validate_projection(value)
    supervision = root["supervision"]
    if supervision["state"] == "verified":
        native, topology = supervision["receipt"]["native"], supervision["receipt"]["topology"]
        facts = {"Parent": native["parent_locator"], "Supervisor": native["supervisor_locator"], "Internal Workers": topology["internal_worker_count"]}
    else:
        facts = {"Parent": "unavailable", "Supervisor": "unavailable", "Internal Workers": "unavailable"}
    current = None if root["active_selection"]["head"] is None else root["active_selection"]["head"]["selection"]
    facts.update({"Preset": None if current is None else current["preset_id"], "Available presets": ", ".join(item["preset_id"] for item in root["preset_catalog"]["presets"]) or "unavailable", "Lifecycle": root["run"]["lifecycle"], "Supervision": supervision["reason"] or "verified"})
    rows = "".join(f"<dt>{html.escape(str(key))}</dt><dd>{html.escape(str(item))}</dd>" for key, item in facts.items())
    return f'<section data-artifact="{ARTIFACT_TYPE}"><h1>Standalone operator V2</h1><dl>{rows}</dl></section>'
