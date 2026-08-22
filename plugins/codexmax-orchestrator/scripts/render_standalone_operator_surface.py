#!/usr/bin/env python3
"""Validate and render the deterministic no-effect standalone operator surface."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import html
import importlib.util
import json
import math
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence


VERSION = 1
SNAPSHOT_TYPE = "standalone_operator_snapshot_v1"
BINDING_TYPE = "standalone_operator_surface_binding_v2"
LEGACY_BINDING_TYPE = "standalone_operator_surface_binding_v1"
CASES_TYPE = "standalone_operator_surface_cases_v1"
CASES_V2_TYPE = "standalone_operator_surface_cases_v2"
RECEIPT_TYPE = "standalone_operator_surface_cases_receipt_v1"
ACCEPTED_CLI_SHA256 = "sha256:d280030dec49dee42c11f01bc244f96e2f63e40750a21b35e4eb5a8caf3cc8cf"
CLI_PATH = Path(__file__).resolve().with_name("standalone_runtime_cli.py")
SOURCE_MANIFEST_SHA256 = "sha256:8532761f9ee497202b0a8a670fbed41fbaa56bd435c7ba9e215e533372c4884c"
V1_CASES_PATH = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "standalone-operator-surface" / "cases.json"
# Frozen synthetic/local root maximum from standalone-runtime-contract.md.
SOURCE_MAX_TTL_SECONDS = 3600
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PROPOSAL_VALIDATION = {
    "valid": True,
    "codes": ["schema_closed", "diff_deterministic", "activation_forbidden"],
}
PLANE_GATES = {
    "observed_capability": "observed_positive_active_fresh_capability",
    "role_policy": "role_and_route_compatible",
    "task_requirement": "task_evidence_exactly_bound",
    "human_authority": "planning_authority_active_and_bound",
    "billing": "billing_within_ceilings",
    "health": "health_observed_healthy_fresh",
}
EFFECT_FIELDS = {
    "service_started", "network_used", "provider_called", "lease_created",
    "dispatch_started", "run_mutated", "journal_written", "policy_persisted",
    "policy_activated", "authority_granted", "acceptance_granted",
}
EFFECT_GUARANTEES = {field: False for field in sorted(EFFECT_FIELDS)}
ANCHOR_EFFECT_FIELDS = EFFECT_FIELDS | {"installed", "released", "published", "aol_admitted"}
ANCHOR_EFFECT_GUARANTEES = {field: False for field in sorted(ANCHOR_EFFECT_FIELDS)}
SLOT_COMMANDS = {
    "status": "status", "plan": "plan", "run": "run", "delegate": "delegate",
    "lineage": "lineage", "journal": "journal", "policy_proposal": "policy-propose",
}


class SurfaceError(ValueError):
    def __init__(self, code: str, path: str = "$"):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    def reject(child: Any, path: str = "$") -> None:
        if isinstance(child, float) and not math.isfinite(child):
            raise SurfaceError("nonfinite_number", path)
        if isinstance(child, dict):
            for key, item in child.items():
                reject(item, f"{path}.{key}")
        elif isinstance(child, list):
            for index, item in enumerate(child):
                reject(item, f"{path}[{index}]")
    reject(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SurfaceError("canonical_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SurfaceError("duplicate_json_key", key)
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise SurfaceError("nonfinite_number", value)


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SurfaceError("input_read_failed", str(path)) from exc
    try:
        return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant)
    except UnicodeDecodeError as exc:
        raise SurfaceError("utf8_invalid", str(exc.start)) from exc
    except SurfaceError:
        raise
    except json.JSONDecodeError as exc:
        raise SurfaceError("json_invalid", f"line:{exc.lineno}:column:{exc.colno}") from exc


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SurfaceError("object_required", path)
    extra = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if extra:
        raise SurfaceError("unknown_field", f"{path}.{extra[0]}")
    if missing:
        raise SurfaceError("missing_field", f"{path}.{missing[0]}")
    return value


def _identifier(value: Any, path: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise SurfaceError("identifier_invalid", path)
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise SurfaceError("string_required", path)
    return value


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise SurfaceError("boolean_required", path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise SurfaceError("timestamp_invalid", path)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SurfaceError("timestamp_invalid", path) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise SurfaceError("timestamp_invalid", path)
    return parsed


def _strings(value: Any, path: str, *, identifiers: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise SurfaceError("array_required", path)
    result = [(_identifier(item, f"{path}[{index}]") if identifiers else _text(item, f"{path}[{index}]")) for index, item in enumerate(value)]
    if len(result) != len(set(result)):
        raise SurfaceError("array_duplicate", path)
    return result


def _load_accepted_cli(supplied_sha256: Any) -> Any:
    # Even fixture repair helpers may not import executable CLI code before the
    # immutable package anchor has passed raw-byte and file-kind verification.
    _load_source_manifest()
    if supplied_sha256 != ACCEPTED_CLI_SHA256:
        raise SurfaceError("surface_cli_identity_mismatch", "$.accepted_cli_sha256")
    try:
        raw = CLI_PATH.read_bytes()
    except OSError as exc:
        raise SurfaceError("surface_cli_identity_mismatch", str(CLI_PATH)) from exc
    observed = "sha256:" + hashlib.sha256(raw).hexdigest()
    if observed != ACCEPTED_CLI_SHA256:
        raise SurfaceError("surface_cli_identity_mismatch", str(CLI_PATH))
    scripts = str(CLI_PATH.parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("codexmax_surface_accepted_cli", CLI_PATH)
    if spec is None or spec.loader is None:
        raise SurfaceError("surface_cli_identity_mismatch", str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest_shape(value: Any) -> dict[str, Any]:
    """Validate the closed manifest shape without importing executable product code."""
    try:
        root = _closed(value, {"schema_version", "artifact_type", "scope", "canonicalization", "bundles"}, "$")
        if (
            root["schema_version"] != 1
            or root["artifact_type"] != "standalone_operator_source_manifest_v1"
            or root["scope"] != "package_source_local_synthetic_no_effect"
            or root["canonicalization"] != "standalone_runtime_cli_canonical_json_v1"
            or not isinstance(root["bundles"], list)
            or not root["bundles"]
        ):
            raise SurfaceError("shape", "$")
        bundle_fields = {
            "bundle_id", "workspace_id", "proof_boundary", "role_ids", "supported_versions",
            "validity", "recall", "source_memberships", "request_memberships",
            "route_memberships", "identity_memberships", "effect_guarantees",
        }
        bundle_ids: list[str] = []
        for index, raw_bundle in enumerate(root["bundles"]):
            path = f"$.bundles[{index}]"
            bundle = _closed(raw_bundle, bundle_fields, path)
            bundle_ids.append(_identifier(bundle["bundle_id"], f"{path}.bundle_id"))
            _identifier(bundle["workspace_id"], f"{path}.workspace_id")
            if bundle["proof_boundary"] != "synthetic_local":
                raise SurfaceError("shape", f"{path}.proof_boundary")
            roles = _strings(bundle["role_ids"], f"{path}.role_ids", identifiers=True)
            if not roles or roles != sorted(roles, key=lambda item: item.encode("ascii")):
                raise SurfaceError("shape", f"{path}.role_ids")
            _closed(bundle["supported_versions"], {"cli", "binding", "runtime_manifest", "planner", "adapter_snapshot", "runtime_evidence", "policy_proposal"}, f"{path}.supported_versions")
            validity = _closed(bundle["validity"], {"evaluated_not_before", "evaluated_not_after"}, f"{path}.validity")
            _timestamp(validity["evaluated_not_before"], f"{path}.validity.evaluated_not_before")
            _timestamp(validity["evaluated_not_after"], f"{path}.validity.evaluated_not_after")
            recall = _closed(bundle["recall"], {"status", "recall_evidence_sha256s", "recalled_artifact_ids"}, f"{path}.recall")
            if recall["status"] not in {"not_recalled", "recalled"} or not isinstance(recall["recall_evidence_sha256s"], list):
                raise SurfaceError("shape", f"{path}.recall")
            _strings(recall["recalled_artifact_ids"], f"{path}.recall.recalled_artifact_ids", identifiers=True)
            _closed(bundle["source_memberships"], {"accepted_cli_sha256", "runtime_id", "runtime_version", "api_version", "runtime_source_sha256", "runtime_candidate_sha256", "workspace_root_sha256", "evidence_source_sha256", "policy_sha256"}, f"{path}.source_memberships")
            identities = _closed(bundle["identity_memberships"], {"registry_sha256s", "capability_card_sha256s", "conformance_certificate_sha256s", "evaluation_manifest_sha256s", "task_profile_sha256s", "evidence_sha256s"}, f"{path}.identity_memberships")
            if any(not isinstance(identities[name], list) or len(identities[name]) != len(set(identities[name])) for name in identities):
                raise SurfaceError("shape", f"{path}.identity_memberships")
            if not isinstance(bundle["request_memberships"], list) or not isinstance(bundle["route_memberships"], list):
                raise SurfaceError("shape", path)
            if _closed(bundle["effect_guarantees"], set(ANCHOR_EFFECT_GUARANTEES), f"{path}.effect_guarantees") != ANCHOR_EFFECT_GUARANTEES:
                raise SurfaceError("shape", f"{path}.effect_guarantees")
        if len(bundle_ids) != len(set(bundle_ids)) or bundle_ids != sorted(bundle_ids, key=lambda item: item.encode("ascii")):
            raise SurfaceError("shape", "$.bundles")
        return root
    except (KeyError, TypeError, SurfaceError) as exc:
        path = getattr(exc, "path", "$")
        raise SurfaceError("surface_anchor_shape_invalid", path) from exc


def _load_source_manifest() -> dict[str, Any]:
    """Load only the one package-owned regular, non-symlink raw-byte anchor."""
    # co_filename is fixed when this trusted renderer is compiled.  The anchor
    # locator is intentionally not stored in mutable module state or accepted
    # from a caller, binding, argument, environment, or configuration value.
    anchor_path = (
        Path(_load_source_manifest.__code__.co_filename).resolve().parent.parent
        / "assets" / "manifests" / "standalone-operator-source-manifest-v1.json"
    )
    try:
        metadata = anchor_path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("anchor is not a regular non-symlink file")
        raw = anchor_path.read_bytes()
    except OSError as exc:
        raise SurfaceError("surface_anchor_unavailable", str(anchor_path)) from exc
    observed = "sha256:" + hashlib.sha256(raw).hexdigest()
    if observed != SOURCE_MANIFEST_SHA256:
        raise SurfaceError("surface_anchor_identity_mismatch", str(anchor_path))
    try:
        decoded = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs, parse_constant=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, SurfaceError) as exc:
        raise SurfaceError("surface_anchor_shape_invalid", str(anchor_path)) from exc
    return _manifest_shape(decoded)


def _load_runtime_adapter() -> Any:
    path = CLI_PATH.with_name("runtime_adapter.py")
    scripts = str(path.parent)
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("codexmax_surface_runtime_adapter", path)
    if spec is None or spec.loader is None:
        raise SurfaceError("surface_anchor_digest_mismatch", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _walk_values(value: Any, names: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in names:
                found.append(child)
            found.extend(_walk_values(child, names))
    elif isinstance(value, list):
        for child in value:
            found.extend(_walk_values(child, names))
    return found


def _request_memberships(root: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for slot_id, command in SLOT_COMMANDS.items():
        slot = root[slot_id]
        rows.append({"slot_id": "policy-proposal" if slot_id == "policy_proposal" else slot_id, "command": command, "role_id": None, "request_sha256": slot["request_sha256"], "receipt_sha256": slot["receipt_sha256"]})
    for slot in root["routes_by_role"]:
        rows.append({"slot_id": f'routes-{slot["role_id"]}', "command": "routes", "role_id": slot["role_id"], "request_sha256": slot["request_sha256"], "receipt_sha256": slot["receipt_sha256"]})
    return sorted(rows, key=lambda row: row["slot_id"].encode("ascii"))


def _verify_source_membership(root: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Reject caller-recomputed source families before the accepted CLI is imported."""
    try:
        if root["source_manifest_sha256"] != SOURCE_MANIFEST_SHA256:
            raise SurfaceError("surface_anchor_identity_mismatch", "$.source_manifest_sha256")
        selected = [item for item in manifest["bundles"] if item["bundle_id"] == root["source_bundle_id"]]
        if len(selected) != 1:
            raise SurfaceError("surface_anchor_bundle_unknown", "$.source_bundle_id")
        bundle = selected[0]
        if bundle["role_ids"] != root["role_ids"]:
            raise SurfaceError("surface_anchor_scope_mismatch", "$.role_ids")
        if bundle["effect_guarantees"] != ANCHOR_EFFECT_GUARANTEES:
            raise SurfaceError("surface_source_membership_mismatch", "$.effect_guarantees")
        status_source = root["status"]["request"]["input"]
        planner_sources = [_planner_source(slot["request"]) for slot in root["routes_by_role"]] + [_planner_source(root["plan"]["request"])]
        evidence_sources = [root[name]["request"]["input"] for name in ("delegate", "lineage", "journal")]
        workspaces = {status_source["workspace_id"], *(source["workspace_id"] for source in planner_sources), *(source["bindings"]["workspace_id"] for source in evidence_sources)}
        if workspaces != {bundle["workspace_id"]}:
            raise SurfaceError("surface_anchor_scope_mismatch", "$.workspace_id")
        versions = bundle["supported_versions"]
        observed_versions = {
            "cli": {slot["request"]["cli_version"] for slot in [root["status"], *root["routes_by_role"], root["plan"], root["run"], root["delegate"], root["lineage"], root["journal"], root["policy_proposal"]]},
            "binding": {root["schema_version"]},
            "runtime_manifest": {status_source["schema_version"]},
            "planner": {source["planner_version"] for source in planner_sources},
            "adapter_snapshot": {source["adapter_snapshot"]["schema_version"] for source in planner_sources},
            "runtime_evidence": {source["evidence_version"] for source in evidence_sources},
            "policy_proposal": {1},
        }
        if any(values != {versions[name]} for name, values in observed_versions.items()):
            raise SurfaceError("surface_anchor_version_mismatch", "$.supported_versions")
        runtime = status_source["runtime_manifest"]
        evidence_bindings = evidence_sources[0]["bindings"]
        sources = {
            "accepted_cli_sha256": root["accepted_cli_sha256"], "runtime_id": runtime["runtime_id"],
            "runtime_version": runtime["runtime_version"], "api_version": runtime["api_version"],
            "runtime_source_sha256": runtime["source_sha256"], "runtime_candidate_sha256": runtime["candidate_sha256"],
            "workspace_root_sha256": runtime["workspace_root_sha256"], "evidence_source_sha256": evidence_bindings["source_sha256"],
            "policy_sha256": evidence_bindings["policy_sha256"],
        }
        if sources != bundle["source_memberships"]:
            raise SurfaceError("surface_source_not_accepted", "$.source_memberships")
        if _request_memberships(root) != bundle["request_memberships"]:
            raise SurfaceError("surface_source_not_accepted", "$.request_memberships")

        adapter = _load_runtime_adapter()
        accepted_routes = {row["route_id"]: row for row in bundle["route_memberships"]}
        for row in bundle["route_memberships"]:
            if adapter.adapter_identity_digest(row["identity"]) != row["adapter_identity_sha256"]:
                raise SurfaceError("surface_anchor_digest_mismatch", f'$.route_memberships.{row["route_id"]}')
        for source in planner_sources:
            snapshot = source["adapter_snapshot"]
            for category in ("adapter_snapshots", "route_snapshots", "capability_snapshots", "health_snapshots", "billing_snapshots", "usage_snapshots", "conformance_snapshots"):
                rows = snapshot[category]
                if {row["identity"]["route_id"] for row in rows} != set(accepted_routes):
                    raise SurfaceError("surface_route_membership_mismatch", f"$.adapter_snapshot.{category}")
                for row in rows:
                    expected = accepted_routes[row["identity"]["route_id"]]
                    observed_digest = adapter.adapter_identity_digest(row["identity"])
                    if row["identity"] != expected["identity"] or row["adapter_identity_sha256"] != expected["adapter_identity_sha256"] or observed_digest != expected["adapter_identity_sha256"]:
                        raise SurfaceError("surface_route_membership_mismatch", f"$.adapter_snapshot.{category}")

        identities = bundle["identity_memberships"]
        for source in planner_sources:
            snapshot = source["adapter_snapshot"]
            observed = {
                "registry_sha256s": sorted(set(_walk_values(source, {"registry_sha256"}))),
                "capability_card_sha256s": sorted(set(_walk_values(source, {"capability_card_sha256"}))),
                "conformance_certificate_sha256s": sorted(set(_walk_values(source, {"conformance_certificate_sha256"}))),
                "evaluation_manifest_sha256s": sorted(set(_walk_values(source, {"evaluation_manifest_sha256"}))),
                "task_profile_sha256s": sorted(set(_walk_values(source, {"task_profile_sha256"}))),
                "evidence_sha256s": sorted(set(_walk_values(snapshot, {"evidence_sha256", "usage_evidence_sha256"}) + [evidence_bindings["source_sha256"]])),
            }
            if observed != identities:
                raise SurfaceError("surface_source_membership_mismatch", "$.identity_memberships")

        lower = _timestamp(bundle["validity"]["evaluated_not_before"], "$.validity.evaluated_not_before")
        upper = _timestamp(bundle["validity"]["evaluated_not_after"], "$.validity.evaluated_not_after")
        if lower > upper:
            raise SurfaceError("surface_anchor_window_invalid", "$.validity")
        timestamp_sources = [status_source, *planner_sources, *evidence_sources]
        for raw in _walk_values(timestamp_sources, {"evaluated_at", "collected_at", "recorded_at", "issued_at", "created_at"}):
            when = _timestamp(raw, "$.source_evaluation")
            if when < lower:
                raise SurfaceError("surface_anchor_window_invalid", "$.source_evaluation")
            if when > upper:
                raise SurfaceError("surface_anchor_expired", "$.source_evaluation")
        for raw in _walk_values(timestamp_sources, {"expires_at"}):
            if _timestamp(raw, "$.source_expiry") > upper:
                raise SurfaceError("surface_anchor_expired", "$.source_expiry")

        recall_evidence = sorted(set(_walk_values(planner_sources, {"recall_evidence_sha256"})))
        recalled_artifacts = sorted({item["artifact_id"] for source in evidence_sources for item in source["artifacts"] if item["recalled"] is True})
        recall_events = [item for source in evidence_sources for item in source["journal"]["recalls"]]
        observed_recall = {"status": "recalled" if recalled_artifacts or recall_events else "not_recalled", "recall_evidence_sha256s": recall_evidence, "recalled_artifact_ids": recalled_artifacts}
        if observed_recall != bundle["recall"]:
            raise SurfaceError("surface_anchor_recall_mismatch", "$.recall")
        return bundle
    except SurfaceError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise SurfaceError("surface_source_membership_mismatch", "$") from exc


def _validate_effects(value: Any, path: str) -> None:
    effects = _closed(value, set(EFFECT_GUARANTEES), path)
    if effects != EFFECT_GUARANTEES:
        raise SurfaceError("surface_effect_claimed", path)


def _execute_slot(cli: Any, slot: Any, command: str, path: str, *, role: bool = False) -> dict[str, Any]:
    fields = {"request", "request_sha256", "receipt_sha256"} | ({"role_id"} if role else set())
    try:
        row = _closed(slot, fields, path)
    except SurfaceError as exc:
        raise SurfaceError("surface_binding_shape_invalid", exc.path) from exc
    request = row["request"]
    if not isinstance(request, dict) or request.get("command") != command:
        raise SurfaceError("surface_command_slot_mismatch", f"{path}.request.command")
    if row["request_sha256"] != digest(request):
        raise SurfaceError("surface_request_digest_mismatch", f"{path}.request_sha256")
    try:
        receipt = cli.execute(copy.deepcopy(request))
    except Exception as exc:
        error_path = getattr(exc, "path", f"{path}.request")
        raise SurfaceError("surface_cli_request_rejected", f"{error_path}:{getattr(exc, 'code', type(exc).__name__)}") from exc
    if row["receipt_sha256"] != receipt.get("receipt_sha256"):
        raise SurfaceError("surface_receipt_digest_mismatch", f"{path}.receipt_sha256")
    if (
        receipt.get("artifact_type") != "standalone_runtime_cli_receipt_v1"
        or receipt.get("proof_boundary") != "synthetic_local"
        or receipt.get("structured_output") is not True
        or receipt.get("side_effect_free") is not True
    ):
        raise SurfaceError("surface_receipt_shape_invalid", path)
    _validate_effects(receipt.get("effect_guarantees"), f"{path}.receipt.effect_guarantees")
    return receipt


def _planner_source(request: Mapping[str, Any]) -> Mapping[str, Any]:
    source = request["input"]
    if isinstance(source, dict) and source.get("artifact_type") == "runtime_plan_binding_v1":
        source = source.get("request")
    if not isinstance(source, dict):
        raise SurfaceError("surface_plan_binding_mismatch", "$.plan.request.input")
    return source


def validate_binding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("artifact_type") != BINDING_TYPE:
        raise SurfaceError("surface_provenance_anchor_required")
    root_fields = {
        "schema_version", "artifact_type", "source_manifest_sha256", "source_bundle_id",
        "accepted_cli_sha256", "role_ids", "status",
        "routes_by_role", "plan", "run", "delegate", "lineage", "journal",
        "policy_proposal", "effect_guarantees", "binding_sha256",
    }
    try:
        root = _closed(copy.deepcopy(value), root_fields, "$")
    except SurfaceError as exc:
        raise SurfaceError("surface_binding_shape_invalid", exc.path) from exc
    if root["schema_version"] != 2:
        raise SurfaceError("surface_binding_version_invalid", "$.schema_version")
    role_ids = root["role_ids"]
    if (
        not isinstance(role_ids, list) or not role_ids
        or any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in role_ids)
        or len(role_ids) != len(set(role_ids))
        or role_ids != sorted(role_ids, key=lambda item: item.encode("ascii"))
    ):
        raise SurfaceError("surface_role_order_invalid", "$.role_ids")
    routes_slots = root["routes_by_role"]
    if not isinstance(routes_slots, list) or len(routes_slots) != len(role_ids):
        raise SurfaceError("surface_role_order_invalid", "$.routes_by_role")
    route_slot_roles = [item.get("role_id") if isinstance(item, dict) else None for item in routes_slots]
    if route_slot_roles != role_ids:
        raise SurfaceError("surface_role_order_invalid", "$.routes_by_role")
    _validate_effects(root["effect_guarantees"], "$.effect_guarantees")
    manifest = _load_source_manifest()
    bundle = _verify_source_membership(root, manifest)
    cli = _load_accepted_cli(root["accepted_cli_sha256"])

    receipts: dict[str, Any] = {}
    receipts["status"] = _execute_slot(cli, root["status"], "status", "$.status")
    route_receipts: list[dict[str, Any]] = []
    for index, (role_id, slot) in enumerate(zip(role_ids, routes_slots)):
        receipt = _execute_slot(cli, slot, "routes", f"$.routes_by_role[{index}]", role=True)
        if receipt.get("role_id") != role_id:
            raise SurfaceError("surface_role_binding_mismatch", f"$.routes_by_role[{index}].role_id")
        route_receipts.append(receipt)
    for slot_name, command in SLOT_COMMANDS.items():
        if slot_name != "status":
            receipts[slot_name] = _execute_slot(cli, root[slot_name], command, f"$.{slot_name}")
    receipts["routes_by_role"] = route_receipts

    reference_ids: list[str] | None = None
    reference_identity: dict[str, tuple[str, Any]] = {}
    for index, receipt in enumerate(route_receipts):
        rows = receipt.get("routes")
        if not isinstance(rows, list):
            raise SurfaceError("surface_receipt_shape_invalid", f"$.routes_by_role[{index}]")
        ids = [row.get("route_id") for row in rows if isinstance(row, dict)]
        if len(ids) != len(rows) or len(ids) != len(set(ids)):
            raise SurfaceError("surface_route_set_mismatch", f"$.routes_by_role[{index}]")
        if reference_ids is None:
            reference_ids = ids
            reference_identity = {row["route_id"]: (row.get("adapter_identity_sha256"), row.get("identity")) for row in rows}
        elif ids != reference_ids:
            raise SurfaceError("surface_route_set_mismatch", f"$.routes_by_role[{index}]")
        elif any(reference_identity[row["route_id"]] != (row.get("adapter_identity_sha256"), row.get("identity")) for row in rows):
            raise SurfaceError("surface_route_identity_mismatch", f"$.routes_by_role[{index}]")

    plan = receipts["plan"]
    plan_role = plan.get("role_id")
    if plan_role not in role_ids:
        raise SurfaceError("surface_plan_binding_mismatch", "$.plan")
    matching_index = role_ids.index(plan_role)
    route_request = routes_slots[matching_index]["request"]
    if root["plan"]["request"].get("input") != route_request.get("input"):
        raise SurfaceError("surface_plan_binding_mismatch", "$.plan.request.input")
    matching_routes = route_receipts[matching_index]
    if plan.get("routes") != matching_routes.get("routes"):
        raise SurfaceError("surface_plan_binding_mismatch", "$.plan")
    selected = plan.get("selected")
    selected_row = None if not isinstance(selected, dict) else next((row for row in plan["routes"] if row.get("route_id") == selected.get("route_id")), None)
    if selected_row is None or selected_row.get("eligible") is not True or selected_row.get("adapter_identity_sha256") != selected.get("adapter_identity_sha256"):
        raise SurfaceError("surface_plan_binding_mismatch", "$.plan.selected")

    evidence_inputs = [root[name]["request"]["input"] for name in ("delegate", "lineage", "journal")]
    if not (evidence_inputs[0] == evidence_inputs[1] == evidence_inputs[2]):
        raise SurfaceError("surface_evidence_source_mismatch", "$.delegate")
    evidence_sources = [receipts[name].get("source_sha256") for name in ("delegate", "lineage", "journal")]
    if len(set(evidence_sources)) != 1:
        raise SurfaceError("surface_evidence_source_mismatch", "$.delegate")
    evidence = cli._validate_evidence_source(copy.deepcopy(evidence_inputs[0]))
    bindings = evidence.get("bindings", {})
    planner_source = _planner_source(root["plan"]["request"])
    status_runtime = receipts["status"].get("runtime", {})
    if status_runtime.get("workspace_id") != planner_source.get("workspace_id") or status_runtime.get("workspace_id") != bindings.get("workspace_id"):
        raise SurfaceError("surface_workspace_mismatch")
    if plan.get("task_id") != bindings.get("task_id"):
        raise SurfaceError("surface_task_mismatch")
    run = receipts["run"].get("run", {})
    lineage = receipts["lineage"].get("lineage", {})
    journal = receipts["journal"].get("journal", {})
    if run.get("run_id") != bindings.get("run_id") or run.get("run_id") != lineage.get("current_run_id"):
        raise SurfaceError("surface_run_lineage_mismatch", "$.run")
    if lineage.get("root_run_id") != bindings.get("root_run_id"):
        raise SurfaceError("surface_run_lineage_mismatch", "$.lineage")
    run_bindings = run.get("bindings", {})
    for field in ("authority_sha256", "route_sha256", "policy_sha256", "source_sha256"):
        if run_bindings.get(field) != bindings.get(field):
            raise SurfaceError("surface_run_lineage_mismatch", f"$.run.{field}")
    if selected.get("route_id") != bindings.get("route_id") or selected_row.get("identity", {}).get("adapter_sha256") != bindings.get("adapter_sha256"):
        raise SurfaceError("surface_run_lineage_mismatch", "$.plan.selected")
    expected_journal = {
        "root_run_id": bindings.get("root_run_id"), "current_run_id": bindings.get("run_id"),
    }
    if any(field in journal and journal.get(field) != expected for field, expected in expected_journal.items()):
        raise SurfaceError("surface_run_lineage_mismatch", "$.journal")
    proposal = receipts["policy_proposal"].get("proposal", {})
    if proposal.get("base_policy_sha256") != bindings.get("policy_sha256"):
        raise SurfaceError("surface_policy_binding_mismatch", "$.policy_proposal")
    for field, expected in (("append_only", True), ("dry_run", True), ("policy_persisted", False), ("policy_activated", False), ("authority_granted", False), ("acceptance_granted", False)):
        if proposal.get(field) is not expected:
            raise SurfaceError("surface_policy_binding_mismatch", f"$.policy_proposal.{field}")
    expected_binding = digest({key: item for key, item in root.items() if key != "binding_sha256"})
    if root["binding_sha256"] != expected_binding:
        raise SurfaceError("surface_binding_digest_mismatch", "$.binding_sha256")
    return {"binding": root, "receipts": receipts, "evidence": evidence, "source_bundle": bundle}


def _derive_snapshot(validated: Mapping[str, Any]) -> dict[str, Any]:
    root, receipts, evidence = validated["binding"], validated["receipts"], validated["evidence"]
    status, plan, run = receipts["status"], receipts["plan"], receipts["run"]["run"]
    lineage, journal = receipts["lineage"]["lineage"], receipts["journal"]["journal"]
    bindings = evidence["bindings"]
    roles = [{"role_id": role_id, "label": role_id.replace("_", " ").title()} for role_id in root["role_ids"]]
    routes: list[dict[str, Any]] = []
    for route_index, route_id in enumerate(row["route_id"] for row in receipts["routes_by_role"][0]["routes"]):
        role_states = []
        identity = receipts["routes_by_role"][0]["routes"][route_index]["identity"]
        for role_id, role_receipt in zip(root["role_ids"], receipts["routes_by_role"]):
            row = role_receipt["routes"][route_index]
            role_states.append({
                "role_id": role_id, "eligible": row["eligible"], "hard_gates": [
                    {"code": gate["code"], "passed": gate["passed"], "plane": next(name for name, code in PLANE_GATES.items() if code == gate["code"])}
                    for gate in row["hard_gates"] if gate["code"] in PLANE_GATES.values()
                ], "blockers": row["eligibility_reasons"], "planes": copy.deepcopy(row["planes"]),
            })
        routes.append({
            "route_id": route_id, "label": route_id, "provider": identity["provider_id"],
            "runtime": f'{identity["runtime_id"]}@{identity["runtime_version"]}',
            "billing_basis": identity["billing_basis"], "role_states": role_states,
        })
    messages = []
    for message in journal["messages"]:
        messages.append({
            "message_id": message["message_id"], "type": message["message_type"],
            "sender_run_id": message["sender_run_id"], "content": json.dumps(message["content"], sort_keys=True, ensure_ascii=False),
            "artifact_refs": copy.deepcopy(message["artifact_refs"]), "created_at": message["created_at"],
            "expires_at": f'{message["created_at"]} + {message["ttl_seconds"]}s',
        })
    recalls = journal.get("recalls", [])
    recall = {
        "status": "active" if not recalls else "recalled", "subject_type": "journal",
        "subject_id": journal["journal_id"], "reason": "No recall event is active." if not recalls else recalls[-1]["reason"],
        "history_preserved": True, "provenance": receipts["journal"]["source_sha256"],
    }
    proposal = copy.deepcopy(receipts["policy_proposal"]["proposal"])
    proposal["applied"] = False
    return {
        "schema_version": 1, "artifact_type": SNAPSHOT_TYPE, "title": "Codexmax Standalone Runtime",
        "generated_at": status["runtime"]["evaluated_at"],
        "source_provenance": f'{ACCEPTED_CLI_SHA256} · {root["binding_sha256"]}',
        "roles": roles, "routes": routes,
        "status": {
            "runtime_id": status["runtime"]["runtime_manifest"]["runtime_id"],
            "runtime_version": status["runtime"]["runtime_manifest"]["runtime_version"],
            "health": status["status"]["health"]["status"],
            "lifecycle": copy.deepcopy(status["status"]["lifecycle"]),
            "endpoint": copy.deepcopy(status["status"]["endpoint"]),
        },
        "plan": {
            "workspace_id": bindings["workspace_id"], "workgraph_id": journal["journal_id"], "scope": journal["scope"],
            "role_id": plan["role_id"], "task_id": plan["task_id"], "selected_route_id": plan["selected"]["route_id"],
            "execution_started": False, "provider_called": False, "lease_created": False,
        },
        "run": {
            "run_id": run["run_id"], "lifecycle": run["lifecycle"], "terminal_outcome": run["terminal_outcome"],
            "events": [event["event_type"] for event in run["events"]],
            "receipts": [run["scheduler_receipt_sha256"], run["broker_receipt_sha256"]],
            "operation_performed": receipts["run"]["operation_preview"]["performed"],
        },
        "delegation": copy.deepcopy(receipts["delegate"]["delegation"]),
        "lineage": {**copy.deepcopy(lineage), "provenance": receipts["lineage"]["source_sha256"]},
        "journal": {
            "workspace_id": bindings["workspace_id"], "task_id": bindings["task_id"], "workgraph_id": journal["journal_id"],
            "scope": journal["scope"], "ttl_seconds": max((item["ttl_seconds"] for item in journal["messages"]), default=SOURCE_MAX_TTL_SECONDS),
            "trust": "untrusted_evidence", "provenance": receipts["journal"]["source_sha256"], "messages_executable": False,
            "disclosure_refs": copy.deepcopy(bindings["disclosure_refs"]), "recalled": bool(recalls), "messages": messages,
        },
        "recall": recall, "policy_proposal": proposal, "effect_guarantees": copy.deepcopy(EFFECT_GUARANTEES),
    }


def _validate_route_state(value: Any, path: str, role_ids: set[str], route_id: str) -> dict[str, Any]:
    row = _closed(value, {"role_id", "eligible", "hard_gates", "blockers", "planes"}, path)
    role_id = _identifier(row["role_id"], f"{path}.role_id")
    if role_id not in role_ids:
        raise SurfaceError("role_unknown", f"{path}.role_id")
    eligible = _boolean(row["eligible"], f"{path}.eligible")
    gates_raw = row["hard_gates"]
    if not isinstance(gates_raw, list) or not gates_raw:
        raise SurfaceError("gates_invalid", f"{path}.hard_gates")
    gates: dict[str, bool] = {}
    for index, raw in enumerate(gates_raw):
        gate = _closed(raw, {"code", "passed", "plane"}, f"{path}.hard_gates[{index}]")
        code = _identifier(gate["code"], f"{path}.hard_gates[{index}].code")
        plane = _identifier(gate["plane"], f"{path}.hard_gates[{index}].plane")
        if code in gates or plane not in PLANE_GATES or PLANE_GATES[plane] != code:
            raise SurfaceError("gates_invalid", f"{path}.hard_gates[{index}]")
        gates[code] = _boolean(gate["passed"], f"{path}.hard_gates[{index}].passed")
    if set(gates) != set(PLANE_GATES.values()):
        raise SurfaceError("gates_incomplete", f"{path}.hard_gates")
    derived = all(gates.values())
    blockers = _strings(row["blockers"], f"{path}.blockers", identifiers=True)
    expected_blockers = [gate["code"] for gate in gates_raw if not gate["passed"]] or ["eligible_all_hard_gates_passed"]
    if eligible is not derived or blockers != expected_blockers:
        raise SurfaceError("eligibility_contradiction", path)
    planes = _closed(row["planes"], set(PLANE_GATES) | {"capacity"}, f"{path}.planes")
    for plane, code in PLANE_GATES.items():
        plane_row = _closed(planes[plane], {"required_for_plan", "passed"}, f"{path}.planes.{plane}")
        if plane_row["required_for_plan"] is not True or plane_row["passed"] is not gates[code]:
            raise SurfaceError("plane_contradiction", f"{path}.planes.{plane}")
    capacity = _closed(planes["capacity"], {"required_for_plan", "status", "admitted"}, f"{path}.planes.capacity")
    if capacity != {"required_for_plan": False, "status": "not_admitted", "admitted": False}:
        raise SurfaceError("capacity_contradiction", f"{path}.planes.capacity")
    result = copy.deepcopy(row)
    result["route_id"] = route_id
    return result


def _validate_derived_snapshot(value: Any) -> dict[str, Any]:
    fields = {"schema_version", "artifact_type", "title", "generated_at", "source_provenance", "roles", "routes", "plan", "run", "lineage", "journal", "recall", "policy_proposal", "effect_guarantees"}
    root = _closed(copy.deepcopy(value), fields, "$")
    if root["schema_version"] != VERSION or root["artifact_type"] != SNAPSHOT_TYPE:
        raise SurfaceError("version_or_type_unsupported")
    _text(root["title"], "$.title")
    _text(root["source_provenance"], "$.source_provenance")
    generated_at = _timestamp(root["generated_at"], "$.generated_at")
    if not isinstance(root["roles"], list) or not root["roles"]:
        raise SurfaceError("roles_invalid", "$.roles")
    role_ids: set[str] = set()
    for index, raw in enumerate(root["roles"]):
        role = _closed(raw, {"role_id", "label"}, f"$.roles[{index}]")
        role_id = _identifier(role["role_id"], f"$.roles[{index}].role_id")
        _text(role["label"], f"$.roles[{index}].label")
        if role_id in role_ids:
            raise SurfaceError("role_duplicate", f"$.roles[{index}].role_id")
        role_ids.add(role_id)
    if not isinstance(root["routes"], list) or not root["routes"]:
        raise SurfaceError("routes_invalid", "$.routes")
    route_ids: set[str] = set()
    matrix: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(root["routes"]):
        path = f"$.routes[{index}]"
        route = _closed(raw, {"route_id", "label", "provider", "runtime", "billing_basis", "role_states"}, path)
        route_id = _identifier(route["route_id"], f"{path}.route_id")
        if route_id in route_ids:
            raise SurfaceError("route_duplicate", f"{path}.route_id")
        route_ids.add(route_id)
        for field in ("label", "provider", "runtime", "billing_basis"):
            _text(route[field], f"{path}.{field}")
        if not isinstance(route["role_states"], list) or len(route["role_states"]) != len(role_ids):
            raise SurfaceError("matrix_incomplete", f"{path}.role_states")
        seen: set[str] = set()
        for state_index, state in enumerate(route["role_states"]):
            normalized = _validate_route_state(state, f"{path}.role_states[{state_index}]", role_ids, route_id)
            if normalized["role_id"] in seen:
                raise SurfaceError("matrix_duplicate", f"{path}.role_states[{state_index}].role_id")
            seen.add(normalized["role_id"])
            matrix[(normalized["role_id"], route_id)] = normalized
        if seen != role_ids:
            raise SurfaceError("matrix_incomplete", f"{path}.role_states")
    plan = _closed(root["plan"], {"workspace_id", "workgraph_id", "scope", "role_id", "task_id", "selected_route_id", "execution_started", "provider_called", "lease_created"}, "$.plan")
    for field in ("workspace_id", "workgraph_id", "task_id"):
        _identifier(plan[field], f"$.plan.{field}")
    _text(plan["scope"], "$.plan.scope")
    role_id = _identifier(plan["role_id"], "$.plan.role_id")
    if role_id not in role_ids:
        raise SurfaceError("role_unknown", "$.plan.role_id")
    selected = plan["selected_route_id"]
    if selected is not None:
        _identifier(selected, "$.plan.selected_route_id")
        if selected not in route_ids or not matrix[(role_id, selected)]["eligible"]:
            raise SurfaceError("plan_selected_ineligible", "$.plan.selected_route_id")
    for field in ("execution_started", "provider_called", "lease_created"):
        if _boolean(plan[field], f"$.plan.{field}"):
            raise SurfaceError("plan_effect_claimed", f"$.plan.{field}")
    run = _closed(root["run"], {"run_id", "lifecycle", "terminal_outcome", "events", "receipts", "operation_performed"}, "$.run")
    _identifier(run["run_id"], "$.run.run_id")
    _identifier(run["lifecycle"], "$.run.lifecycle")
    if run["terminal_outcome"] is not None:
        _identifier(run["terminal_outcome"], "$.run.terminal_outcome")
    _strings(run["events"], "$.run.events")
    _strings(run["receipts"], "$.run.receipts")
    if _boolean(run["operation_performed"], "$.run.operation_performed"):
        raise SurfaceError("run_effect_claimed", "$.run.operation_performed")
    lineage = _closed(root["lineage"], {"root_run_id", "current_run_id", "parent_run_id", "depth", "ancestor_run_ids", "provenance"}, "$.lineage")
    for field in ("root_run_id", "current_run_id"):
        _identifier(lineage[field], f"$.lineage.{field}")
    if lineage["parent_run_id"] is not None:
        _identifier(lineage["parent_run_id"], "$.lineage.parent_run_id")
    if type(lineage["depth"]) is not int or lineage["depth"] < 0:
        raise SurfaceError("lineage_invalid", "$.lineage.depth")
    ancestors = _strings(lineage["ancestor_run_ids"], "$.lineage.ancestor_run_ids", identifiers=True)
    _text(lineage["provenance"], "$.lineage.provenance")
    if lineage["depth"] != len(ancestors) or lineage["current_run_id"] in ancestors:
        raise SurfaceError("lineage_invalid", "$.lineage")
    if lineage["depth"] == 0:
        if lineage["root_run_id"] != lineage["current_run_id"] or lineage["parent_run_id"] is not None or ancestors:
            raise SurfaceError("lineage_invalid", "$.lineage")
    elif not ancestors or ancestors[0] != lineage["root_run_id"] or ancestors[-1] != lineage["parent_run_id"]:
        raise SurfaceError("lineage_invalid", "$.lineage")
    accepted_lineage = {lineage["root_run_id"], lineage["current_run_id"], *ancestors}
    if lineage["parent_run_id"] is not None:
        accepted_lineage.add(lineage["parent_run_id"])
    if run["run_id"] not in accepted_lineage:
        raise SurfaceError("run_lineage_mismatch", "$.run.run_id")
    journal = _closed(root["journal"], {"workspace_id", "task_id", "workgraph_id", "scope", "ttl_seconds", "trust", "provenance", "messages_executable", "disclosure_refs", "recalled", "messages"}, "$.journal")
    for field in ("workspace_id", "task_id", "workgraph_id"):
        _identifier(journal[field], f"$.journal.{field}")
        if journal[field] != plan[field]:
            raise SurfaceError("journal_scope_mismatch", f"$.journal.{field}")
    _text(journal["scope"], "$.journal.scope")
    if journal["scope"] != plan["scope"]:
        raise SurfaceError("journal_scope_mismatch", "$.journal.scope")
    if type(journal["ttl_seconds"]) is not int or journal["ttl_seconds"] < 1:
        raise SurfaceError("journal_ttl_invalid", "$.journal.ttl_seconds")
    if journal["ttl_seconds"] > SOURCE_MAX_TTL_SECONDS:
        raise SurfaceError("journal_ttl_exceeded", "$.journal.ttl_seconds")
    if journal["trust"] != "untrusted_evidence" or _boolean(journal["messages_executable"], "$.journal.messages_executable"):
        raise SurfaceError("journal_executable", "$.journal")
    _text(journal["provenance"], "$.journal.provenance")
    disclosure = _strings(journal["disclosure_refs"], "$.journal.disclosure_refs")
    recalled = _boolean(journal["recalled"], "$.journal.recalled")
    if recalled:
        raise SurfaceError("recalled_journal_reopened", "$.journal.recalled")
    if not isinstance(journal["messages"], list):
        raise SurfaceError("journal_messages_invalid", "$.journal.messages")
    message_ids: set[str] = set()
    for index, raw in enumerate(journal["messages"]):
        message = _closed(raw, {"message_id", "type", "sender_run_id", "content", "artifact_refs", "created_at", "expires_at"}, f"$.journal.messages[{index}]")
        for field in ("message_id", "type", "sender_run_id"):
            _identifier(message[field], f"$.journal.messages[{index}].{field}")
        if message["message_id"] in message_ids:
            raise SurfaceError("journal_message_duplicate", f"$.journal.messages[{index}].message_id")
        message_ids.add(message["message_id"])
        if message["sender_run_id"] not in accepted_lineage:
            raise SurfaceError("journal_cross_lineage_forbidden", f"$.journal.messages[{index}].sender_run_id")
        _text(message["content"], f"$.journal.messages[{index}].content")
        refs = _strings(message["artifact_refs"], f"$.journal.messages[{index}].artifact_refs")
        if not set(refs) <= set(disclosure):
            raise SurfaceError("journal_disclosure_mismatch", f"$.journal.messages[{index}].artifact_refs")
        created_at = _timestamp(message["created_at"], f"$.journal.messages[{index}].created_at")
        expires_at = _timestamp(message["expires_at"], f"$.journal.messages[{index}].expires_at")
        if created_at > generated_at:
            raise SurfaceError("journal_message_from_future", f"$.journal.messages[{index}].created_at")
        if expires_at <= generated_at:
            raise SurfaceError("journal_message_expired", f"$.journal.messages[{index}].expires_at")
        if expires_at <= created_at:
            raise SurfaceError("journal_expiry_invalid", f"$.journal.messages[{index}].expires_at")
        elapsed_seconds = (expires_at - created_at).total_seconds()
        if elapsed_seconds > journal["ttl_seconds"]:
            raise SurfaceError("journal_ttl_exceeded", f"$.journal.messages[{index}].expires_at")
    recall = _closed(root["recall"], {"status", "subject_type", "subject_id", "reason", "history_preserved", "provenance"}, "$.recall")
    if recall["status"] not in {"active", "recalled"}:
        raise SurfaceError("recall_status_invalid", "$.recall.status")
    if recall["subject_type"] not in {"artifact", "journal", "message", "run"}:
        raise SurfaceError("recall_subject_type_invalid", "$.recall.subject_type")
    _identifier(recall["subject_id"], "$.recall.subject_id")
    _text(recall["reason"], "$.recall.reason")
    _text(recall["provenance"], "$.recall.provenance")
    if recall["history_preserved"] is not True:
        raise SurfaceError("recall_history_rewrite", "$.recall.history_preserved")
    allowed_recall_subjects = {
        "artifact": set(disclosure),
        "journal": {journal["workgraph_id"]},
        "message": message_ids,
        "run": accepted_lineage,
    }
    if recall["subject_id"] not in allowed_recall_subjects[recall["subject_type"]]:
        raise SurfaceError("recall_subject_unknown", "$.recall.subject_id")
    if recall["status"] == "recalled":
        recall_errors = {
            "artifact": ("recalled_artifact_disclosed", "$.journal.disclosure_refs"),
            "journal": ("recalled_journal_reopened", "$.journal"),
            "message": ("recalled_message_disclosed", "$.journal.messages"),
            "run": ("recalled_lineage_evidence_visible", "$.journal.messages"),
        }
        code, path = recall_errors[recall["subject_type"]]
        raise SurfaceError(code, path)
    proposal = _closed(root["policy_proposal"], {"artifact_type", "proposal_id", "validation", "explanation", "changes", "rollback", "append_only", "dry_run", "policy_persisted", "policy_activated", "applied"}, "$.policy_proposal")
    if proposal["artifact_type"] != "standalone_runtime_policy_proposal_v1":
        raise SurfaceError("proposal_type_invalid", "$.policy_proposal.artifact_type")
    _identifier(proposal["proposal_id"], "$.policy_proposal.proposal_id")
    validation = _closed(proposal["validation"], {"valid", "codes"}, "$.policy_proposal.validation")
    _boolean(validation["valid"], "$.policy_proposal.validation.valid")
    _strings(validation["codes"], "$.policy_proposal.validation.codes", identifiers=True)
    if validation != PROPOSAL_VALIDATION:
        raise SurfaceError("proposal_validation_invalid", "$.policy_proposal.validation")
    _text(proposal["explanation"], "$.policy_proposal.explanation")
    if not isinstance(proposal["changes"], list) or not proposal["changes"]:
        raise SurfaceError("proposal_changes_invalid", "$.policy_proposal.changes")
    change_paths: list[str] = []
    for index, change in enumerate(proposal["changes"]):
        change = _closed(change, {"op", "path", "before", "after"}, f"$.policy_proposal.changes[{index}]")
        if change["op"] not in {"add", "remove", "replace"} or not isinstance(change["path"], str) or not change["path"].startswith("/"):
            raise SurfaceError("proposal_changes_invalid", f"$.policy_proposal.changes[{index}]")
        change_paths.append(change["path"])
        consistent = (
            (change["op"] == "add" and change["before"] is None)
            or (change["op"] == "remove" and change["after"] is None)
            or (change["op"] == "replace" and canonical_json(change["before"]) != canonical_json(change["after"]))
        )
        if not consistent:
            raise SurfaceError("proposal_change_inconsistent", f"$.policy_proposal.changes[{index}]")
    if change_paths != sorted(change_paths) or len(change_paths) != len(set(change_paths)):
        raise SurfaceError("proposal_change_order_invalid", "$.policy_proposal.changes")
    rollback = _closed(proposal["rollback"], {"strategy", "reason", "history_rewritten"}, "$.policy_proposal.rollback")
    if rollback["strategy"] != "forward_proposal" or rollback["history_rewritten"] is not False:
        raise SurfaceError("proposal_rollback_invalid", "$.policy_proposal.rollback")
    _text(rollback["reason"], "$.policy_proposal.rollback.reason")
    for field, expected in (("append_only", True), ("dry_run", True), ("policy_persisted", False), ("policy_activated", False), ("applied", False)):
        if proposal[field] is not expected:
            raise SurfaceError("proposal_applied_confusion", f"$.policy_proposal.{field}")
    effects = _closed(root["effect_guarantees"], EFFECT_FIELDS, "$.effect_guarantees")
    if any(_boolean(effects[field], f"$.effect_guarantees.{field}") for field in sorted(EFFECT_FIELDS)):
        raise SurfaceError("effect_claimed", "$.effect_guarantees")
    return root


def validate_snapshot(value: Any) -> dict[str, Any]:
    """Validate one closed source binding and return its receipt-derived display model."""
    return _derive_snapshot(validate_binding(value))


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _badge(passed: bool, yes: str = "Pass", no: str = "Blocked") -> str:
    label = yes if passed else no
    kind = "pass" if passed else "blocked"
    return f'<span class="badge {kind}">{label}</span>'


def render_snapshot(value: Any) -> str:
    snapshot = validate_snapshot(value)
    roles = {role["role_id"]: role["label"] for role in snapshot["roles"]}
    rows: list[str] = []
    for route in snapshot["routes"]:
        for state in route["role_states"]:
            plane_cells = "".join(
                f'<td data-plane="{_e(plane)}">{_badge(state["planes"][plane]["passed"])}</td>'
                for plane in PLANE_GATES
            )
            capacity = state["planes"]["capacity"]
            blockers = ", ".join(state["blockers"])
            rows.append(
                f'<tr data-role="{_e(state["role_id"])}" data-route="{_e(route["route_id"])}">'
                f'<th scope="row">{_e(route["label"])}</th><td>{_e(roles[state["role_id"]])}</td>'
                f'<td>{_e(route["provider"])}</td><td>{_e(route["runtime"])}</td><td>{_e(route["billing_basis"])}</td>'
                f'<td>{_badge(state["eligible"], "Eligible", "Ineligible")}</td>{plane_cells}'
                f'<td><span class="badge neutral">{_e(capacity["status"])}</span></td>'
                f'<td><code>{_e(blockers)}</code></td></tr>'
            )
    role_options = "".join(f'<option value="{_e(role_id)}">{_e(label)}</option>' for role_id, label in roles.items())
    events = "".join(f"<li>{_e(item)}</li>" for item in snapshot["run"]["events"])
    receipts = "".join(f"<li><code>{_e(item)}</code></li>" for item in snapshot["run"]["receipts"])
    messages = "".join(
        f'<article class="message"><h3>{_e(item["type"])} · {_e(item["message_id"])}</h3>'
        f'<p>{_e(item["content"])}</p><dl><dt>Sender</dt><dd>{_e(item["sender_run_id"])}</dd>'
        f'<dt>Created</dt><dd>{_e(item["created_at"])}</dd><dt>Expires</dt><dd>{_e(item["expires_at"])}</dd><dt>Artifacts</dt><dd>{_e(", ".join(item["artifact_refs"]) or "none")}</dd></dl></article>'
        for item in snapshot["journal"]["messages"]
    ) or "<p>No messages.</p>"
    changes = "".join(f'<li><code>{_e(item["op"])} {_e(item["path"])}</code></li>' for item in snapshot["policy_proposal"]["changes"])
    source_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c")
    selected = snapshot["plan"]["selected_route_id"] or "none"
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(snapshot["title"])}</title><link rel="stylesheet" href="styles.css"></head>
<body><a class="skip-link" href="#main">Skip to content</a>
<header><p class="eyebrow">Synthetic local · no effects</p><h1>{_e(snapshot["title"])}</h1>
<p>Snapshot {_e(snapshot["generated_at"])} · provenance {_e(snapshot["source_provenance"])}. This surface displays validated evidence; it grants no authority or acceptance.</p></header>
<main id="main">
<section aria-labelledby="matrix-heading"><div class="section-heading"><div><p class="eyebrow">Routing truth</p><h2 id="matrix-heading">Complete role-route matrix</h2></div>
<label for="role-filter">Filter role <select id="role-filter"><option value="all">All roles</option>{role_options}</select></label></div>
<div class="table-wrap" tabindex="0" aria-label="Scrollable route matrix"><table><thead><tr><th>Route</th><th>Role</th><th>Provider</th><th>Runtime</th><th>Billing</th><th>Eligibility</th><th>Capability</th><th>Role policy</th><th>Task</th><th>Authority</th><th>Billing gate</th><th>Health</th><th>Capacity</th><th>Exact explanation</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></section>
<section class="grid" aria-label="Status, plan and run monitor"><article><p class="eyebrow">Runtime status</p><h2>{_e(snapshot["status"]["runtime_id"])}@{_e(snapshot["status"]["runtime_version"])}</h2><dl><dt>Health</dt><dd>{_e(snapshot["status"]["health"])}</dd><dt>Endpoint</dt><dd>{_e(snapshot["status"]["endpoint"]["kind"])} · {_e(snapshot["status"]["endpoint"]["address"])}</dd><dt>Bound</dt><dd>{"Yes" if snapshot["status"]["endpoint"]["bound"] else "No"}</dd></dl></article><article><p class="eyebrow">Plan preview</p><h2>Task {_e(snapshot["plan"]["task_id"])}</h2><dl><dt>Role</dt><dd>{_e(snapshot["plan"]["role_id"])}</dd><dt>Selected route</dt><dd>{_e(selected)}</dd><dt>Execution</dt><dd>Not started</dd><dt>Lease</dt><dd>Not created</dd><dt>Delegation</dt><dd>{_e(snapshot["delegation"]["admission_status"])}</dd><dt>Child launched</dt><dd>No</dd></dl></article>
<article><p class="eyebrow">Run monitor</p><h2>{_e(snapshot["run"]["run_id"])}</h2><dl><dt>Lifecycle</dt><dd>{_e(snapshot["run"]["lifecycle"])}</dd><dt>Terminal outcome</dt><dd>{_e(snapshot["run"]["terminal_outcome"] or "none")}</dd><dt>Operation performed</dt><dd>No</dd></dl><h3>Events</h3><ol>{events}</ol><h3>Receipts</h3><ul>{receipts}</ul></article></section>
<section class="grid" aria-label="Lineage and recall"><article><p class="eyebrow">Lineage</p><h2>{_e(snapshot["lineage"]["current_run_id"])}</h2><dl><dt>Root</dt><dd>{_e(snapshot["lineage"]["root_run_id"])}</dd><dt>Parent</dt><dd>{_e(snapshot["lineage"]["parent_run_id"] or "none")}</dd><dt>Depth</dt><dd>{_e(snapshot["lineage"]["depth"])}</dd><dt>Ancestors</dt><dd>{_e(", ".join(snapshot["lineage"]["ancestor_run_ids"]) or "none")}</dd><dt>Provenance</dt><dd>{_e(snapshot["lineage"]["provenance"])}</dd></dl></article>
<article><p class="eyebrow">Recall</p><h2>{_e(snapshot["recall"]["status"])}</h2><dl><dt>Subject</dt><dd>{_e(snapshot["recall"]["subject_type"])} · {_e(snapshot["recall"]["subject_id"])}</dd><dt>Reason</dt><dd>{_e(snapshot["recall"]["reason"])}</dd><dt>History preserved</dt><dd>Yes</dd><dt>Provenance</dt><dd>{_e(snapshot["recall"]["provenance"])}</dd></dl></article></section>
<section aria-labelledby="journal-heading"><p class="eyebrow">Scoped coordination</p><h2 id="journal-heading">Journal · untrusted evidence</h2><dl class="inline"><dt>Workspace</dt><dd>{_e(snapshot["journal"]["workspace_id"])}</dd><dt>Task</dt><dd>{_e(snapshot["journal"]["task_id"])}</dd><dt>Scope</dt><dd>{_e(snapshot["journal"]["scope"])}</dd><dt>TTL</dt><dd>{_e(snapshot["journal"]["ttl_seconds"])} seconds</dd><dt>Source maximum TTL</dt><dd>{SOURCE_MAX_TTL_SECONDS} seconds</dd><dt>Trust</dt><dd>{_e(snapshot["journal"]["trust"])}</dd><dt>Provenance</dt><dd>{_e(snapshot["journal"]["provenance"])}</dd><dt>Executable</dt><dd>No</dd><dt>Disclosure</dt><dd>{_e(", ".join(snapshot["journal"]["disclosure_refs"]) or "none")}</dd></dl><div class="messages">{messages}</div></section>
<section class="proposal" aria-labelledby="proposal-heading"><p class="eyebrow">Dry-run policy proposal</p><h2 id="proposal-heading">{_e(snapshot["policy_proposal"]["proposal_id"])} · Proposed, not applied</h2><p>{_e(snapshot["policy_proposal"]["explanation"])}</p><ul>{changes}</ul><dl><dt>Status</dt><dd>Validated proposal only</dd><dt>Validation codes</dt><dd>{_e(", ".join(snapshot["policy_proposal"]["validation"]["codes"]))}</dd><dt>Persisted</dt><dd>No</dd><dt>Activated</dt><dd>No</dd><dt>Rollback</dt><dd>{_e(snapshot["policy_proposal"]["rollback"]["strategy"])} · {_e(snapshot["policy_proposal"]["rollback"]["reason"])}</dd></dl></section>
<section class="safety" aria-labelledby="safety-heading"><h2 id="safety-heading">No-effect guarantees</h2><p>Server not started · network not used · provider not called · no lease or dispatch · no persistence · no authority · no acceptance.</p></section>
</main><script id="snapshot-data" type="application/json">{source_json}</script><script src="app.js" defer></script></body></html>'''


def _set_path(document: dict[str, Any], path: list[Any], value: Any) -> None:
    cursor: Any = document
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value


def _repair_case_binding(document: dict[str, Any], slots: Sequence[str]) -> None:
    """Case-runner helper: rehash caller JSON without importing or executing the CLI."""
    for name in slots:
        if name == "@binding":
            continue
        if name.startswith("routes_by_role."):
            index = int(name.rsplit(".", 1)[1])
            slot = document["routes_by_role"][index]
        else:
            slot = document[name]
        slot["request_sha256"] = digest(slot["request"])
    document["binding_sha256"] = digest({key: item for key, item in document.items() if key != "binding_sha256"})


def expand_v2_cases(document: Any) -> dict[str, Any]:
    """Expand the compact v2 adversary catalog over the fixed sibling v1 source family."""
    row = _closed(document, {"schema_version", "artifact_type", "adversarial"}, "$")
    if row["schema_version"] != 2 or row["artifact_type"] != CASES_V2_TYPE:
        raise SurfaceError("cases_version_or_type_unsupported")
    base = load_json(V1_CASES_PATH)
    valid = copy.deepcopy(base["valid"])
    valid["schema_version"] = 2
    valid["artifact_type"] = BINDING_TYPE
    valid["source_manifest_sha256"] = SOURCE_MANIFEST_SHA256
    valid["source_bundle_id"] = "source-local-fixture-20260806"
    valid["binding_sha256"] = digest({key: item for key, item in valid.items() if key != "binding_sha256"})
    return {"schema_version": 1, "artifact_type": CASES_TYPE, "valid": valid, "adversarial": copy.deepcopy(row["adversarial"])}


def run_cases(document: Any, source: Path | None = None) -> dict[str, Any]:
    if isinstance(document, dict) and document.get("artifact_type") == CASES_V2_TYPE:
        document = expand_v2_cases(document)
    row = _closed(document, {"schema_version", "artifact_type", "valid", "adversarial"}, "$")
    if row["schema_version"] != VERSION or row["artifact_type"] != CASES_TYPE:
        raise SurfaceError("cases_version_or_type_unsupported")
    valid_html = render_snapshot(row["valid"])
    if not isinstance(row["adversarial"], list):
        raise SurfaceError("array_required", "$.adversarial")
    results: list[dict[str, Any]] = []
    for index, raw in enumerate(row["adversarial"]):
        case_path = f"$.adversarial[{index}]"
        allowed_common = {"name", "expected_error", "repair_slots"}
        if isinstance(raw, dict) and set(raw) in ({"name", "path", "value", "expected_error"}, {"name", "path", "value", "expected_error", "repair_slots"}):
            case = _closed(raw, set(raw), case_path)
            mutations = [{"path": case["path"], "value": case["value"]}]
        elif isinstance(raw, dict) and set(raw) in ({"name", "mutations", "expected_error"}, {"name", "mutations", "expected_error", "repair_slots"}):
            case = _closed(raw, set(raw), case_path)
            if not isinstance(case["mutations"], list) or not case["mutations"]:
                raise SurfaceError("mutations_invalid", f"{case_path}.mutations")
            mutations = [
                _closed(item, {"path", "value"}, f"{case_path}.mutations[{mutation_index}]")
                for mutation_index, item in enumerate(case["mutations"])
            ]
        else:
            raise SurfaceError("case_fields_invalid", case_path)
        name = _identifier(case["name"], f"$.adversarial[{index}].name")
        mutated = copy.deepcopy(row["valid"])
        for mutation_index, mutation in enumerate(mutations):
            if not isinstance(mutation["path"], list) or not mutation["path"]:
                raise SurfaceError("path_invalid", f"{case_path}.mutations[{mutation_index}].path")
            _set_path(mutated, mutation["path"], copy.deepcopy(mutation["value"]))
        repair_slots = case.get("repair_slots", [])
        if not isinstance(repair_slots, list) or any(not isinstance(item, str) for item in repair_slots):
            raise SurfaceError("case_fields_invalid", f"{case_path}.repair_slots")
        if repair_slots:
            _repair_case_binding(mutated, repair_slots)
        try:
            render_snapshot(mutated)
            actual = None
        except SurfaceError as exc:
            actual = exc.code
        results.append({"name": name, "passed": actual == case["expected_error"], "error": actual})
    receipt = {
        "schema_version": VERSION,
        "artifact_type": RECEIPT_TYPE,
        "source": None if source is None else str(source),
        "binding_sha256": row["valid"].get("binding_sha256"),
        "valid_binding_document_sha256": digest(row["valid"]),
        "rendered_html_sha256": "sha256:" + hashlib.sha256(valid_html.encode("utf-8")).hexdigest(),
        "render_repeatable": valid_html == render_snapshot(row["valid"]),
        "total": len(results),
        "passed": sum(item["passed"] for item in results),
        "failed": sum(not item["passed"] for item in results),
        "results": results,
        "side_effect_free": True,
        "effect_guarantees": {field: False for field in sorted(EFFECT_FIELDS)},
    }
    receipt["receipt_sha256"] = digest(receipt)
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        document = load_json(args.input)
        result: str | dict[str, Any] = run_cases(document, args.input) if isinstance(document, dict) and document.get("artifact_type") in {CASES_TYPE, CASES_V2_TYPE} else render_snapshot(document)
    except SurfaceError as exc:
        print(json.dumps({"artifact_type": "standalone_operator_surface_error_v1", "code": exc.code, "path": exc.path, "side_effect_free": True}, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        return 2
    output = json.dumps(result, sort_keys=True, indent=2) if isinstance(result, dict) else result
    if args.output == "-":
        print(output)
    else:
        raise SurfaceError("output_persistence_forbidden", "--output")
    return 0 if not isinstance(result, dict) or result["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
