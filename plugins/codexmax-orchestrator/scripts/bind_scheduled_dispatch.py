#!/usr/bin/env python3
"""Bind one admitted scheduler lease to the strict run-one dispatcher input.

The bridge is deliberately non-executing.  It performs no provider, network,
authentication, installation, ledger, or evidence write.  Its only output is
the deterministic single-attempt lease binding accepted by
``run_headless_provider_dispatch.py run-one``.
"""

from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")

PLAN_FIELDS = {
    "schema_version", "artifact_type", "created_at", "envelope_sha256",
    "identity", "bindings", "ledger_head_before", "binding_sources",
    "ledger_sequence_before", "eligible_routes", "rejected_routes",
    "selected_route", "provider_call_started", "plan_sha256",
}
ADMISSION_FIELDS = PLAN_FIELDS | {
    "status", "lease", "reserved_usage", "observed_usage",
    "ledger_sequence_after", "ledger_head_after",
}
IDENTITY_FIELDS = {"goal_id", "checkpoint_id", "task_id", "assignment_id"}
BINDING_FIELDS = {
    "board_sha256", "config_sha256", "authority_sha256",
    "workgraph_sha256", "supervisor_sha256",
}
LEASE_FIELDS = {
    "lease_id", "fencing_token", "workgraph_claim_token",
    "workgraph_fencing_token", "granted_at", "expires_at", "writer",
    "artifact_only", "write_scopes", "artifact_scopes",
}
ENVELOPE_FIELDS = {
    "schema_version", "artifact_type", "envelope_id", "goal_id",
    "checkpoint_id", "task_id", "assignment_id", "bindings",
    "semantic_role", "task_class", "mutation_mode", "source", "scope",
    "commands", "consequence", "independence", "execution", "queue",
    "budget", "quality_policy", "context", "route_binding", "compiled_at", "provider_work",
}
RUN_ONE_BINDING_FIELDS = {
    "schema_version", "lease_id", "fencing_token", "attempt_id", "task_id",
    "assignment_id", "route_name", "envelope_sha256", "preflight_sha256",
    "authority_sha256", "effective_config_sha256", "evidence_directory",
    "expires_at", "execution_mode", "receiver_qualification_sha256",
}


def _load_sibling(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(f"codexmax_binding_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCHEDULER = _load_sibling("schedule_headless_dispatch")
RUNNER = _load_sibling("run_headless_provider_dispatch")
LEDGER = SCHEDULER.LEDGER


class BindingError(ValueError):
    """A fail-closed scheduler-to-dispatch binding rejection."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _strict(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise BindingError("shape_invalid", field)
    return value


def _text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str) or not value or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BindingError("identity_invalid", field)
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise BindingError("identity_invalid", field)
    return value


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise BindingError("digest_invalid", field)
    return value


def _raw_sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or RAW_SHA256.fullmatch(value) is None:
        raise BindingError("digest_invalid", field)
    return value


def _timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BindingError("timestamp_invalid", field)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BindingError("timestamp_invalid", field) from exc
    return parsed.astimezone(dt.timezone.utc)


def _same(value: Any, expected: Any, code: str, detail: str) -> None:
    if canonical_json(value) != canonical_json(expected):
        raise BindingError(code, detail)


def _validate_admission(value: Any, *, now: dt.datetime) -> dict[str, Any]:
    admission = copy.deepcopy(_strict(value, "admission", ADMISSION_FIELDS))
    if (
        admission["schema_version"] != SCHEMA_VERSION
        or admission["artifact_type"] != "DispatchSchedulePlan"
        or admission["status"] != "admitted"
        or admission["provider_call_started"] is not False
    ):
        raise BindingError("admission_invalid", "schema, status, or execution marker")

    created_at = _timestamp(admission["created_at"], "admission.created_at")
    if created_at > now:
        raise BindingError("admission_from_future", admission["created_at"])
    _sha(admission["envelope_sha256"], "admission.envelope_sha256")
    _sha(admission["plan_sha256"], "admission.plan_sha256")
    _raw_sha(admission["ledger_head_before"], "admission.ledger_head_before")
    _raw_sha(admission["ledger_head_after"], "admission.ledger_head_after")

    identity = _strict(admission["identity"], "admission.identity", IDENTITY_FIELDS)
    for field in IDENTITY_FIELDS:
        _text(identity[field], f"admission.identity.{field}")
    bindings = _strict(admission["bindings"], "admission.bindings", BINDING_FIELDS)
    for field in BINDING_FIELDS:
        _sha(bindings[field], f"admission.bindings.{field}")

    if not isinstance(admission["binding_sources"], dict) or set(
        admission["binding_sources"]
    ) != set(SCHEDULER.BINDING_NAMES):
        raise BindingError("admission_invalid", "binding_sources")
    for name in SCHEDULER.BINDING_NAMES:
        descriptor = _strict(
            admission["binding_sources"][name],
            f"admission.binding_sources.{name}",
            {"path", "sha256", "size_bytes"},
        )
        _text(descriptor["path"], f"admission.binding_sources.{name}.path")
        _sha(descriptor["sha256"], f"admission.binding_sources.{name}.sha256")
        if (
            not isinstance(descriptor["size_bytes"], int)
            or isinstance(descriptor["size_bytes"], bool)
            or descriptor["size_bytes"] < 0
        ):
            raise BindingError("admission_invalid", f"binding_sources.{name}.size_bytes")

    if (
        not isinstance(admission["eligible_routes"], list)
        or not admission["eligible_routes"]
        or any(not isinstance(name, str) or not name for name in admission["eligible_routes"])
        or len(set(admission["eligible_routes"])) != len(admission["eligible_routes"])
    ):
        raise BindingError("admission_invalid", "eligible_routes")
    if not isinstance(admission["rejected_routes"], list):
        raise BindingError("admission_invalid", "rejected_routes")
    rejected_names: set[str] = set()
    for index, row in enumerate(admission["rejected_routes"]):
        rejected = _strict(row, f"admission.rejected_routes[{index}]", {"name", "reason"})
        rejected_names.add(_text(rejected["name"], f"rejected_routes[{index}].name"))
        _text(rejected["reason"], f"rejected_routes[{index}].reason")

    try:
        selected = SCHEDULER.validate_route(copy.deepcopy(admission["selected_route"]))
    except Exception as exc:
        raise BindingError("selected_route_invalid", str(exc)) from exc
    if (
        admission["eligible_routes"].count(selected["name"]) != 1
        or selected["name"] in rejected_names
    ):
        raise BindingError("selected_route_mismatch", selected["name"])

    lease = _strict(admission["lease"], "admission.lease", LEASE_FIELDS)
    for field in ("lease_id", "workgraph_claim_token", "granted_at", "expires_at"):
        _text(lease[field], f"admission.lease.{field}")
    fence = _positive(lease["fencing_token"], "admission.lease.fencing_token")
    workgraph_fence = _positive(
        lease["workgraph_fencing_token"], "admission.lease.workgraph_fencing_token"
    )
    if fence != workgraph_fence:
        raise BindingError("lease_fencing_mismatch", "scheduler and WorkGraph fencing differ")
    if type(lease["writer"]) is not bool or type(lease["artifact_only"]) is not bool:
        raise BindingError("admission_invalid", "lease writer/artifact mode")
    for field in ("write_scopes", "artifact_scopes"):
        if (
            not isinstance(lease[field], list)
            or any(not isinstance(scope, str) or not scope for scope in lease[field])
            or lease[field] != sorted(set(lease[field]))
        ):
            raise BindingError("admission_invalid", f"lease.{field}")
    if lease["writer"] is False and lease["write_scopes"] != []:
        raise BindingError("scope_drift", "non-writer lease.write_scopes must remain empty")
    granted_at = _timestamp(lease["granted_at"], "admission.lease.granted_at")
    expires_at = _timestamp(lease["expires_at"], "admission.lease.expires_at")
    if granted_at != created_at or expires_at <= granted_at:
        raise BindingError("lease_window_invalid", lease["lease_id"])

    before = admission["ledger_sequence_before"]
    after = admission["ledger_sequence_after"]
    if (
        not isinstance(before, int) or isinstance(before, bool) or before < 0
        or not isinstance(after, int) or isinstance(after, bool) or after != before + 1
    ):
        raise BindingError("admission_ledger_range_mismatch")
    _strict(admission["reserved_usage"], "admission.reserved_usage", {
        "allowance_class", "allowance_units_reserved", "token_reservation",
        "observed_tokens", "observed_cost",
    })
    observed = _strict(
        admission["observed_usage"], "admission.observed_usage", {"tokens", "cost"}
    )
    if observed != {"tokens": "unknown", "cost": "unknown"}:
        raise BindingError("unknown_accounting_erased", "admission.observed_usage")

    plan_payload = {
        field: copy.deepcopy(admission[field])
        for field in PLAN_FIELDS - {"plan_sha256"}
    }
    if digest(plan_payload) != admission["plan_sha256"]:
        raise BindingError("admission_plan_digest_mismatch")
    return admission


def _validate_envelope(
    value: Any, admission: dict[str, Any], selected: dict[str, Any], *, now_text: str
) -> dict[str, Any]:
    fields = (
        ENVELOPE_FIELDS
        if isinstance(value, dict) and "provider_work" in value
        else ENVELOPE_FIELDS - {"provider_work"}
    )
    envelope = copy.deepcopy(_strict(value, "task_envelope", fields))
    try:
        SCHEDULER._validate_envelope(envelope, admission["bindings"], now_text)
    except Exception as exc:
        raise BindingError("envelope_invalid", str(exc)) from exc

    # Enforce the compiled envelope's exact nested v1 shape even though the
    # context pack is not an input to this post-admission bridge.
    nested_shapes = {
        "bindings": BINDING_FIELDS,
        "source": {"source_mode", "input_mode", "inputs"},
        "scope": {"requested_read", "requested_write", "authority_read", "authority_write"},
        "independence": {"required", "group", "exclusions"},
        "execution": {"idempotent", "cancellable", "hedge_requested"},
        "queue": {"enqueued_at", "deadline", "max_queue_age_seconds", "priority"},
        "budget": {"token_limit", "allowance_class", "external_cash_authorized", "accounting"},
        "quality_policy": {"policy_id", "artifact_format", "min_bytes", "max_bytes", "required_sections"},
        "context": {"context_pack_id", "context_pack_sha256"},
        "route_binding": {"provider", "model", "reasoning"},
    }
    for field, keys in nested_shapes.items():
        _strict(envelope[field], f"task_envelope.{field}", keys)
    _strict(envelope["budget"]["accounting"], "task_envelope.budget.accounting", {"tokens", "cost"})
    for field in ("tokens", "cost"):
        _strict(
            envelope["budget"]["accounting"][field],
            f"task_envelope.budget.accounting.{field}",
            {"value", "reason"},
        )
    if not isinstance(envelope["commands"], list):
        raise BindingError("envelope_invalid", "commands")
    for index, command in enumerate(envelope["commands"]):
        _strict(command, f"task_envelope.commands[{index}]", {"command_id", "argv", "cwd"})

    if digest(envelope) != admission["envelope_sha256"]:
        raise BindingError("envelope_digest_mismatch")
    _same(envelope["bindings"], admission["bindings"], "binding_mismatch", "envelope")
    expected_identity = {
        field: envelope[field] for field in IDENTITY_FIELDS
    }
    _same(admission["identity"], expected_identity, "identity_mismatch", "envelope/admission")

    route_binding = envelope["route_binding"]
    expected_route_binding = {
        "provider": selected["provider"],
        "model": selected["exact_model"],
        "reasoning": selected["reasoning"],
    }
    _same(route_binding, expected_route_binding, "route_mismatch", "envelope.route_binding")
    expected_artifact_only = envelope["mutation_mode"] == "artifact_only"
    expected_writer = envelope["mutation_mode"] == "scoped_write"
    if admission["lease"]["writer"] is not expected_writer:
        raise BindingError("scope_drift", "lease.writer")
    if admission["lease"]["artifact_only"] is not expected_artifact_only:
        raise BindingError("scope_drift", "lease.artifact_only")
    expected_write_scopes = (
        sorted(SCHEDULER._normalize_scope(path) for path in envelope["scope"]["requested_write"])
        if expected_writer else []
    )
    if admission["lease"]["write_scopes"] != expected_write_scopes:
        raise BindingError("scope_drift", "lease.write_scopes")
    expected_scopes = sorted(
        SCHEDULER._normalize_scope(scope)
        for scope in envelope["scope"]["requested_write"]
    )
    if admission["lease"]["artifact_scopes"] != expected_scopes:
        raise BindingError("scope_drift", "lease.artifact_scopes")
    return envelope


def _validate_assignment(
    value: Any, root: Path, envelope: dict[str, Any], selected: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BindingError("assignment_invalid", "assignment must be an object")
    try:
        assignment = RUNNER._require_assignment(copy.deepcopy(value), root)
    except Exception as exc:
        raise BindingError("assignment_invalid", str(exc)) from exc

    evidence_directory = root / assignment["evidence_directory"]
    if evidence_directory.exists() or evidence_directory.is_symlink():
        raise BindingError(
            "evidence_collision",
            "assignment evidence_directory is single-use and must be absent at binding",
        )

    checks = {
        "supervisor_assignment_id": envelope["assignment_id"],
        "semantic_role": envelope["semantic_role"],
    }
    for field, expected in checks.items():
        if assignment[field] != expected:
            raise BindingError("assignment_mismatch", field)
    if assignment["route_packet"].get("task_id") != envelope["task_id"]:
        raise BindingError("task_drift", "assignment.route_packet.task_id")
    if assignment["expected_artifact"] != selected["evidence_path"]:
        raise BindingError("evidence_mismatch", "assignment.expected_artifact")
    if envelope["mutation_mode"] == "artifact_only":
        artifact = assignment["expected_artifact"]
        for field in ("requested_write", "authority_write"):
            if not RUNNER._scope_allows(artifact, envelope["scope"][field]):
                raise BindingError("scope_drift", f"expected_artifact outside {field}")
    return assignment


def _verify_binding_sources(root: Path, admission: dict[str, Any]) -> None:
    descriptors = {
        name: {
            "path": admission["binding_sources"][name]["path"],
            "sha256": admission["binding_sources"][name]["sha256"],
        }
        for name in SCHEDULER.BINDING_NAMES
    }
    try:
        current = SCHEDULER.verify_binding_sources(
            root, descriptors, admission["bindings"]
        )
    except Exception as exc:
        raise BindingError("binding_source_drift", str(exc)) from exc
    _same(
        current, admission["binding_sources"],
        "binding_source_drift", "descriptor identity",
    )


def _verify_config_source(
    root: Path, admission: dict[str, Any], workspace_config: Path | None
) -> None:
    bound = admission["binding_sources"]["config"]["path"]
    active_paths: list[Path] = []
    if workspace_config is not None:
        try:
            active_paths.append(workspace_config.resolve(strict=True))
        except OSError as exc:
            raise BindingError("config_drift", "workspace config unavailable") from exc
    repository_config = root / "codexmax.config.yaml"
    if repository_config.exists() or repository_config.is_symlink():
        try:
            resolved = repository_config.resolve(strict=True)
        except OSError as exc:
            raise BindingError("config_drift", "repository config unavailable") from exc
        if resolved not in active_paths:
            active_paths.append(resolved)
    if not active_paths:
        return
    if len(active_paths) != 1:
        raise BindingError(
            "config_binding_ambiguous",
            "one config digest cannot identify multiple active config files",
        )
    try:
        relative = active_paths[0].relative_to(root).as_posix()
    except ValueError as exc:
        raise BindingError("config_drift", "active config is outside repository") from exc
    if bound != relative:
        raise BindingError("config_drift", "bound config path is not the active config")


def _route_event(selected: dict[str, Any]) -> dict[str, Any]:
    return {
        "route_name": selected["name"],
        "provider": selected["provider"],
        "exact_model": selected["exact_model"],
        "route_id": selected["route_id"],
        "runtime": selected["runtime"],
        "runtime_host": selected["runtime_host"],
        "reasoning": selected["reasoning"],
        "independence_group": selected["independence_group"],
        "preflight_key_sha256": selected["preflight_key_sha256"],
        "preflight_receipt_digest": selected["preflight_observation"].get("receipt_digest"),
    }


def _expected_grant_event(
    admission: dict[str, Any], envelope: dict[str, Any], selected: dict[str, Any]
) -> dict[str, Any]:
    evidence = {
        "output_path": selected["evidence_path"],
        "idempotency_key": envelope["envelope_id"],
        "authority_sha256": admission["bindings"]["authority_sha256"],
        "workgraph_sha256": admission["bindings"]["workgraph_sha256"],
        "supervisor_sha256": admission["bindings"]["supervisor_sha256"],
        "plan_sha256": admission["plan_sha256"],
    }
    try:
        return SCHEDULER._event(
            envelope, admission["bindings"], "lease_granted",
            admission["created_at"], route=_route_event(selected),
            lease=copy.deepcopy(admission["lease"]),
            accounting=copy.deepcopy(admission["reserved_usage"]),
            evidence=evidence,
        )
    except Exception as exc:
        raise BindingError("admission_ledger_row_mismatch", str(exc)) from exc


def _validate_ledger(
    verified: dict[str, Any], admission: dict[str, Any], envelope: dict[str, Any],
    selected: dict[str, Any], *, now: dt.datetime,
) -> None:
    before = admission["ledger_sequence_before"]
    after = admission["ledger_sequence_after"]
    if after > verified["event_count"]:
        raise BindingError("admission_ledger_range_mismatch")
    row = verified["rows"][after - 1]
    expected_before = LEDGER.ZERO_HASH if before == 0 else verified["rows"][before - 1]["event_hash"]
    if admission["ledger_head_before"] != expected_before:
        raise BindingError("admission_ledger_head_mismatch", "head_before")
    if admission["ledger_head_after"] != row["event_hash"]:
        raise BindingError("admission_ledger_head_mismatch", "head_after")
    if row["previous_event_hash"] != expected_before or row["sequence"] != after:
        raise BindingError("admission_ledger_range_mismatch")
    expected_event = _expected_grant_event(admission, envelope, selected)
    actual_event = {field: copy.deepcopy(row[field]) for field in LEDGER.EVENT_FIELDS}
    _same(actual_event, expected_event, "admission_ledger_row_mismatch", "lease_granted")

    lease_id = admission["lease"]["lease_id"]
    grant_rows = [
        candidate for candidate in verified["rows"]
        if candidate["event_type"] == "lease_granted"
        and candidate["lease"].get("lease_id") == lease_id
    ]
    if len(grant_rows) != 1 or grant_rows[0]["sequence"] != after:
        raise BindingError("lease_not_active", lease_id)

    later_for_lease = [
        candidate for candidate in verified["rows"][after:]
        if candidate["lease"].get("lease_id") == lease_id
    ]
    terminal_codes = {
        "lease_released": "lease_released",
        "lease_expired": "lease_expired",
        "lease_recovered": "lease_recovered",
        "execution_unknown": "lease_execution_unknown",
        "dispatch_started": "lease_already_started",
        "dispatch_finished": "lease_already_started",
    }
    if later_for_lease:
        latest = later_for_lease[-1]
        raise BindingError(
            terminal_codes.get(latest["event_type"], "lease_state_unknown"),
            latest["event_type"],
        )

    replayed = LEDGER.replay(verified)
    active = replayed["active_leases"].get(lease_id)
    if not isinstance(active, dict) or active.get("event_hash") != row["event_hash"]:
        raise BindingError("lease_not_active", lease_id)

    current_fence = admission["lease"]["fencing_token"]
    for candidate in verified["rows"][after:]:
        if candidate["task_id"] != envelope["task_id"]:
            continue
        candidate_fence = candidate["lease"].get("fencing_token")
        if (
            candidate["event_type"] == "lease_granted"
            or isinstance(candidate_fence, int) and candidate_fence > current_fence
        ):
            raise BindingError("lease_superseded", str(candidate.get("sequence")))
        if candidate["event_type"] == "execution_unknown":
            raise BindingError("lease_execution_unknown", str(candidate.get("sequence")))

    granted_at = _timestamp(admission["lease"]["granted_at"], "lease.granted_at")
    expires_at = _timestamp(admission["lease"]["expires_at"], "lease.expires_at")
    if now < granted_at:
        raise BindingError("lease_from_future", lease_id)
    if now >= expires_at:
        raise BindingError("lease_expired", lease_id)


def _preflight_is_current(value: Any, *, now: dt.datetime, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BindingError("preflight_drift", field)
    if value.get("fresh") is not True:
        raise BindingError("preflight_stale", field)
    observed = _timestamp(value.get("observed_at"), f"{field}.observed_at")
    expires = _timestamp(value.get("expires_at"), f"{field}.expires_at")
    if observed > now:
        raise BindingError("preflight_from_future", field)
    if expires <= now:
        raise BindingError("preflight_expired", field)
    return value


def _validate_current_packet(
    assignment: dict[str, Any], envelope: dict[str, Any], admission: dict[str, Any],
    selected: dict[str, Any], effective: dict[str, Any], *, now: dt.datetime,
) -> tuple[dict[str, Any], str]:
    route_name = selected["name"]
    try:
        current = RUNNER._prepare_packet(
            assignment, effective, scheduler_mode=True, scheduler_route=route_name
        )
    except Exception as exc:
        raise BindingError("config_drift", str(exc)) from exc

    admitted = selected["resolver_packet"]
    admitted_digest = selected["resolver_packet_sha256"]
    if digest(admitted) != admitted_digest:
        raise BindingError("packet_digest_mismatch", "admitted resolver packet")
    if digest(current) != admitted_digest or canonical_json(current) != canonical_json(admitted):
        if current.get("registry") != admitted.get("registry") or current.get("profile") != admitted.get("profile"):
            raise BindingError("config_drift", "scheduler-mode registry or profile")
        if current.get("preflights") != admitted.get("preflights"):
            raise BindingError("preflight_drift", "assignment/admission")
        raise BindingError("packet_drift", "assignment/admission")

    expected_role = RUNNER.SEMANTIC_TO_RESOLVER_ROLE[envelope["semantic_role"]]
    exact = {
        "task_id": envelope["task_id"],
        "role": expected_role,
        "resolution_phase": "pre_dispatch",
        "resolution_time": admission["created_at"],
        "token_limit": envelope["budget"]["token_limit"],
        "read_scope": sorted(envelope["scope"]["requested_read"]),
        "write_scope": sorted(envelope["scope"]["requested_write"]),
        "authority_scope": sorted(
            set(envelope["scope"]["authority_read"])
            | set(envelope["scope"]["authority_write"])
        ),
        "consequence_floor": envelope["consequence"],
        "independence_required": envelope["independence"]["required"],
        "independence_exclusions": sorted(envelope["independence"]["exclusions"]),
    }
    for field, expected in exact.items():
        if current.get(field) != expected:
            code = "scope_drift" if field.endswith("_scope") else "task_drift"
            raise BindingError(code, f"route_packet.{field}")
    if current.get("attempt_results") != {}:
        raise BindingError("packet_drift", "attempt_results must be empty")
    if set(current.get("preflights", {})) != {route_name}:
        raise BindingError("preflight_drift", "exactly one admitted route required")
    try:
        ordered = SCHEDULER.RESOLVER._ordered_profile_routes(
            current["registry"], current["profile"]
        )
    except Exception as exc:
        raise BindingError("config_drift", str(exc)) from exc
    if ordered != [route_name]:
        raise BindingError("config_drift", "selected route is not the only profile route")

    preflight = _preflight_is_current(
        current["preflights"][route_name], now=now, field="resolver_preflight"
    )
    broker_observation = selected["preflight_observation"]
    broker_observed = _timestamp(
        broker_observation.get("observed_at"), "broker_preflight.observed_at"
    )
    broker_expires = _timestamp(
        broker_observation.get("expires_at"), "broker_preflight.expires_at"
    )
    if broker_observed > now:
        raise BindingError("preflight_from_future", "broker_preflight")
    if broker_expires <= now:
        raise BindingError("preflight_expired", "broker_preflight")

    eligible, reason = SCHEDULER._verify_task_bound_resolver(
        selected, envelope, admission["created_at"]
    )
    if not eligible:
        raise BindingError("packet_drift", reason)
    try:
        resolution = RUNNER._resolve_pre_dispatch(current)
    except Exception as exc:
        raise BindingError("packet_drift", str(exc)) from exc
    next_attempt = resolution.get("next_attempt")
    if (
        resolution.get("status") != "dispatch_required"
        or resolution.get("stop_reason") != "dispatch_required"
        or not isinstance(next_attempt, dict)
        or next_attempt.get("route_name") != route_name
    ):
        raise BindingError("route_not_currently_eligible", str(resolution.get("stop_reason")))
    expected_identity = {
        "route_name": route_name,
        "provider": selected["provider"],
        "model": selected["exact_model"],
        "route": selected["route_id"],
        "runtime": selected["runtime"],
        "reasoning": selected["reasoning"],
        "billing": selected["billing_basis"],
    }
    identity = next_attempt.get("identity", {})
    if any(identity.get(field) != expected for field, expected in expected_identity.items()):
        raise BindingError("route_mismatch", "resolver next_attempt identity")
    return current, digest(preflight)


def _verify_current_broker_binding(
    selected: dict[str, Any], root: Path, *, now_text: str
) -> None:
    try:
        current, reason = SCHEDULER._verify_broker_binding(
            selected, root, now_text
        )
    except Exception as exc:
        raise BindingError("preflight_drift", str(exc)) from exc
    if not current:
        raise BindingError("preflight_drift", reason)


def _attempt_id(binding_without_attempt: dict[str, Any], admission: dict[str, Any]) -> str:
    seed = {
        "artifact_type": "DispatchExecutionAttemptIdentity",
        "binding": copy.deepcopy(binding_without_attempt),
        "schedule_plan_sha256": admission["plan_sha256"],
        "ledger_sequence": admission["ledger_sequence_after"],
        "ledger_head": admission["ledger_head_after"],
    }
    return "attempt-" + hashlib.sha256(canonical_json(seed)).hexdigest()


def _read_ledger_locked(path: Path, root: Path) -> dict[str, Any]:
    safe = RUNNER._regular_single_link(
        path, root, "ledger", max_bytes=MAX_LEDGER_BYTES
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(safe, flags)
    try:
        before = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_LEDGER_BYTES:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_LEDGER_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        current = os.lstat(safe)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_LEDGER_BYTES:
        raise BindingError("ledger_too_large")
    identity = lambda info: (
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink
    )
    if (
        identity(before) != identity(after) or identity(after) != identity(current)
        or not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
    ):
        raise BindingError("ledger_changed")
    if raw and not raw.endswith(b"\n"):
        raise BindingError("ledger_truncated", "missing terminal newline")
    try:
        lines = bytes(raw).decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise BindingError("ledger_invalid_utf8") from exc
    try:
        return LEDGER.verify_lines(lines)
    except Exception as exc:
        raise BindingError("ledger_invalid", str(exc)) from exc


@contextmanager
def _locked_ledger_snapshot(path: Path, root: Path) -> Iterator[dict[str, Any]]:
    scheduler_lock = path.with_name(path.name + ".scheduler.lock")
    ledger_lock = path.with_name(path.name + ".lock")
    try:
        safe_scheduler = RUNNER._regular_single_link(
            scheduler_lock, root, "scheduler_lock"
        )
        safe_ledger = RUNNER._regular_single_link(ledger_lock, root, "ledger_lock")
    except Exception as exc:
        raise BindingError("ledger_lock_unavailable", str(exc)) from exc
    scheduler_fd = os.open(
        safe_scheduler,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    ledger_fd = os.open(
        safe_ledger,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        fcntl.flock(scheduler_fd, fcntl.LOCK_SH)
        fcntl.flock(ledger_fd, fcntl.LOCK_SH)
        yield _read_ledger_locked(path, root)
    finally:
        fcntl.flock(ledger_fd, fcntl.LOCK_UN)
        fcntl.flock(scheduler_fd, fcntl.LOCK_UN)
        os.close(ledger_fd)
        os.close(scheduler_fd)


def bind_scheduled_dispatch(
    *, admission: dict[str, Any], task_envelope: dict[str, Any],
    assignment: dict[str, Any], repo_root: Path, ledger_path: Path,
    now: str, workspace_config: Path | None = None,
) -> dict[str, Any]:
    """Return the exact run-one binding for one still-current admission."""
    try:
        root = RUNNER._canonical_repo_root(repo_root)
    except Exception as exc:
        raise BindingError("unsafe_repo_root", str(exc)) from exc
    instant = _timestamp(now, "now")
    admitted = _validate_admission(admission, now=instant)
    selected = admitted["selected_route"]
    envelope = _validate_envelope(
        task_envelope, admitted, selected, now_text=now
    )
    strict_assignment = _validate_assignment(
        assignment, root, envelope, selected
    )

    with _locked_ledger_snapshot(ledger_path, root) as verified:
        _validate_ledger(
            verified, admitted, envelope, selected, now=instant
        )
        _verify_binding_sources(root, admitted)
        _verify_config_source(root, admitted, workspace_config)
        _verify_current_broker_binding(selected, root, now_text=now)
        try:
            effective = RUNNER._effective_config(root, workspace_config)
        except Exception as exc:
            raise BindingError("config_drift", str(exc)) from exc
        _, preflight_sha256 = _validate_current_packet(
            strict_assignment, envelope, admitted, selected, effective, now=instant
        )
        receiver_qualification_sha256 = None
        provider_work = envelope.get("provider_work")
        if isinstance(provider_work, dict):
            selected_identity = {
                "provider": selected["provider"], "model": selected["exact_model"],
                "route": selected["route_id"], "runtime": selected["runtime"],
                "billing": selected["billing_basis"],
            }
            try:
                RUNNER._resolved_execution_profile(
                    task_envelope=envelope, route_name=selected["name"],
                    identity=selected_identity,
                )
            except Exception as exc:
                raise BindingError("provider_execution_profile_invalid", str(exc)) from exc
        if envelope["mutation_mode"] == "scoped_write":
            try:
                card = RUNNER._provider_work.validate_capability_card(
                    envelope["provider_work"]["capability_card"]
                )
                grant = RUNNER._provider_work.validate_task_grant(
                    envelope["provider_work"]["task_grant"]
                )
            except Exception as exc:
                raise BindingError("provider_work_invalid", str(exc)) from exc
            current_preflight = selected["resolver_packet"]["preflights"][selected["name"]]
            if current_preflight.get("capability_evidence") != card["qualification_sha256"]:
                raise BindingError("receiver_qualification_mismatch", selected["name"])
            if envelope["bindings"]["authority_sha256"] != grant["grant_sha256"]:
                raise BindingError("grant_authority_mismatch", envelope["task_id"])
            receiver_qualification_sha256 = card["qualification_sha256"]

        base = {
            "schema_version": SCHEMA_VERSION,
            "lease_id": admitted["lease"]["lease_id"],
            "fencing_token": admitted["lease"]["fencing_token"],
            "task_id": envelope["task_id"],
            "assignment_id": strict_assignment["supervisor_assignment_id"],
            "route_name": selected["name"],
            "envelope_sha256": digest(envelope),
            "preflight_sha256": preflight_sha256,
            "receiver_qualification_sha256": receiver_qualification_sha256,
            "authority_sha256": digest(strict_assignment["authority"]),
            "effective_config_sha256": digest(effective),
            "evidence_directory": strict_assignment["evidence_directory"],
            "expires_at": admitted["lease"]["expires_at"],
            "execution_mode": "single_resolved_attempt",
        }
        result = {
            **base,
            "attempt_id": _attempt_id(base, admitted),
        }
        if set(result) != RUN_ONE_BINDING_FIELDS:
            raise BindingError("binding_internal_error", "unexpected output shape")
        return result


def _read_input(path: Path, root: Path, field: str) -> dict[str, Any]:
    try:
        return RUNNER._read_json_file(
            path, root, field, max_bytes=MAX_INPUT_BYTES
        )
    except Exception as exc:
        raise BindingError("input_invalid", f"{field}: {exc}") from exc


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--admission", type=Path, required=True)
    command.add_argument("--task-envelope", type=Path, required=True)
    command.add_argument("--assignment", type=Path, required=True)
    command.add_argument("--repo-root", type=Path, required=True)
    command.add_argument("--ledger", type=Path, required=True)
    command.add_argument("--workspace-config", type=Path)
    command.add_argument("--now", required=True, help="injected ISO-8601 UTC time")
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        root = RUNNER._canonical_repo_root(args.repo_root)
        result = bind_scheduled_dispatch(
            admission=_read_input(args.admission, root, "admission"),
            task_envelope=_read_input(args.task_envelope, root, "task_envelope"),
            assignment=_read_input(args.assignment, root, "assignment"),
            repo_root=root,
            ledger_path=args.ledger,
            workspace_config=args.workspace_config,
            now=args.now,
        )
    except BindingError as exc:
        print(json.dumps({
            "status": "rejected", "error": exc.code, "detail": exc.detail,
            "provider_call_started": False, "writes_performed": False,
        }, sort_keys=True), file=sys.stderr)
        return 2
    except Exception as exc:
        code = getattr(exc, "code", "binding_error")
        detail = getattr(exc, "detail", str(exc))
        print(json.dumps({
            "status": "rejected", "error": code, "detail": detail,
            "provider_call_started": False, "writes_performed": False,
        }, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
