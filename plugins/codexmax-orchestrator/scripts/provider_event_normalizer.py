#!/usr/bin/env python3
"""Normalize provider observations without granting execution authority."""

from __future__ import annotations

import copy
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Mapping


SCHEMA_VERSION = 1
ARTIFACT_TYPE = "ProviderNormalizedEventV1"
EVENT_TYPES = (
    "admission_observed",
    "binding_observed",
    "spawn_observed",
    "response_observed",
    "tool_request_observed",
    "tool_result_observed",
    "artifact_validation_observed",
    "mutation_reconciliation_observed",
    "receipt_finalization_observed",
    "attempt_terminal_observed",
)
EVENT_INDEX = {name: index for index, name in enumerate(EVENT_TYPES)}
TERMINAL_STATES = {"succeeded", "rejected", "execution_unknown"}
MUTATION_STATES = {"none", "possible", "confirmed", "reconciled", "unknown"}
MUTATION_MODES = {"read_only", "artifact_only", "scoped_write"}
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+~-]{0,255}$")


class NormalizationError(ValueError):
    def __init__(self, code: str, path: str = "") -> None:
        super().__init__(f"{code}: {path}" if path else code)
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NormalizationError("closed_object_invalid", path)
    return copy.deepcopy(dict(value))


def _text(value: Any, path: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or (identifier and not IDENTIFIER.fullmatch(value)):
        raise NormalizationError("text_invalid", path)
    return value


def _sha(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise NormalizationError("digest_invalid", path)
    return value


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise NormalizationError("timestamp_invalid", path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise NormalizationError("timestamp_invalid", path) from exc
    return parsed


def _string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or len(value) != len(set(value)):
        raise NormalizationError("string_list_invalid", path)
    for index, item in enumerate(value):
        _text(item, f"{path}[{index}]", identifier=True)
    return list(value)


def validate_binding(value: Any) -> dict[str, Any]:
    """Validate one exact T170 attempt plus T178 effective capability binding."""
    binding = _closed(value, {
        "route", "model", "transport", "adapter", "lane", "grant", "lease",
        "qualification", "capability_card_sha256", "adapter_harness_sha256",
        "worktree", "evidence_root", "attempt", "expiry", "effective_capability",
    }, "binding")
    route = _closed(binding["route"], {"name", "provider"}, "binding.route")
    _text(route["name"], "binding.route.name", identifier=True)
    _text(route["provider"], "binding.route.provider")
    model = _closed(binding["model"], {"exact_model"}, "binding.model")
    _text(model["exact_model"], "binding.model.exact_model")
    _text(binding["transport"], "binding.transport", identifier=True)
    adapter = _closed(binding["adapter"], {"id", "version"}, "binding.adapter")
    _text(adapter["id"], "binding.adapter.id", identifier=True)
    _text(adapter["version"], "binding.adapter.version", identifier=True)
    qualification = _closed(binding["qualification"], {"id", "sha256"}, "binding.qualification")
    _text(qualification["id"], "binding.qualification.id", identifier=True)
    _sha(qualification["sha256"], "binding.qualification.sha256")
    _sha(binding["capability_card_sha256"], "binding.capability_card_sha256")
    _sha(binding["adapter_harness_sha256"], "binding.adapter_harness_sha256")
    lane = _closed(binding["lane"], {"id", "profile", "mutation_mode"}, "binding.lane")
    _text(lane["id"], "binding.lane.id", identifier=True)
    _text(lane["profile"], "binding.lane.profile", identifier=True)
    if lane["mutation_mode"] not in MUTATION_MODES:
        raise NormalizationError("mutation_mode_invalid", "binding.lane.mutation_mode")
    grant = _closed(binding["grant"], {"id", "sha256"}, "binding.grant")
    _text(grant["id"], "binding.grant.id", identifier=True)
    _sha(grant["sha256"], "binding.grant.sha256")
    lease = _closed(binding["lease"], {"id", "fencing_token", "sha256"}, "binding.lease")
    _text(lease["id"], "binding.lease.id", identifier=True)
    if type(lease["fencing_token"]) is not int or lease["fencing_token"] < 1:
        raise NormalizationError("fencing_token_invalid", "binding.lease.fencing_token")
    _sha(lease["sha256"], "binding.lease.sha256")
    worktree = _closed(binding["worktree"], {"path", "identity_sha256"}, "binding.worktree")
    _text(worktree["path"], "binding.worktree.path")
    _sha(worktree["identity_sha256"], "binding.worktree.identity_sha256")
    _text(binding["evidence_root"], "binding.evidence_root")
    attempt = _closed(binding["attempt"], {"id", "index"}, "binding.attempt")
    _text(attempt["id"], "binding.attempt.id", identifier=True)
    if type(attempt["index"]) is not int or attempt["index"] < 1:
        raise NormalizationError("attempt_index_invalid", "binding.attempt.index")
    expiry = _closed(binding["expiry"], {
        "capability", "qualification", "grant", "execution_binding", "effective",
    }, "binding.expiry")
    expiry_values = {name: _timestamp(item, f"binding.expiry.{name}") for name, item in expiry.items()}
    if expiry_values["effective"] != min(
        expiry_values[name] for name in ("capability", "qualification", "grant", "execution_binding")
    ):
        raise NormalizationError("effective_expiry_not_minimum", "binding.expiry.effective")
    capability = _closed(binding["effective_capability"], {
        "required_primitives", "adapter_supported_primitives", "qualified_primitives",
        "granted_primitives", "effective_primitives", "exact_tool_allowlist",
        "capability_sha256",
    }, "binding.effective_capability")
    sets = {
        name: set(_string_list(capability[name], f"binding.effective_capability.{name}"))
        for name in (
            "required_primitives", "adapter_supported_primitives", "qualified_primitives",
            "granted_primitives", "effective_primitives",
        )
    }
    expected = sets["required_primitives"]
    for name in ("adapter_supported_primitives", "qualified_primitives", "granted_primitives"):
        expected &= sets[name]
    if sets["effective_primitives"] != expected or not sets["required_primitives"].issubset(expected):
        raise NormalizationError("effective_capability_not_intersection", "binding.effective_capability")
    _string_list(capability["exact_tool_allowlist"], "binding.effective_capability.exact_tool_allowlist")
    supplied = _sha(capability["capability_sha256"], "binding.effective_capability.capability_sha256")
    capability_core = {key: item for key, item in capability.items() if key != "capability_sha256"}
    if supplied != digest(capability_core):
        raise NormalizationError("effective_capability_digest_mismatch", "binding.effective_capability")
    return binding


def normalize_transport_event(raw_value: Any, binding_value: Any) -> dict[str, Any]:
    """Normalize one provider observation and preserve its provider facts."""
    raw = _closed(raw_value, {
        "event_type", "stage", "terminal_state", "mutation_state", "timestamp",
        "raw_evidence", "provider_facts",
    }, "raw_event")
    event_type = _text(raw["event_type"], "raw_event.event_type", identifier=True)
    if event_type not in EVENT_INDEX:
        raise NormalizationError("event_type_unknown", "raw_event.event_type")
    _text(raw["stage"], "raw_event.stage", identifier=True)
    terminal = raw["terminal_state"]
    if event_type == "attempt_terminal_observed":
        if terminal not in TERMINAL_STATES:
            raise NormalizationError("terminal_state_invalid", "raw_event.terminal_state")
    elif terminal is not None:
        raise NormalizationError("terminal_state_before_terminal", "raw_event.terminal_state")
    if raw["mutation_state"] not in MUTATION_STATES:
        raise NormalizationError("mutation_state_invalid", "raw_event.mutation_state")
    _timestamp(raw["timestamp"], "raw_event.timestamp")
    if not isinstance(raw["raw_evidence"], Mapping):
        raise NormalizationError("raw_evidence_invalid", "raw_event.raw_evidence")
    facts = _closed(raw["provider_facts"], {
        "identity", "billing", "safety", "mutation",
    }, "raw_event.provider_facts")
    if any(not isinstance(facts[name], Mapping) for name in facts):
        raise NormalizationError("provider_fact_invalid", "raw_event.provider_facts")
    if raw["mutation_state"] in {"possible", "unknown"} and terminal not in {None, "execution_unknown"}:
        raise NormalizationError("uncertain_mutation_requires_unknown", "raw_event.terminal_state")
    binding = validate_binding(binding_value)
    event = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": ARTIFACT_TYPE,
        "event_type": event_type,
        "stage": raw["stage"],
        "terminal_state": terminal,
        "mutation_state": raw["mutation_state"],
        "timestamp": raw["timestamp"],
        "raw_evidence": copy.deepcopy(dict(raw["raw_evidence"])),
        "raw_evidence_digest": digest(raw["raw_evidence"]),
        "provider_facts": facts,
        "binding": binding,
        "binding_sha256": digest(binding),
        "retry_allowed": False,
        "fallback_allowed": False,
        "hedging_allowed": False,
        "authority_granted": False,
        "accepted_by_parent": False,
        "board_mutation_performed": False,
        "fold_performed": False,
    }
    event["event_sha256"] = digest(event)
    return event


def validate_event_sequence(events: Any) -> list[dict[str, Any]]:
    """Require one ordered, closed lifecycle for one exact attempt."""
    if not isinstance(events, list) or not events:
        raise NormalizationError("event_sequence_empty", "events")
    rows = copy.deepcopy(events)
    prior_index = -1
    prior_time: datetime | None = None
    binding_sha256: str | None = None
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or row.get("artifact_type") != ARTIFACT_TYPE:
            raise NormalizationError("normalized_event_required", f"events[{index}]")
        supplied = row.get("event_sha256")
        core = {key: copy.deepcopy(item) for key, item in row.items() if key != "event_sha256"}
        if supplied != digest(core):
            raise NormalizationError("event_digest_mismatch", f"events[{index}]")
        validate_binding(row.get("binding"))
        if row.get("binding_sha256") != digest(row["binding"]):
            raise NormalizationError("binding_digest_mismatch", f"events[{index}]")
        if binding_sha256 is None:
            binding_sha256 = row["binding_sha256"]
        elif row["binding_sha256"] != binding_sha256:
            raise NormalizationError("attempt_binding_changed", f"events[{index}]")
        event_type = row.get("event_type")
        if event_type not in EVENT_INDEX or event_type in seen or EVENT_INDEX[event_type] <= prior_index:
            raise NormalizationError("event_order_invalid", f"events[{index}]")
        seen.add(event_type)
        prior_index = EVENT_INDEX[event_type]
        current_time = _timestamp(row.get("timestamp"), f"events[{index}].timestamp")
        if prior_time is not None and current_time < prior_time:
            raise NormalizationError("event_time_regressed", f"events[{index}]")
        prior_time = current_time
    if rows[-1].get("event_type") != "attempt_terminal_observed":
        raise NormalizationError("terminal_event_missing", "events")
    if "tool_result_observed" in seen and "tool_request_observed" not in seen:
        raise NormalizationError("tool_result_without_request", "events")
    if "mutation_reconciliation_observed" in seen and rows[0]["binding"]["lane"]["mutation_mode"] != "scoped_write":
        raise NormalizationError("mutation_reconciliation_without_write", "events")
    return rows
