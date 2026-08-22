#!/usr/bin/env python3
"""Closed served-agent presets and Responses-to-effect translation.

This module validates and translates data only.  It never verifies authority,
invokes an action, opens a transport, or creates response content from a hash.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any, Mapping

import package_host_capability_adapter as package_host
import runtime_execution_gateway as gateway


SCHEMA_VERSION = 1
BUNDLE_TYPE = "served_agent_preset_bundle_v1"
REQUEST_TYPE = "standalone_responses_request_v1"
RECEIPT_TYPE = "standalone_responses_bridge_receipt_v1"
OBSERVATION_TYPE = "standalone_responses_observation_v1"
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
FORBIDDEN_KEYS = {
    "model", "model_id", "provider", "provider_id", "url", "uri",
    "transport", "endpoint", "credential", "credentials", "token",
    "secret", "attachment", "attachments", "image", "audio", "reasoning",
}
MAX_INPUT_ITEMS = 32
MAX_TEXT_CHARS = 16_384
MAX_OUTPUT_ITEMS = 32
MAX_STREAM_EVENTS = 128
MAX_TOOL_REFS = 16
def _package_bridge_receipt_verifier(receipt: dict[str, Any], context: dict[str, Any]) -> bool:
    try:
        identity = {field: context[field] for field in ("workspace_id", "source_sha256", "candidate_sha256")}
    except KeyError as exc:
        raise PresetError("bridge_authority_missing") from exc
    return package_host.verify_responses_bridge(receipt, context, identity)


_PACKAGE_BRIDGE_RECEIPT_VERIFIER = _package_bridge_receipt_verifier


class PresetError(ValueError):
    def __init__(self, code: str, path: str = "$"):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PresetError("canonical_json_invalid") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _closed(value: Any, fields: set[str], code: str, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PresetError(code, path)
    row = dict(value)
    if set(row) != fields:
        raise PresetError(code, path)
    return row


def _identifier(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise PresetError(code, path)
    return value


def _digest(value: Any, code: str, path: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise PresetError(code, path)
    return value


def _reject_forbidden_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or key.lower() in FORBIDDEN_KEYS:
                raise PresetError("direct_route_or_modality_input", f"{path}.{key}")
            _reject_forbidden_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_keys(child, f"{path}[{index}]")


_DEFAULT_BODY = {
    "schema_version": 1,
    "artifact_type": BUNDLE_TYPE,
    "bundle_id": "standalone-default",
    "generation": 1,
    "presets": [{
        "preset_id": "worker-default",
        "family_id": "worker",
        "role": "worker",
        "instructions_sha256": "sha256:" + "1" * 64,
        "route": {"route_id": "route-a", "model_id": "codexmax", "host_id": "local-package"},
        "adapter": {
            "adapter_id": "adapter-a", "action_id": "action-a", "tool_id": "tool-a",
            "transport": "fixture-local", "qualification_status": "qualified",
        },
        "policy": {"policy_id": "policy-a", "active": True},
        "limits": {
            "max_input_chars": MAX_TEXT_CHARS, "max_output_chars": MAX_TEXT_CHARS,
            "max_stream_events": MAX_STREAM_EVENTS, "max_tool_refs": MAX_TOOL_REFS,
        },
        "metadata_allowlist": ["classification", "trace"],
    }],
}
DEFAULT_PRESET_BUNDLE = {**copy.deepcopy(_DEFAULT_BODY), "bundle_sha256": digest(_DEFAULT_BODY)}


def validate_bundle(value: Any) -> dict[str, Any]:
    row = _closed(value, {"schema_version", "artifact_type", "bundle_id", "generation", "presets", "bundle_sha256"}, "preset_bundle_invalid", "$")
    if row["schema_version"] != 1 or row["artifact_type"] != BUNDLE_TYPE:
        raise PresetError("preset_bundle_invalid")
    _identifier(row["bundle_id"], "preset_bundle_invalid", "$.bundle_id")
    if type(row["generation"]) is not int or row["generation"] < 1:
        raise PresetError("preset_bundle_invalid", "$.generation")
    if not isinstance(row["presets"], list) or not 1 <= len(row["presets"]) <= 32:
        raise PresetError("preset_bundle_invalid", "$.presets")
    seen: set[str] = set()
    for index, value in enumerate(row["presets"]):
        path = f"$.presets[{index}]"
        preset = _closed(value, {"preset_id", "family_id", "role", "instructions_sha256", "route", "adapter", "policy", "limits", "metadata_allowlist"}, "preset_bundle_invalid", path)
        for field in ("preset_id", "family_id", "role"):
            _identifier(preset[field], "preset_bundle_invalid", f"{path}.{field}")
        if preset["preset_id"] in seen:
            raise PresetError("preset_bundle_invalid", path)
        seen.add(preset["preset_id"])
        _digest(preset["instructions_sha256"], "preset_bundle_invalid", f"{path}.instructions_sha256")
        route = _closed(preset["route"], {"route_id", "model_id", "host_id"}, "preset_bundle_invalid", f"{path}.route")
        adapter = _closed(preset["adapter"], {"adapter_id", "action_id", "tool_id", "transport", "qualification_status"}, "preset_bundle_invalid", f"{path}.adapter")
        policy = _closed(preset["policy"], {"policy_id", "active"}, "preset_bundle_invalid", f"{path}.policy")
        limits = _closed(preset["limits"], {"max_input_chars", "max_output_chars", "max_stream_events", "max_tool_refs"}, "preset_bundle_invalid", f"{path}.limits")
        for field in route:
            _identifier(route[field], "preset_bundle_invalid", f"{path}.route.{field}")
        for field in ("adapter_id", "action_id", "tool_id", "transport"):
            _identifier(adapter[field], "preset_bundle_invalid", f"{path}.adapter.{field}")
        if adapter["qualification_status"] != "qualified" or policy["active"] is not True:
            raise PresetError("unqualified_identity", path)
        _identifier(policy["policy_id"], "preset_bundle_invalid", f"{path}.policy.policy_id")
        for field, maximum in (("max_input_chars", MAX_TEXT_CHARS), ("max_output_chars", MAX_TEXT_CHARS), ("max_stream_events", MAX_STREAM_EVENTS), ("max_tool_refs", MAX_TOOL_REFS)):
            if type(limits[field]) is not int or not 1 <= limits[field] <= maximum:
                raise PresetError("preset_limits_invalid", f"{path}.limits.{field}")
        if (
            not isinstance(preset["metadata_allowlist"], list)
            or len(preset["metadata_allowlist"]) > 32
            or len(preset["metadata_allowlist"]) != len(set(preset["metadata_allowlist"]))
            or any(not isinstance(item, str) for item in preset["metadata_allowlist"])
        ):
            raise PresetError("preset_bundle_invalid", f"{path}.metadata_allowlist")
    supplied = _digest(row["bundle_sha256"], "preset_bundle_invalid", "$.bundle_sha256")
    if supplied != digest({key: item for key, item in row.items() if key != "bundle_sha256"}):
        raise PresetError("preset_bundle_digest_mismatch")
    return copy.deepcopy(row)


SELECTION_FIELDS = {"bundle_sha256", "preset_id", "family_id", "expected_generation", "scope", "thread_id", "thread_generation", "current_preset_id", "current_family_id", "in_flight"}


def validate_selection(value: Any, bundle_value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    bundle = validate_bundle(bundle_value)
    row = _closed(value, SELECTION_FIELDS, "preset_selection_invalid", "$.selection")
    if (
        row["bundle_sha256"] != bundle["bundle_sha256"]
        or type(row["expected_generation"]) is not int
        or row["expected_generation"] != bundle["generation"]
    ):
        raise PresetError("preset_selection_stale", "$.selection")
    for field in ("preset_id", "family_id", "thread_id"):
        _identifier(row[field], "preset_selection_invalid", f"$.selection.{field}")
    if row["scope"] not in {"new_thread", "next_turn"} or type(row["thread_generation"]) is not int or row["thread_generation"] < 1 or type(row["in_flight"]) is not bool:
        raise PresetError("preset_selection_invalid", "$.selection")
    if (row["current_preset_id"] is None) != (row["current_family_id"] is None):
        raise PresetError("preset_selection_invalid", "$.selection")
    preset = next((item for item in bundle["presets"] if item["preset_id"] == row["preset_id"]), None)
    if preset is None or preset["family_id"] != row["family_id"]:
        raise PresetError("preset_route_mismatch", "$.selection")
    switched = row["current_preset_id"] not in (None, row["preset_id"]) or row["current_family_id"] not in (None, row["family_id"])
    if row["in_flight"] and switched:
        raise PresetError("preset_switch_in_flight", "$.selection")
    if row["scope"] == "new_thread" and row["current_preset_id"] is not None:
        raise PresetError("preset_selection_invalid", "$.selection.scope")
    if row["scope"] == "next_turn" and (
        row["current_preset_id"] != row["preset_id"]
        or row["current_family_id"] != row["family_id"]
    ):
        raise PresetError("thread_pin_mismatch", "$.selection")
    return copy.deepcopy(row), copy.deepcopy(preset)


REQUEST_FIELDS = {"schema_version", "artifact_type", "request_id", "operation", "workspace_id", "goal_id", "task_id", "actor", "idempotency_key", "created_at", "selection", "input", "stream", "tool_references", "cancellation_reference", "metadata"}


def validate_responses_request(value: Any, bundle_value: Any = DEFAULT_PRESET_BUNDLE) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _reject_forbidden_keys(value)
    row = _closed(value, REQUEST_FIELDS, "responses_request_invalid", "$")
    if row["schema_version"] != 1 or row["artifact_type"] != REQUEST_TYPE or row["operation"] not in gateway.EFFECT_OPERATIONS:
        raise PresetError("responses_request_invalid")
    for field in ("request_id", "workspace_id", "goal_id", "task_id", "actor", "idempotency_key"):
        _identifier(row[field], "responses_request_invalid", f"$.{field}")
    selection, preset = validate_selection(row["selection"], bundle_value)
    if not isinstance(row["input"], list) or not 1 <= len(row["input"]) <= MAX_INPUT_ITEMS:
        raise PresetError("responses_input_unbounded", "$.input")
    total = 0
    for index, item in enumerate(row["input"]):
        message = _closed(item, {"role", "content"}, "responses_input_invalid", f"$.input[{index}]")
        if message["role"] not in {"user", "assistant"} or not isinstance(message["content"], str):
            raise PresetError("unsupported_modality", f"$.input[{index}]")
        total += len(message["content"])
    if total > preset["limits"]["max_input_chars"]:
        raise PresetError("responses_input_unbounded", "$.input")
    stream = _closed(row["stream"], {"enabled", "max_events"}, "responses_stream_invalid", "$.stream")
    if type(stream["enabled"]) is not bool or type(stream["max_events"]) is not int or not 1 <= stream["max_events"] <= preset["limits"]["max_stream_events"]:
        raise PresetError("responses_stream_unbounded", "$.stream")
    if not isinstance(row["tool_references"], list) or len(row["tool_references"]) > preset["limits"]["max_tool_refs"]:
        raise PresetError("responses_tool_loop_unbounded", "$.tool_references")
    for index, item in enumerate(row["tool_references"]):
        ref = _closed(item, {"call_id", "tool_id", "result_ref", "status"}, "tool_reference_invalid", f"$.tool_references[{index}]")
        for field in ("call_id", "tool_id", "result_ref"):
            _identifier(ref[field], "tool_reference_invalid", f"$.tool_references[{index}].{field}")
        if ref["tool_id"] != preset["adapter"]["tool_id"] or ref["status"] not in {"called", "observed"}:
            raise PresetError("unregistered_tool", f"$.tool_references[{index}]")
    cancel = row["cancellation_reference"]
    if cancel is not None:
        cancel = _closed(cancel, {"run_id", "predecessor_run_id"}, "cancellation_reference_invalid", "$.cancellation_reference")
        _identifier(cancel["run_id"], "cancellation_reference_invalid", "$.cancellation_reference.run_id")
        if cancel["predecessor_run_id"] is not None:
            _identifier(cancel["predecessor_run_id"], "cancellation_reference_invalid", "$.cancellation_reference.predecessor_run_id")
    if row["operation"] == "run" and cancel is not None:
        raise PresetError("cancellation_reference_invalid")
    if row["operation"] in {"cancel", "recover"} and cancel is None:
        raise PresetError("cancellation_reference_invalid")
    if cancel is not None and (
        (row["operation"] == "cancel" and cancel["predecessor_run_id"] is not None)
        or (row["operation"] == "recover" and cancel["predecessor_run_id"] is None)
    ):
        raise PresetError("cancellation_reference_invalid")
    metadata = row["metadata"]
    if not isinstance(metadata, Mapping) or any(key not in preset["metadata_allowlist"] or value != "[redacted]" for key, value in metadata.items()):
        raise PresetError("metadata_not_redacted", "$.metadata")
    return copy.deepcopy(row), selection, preset


CONTEXT_FIELDS = {"authority_receipt", "source_bundle", "thread_snapshot", "lease", "run", "cas", "captured_at", "expires_at"}


def translate_responses_request(value: Any, context_value: Any, bundle_value: Any = DEFAULT_PRESET_BUNDLE) -> dict[str, Any]:
    request, selection, preset = validate_responses_request(value, bundle_value)
    context = _closed(context_value, CONTEXT_FIELDS, "effect_context_invalid", "$.effect_context")
    thread = context["thread_snapshot"]
    if not isinstance(thread, Mapping) or thread.get("thread_id") != selection["thread_id"] or thread.get("generation") != selection["thread_generation"]:
        raise PresetError("thread_selection_mismatch", "$.effect_context.thread_snapshot")
    cancellation = request["cancellation_reference"]
    if cancellation is not None and (
        context["run"].get("run_id") != cancellation["run_id"]
        or context["run"].get("predecessor_run_id") != cancellation["predecessor_run_id"]
    ):
        raise PresetError("cancellation_reference_invalid", "$.effect_context.run")
    effect = {
        "schema_version": 1, "artifact_type": gateway.EFFECT_REQUEST_TYPE,
        "request_id": request["request_id"], "idempotency_key": request["idempotency_key"],
        "operation": request["operation"], "workspace_id": request["workspace_id"],
        "goal_id": request["goal_id"], "task_id": request["task_id"], "actor": request["actor"],
        "authority_receipt": copy.deepcopy(context["authority_receipt"]),
        "source_bundle": copy.deepcopy(context["source_bundle"]),
        "thread_snapshot": copy.deepcopy(thread),
        "preset_snapshot": {"preset_id": preset["preset_id"], "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "route_snapshot": {"route_id": preset["route"]["route_id"], "requested_model": preset["route"]["model_id"], "requested_host": preset["route"]["host_id"], "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "adapter_snapshot": {**copy.deepcopy(preset["adapter"]), "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "policy_snapshot": {**copy.deepcopy(preset["policy"]), "captured_at": context["captured_at"], "expires_at": context["expires_at"], "snapshot_sha256": ""},
        "lease": copy.deepcopy(context["lease"]), "run": copy.deepcopy(context["run"]), "cas": copy.deepcopy(context["cas"]),
        "input": {"tool_id": preset["adapter"]["tool_id"], "parameters": {"message": "\n".join(item["content"] for item in request["input"])}},
        "created_at": request["created_at"], "request_sha256": "",
    }
    for field in ("preset_snapshot", "route_snapshot", "adapter_snapshot", "policy_snapshot"):
        effect[field]["snapshot_sha256"] = gateway.digest({key: item for key, item in effect[field].items() if key != "snapshot_sha256"})
    effect["request_sha256"] = gateway.digest({key: item for key, item in effect.items() if key != "request_sha256"})
    return effect


def _project_observed_response_for_test(
    request_value: Any,
    bundle_value: Any,
    selection_value: Any,
    effect_request: Any,
    effect_receipt: Any,
    observation_value: Any,
    *,
    test_capability: Any,
) -> dict[str, Any]:
    capability = _closed(test_capability, {"capability_id", "test_only"}, "direct_effect_bypass", "$.test_capability")
    if capability["test_only"] is not True:
        raise PresetError("direct_effect_bypass", "$.test_capability")
    _identifier(capability["capability_id"], "direct_effect_bypass", "$.test_capability.capability_id")
    request, selection, preset = validate_responses_request(request_value, bundle_value)
    if selection != selection_value:
        raise PresetError("preset_selection_stale")
    if not isinstance(effect_receipt, Mapping) or effect_receipt.get("request_sha256") != effect_request.get("request_sha256"):
        raise PresetError("effect_receipt_mismatch")
    if effect_receipt.get("post_state") == "execution_unknown" or effect_receipt.get("disposition") == "execution_unknown":
        raise PresetError("execution_unknown")
    action = effect_receipt.get("action_receipt")
    if not isinstance(action, Mapping):
        raise PresetError("effect_observation_missing")
    observation = _closed(observation_value, {"schema_version", "artifact_type", "response_id", "request_sha256", "output_items", "output_bytes", "output_sha256", "stream_events", "tool_results"}, "response_observation_invalid", "$.observation")
    if observation["schema_version"] != 1 or observation["artifact_type"] != OBSERVATION_TYPE or observation["request_sha256"] != effect_request["request_sha256"]:
        raise PresetError("response_observation_invalid")
    _identifier(observation["response_id"], "response_observation_invalid", "$.observation.response_id")
    if not isinstance(observation["output_items"], list) or len(observation["output_items"]) > MAX_OUTPUT_ITEMS:
        raise PresetError("response_output_unbounded")
    texts: list[str] = []
    for index, item in enumerate(observation["output_items"]):
        output = _closed(item, {"type", "text"}, "response_observation_invalid", f"$.observation.output_items[{index}]")
        if output["type"] != "output_text" or not isinstance(output["text"], str):
            raise PresetError("unsupported_modality")
        texts.append(output["text"])
    if not isinstance(observation["output_bytes"], str) or observation["output_bytes"] != "".join(texts) or len(observation["output_bytes"]) > preset["limits"]["max_output_chars"]:
        raise PresetError("output_hash_drift")
    observed_sha = bytes_digest(observation["output_bytes"].encode("utf-8"))
    if observation["output_sha256"] != observed_sha or action.get("output_sha256") != observed_sha:
        raise PresetError("output_hash_drift")
    if (
        not isinstance(observation["stream_events"], list)
        or len(observation["stream_events"]) > preset["limits"]["max_stream_events"]
        or len(observation["stream_events"]) > request["stream"]["max_events"]
        or (request["stream"]["enabled"] is False and observation["stream_events"])
    ):
        raise PresetError("responses_stream_unbounded")
    for index, item in enumerate(observation["stream_events"]):
        event = _closed(item, {"sequence", "type"}, "response_observation_invalid", f"$.observation.stream_events[{index}]")
        if event["sequence"] != index + 1 or event["type"] not in {"output_text.delta", "response.completed"}:
            raise PresetError("response_observation_invalid", f"$.observation.stream_events[{index}]")
    if not isinstance(observation["tool_results"], list) or len(observation["tool_results"]) > preset["limits"]["max_tool_refs"]:
        raise PresetError("responses_tool_loop_unbounded")
    requested_refs = {(item["call_id"], item["result_ref"]) for item in request["tool_references"]}
    for index, item in enumerate(observation["tool_results"]):
        result = _closed(item, {"call_id", "result_ref", "status"}, "tool_reference_invalid", f"$.observation.tool_results[{index}]")
        if (result["call_id"], result["result_ref"]) not in requested_refs or result["status"] != "observed":
            raise PresetError("tool_reference_invalid", f"$.observation.tool_results[{index}]")
    receipt = {
        "schema_version": 1, "artifact_type": RECEIPT_TYPE, "response_id": observation["response_id"],
        "responses_request_sha256": digest(request), "responses_intent_sha256": digest({key: item for key, item in request.items() if key not in {"metadata"}}),
        "preset_bundle_sha256": bundle_value["bundle_sha256"], "preset_selection_sha256": digest(selection),
        "thread_snapshot_sha256": effect_request["thread_snapshot"]["snapshot_sha256"], "route_snapshot_sha256": effect_request["route_snapshot"]["snapshot_sha256"],
        "effect_request_sha256": effect_request["request_sha256"], "effect_receipt_sha256": effect_receipt["receipt_sha256"],
        "action_receipt_sha256": action["receipt_sha256"],
        "observation_sha256": digest(observation),
        "output_bytes": observation["output_bytes"], "output_bytes_sha256": observed_sha,
        "action_output_sha256": action["output_sha256"], "observation_output_sha256": observation["output_sha256"],
        "operation": request["operation"], "disposition": effect_receipt["disposition"], "output_items": copy.deepcopy(observation["output_items"]),
        "stream_events": copy.deepcopy(observation["stream_events"]), "tool_results": copy.deepcopy(observation["tool_results"]),
        "requested_route": copy.deepcopy(effect_receipt["route_requested"]), "observed_route": copy.deepcopy(effect_receipt["route_observed"]),
        "authority_granted_by_bridge": False, "provider_called_by_bridge": False, "receipt_sha256": "",
    }
    receipt["receipt_sha256"] = digest({key: item for key, item in receipt.items() if key != "receipt_sha256"})
    return receipt


def _validate_bridge_receipt(
    value: Any, request_value: Any, bundle_value: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    request, selection, preset = validate_responses_request(request_value, bundle_value)
    fields = {
        "schema_version", "artifact_type", "response_id", "responses_request_sha256",
        "responses_intent_sha256", "preset_bundle_sha256", "preset_selection_sha256",
        "thread_snapshot_sha256", "route_snapshot_sha256", "effect_request_sha256",
        "effect_receipt_sha256", "action_receipt_sha256", "observation_sha256",
        "output_bytes", "output_bytes_sha256", "action_output_sha256",
        "observation_output_sha256", "operation", "disposition", "output_items",
        "stream_events", "tool_results", "requested_route", "observed_route",
        "authority_granted_by_bridge", "provider_called_by_bridge", "receipt_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise PresetError("bridge_receipt_invalid")
    row = copy.deepcopy(dict(value))
    if (
        row["schema_version"] != 1
        or row["artifact_type"] != RECEIPT_TYPE
        or row["operation"] != request["operation"]
        or row["authority_granted_by_bridge"] is not False
        or row["provider_called_by_bridge"] is not False
        or row["disposition"] == "execution_unknown"
    ):
        raise PresetError("bridge_receipt_invalid")
    expected_request = digest(request)
    expected_intent = digest({key: item for key, item in request.items() if key != "metadata"})
    if (
        row["responses_request_sha256"] != expected_request
        or row["responses_intent_sha256"] != expected_intent
        or row["preset_bundle_sha256"] != bundle_value["bundle_sha256"]
        or row["preset_selection_sha256"] != digest(selection)
    ):
        raise PresetError("bridge_request_binding_mismatch")
    for field in (
        "thread_snapshot_sha256", "route_snapshot_sha256", "effect_request_sha256",
        "effect_receipt_sha256", "action_receipt_sha256", "observation_sha256",
        "output_bytes_sha256", "action_output_sha256", "observation_output_sha256",
    ):
        _digest(row[field], "bridge_receipt_invalid", f"$.{field}")
    if not isinstance(row["output_items"], list) or len(row["output_items"]) > MAX_OUTPUT_ITEMS:
        raise PresetError("response_output_unbounded")
    texts: list[str] = []
    for index, item in enumerate(row["output_items"]):
        output = _closed(item, {"type", "text"}, "bridge_receipt_invalid", f"$.output_items[{index}]")
        if output["type"] != "output_text" or not isinstance(output["text"], str):
            raise PresetError("unsupported_modality")
        texts.append(output["text"])
    if (
        not isinstance(row["output_bytes"], str)
        or row["output_bytes"] != "".join(texts)
        or len(row["output_bytes"]) > preset["limits"]["max_output_chars"]
    ):
        raise PresetError("output_hash_drift")
    output_sha = bytes_digest(row["output_bytes"].encode("utf-8"))
    if not (
        row["output_bytes_sha256"] == output_sha
        and row["action_output_sha256"] == output_sha
        and row["observation_output_sha256"] == output_sha
    ):
        raise PresetError("output_hash_drift")
    if (
        not isinstance(row["stream_events"], list)
        or len(row["stream_events"]) > request["stream"]["max_events"]
        or len(row["stream_events"]) > preset["limits"]["max_stream_events"]
        or (request["stream"]["enabled"] is False and row["stream_events"])
    ):
        raise PresetError("responses_stream_unbounded")
    for index, item in enumerate(row["stream_events"]):
        event = _closed(item, {"sequence", "type"}, "bridge_receipt_invalid", f"$.stream_events[{index}]")
        if event["sequence"] != index + 1 or event["type"] not in {"output_text.delta", "response.completed"}:
            raise PresetError("bridge_receipt_invalid", f"$.stream_events[{index}]")
    if not isinstance(row["tool_results"], list) or len(row["tool_results"]) > preset["limits"]["max_tool_refs"]:
        raise PresetError("responses_tool_loop_unbounded")
    requested_refs = {(item["call_id"], item["result_ref"]) for item in request["tool_references"]}
    for index, item in enumerate(row["tool_results"]):
        result = _closed(item, {"call_id", "result_ref", "status"}, "tool_reference_invalid", f"$.tool_results[{index}]")
        if (result["call_id"], result["result_ref"]) not in requested_refs or result["status"] != "observed":
            raise PresetError("tool_reference_invalid", f"$.tool_results[{index}]")
    for field in ("requested_route", "observed_route"):
        route = _closed(row[field], {"route_id", "model", "host"}, "bridge_receipt_invalid", f"$.{field}")
        for name, item in route.items():
            if item != "unknown":
                _identifier(item, "bridge_receipt_invalid", f"$.{field}.{name}")
    supplied = row.get("receipt_sha256")
    if not isinstance(supplied, str) or supplied != digest({key: item for key, item in row.items() if key != "receipt_sha256"}):
        raise PresetError("bridge_receipt_digest_mismatch")
    context = {
        "responses_request_sha256": expected_request,
        "responses_intent_sha256": expected_intent,
        "preset_bundle_sha256": bundle_value["bundle_sha256"],
        "preset_selection_sha256": digest(selection),
        "effect_request_sha256": row["effect_request_sha256"],
        "effect_receipt_sha256": row["effect_receipt_sha256"],
        "action_receipt_sha256": row["action_receipt_sha256"],
        "observation_sha256": row["observation_sha256"],
        "output_bytes_sha256": output_sha,
    }
    return row, context


def verify_bridge_receipt(
    value: Any, request_value: Any, bundle_value: Any = DEFAULT_PRESET_BUNDLE,
) -> dict[str, Any]:
    """Production verification using only package-owned receipt authority."""

    row, context = _validate_bridge_receipt(value, request_value, bundle_value)
    verifier = _PACKAGE_BRIDGE_RECEIPT_VERIFIER
    if verifier is None or not callable(verifier):
        raise PresetError("bridge_authority_missing")
    try:
        verified = verifier(copy.deepcopy(row), copy.deepcopy(context))
    except PresetError:
        raise
    except Exception as exc:
        raise PresetError("bridge_receipt_not_authorized") from exc
    if verified is not True:
        raise PresetError("bridge_receipt_not_authorized")
    return row


def _verify_bridge_receipt_for_test(
    value: Any,
    request_value: Any,
    trusted_receipt_sha256: str,
    bundle_value: Any = DEFAULT_PRESET_BUNDLE,
) -> dict[str, Any]:
    """TEST ONLY: bind validation to a separately captured receipt digest."""

    row, _ = _validate_bridge_receipt(value, request_value, bundle_value)
    _digest(trusted_receipt_sha256, "bridge_receipt_not_authorized", "$.trusted_receipt_sha256")
    if row["receipt_sha256"] != trusted_receipt_sha256:
        raise PresetError("bridge_receipt_not_authorized")
    return row


def _cross_bind_bridge_artifacts(
    request_value: Any, effect_request: Any, effect_receipt: Any, bridge: dict[str, Any],
    bundle_value: Any = DEFAULT_PRESET_BUNDLE,
) -> dict[str, Any]:
    request, selection, _ = validate_responses_request(request_value, bundle_value)
    if not isinstance(effect_request, Mapping) or set(effect_request) != gateway.EFFECT_REQUEST_FIELDS:
        raise PresetError("effect_request_mismatch")
    if effect_request.get("schema_version") != 1 or effect_request.get("artifact_type") != gateway.EFFECT_REQUEST_TYPE:
        raise PresetError("effect_request_mismatch")
    if not isinstance(effect_receipt, Mapping) or set(effect_receipt) != gateway.EFFECT_RECEIPT_FIELDS:
        raise PresetError("effect_receipt_mismatch")
    if effect_receipt.get("schema_version") != 1 or effect_receipt.get("artifact_type") != gateway.EFFECT_RECEIPT_TYPE:
        raise PresetError("effect_receipt_mismatch")
    action = effect_receipt.get("action_receipt")
    if not isinstance(action, Mapping) or set(action) != gateway.ACTION_RECEIPT_FIELDS or action.get("artifact_type") != gateway.ACTION_RECEIPT_TYPE:
        raise PresetError("effect_observation_missing")
    if (
        effect_request.get("request_sha256") != effect_receipt.get("request_sha256")
        or effect_request.get("request_sha256") != bridge["effect_request_sha256"]
        or effect_receipt.get("receipt_sha256") != bridge["effect_receipt_sha256"]
        or action.get("receipt_sha256") != bridge["action_receipt_sha256"]
        or action.get("request_sha256") != effect_request.get("request_sha256")
        or bridge["responses_request_sha256"] != digest(request)
        or bridge["preset_selection_sha256"] != digest(selection)
        or bridge["thread_snapshot_sha256"] != effect_request["thread_snapshot"]["snapshot_sha256"]
        or bridge["route_snapshot_sha256"] != effect_request["route_snapshot"]["snapshot_sha256"]
        or bridge["requested_route"] != effect_receipt["route_requested"]
        or bridge["observed_route"] != effect_receipt["route_observed"]
        or bridge["observed_route"] != action["observed_identity"]
        or bridge["action_output_sha256"] != action["output_sha256"]
    ):
        raise PresetError("bridge_request_binding_mismatch")
    return {
        "responses_request": copy.deepcopy(request),
        "selection": copy.deepcopy(selection),
        "effect_request": copy.deepcopy(dict(effect_request)),
        "effect_receipt": copy.deepcopy(dict(effect_receipt)),
        "action_receipt": copy.deepcopy(dict(action)),
        "bridge_receipt": copy.deepcopy(bridge),
    }


def validate_responses_artifact_set(
    request_value: Any, effect_request: Any, effect_receipt: Any, bridge_value: Any,
) -> dict[str, Any]:
    """Production validation of the exact Responses/effect lineage."""

    bridge, context = _validate_bridge_receipt(bridge_value, request_value, DEFAULT_PRESET_BUNDLE)
    if not isinstance(effect_request, Mapping):
        raise PresetError("effect_request_mismatch")
    identity = {
        "workspace_id": effect_request.get("workspace_id"),
        "source_sha256": effect_request.get("source_bundle", {}).get("source_sha256"),
        "candidate_sha256": effect_request.get("source_bundle", {}).get("candidate_sha256"),
    }
    try:
        accepted = package_host.verify_responses_bridge(bridge, context, identity)
    except package_host.HostCapabilityError as exc:
        raise PresetError("bridge_receipt_not_authorized") from exc
    if accepted is not True:
        raise PresetError("bridge_receipt_not_authorized")
    return _cross_bind_bridge_artifacts(request_value, effect_request, effect_receipt, bridge)


def _validate_responses_artifact_set_with_resolved_bundle(
    request_value: Any, effect_request: Any, effect_receipt: Any,
    bridge_value: Any, bundle_value: Any,
) -> dict[str, Any]:
    """PACKAGE INTERNAL: validate exact artifacts against a host-resolved bundle."""
    bundle = validate_bundle(bundle_value)
    bridge, context = _validate_bridge_receipt(bridge_value, request_value, bundle)
    if not isinstance(effect_request, Mapping):
        raise PresetError("effect_request_mismatch")
    identity = {
        "workspace_id": effect_request.get("workspace_id"),
        "source_sha256": effect_request.get("source_bundle", {}).get("source_sha256"),
        "candidate_sha256": effect_request.get("source_bundle", {}).get("candidate_sha256"),
    }
    try:
        accepted = package_host.verify_responses_bridge(bridge, context, identity)
    except package_host.HostCapabilityError as exc:
        raise PresetError("bridge_receipt_not_authorized") from exc
    if accepted is not True:
        raise PresetError("bridge_receipt_not_authorized")
    return _cross_bind_bridge_artifacts(
        request_value, effect_request, effect_receipt, bridge, bundle,
    )


def _validate_responses_artifact_set_for_test(
    request_value: Any,
    effect_request: Any,
    effect_receipt: Any,
    bridge_value: Any,
    *,
    trusted_bridge_receipt_sha256: str,
) -> dict[str, Any]:
    """TEST ONLY: validate exact lineage against a separately trusted bridge."""

    bridge = _verify_bridge_receipt_for_test(
        bridge_value, request_value, trusted_bridge_receipt_sha256,
        DEFAULT_PRESET_BUNDLE,
    )
    return _cross_bind_bridge_artifacts(request_value, effect_request, effect_receipt, bridge)
