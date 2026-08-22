#!/usr/bin/env python3
"""Strict newline JSON-RPC stdio facade over the no-effect runtime CLI."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import sys
from typing import Any, BinaryIO, Mapping

import standalone_runtime_cli


PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "codexmax-standalone-runtime"
SERVER_VERSION = "1"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_DEPTH = 32
MAX_ITEMS = 10000
CLI_SHA256 = "7f369441d91ee5a6f60ce7cd6f2d8025e01b4b55e9b5abc2bf53cabb697d1c20"
JSONRPC_FIELDS = {"jsonrpc", "id", "method", "params"}
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOOL_COMMANDS = {
    "codexmax_status_v1": "status",
    "codexmax_plan_v1": "plan",
    "codexmax_run_preview_v1": "run",
}
EFFECT_FIELDS = {
    "service_started", "network_used", "provider_called", "lease_created",
    "dispatch_started", "run_mutated", "journal_written", "policy_persisted",
    "policy_activated", "authority_granted", "acceptance_granted",
}
FORBIDDEN_POSITIVE_CLAIMS = {
    *EFFECT_FIELDS,
    "execution_started", "execution_performed", "effects_performed",
    "child_dispatched", "filesystem_mutated", "persistence_granted",
    "capability_granted", "eligibility_granted", "reconnected",
    "shutdown_observed", "persistent_state_changed",
}
CREDENTIAL_KEY = re.compile(
    r"(?i)(?:authorization|credential|password|passwd|api[_-]?key|access[_-]?token|secret)"
)


class FacadeError(ValueError):
    """Stable protocol validation error, never populated from secrets."""

    def __init__(self, rpc_code: int, message: str):
        super().__init__(message)
        self.rpc_code = rpc_code
        self.message = message


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FacadeError(-32700, "Parse error")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise FacadeError(-32700, "Parse error")


def _bounded(value: Any, depth: int = 1) -> int:
    if depth > MAX_DEPTH:
        raise FacadeError(-32600, "Invalid Request")
    if isinstance(value, float) and not math.isfinite(value):
        raise FacadeError(-32700, "Parse error")
    count = 1
    if isinstance(value, dict):
        for child in value.values():
            count += _bounded(child, depth + 1)
            if count > MAX_ITEMS:
                raise FacadeError(-32600, "Invalid Request")
    elif isinstance(value, list):
        for child in value:
            count += _bounded(child, depth + 1)
            if count > MAX_ITEMS:
                raise FacadeError(-32600, "Invalid Request")
    return count


def parse_message(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
        raise FacadeError(-32600, "Invalid Request")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FacadeError(-32700, "Parse error") from exc
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except FacadeError:
        raise
    except json.JSONDecodeError as exc:
        raise FacadeError(-32700, "Parse error") from exc
    _bounded(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FacadeError(-32603, "Internal error") from exc


def _response_bytes(value: Any) -> bytes:
    try:
        _bounded(value)
        raw = canonical_bytes(value)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise FacadeError(-32603, "Internal error")
        return raw + b"\n"
    except FacadeError:
        return canonical_bytes(_rpc_error(None, -32603, "Internal error")) + b"\n"


def _closed(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise FacadeError(-32600, "Invalid Request")
    return value


def _params(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise FacadeError(-32602, "Invalid params")
    return value


def _request_id(value: Any) -> str | int:
    if type(value) is int:
        return value
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    raise FacadeError(-32600, "Invalid Request")


def _rpc_result(request_id: str | int, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": copy.deepcopy(result)}


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    safe_id = request_id if type(request_id) is int or isinstance(request_id, str) else None
    return {"jsonrpc": "2.0", "id": safe_id, "error": {"code": code, "message": message}}


def _tool_descriptor(name: str, command: str, description: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["input"],
            "properties": {"input": {}},
        },
        "annotations": {
            "title": name,
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
        "x-codexmax-cli-command": command,
        "x-codexmax-preview-only": True,
    }


TOOLS = [
    _tool_descriptor(
        "codexmax_status_v1", "status",
        "Validate an accepted runtime manifest and return a local no-effect status view.",
    ),
    _tool_descriptor(
        "codexmax_plan_v1", "plan",
        "Validate planner truth and return the deterministic no-effect plan preview.",
    ),
    _tool_descriptor(
        "codexmax_run_preview_v1", "run",
        "Validate gateway state and return the current run preview without performing work.",
    ),
]


def _verify_cli_anchor() -> None:
    expected = Path(_verify_cli_anchor.__code__.co_filename).resolve().with_name(
        "standalone_runtime_cli.py"
    )
    observed = Path(getattr(standalone_runtime_cli, "__file__", "")).resolve()
    if observed != expected:
        raise FacadeError(-32603, "Internal error")
    try:
        metadata = expected.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("unsafe CLI source")
        raw = expected.read_bytes()
    except OSError as exc:
        raise FacadeError(-32603, "Internal error") from exc
    if hashlib.sha256(raw).hexdigest() != CLI_SHA256:
        raise FacadeError(-32603, "Internal error")


def _expected_cli_body(command: str, source: Any) -> dict[str, Any]:
    """Independently reconstruct the complete accepted command receipt body."""
    expected = standalone_runtime_cli._base(command, source)
    if command == "status":
        runtime = standalone_runtime_cli._validate_service_source(source)
        expected["runtime"] = runtime
        expected["status"] = {
            "lifecycle": copy.deepcopy(runtime["lifecycle"]),
            "health": copy.deepcopy(runtime["health"]),
            "endpoint": copy.deepcopy(runtime["endpoint"]),
        }
    elif command == "plan":
        plan_result = standalone_runtime_cli._validate_plan_source(source)
        standalone_runtime_cli._validate_plan_consistency(plan_result)
        expected["role_id"] = plan_result["role_id"]
        expected["task_id"] = plan_result["task_id"]
        expected["routes"] = standalone_runtime_cli._route_rows(plan_result)
        expected["selected"] = copy.deepcopy(plan_result["selected"])
        expected["child_preview"] = copy.deepcopy(plan_result.get("child_preview"))
        expected["execution_started"] = False
    elif command == "run":
        command_input = standalone_runtime_cli._closed(
            source, {"gateway_state", "run_id"}, "$.input"
        )
        state = standalone_runtime_cli._validate_gateway_source(command_input["gateway_state"])
        run_id = standalone_runtime_cli._identifier(command_input["run_id"], "$.input.run_id")
        run = standalone_runtime_cli.gateway.read_run(state, run_id)
        expected["run"] = run
        expected["operation_preview"] = {
            "requested": True,
            "performed": False,
            "operation": "inspect_run",
            "requires_separate_admission": False,
        }
    else:
        raise FacadeError(-32603, "Internal error")
    return expected


def _reject_claim_drift(actual: Any, expected: Any) -> None:
    """Reject added positive effects/authority or credential-shaped fields."""
    if isinstance(actual, dict):
        expected_map = expected if isinstance(expected, dict) else {}
        for key, child in actual.items():
            expected_child = expected_map.get(key)
            if CREDENTIAL_KEY.search(key):
                raise FacadeError(-32603, "Internal error")
            if key in FORBIDDEN_POSITIVE_CLAIMS and child is True:
                raise FacadeError(-32603, "Internal error")
            _reject_claim_drift(child, expected_child)
    elif isinstance(actual, list):
        expected_list = expected if isinstance(expected, list) else []
        for index, child in enumerate(actual):
            expected_child = expected_list[index] if index < len(expected_list) else None
            _reject_claim_drift(child, expected_child)


def _validate_cli_receipt(value: Any, command: str, source: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or "receipt_sha256" not in value:
        raise FacadeError(-32603, "Internal error")
    receipt_sha256 = value["receipt_sha256"]
    if not isinstance(receipt_sha256, str) or DIGEST.fullmatch(receipt_sha256) is None:
        raise FacadeError(-32603, "Internal error")
    expected_body = _expected_cli_body(command, copy.deepcopy(source))
    actual_body = {
        key: copy.deepcopy(item) for key, item in value.items() if key != "receipt_sha256"
    }
    _reject_claim_drift(actual_body, expected_body)
    if actual_body != expected_body:
        raise FacadeError(-32603, "Internal error")
    expected_digest = standalone_runtime_cli.digest(expected_body)
    if receipt_sha256 != expected_digest:
        raise FacadeError(-32603, "Internal error")
    return copy.deepcopy(value)


def _tool_error() -> dict[str, Any]:
    value = {
        "artifact_type": "standalone_runtime_mcp_tool_error_v1",
        "code": "cli_request_rejected",
        "side_effect_free": True,
        "effect_guarantees": {field: False for field in sorted(EFFECT_FIELDS)},
    }
    return {
        "content": [{"type": "text", "text": canonical_bytes(value).decode("utf-8")}],
        "structuredContent": value,
        "isError": True,
    }


def _tool_success(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(receipt)
    return {
        "content": [{"type": "text", "text": canonical_bytes(value).decode("utf-8")}],
        "structuredContent": value,
        "isError": False,
    }


class StdioMcpFacadeV1:
    """One deterministic MCP session with no transport beyond caller stdio."""

    def __init__(self) -> None:
        self.state = "created"

    def _initialize(self, request_id: str | int, params: Any) -> dict[str, Any]:
        if self.state != "created":
            raise FacadeError(-32600, "Invalid Request")
        row = _params(params, {"protocolVersion", "capabilities", "clientInfo"})
        if row["protocolVersion"] != PROTOCOL_VERSION or row["capabilities"] != {}:
            raise FacadeError(-32602, "Invalid params")
        client = _params(row["clientInfo"], {"name", "version"})
        for field in ("name", "version"):
            if not isinstance(client[field], str) or not client[field] or "\x00" in client[field]:
                raise FacadeError(-32602, "Invalid params")
        self.state = "initializing"
        return _rpc_result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": "Local deterministic status, plan, and run-preview tools only; no effects or authority.",
        })

    def _tools_call(self, request_id: str | int, params: Any) -> dict[str, Any]:
        row = _params(params, {"name", "arguments"})
        name = row["name"]
        if not isinstance(name, str) or name not in TOOL_COMMANDS:
            raise FacadeError(-32602, "Invalid params")
        arguments = _params(row["arguments"], {"input"})
        command = TOOL_COMMANDS[name]
        _verify_cli_anchor()
        request = {
            "cli_version": 1,
            "artifact_type": "standalone_runtime_cli_request_v1",
            "command": command,
            "input": copy.deepcopy(arguments["input"]),
        }
        try:
            raw = standalone_runtime_cli.execute(request)
        except standalone_runtime_cli.CliError:
            return _rpc_result(request_id, _tool_error())
        receipt = _validate_cli_receipt(raw, command, arguments["input"])
        return _rpc_result(request_id, _tool_success(receipt))

    def handle(self, message: Any) -> dict[str, Any] | None:
        if isinstance(message, list):
            raise FacadeError(-32600, "Invalid Request")
        if not isinstance(message, dict):
            raise FacadeError(-32600, "Invalid Request")
        notification = "id" not in message
        if notification:
            if set(message) not in ({"jsonrpc", "method"}, {"jsonrpc", "method", "params"}):
                return None
            if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
                return None
            if message["method"] == "notifications/initialized":
                if self.state == "initializing" and message.get("params", {}) == {}:
                    self.state = "ready"
                return None
            return None

        if set(message) not in ({"jsonrpc", "id", "method"}, JSONRPC_FIELDS):
            raise FacadeError(-32600, "Invalid Request")
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            raise FacadeError(-32600, "Invalid Request")
        request_id = _request_id(message["id"])
        method = message["method"]
        params = message.get("params", {})
        if method == "initialize":
            if "params" not in message:
                raise FacadeError(-32602, "Invalid params")
            return self._initialize(request_id, params)
        if self.state != "ready":
            raise FacadeError(-32002, "Server not initialized")
        if method == "ping":
            if params != {}:
                raise FacadeError(-32602, "Invalid params")
            return _rpc_result(request_id, {})
        if method == "tools/list":
            if params != {}:
                raise FacadeError(-32602, "Invalid params")
            return _rpc_result(request_id, {"tools": copy.deepcopy(TOOLS)})
        if method == "tools/call":
            if "params" not in message:
                raise FacadeError(-32602, "Invalid params")
            return self._tools_call(request_id, params)
        raise FacadeError(-32601, "Method not found")

    def process_bytes(self, raw: bytes) -> bytes | None:
        request_id: Any = None
        try:
            message = parse_message(raw)
            if isinstance(message, dict):
                request_id = message.get("id")
            response = self.handle(message)
        except FacadeError as exc:
            if isinstance(message if "message" in locals() else None, dict) and "id" not in message:
                return None
            response = _rpc_error(request_id, exc.rpc_code, exc.message)
        except Exception:
            response = _rpc_error(request_id, -32603, "Internal error")
        return None if response is None else _response_bytes(response)


def run_stream(reader: BinaryIO, writer: BinaryIO) -> int:
    facade = StdioMcpFacadeV1()
    while True:
        raw = reader.readline(MAX_MESSAGE_BYTES + 2)
        if raw == b"":
            return 0
        if len(raw) > MAX_MESSAGE_BYTES + 1 or (len(raw) == MAX_MESSAGE_BYTES + 1 and not raw.endswith(b"\n")):
            while raw and not raw.endswith(b"\n"):
                raw = reader.readline(MAX_MESSAGE_BYTES + 2)
            output = canonical_bytes(_rpc_error(None, -32600, "Invalid Request")) + b"\n"
        else:
            payload = raw[:-1] if raw.endswith(b"\n") else raw
            if payload.endswith(b"\r"):
                payload = payload[:-1]
            output = facade.process_bytes(payload)
        if output is not None:
            writer.write(output)
            writer.flush()


def main() -> int:
    return run_stream(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
