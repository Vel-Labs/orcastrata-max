#!/usr/bin/env python3
"""Optional exact-envelope facade over the canonical WorkGraph GoalBuddy API."""

from __future__ import annotations

import copy
import builtins
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types
from typing import Any, Mapping


FACADE_VERSION = 1
REQUEST_TYPE = "standalone_runtime_goalbuddy_request_v1"
RECEIPT_TYPE = "standalone_runtime_goalbuddy_receipt_v1"
OPERATIONS = {"capabilities", "snapshot", "apply", "recover"}
ANCHORS = {
    "workgraph.py": "d6ac455cbc6dc3f88014d94dfc0db37d80a186aa3b9e61dc625eb7c802000612",
    "workgraph_dependencies.py": "41e5ad54e8eebc39cd116b195713be5c62b3be61b3ae36872d548e78940fc112",
    "workgraph_activity.py": "a05f5370d5aecfa86a27e8e45fb4337c1640f473414c86772aa9b13da588448b",
    "workgraph_updates.py": "2ee2169f4cb960b7ba8a7e7342551504bcab51d671dd8debcaac02bdd90ebcdc",
    "workgraph_goalbuddy_adapter.py": "00ea99a1b0b42323f17fe1f1c7483c0b24c8f33f80e5041b94eeb162312a6a94",
    "workgraph_notes.py": "a7749777f583eb4d583ad8895f5d67dee464050adb10456fd91b595371223532",
    "workgraph_cli.py": "47cc361e0c62dba324b2f908ff6abe04839803f951b277891132d3cfc8922fd3",
}
ARGUMENT_FIELDS = {
    "capabilities": set(),
    "snapshot": {"board_path"},
    "apply": {"board_path", "updates_path", "journal_path", "update_id", "timestamp"},
    "recover": {"board_path", "updates_path", "journal_path", "timestamp"},
}
READ_ONLY_EFFECTS = {
    "board_mutated": False,
    "wal_written": False,
    "updates_appended": False,
    "network_used": False,
    "provider_called": False,
    "authority_granted": False,
    "acceptance_granted": False,
}
WORKGRAPH_CAPABILITIES = {
    "acceptance_authority": False,
    "billing_or_provider_access": False,
    "canonical_board_owner": "GoalBuddy",
    "operations": ["apply", "consume", "explain-blocked", "inspect", "note", "propose", "ready", "recover", "review", "snapshot"],
    "protocol_versions": {
        "activity": 1,
        "dependencies": 1,
        "goalbuddy_adapter": 1,
        "notes": 1,
        "tool_api": 1,
        "updates": 1,
        "workgraph": 1,
    },
    "support": {
        "apply_goalbuddy_v2": True,
        "migration": False,
        "network": False,
        "read": True,
        "recover_goalbuddy_v2": True,
        "transcript": False,
        "write_activity": True,
        "write_updates": True,
    },
}


class FacadeError(ValueError):
    def __init__(self, code: str, path: str = "$"):
        super().__init__(f"{code}: {path}")
        self.code = code
        self.path = path


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FacadeError("facade_json_invalid") from exc


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _closed(value: Any, fields: set[str], path: str, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FacadeError(code, path)
    extra = sorted(set(value) - fields)
    missing = sorted(fields - set(value))
    if extra:
        raise FacadeError(code, f"{path}.{extra[0]}")
    if missing:
        raise FacadeError(code, f"{path}.{missing[0]}")
    return value


def _assert_anchor_identity(path: Path, descriptor: int, original: os.stat_result) -> None:
    try:
        opened = os.fstat(descriptor)
        named = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise FacadeError("facade_anchor_identity_changed", path.name) from exc
    identity = (original.st_dev, original.st_ino)
    if (
        resolved != path
        or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(named.st_mode)
        or opened.st_nlink != 1
        or named.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != identity
        or (named.st_dev, named.st_ino) != identity
        or opened.st_size != original.st_size
    ):
        raise FacadeError("facade_anchor_identity_changed", path.name)


def _load_workgraph_cli(
    _anchor_hashes: Mapping[str, str] = types.MappingProxyType(dict(ANCHORS)),
    _assert_identity: Any = _assert_anchor_identity,
    _source_filename: str = __file__,
) -> Any:
    """Compile and execute only descriptor-read bytes from the fixed seven-file closure."""
    root = Path(_source_filename).resolve().parent
    descriptors: dict[str, int] = {}
    metadata: dict[str, os.stat_result] = {}
    sources: dict[str, bytes] = {}
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for name, expected in _anchor_hashes.items():
            path = root / name
            try:
                descriptor = os.open(path, flags)
                opened = os.fstat(descriptor)
            except OSError as exc:
                raise FacadeError("facade_anchor_unavailable", name) from exc
            descriptors[name] = descriptor
            metadata[name] = opened
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise FacadeError("facade_anchor_alias_forbidden", name)
            _assert_identity(path, descriptor, opened)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 131072)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
            _assert_identity(path, descriptor, opened)
            if len(raw) != opened.st_size or hashlib.sha256(raw).hexdigest() != expected:
                raise FacadeError("facade_anchor_identity_mismatch", name)
            sources[name] = raw

        identities = {(item.st_dev, item.st_ino) for item in metadata.values()}
        if len(identities) != len(_anchor_hashes):
            raise FacadeError("facade_anchor_alias_forbidden", "dependency_closure")

        module_names = {
            "codexmax_tool_workgraph": "workgraph.py",
            "codexmax_tool_workgraph_dependencies": "workgraph_dependencies.py",
            "codexmax_tool_workgraph_activity": "workgraph_activity.py",
            "codexmax_tool_workgraph_updates": "workgraph_updates.py",
            "codexmax_tool_workgraph_goalbuddy_adapter": "workgraph_goalbuddy_adapter.py",
            "codexmax_tool_workgraph_notes": "workgraph_notes.py",
            "codexmax_t002_workgraph": "workgraph.py",
            "codexmax_t003_workgraph_updates": "workgraph_updates.py",
            "workgraph_activity_notes_dependency": "workgraph_activity.py",
        }

        class PinnedLoader:
            def __init__(self, module_name: str, source_name: str):
                self.module_name = module_name
                self.source_name = source_name

            def exec_module(self, module: types.ModuleType) -> None:
                module.__dict__["__builtins__"] = pinned_builtins
                code = compile(sources[self.source_name], str(root / self.source_name), "exec", dont_inherit=True)
                exec(code, module.__dict__)

        class PinnedSpec:
            def __init__(self, module_name: str, source_name: str):
                self.name = module_name
                self.loader = PinnedLoader(module_name, source_name)
                self.origin = str(root / source_name)

        class PinnedUtil:
            @staticmethod
            def spec_from_file_location(module_name: str, location: object) -> PinnedSpec:
                source_name = module_names.get(module_name)
                if source_name is None or Path(location) != root / source_name:
                    raise FacadeError("facade_dependency_selector_forbidden")
                return PinnedSpec(module_name, source_name)

            @staticmethod
            def module_from_spec(spec: PinnedSpec) -> types.ModuleType:
                if not isinstance(spec, PinnedSpec):
                    raise FacadeError("facade_dependency_selector_forbidden")
                module = types.ModuleType(spec.name)
                module.__file__ = spec.origin
                module.__loader__ = spec.loader
                module.__package__ = ""
                module.__spec__ = spec
                return module

        pinned_importlib = types.SimpleNamespace(util=PinnedUtil())
        original_import = builtins.__import__

        def pinned_import(name: str, globals: object = None, locals: object = None, fromlist: object = (), level: int = 0) -> Any:
            if name in {"importlib", "importlib.util"}:
                return pinned_importlib
            return original_import(name, globals, locals, fromlist, level)

        pinned_builtins = dict(vars(builtins))
        pinned_builtins["__import__"] = pinned_import
        cli_loader = PinnedLoader("codexmax_standalone_goalbuddy_workgraph_cli", "workgraph_cli.py")
        module = types.ModuleType("codexmax_standalone_goalbuddy_workgraph_cli")
        module.__file__ = str(root / "workgraph_cli.py")
        module.__loader__ = cli_loader
        module.__package__ = ""
        try:
            cli_loader.exec_module(module)
        except FacadeError:
            raise
        except Exception as exc:
            raise FacadeError("facade_dependency_unavailable", "workgraph_cli.py") from exc
        for name, descriptor in descriptors.items():
            _assert_identity(root / name, descriptor, metadata[name])
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(descriptor, 131072)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except OSError as exc:
                raise FacadeError("facade_anchor_identity_changed", name) from exc
            if hashlib.sha256(b"".join(chunks)).hexdigest() != _anchor_hashes[name]:
                raise FacadeError("facade_anchor_identity_changed", name)
            _assert_identity(root / name, descriptor, metadata[name])
        return module
    finally:
        for descriptor in descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass


def capabilities() -> dict[str, Any]:
    return {
        "acceptance_authority": False,
        "canonical_board_owner": "GoalBuddy",
        "facade_version": 1,
        "operations": ["apply", "capabilities", "recover", "snapshot"],
        "provider_or_billing_access": False,
        "support": {
            "apply_goalbuddy_v2": True,
            "migration": False,
            "network": False,
            "recover_goalbuddy_v2": True,
            "snapshot_goalbuddy_v2_v3": True,
        },
    }


def _effect_boundary(operation: str) -> dict[str, Any]:
    if operation in {"capabilities", "snapshot"}:
        return {
            "canonical_adapter_owned": False,
            "effect_guarantees": copy.deepcopy(READ_ONLY_EFFECTS),
            "possible_partial_wal": False,
        }
    return {
        "all_false_claimed": False,
        "canonical_adapter_owned": True,
        "possible_partial_wal": True,
        "receipt_is_only_effect_truth": True,
    }


def _validate_workgraph_receipt(
    operation: str,
    value: Any,
    _expected_capabilities: Mapping[str, Any] = types.MappingProxyType(copy.deepcopy(WORKGRAPH_CAPABILITIES)),
    _canonical_json: Any = canonical_json,
) -> dict[str, Any]:
    try:
        receipt = copy.deepcopy(value)
    except Exception as exc:
        raise FacadeError("facade_workgraph_receipt_invalid") from exc
    if not isinstance(receipt, dict):
        raise FacadeError("facade_workgraph_receipt_invalid")
    if receipt.get("protocol") != "workgraph_tool_api":
        raise FacadeError("facade_workgraph_protocol_mismatch", "$.workgraph_receipt.protocol")
    version = receipt.get("schema_version")
    if type(version) is not int or version != 1:
        raise FacadeError("facade_workgraph_schema_mismatch", "$.workgraph_receipt.schema_version")
    if receipt.get("operation") != operation:
        raise FacadeError("facade_workgraph_operation_mismatch", "$.workgraph_receipt.operation")
    status_value = receipt.get("status")
    if not isinstance(status_value, str) or status_value not in {"ok", "error"}:
        raise FacadeError("facade_workgraph_status_invalid", "$.workgraph_receipt.status")
    if status_value == "ok":
        required = {"capabilities", "operation", "protocol", "result", "schema_version", "status"}
        if set(receipt) != required or not isinstance(receipt.get("result"), dict) or not receipt["result"]:
            raise FacadeError("facade_workgraph_receipt_invalid")
        claimed = receipt.get("capabilities")
        if isinstance(claimed, dict) and (
            claimed.get("acceptance_authority") is not False
            or claimed.get("billing_or_provider_access") is not False
        ):
            raise FacadeError("facade_workgraph_authority_forbidden", "$.workgraph_receipt.capabilities")
        if claimed != _expected_capabilities:
            raise FacadeError("facade_workgraph_capabilities_mismatch", "$.workgraph_receipt.capabilities")
    else:
        required = {"error", "operation", "protocol", "schema_version", "status"}
        if "details" in receipt:
            required.add("details")
        if set(receipt) != required or not isinstance(receipt.get("error"), str) or not receipt["error"].strip():
            raise FacadeError("facade_workgraph_receipt_invalid")
    try:
        _canonical_json(receipt)
    except FacadeError as exc:
        raise FacadeError("facade_workgraph_receipt_invalid") from exc
    return receipt


def _build_execute() -> Any:
    """Capture the only real loader/delegator privately, then erase its public name."""
    pinned_loader = _load_workgraph_cli
    validate_receipt = _validate_workgraph_receipt
    closed = _closed
    facade_capabilities = capabilities
    effect_boundary = _effect_boundary
    digest = canonical_digest
    facade_version = FACADE_VERSION
    request_type = REQUEST_TYPE
    receipt_type = RECEIPT_TYPE
    operations = frozenset(OPERATIONS)
    argument_fields = {name: frozenset(fields) for name, fields in ARGUMENT_FIELDS.items()}

    def delegate(operation: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        cli = pinned_loader()
        execute_workgraph = cli.execute
        error_receipt = cli.error_receipt
        canonical_errors = (cli.ToolError, *cli.UNDERLYING_ERRORS)
        request = {"schema_version": 1, "operation": operation, "arguments": copy.deepcopy(dict(arguments))}
        try:
            delegated = execute_workgraph(request)
        except canonical_errors as exc:
            try:
                delegated = error_receipt(operation, exc)
            except Exception as receipt_error:
                raise FacadeError("facade_dependency_failure", "workgraph_cli.error_receipt") from receipt_error
        except Exception as exc:
            raise FacadeError("facade_dependency_failure", "workgraph_cli.execute") from exc
        return validate_receipt(operation, delegated)

    def operation_call(request: Any) -> dict[str, Any]:
        root = closed(copy.deepcopy(request), {"schema_version", "artifact_type", "operation", "arguments"}, "$", "facade_request_shape_invalid")
        if type(root["schema_version"]) is not int or root["schema_version"] != facade_version:
            raise FacadeError("facade_version_unsupported", "$.schema_version")
        if root["artifact_type"] != request_type:
            raise FacadeError("facade_artifact_type_unsupported", "$.artifact_type")
        operation = root["operation"]
        if operation not in operations:
            raise FacadeError("facade_operation_unsupported", "$.operation")
        arguments = closed(root["arguments"], set(argument_fields[operation]), "$.arguments", "facade_arguments_invalid")
        if operation == "capabilities":
            return {
                "artifact_type": receipt_type,
                "capabilities": facade_capabilities(),
                "effect_boundary": effect_boundary(operation),
                "operation": operation,
                "schema_version": 1,
                "status": "ok",
            }
        workgraph_receipt = delegate(operation, arguments)
        return {
            "artifact_type": receipt_type,
            "effect_boundary": effect_boundary(operation),
            "operation": operation,
            "schema_version": 1,
            "status": workgraph_receipt["status"],
            "workgraph_receipt": workgraph_receipt,
            "workgraph_receipt_sha256": digest(workgraph_receipt),
        }

    return operation_call


execute = _build_execute()
del _build_execute
del _load_workgraph_cli
