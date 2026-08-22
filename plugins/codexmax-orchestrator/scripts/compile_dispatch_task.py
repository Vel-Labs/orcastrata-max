#!/usr/bin/env python3
"""Compile and validate explicit Codexmax dispatch task envelopes.

This module is deliberately not a prompt classifier. Every authority, scope,
route, time, and context fact must be present in strict JSON input.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


SCHEMA_VERSION = 1
ROLES = {"planner", "architect", "worker", "tester", "documenter", "auditor"}
MUTATION_MODES = {"read_only", "artifact_only", "scoped_write"}
SOURCE_MODES = {"local_filesystem", "embedded_only"}
INPUT_MODES = {"paths_only", "embedded_json"}
CONSEQUENCES = {"low", "medium", "high", "highest"}
QUALITY_POLICIES = {
    "provider_neutral_result_v1",
    "markdown_sections_v1",
    "json_object_v1",
    "opaque_nonempty_v1",
}
FORMATS = {"markdown", "json", "text"}
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
TASK_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class EnvelopeError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _load_provider_work() -> Any:
    path = Path(__file__).with_name("provider_work_authority.py")
    spec = importlib.util.spec_from_file_location("codexmax_provider_work_authority", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROVIDER_WORK = _load_provider_work()


def _load_routing_config() -> Any:
    path = Path(__file__).with_name("resolve_codexmax_config.py")
    spec = importlib.util.spec_from_file_location("codexmax_task_routing_config", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ROUTING_CONFIG = _load_routing_config()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeError("duplicate_json_key", key)
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("invalid_json", f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EnvelopeError("invalid_document", "top level must be an object")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _strict(obj: Any, field: str, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise EnvelopeError("invalid_field", f"{field} must be an object")
    optional = optional or set()
    missing = sorted(required - set(obj))
    unknown = sorted(set(obj) - required - optional)
    if missing:
        raise EnvelopeError("missing_field", f"{field}: {', '.join(missing)}")
    if unknown:
        raise EnvelopeError("unknown_field", f"{field}: {', '.join(unknown)}")
    return obj


def _text(value: Any, field: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise EnvelopeError("invalid_field", f"{field} must be a non-empty trimmed string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EnvelopeError("invalid_field", f"{field} has invalid syntax")
    return value


def _sha(value: Any, field: str) -> str:
    text = _text(value, field)
    if SHA_RE.fullmatch(text) is None:
        raise EnvelopeError("invalid_sha256", field)
    return text


def _timestamp(value: Any, field: str) -> dt.datetime:
    text = _text(value, field)
    if not text.endswith("Z"):
        raise EnvelopeError("invalid_timestamp", f"{field} must end in Z")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise EnvelopeError("invalid_timestamp", field) from exc
    if parsed.utcoffset() != dt.timedelta(0):
        raise EnvelopeError("invalid_timestamp", f"{field} must be UTC")
    return parsed


def _path(value: Any, field: str) -> str:
    text = _text(value, field)
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or text.startswith("./") or "\\" in text:
        raise EnvelopeError("invalid_path", field)
    return path.as_posix()


def _strings(value: Any, field: str, *, allow_empty: bool = True, paths: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise EnvelopeError("invalid_field", f"{field} must be an array")
    result = [(_path(item, f"{field}[]") if paths else _text(item, f"{field}[]")) for item in value]
    if len(result) != len(set(result)):
        raise EnvelopeError("ambiguous_input", f"{field} contains duplicates")
    return sorted(result)


def _argv(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise EnvelopeError("invalid_field", f"{field} must be a non-empty array")
    return [_text(item, f"{field}[]") for item in value]


def _inside_root(root: Path, relative: str, field: str) -> Path:
    root = root.resolve()
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EnvelopeError("source_unavailable", field) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise EnvelopeError("scope_escape", field) from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise EnvelopeError("unsupported_source", field)
    return resolved


def _verify_descriptor(item: Any, field: str, repo_root: Path) -> dict[str, Any]:
    row = _strict(item, field, {"source_id", "path", "sha256", "purpose"})
    _text(row["source_id"], f"{field}.source_id", ID_RE)
    relative = _path(row["path"], f"{field}.path")
    expected = _sha(row["sha256"], f"{field}.sha256")
    _text(row["purpose"], f"{field}.purpose")
    actual = "sha256:" + hashlib.sha256(_inside_root(repo_root, relative, field).read_bytes()).hexdigest()
    if actual != expected:
        raise EnvelopeError("source_sha256_mismatch", relative)
    return row


def validate_context_pack(value: Any, *, repo_root: Path, now: dt.datetime) -> dict[str, Any]:
    pack = _strict(
        value,
        "context_pack",
        {"schema_version", "artifact_type", "context_pack_id", "created_at", "expires_at", "source_mode", "input_mode", "entries", "summary", "exclusions"},
    )
    if pack["schema_version"] != SCHEMA_VERSION or pack["artifact_type"] != "DispatchContextPack":
        raise EnvelopeError("unsupported_schema", "DispatchContextPack v1 required")
    _text(pack["context_pack_id"], "context_pack.context_pack_id", ID_RE)
    created = _timestamp(pack["created_at"], "context_pack.created_at")
    expires = _timestamp(pack["expires_at"], "context_pack.expires_at")
    if created > now:
        raise EnvelopeError("context_from_future", pack["created_at"])
    if expires <= now or expires <= created:
        raise EnvelopeError("stale_context", pack["expires_at"])
    if pack["source_mode"] not in SOURCE_MODES or pack["input_mode"] not in INPUT_MODES:
        raise EnvelopeError("invalid_context_mode", "unsupported source_mode or input_mode")
    if not isinstance(pack["entries"], list):
        raise EnvelopeError("invalid_field", "context_pack.entries must be an array")
    entries = [_verify_descriptor(row, f"context_pack.entries[{index}]", repo_root) for index, row in enumerate(pack["entries"])]
    ids = [row["source_id"] for row in entries]
    paths = [row["path"] for row in entries]
    if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
        raise EnvelopeError("ambiguous_input", "context entries repeat source_id or path")
    if pack["source_mode"] == "local_filesystem" and not entries:
        raise EnvelopeError("missing_context", "local_filesystem requires entries")
    if pack["source_mode"] == "embedded_only" and entries:
        raise EnvelopeError("ambiguous_input", "embedded_only cannot name file entries")
    _text(pack["summary"], "context_pack.summary")
    _strings(pack["exclusions"], "context_pack.exclusions")
    return pack


def _accounting(value: Any, field: str) -> None:
    row = _strict(value, field, {"value", "reason"})
    if row["value"] != "unknown":
        raise EnvelopeError("unsupported_accounting", f"{field}.value must remain unknown before execution")
    _text(row["reason"], f"{field}.reason")


def _validate_envelope_fields(value: Any, *, compiled: bool, repo_root: Path, context_pack: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    base = {
        "schema_version", "envelope_id", "goal_id", "checkpoint_id", "task_id", "assignment_id",
        "bindings", "semantic_role", "task_class", "mutation_mode", "source", "scope", "commands",
        "consequence", "independence", "execution", "queue", "budget", "quality_policy", "context", "route_binding",
    }
    required = base | ({"artifact_type", "compiled_at"} if compiled else set())
    envelope = _strict(value, "envelope", required, {"provider_work"})
    if envelope["schema_version"] != SCHEMA_VERSION:
        raise EnvelopeError("unsupported_schema", "DispatchTaskEnvelope v1 required")
    if compiled and envelope["artifact_type"] != "DispatchTaskEnvelope":
        raise EnvelopeError("unsupported_schema", "artifact_type must be DispatchTaskEnvelope")
    for field in ("envelope_id", "goal_id", "checkpoint_id", "task_id", "assignment_id"):
        _text(envelope[field], field, ID_RE)

    bindings = _strict(envelope["bindings"], "bindings", {"board_sha256", "config_sha256", "authority_sha256", "workgraph_sha256", "supervisor_sha256"})
    for field, digest in bindings.items():
        _sha(digest, f"bindings.{field}")

    role = envelope["semantic_role"]
    if role not in ROLES:
        raise EnvelopeError("invalid_role", str(role))
    _text(envelope["task_class"], "task_class", TASK_CLASS_RE)
    expected_task_class = ROUTING_CONFIG.semantic_task_profile(
        ROUTING_CONFIG.DEFAULTS, role, mutation_mode=envelope["mutation_mode"]
    )
    if envelope["task_class"] != expected_task_class:
        raise EnvelopeError(
            "task_class_role_mismatch",
            f"{role} requires {expected_task_class}",
        )
    if envelope["mutation_mode"] not in MUTATION_MODES:
        if envelope["mutation_mode"] == "repository_write":
            raise EnvelopeError("repository_write_deferred", "this tranche permits read_only or artifact_only only")
        raise EnvelopeError("invalid_mutation_mode", str(envelope["mutation_mode"]))

    source = _strict(envelope["source"], "source", {"source_mode", "input_mode", "inputs"})
    if source["source_mode"] not in SOURCE_MODES or source["input_mode"] not in INPUT_MODES:
        raise EnvelopeError("invalid_source_mode", "unsupported source_mode or input_mode")
    if source["source_mode"] != context_pack["source_mode"] or source["input_mode"] != context_pack["input_mode"]:
        raise EnvelopeError("context_mode_mismatch", "envelope and context pack modes differ")
    if not isinstance(source["inputs"], list):
        raise EnvelopeError("invalid_field", "source.inputs must be an array")
    inputs = [_verify_descriptor(row, f"source.inputs[{index}]", repo_root) for index, row in enumerate(source["inputs"])]
    if len({row["source_id"] for row in inputs}) != len(inputs) or len({row["path"] for row in inputs}) != len(inputs):
        raise EnvelopeError("ambiguous_input", "source inputs repeat source_id or path")
    if source["source_mode"] == "local_filesystem" and not inputs:
        raise EnvelopeError("missing_source", "local_filesystem requires inputs")
    if source["source_mode"] == "embedded_only" and inputs:
        raise EnvelopeError("ambiguous_input", "embedded_only cannot name file inputs")
    context_entries = {row["source_id"]: row for row in context_pack["entries"]}
    if any(context_entries.get(row["source_id"]) != row for row in inputs):
        raise EnvelopeError("source_widening", "every source input must exactly match a context-pack entry")

    scope = _strict(envelope["scope"], "scope", {"requested_read", "requested_write", "authority_read", "authority_write"})
    requested_read = _strings(scope["requested_read"], "scope.requested_read", paths=True)
    requested_write = _strings(scope["requested_write"], "scope.requested_write", paths=True)
    authority_read = _strings(scope["authority_read"], "scope.authority_read", paths=True)
    authority_write = _strings(scope["authority_write"], "scope.authority_write", paths=True)
    if not set(requested_read).issubset(authority_read) or not set(requested_write).issubset(authority_write):
        raise EnvelopeError("scope_widening", "requested scope must be an exact subset of declared authority")
    if envelope["mutation_mode"] == "read_only" and (requested_write or authority_write):
        raise EnvelopeError("scope_widening", "read_only must have empty write scopes")
    if envelope["mutation_mode"] == "artifact_only" and not requested_write:
        raise EnvelopeError("missing_artifact_scope", "artifact_only requires explicit requested_write scope")
    if envelope["mutation_mode"] == "scoped_write" and (role != "worker" or not requested_write):
        raise EnvelopeError("scoped_write_invalid", "scoped_write requires a Worker and explicit write scope")

    if not isinstance(envelope["commands"], list):
        raise EnvelopeError("invalid_field", "commands must be an array")
    for index, item in enumerate(envelope["commands"]):
        command = _strict(item, f"commands[{index}]", {"command_id", "argv", "cwd"})
        _text(command["command_id"], f"commands[{index}].command_id", ID_RE)
        _argv(command["argv"], f"commands[{index}].argv")
        _path(command["cwd"], f"commands[{index}].cwd")
    command_ids = [row["command_id"] for row in envelope["commands"]]
    if len(command_ids) != len(set(command_ids)):
        raise EnvelopeError("ambiguous_input", "commands repeat command_id")

    if envelope["consequence"] not in CONSEQUENCES:
        raise EnvelopeError("invalid_consequence", str(envelope["consequence"]))
    independence = _strict(envelope["independence"], "independence", {"required", "group", "exclusions"})
    if not isinstance(independence["required"], bool):
        raise EnvelopeError("invalid_field", "independence.required must be boolean")
    _text(independence["group"], "independence.group", ID_RE)
    exclusions = _strings(independence["exclusions"], "independence.exclusions")
    if independence["group"] in exclusions:
        raise EnvelopeError("ambiguous_input", "independence group cannot exclude itself")

    execution = _strict(envelope["execution"], "execution", {"idempotent", "cancellable", "hedge_requested"})
    if not isinstance(execution["idempotent"], bool) or not isinstance(execution["cancellable"], bool):
        raise EnvelopeError("invalid_field", "idempotent and cancellable must be boolean")
    if execution["hedge_requested"] is not False:
        raise EnvelopeError("hedging_deferred", "hedge_requested must be false")

    queue = _strict(envelope["queue"], "queue", {"enqueued_at", "deadline", "max_queue_age_seconds", "priority"})
    enqueued = _timestamp(queue["enqueued_at"], "queue.enqueued_at")
    deadline = _timestamp(queue["deadline"], "queue.deadline")
    if not isinstance(queue["max_queue_age_seconds"], int) or isinstance(queue["max_queue_age_seconds"], bool) or queue["max_queue_age_seconds"] <= 0:
        raise EnvelopeError("invalid_field", "max_queue_age_seconds must be a positive integer")
    if not isinstance(queue["priority"], int) or isinstance(queue["priority"], bool) or not 0 <= queue["priority"] <= 100:
        raise EnvelopeError("invalid_field", "priority must be an integer from 0 through 100")
    if enqueued > now:
        raise EnvelopeError("enqueue_from_future", queue["enqueued_at"])
    if deadline <= enqueued or now >= deadline:
        raise EnvelopeError("deadline_expired", queue["deadline"])
    if (now - enqueued).total_seconds() > queue["max_queue_age_seconds"]:
        raise EnvelopeError("queue_age_expired", queue["enqueued_at"])

    budget = _strict(envelope["budget"], "budget", {"token_limit", "allowance_class", "external_cash_authorized", "accounting"})
    if budget["token_limit"] is not None and (not isinstance(budget["token_limit"], int) or isinstance(budget["token_limit"], bool) or budget["token_limit"] <= 0):
        raise EnvelopeError("invalid_field", "token_limit must be null or a positive integer")
    _text(budget["allowance_class"], "budget.allowance_class", TASK_CLASS_RE)
    if budget["external_cash_authorized"] is not False:
        raise EnvelopeError("cash_authority_denied", "external_cash_authorized must be false")
    accounting = _strict(budget["accounting"], "budget.accounting", {"tokens", "cost"})
    _accounting(accounting["tokens"], "budget.accounting.tokens")
    _accounting(accounting["cost"], "budget.accounting.cost")

    quality = _strict(envelope["quality_policy"], "quality_policy", {"policy_id", "artifact_format", "min_bytes", "max_bytes", "required_sections"})
    if quality["policy_id"] not in QUALITY_POLICIES or quality["artifact_format"] not in FORMATS:
        raise EnvelopeError("invalid_quality_policy", "unsupported policy_id or artifact_format")
    if not isinstance(quality["min_bytes"], int) or isinstance(quality["min_bytes"], bool) or quality["min_bytes"] <= 0:
        raise EnvelopeError("invalid_field", "quality_policy.min_bytes must be positive")
    if not isinstance(quality["max_bytes"], int) or isinstance(quality["max_bytes"], bool) or quality["max_bytes"] < quality["min_bytes"]:
        raise EnvelopeError("invalid_field", "quality_policy.max_bytes must be >= min_bytes")
    _strings(quality["required_sections"], "quality_policy.required_sections")

    context = _strict(envelope["context"], "context", {"context_pack_id", "context_pack_sha256"})
    if context["context_pack_id"] != context_pack["context_pack_id"]:
        raise EnvelopeError("context_id_mismatch", str(context["context_pack_id"]))
    if _sha(context["context_pack_sha256"], "context.context_pack_sha256") != sha256_value(context_pack):
        raise EnvelopeError("context_sha256_mismatch", context["context_pack_sha256"])

    route = _strict(envelope["route_binding"], "route_binding", {"provider", "model", "reasoning"})
    for field in route:
        _text(route[field], f"route_binding.{field}")
    native_efforts = ROUTING_CONFIG.NATIVE_REASONING_EFFORTS.get(route["model"])
    if native_efforts is not None and route["reasoning"] not in native_efforts:
        raise EnvelopeError("route_reasoning_invalid", "reasoning is not supported by the selected model")

    provider_work = envelope.get("provider_work")
    if envelope["mutation_mode"] == "scoped_write":
        row = _strict(
            provider_work, "provider_work",
            {"capability_card", "task_grant", "observed_base_tree_sha256"},
        )
        observed_base = _sha(row["observed_base_tree_sha256"], "provider_work.observed_base_tree_sha256")
        try:
            card = PROVIDER_WORK.validate_capability_card(row["capability_card"])
            grant = PROVIDER_WORK.validate_task_grant(row["task_grant"])
            PROVIDER_WORK.effective_authority(card, grant, now=now.isoformat().replace("+00:00", "Z"))
            PROVIDER_WORK.validate_workspace(repo_root, grant)
        except PROVIDER_WORK.ProviderWorkError as exc:
            raise EnvelopeError(exc.code, exc.path) from exc
        if grant["task_id"] != envelope["task_id"]:
            raise EnvelopeError("grant_task_mismatch", "provider_work.task_grant.task_id")
        if grant["base_tree_sha256"] != observed_base:
            raise EnvelopeError("stale_base_tree", "provider_work.observed_base_tree_sha256")
        if grant["read_scope"] != requested_read or grant["write_scope"] != requested_write:
            raise EnvelopeError("grant_scope_mismatch", "provider_work.task_grant")
        expected_commands = [command["argv"] for command in envelope["commands"]]
        if grant["command_allowlist"] != expected_commands:
            raise EnvelopeError("grant_command_mismatch", "provider_work.task_grant.command_allowlist")
        if card["provider"] != route["provider"] or card["exact_model"] != route["model"]:
            raise EnvelopeError("route_substitution", "route_binding")
    elif provider_work is not None:
        raise EnvelopeError("provider_work_without_scoped_write", "provider_work")

    if compiled:
        compiled_at = _timestamp(envelope["compiled_at"], "compiled_at")
        if compiled_at < enqueued or compiled_at > now:
            raise EnvelopeError("compiled_at_invalid", "compiled_at must be between enqueue time and validation now")
    return envelope


def compile_envelope(draft: dict[str, Any], *, context_pack: dict[str, Any], repo_root: Path, now: dt.datetime) -> dict[str, Any]:
    validate_context_pack(context_pack, repo_root=repo_root, now=now)
    _validate_envelope_fields(draft, compiled=False, repo_root=repo_root, context_pack=context_pack, now=now)
    result = dict(draft)
    result["artifact_type"] = "DispatchTaskEnvelope"
    result["compiled_at"] = now.isoformat().replace("+00:00", "Z")
    return result


def validate_envelope(envelope: dict[str, Any], *, context_pack: dict[str, Any], repo_root: Path, now: dt.datetime) -> dict[str, Any]:
    validate_context_pack(context_pack, repo_root=repo_root, now=now)
    return _validate_envelope_fields(envelope, compiled=True, repo_root=repo_root, context_pack=context_pack, now=now)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("compile", "validate"):
        command = sub.add_parser(name)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--context-pack", type=Path, required=True)
        command.add_argument("--repo-root", type=Path, required=True)
        command.add_argument("--now", required=True, help="Injected ISO-8601 UTC timestamp")
    args = parser.parse_args(argv)
    try:
        now = _timestamp(args.now, "now")
        repo_root = args.repo_root.resolve(strict=True)
        if not repo_root.is_dir():
            raise EnvelopeError("invalid_repo_root", str(repo_root))
        source = load_json(args.input)
        context = load_json(args.context_pack)
        result = compile_envelope(source, context_pack=context, repo_root=repo_root, now=now) if args.command == "compile" else validate_envelope(source, context_pack=context, repo_root=repo_root, now=now)
    except (EnvelopeError, OSError) as exc:
        code = exc.code if isinstance(exc, EnvelopeError) else "filesystem_error"
        detail = exc.detail if isinstance(exc, EnvelopeError) else str(exc)
        print(json.dumps({"status": "rejected", "error": code, "detail": detail}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
