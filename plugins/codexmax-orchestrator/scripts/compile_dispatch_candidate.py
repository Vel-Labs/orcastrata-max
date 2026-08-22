#!/usr/bin/env python3
"""Compile one strict scheduler candidate from current broker state.

The compiler only binds a short-lived exact-route callability observation.  It
does not infer or cache task authority, scope, authentication, quota, billing,
capability, or independence facts.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
PROOF_MODE = "scheduler_artifact_only"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DRAFT_KEYS = {
    "name", "provider", "exact_model", "route_id", "runtime", "runtime_host",
    "reasoning", "billing_basis", "independence_group", "concurrency_limit",
    "allowance_units", "token_reservation", "cash_reservation_required",
    "evidence_path", "resolver_packet_sha256", "resolver_packet",
}
OUTPUT_ONLY_KEYS = {
    "adapter_id", "adapter_sha256", "preflight_key_sha256",
    "preflight_observation", "preflight_binding", "explicit_selection",
    "explicit_selection_sha256",
}
BINDING_KEYS = {"state_path", "state_sha256", "entry_sha256"}


class CandidateError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _load_broker() -> Any:
    path = Path(__file__).with_name("preflight_broker.py")
    spec = importlib.util.spec_from_file_location("codexmax_candidate_preflight_broker", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BROKER = _load_broker()


def _load_explicit_selection() -> Any:
    path = Path(__file__).with_name("verify_configured_tool_session.py")
    spec = importlib.util.spec_from_file_location("codexmax_candidate_explicit_selection", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXPLICIT_SELECTION = _load_explicit_selection()


def _load_dispatcher() -> tuple[Any, Path]:
    path = Path(__file__).with_name("run_headless_provider_dispatch.py")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CandidateError("adapter_evidence_unreadable", path.name) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise CandidateError("adapter_evidence_unsafe", path.name)
    spec = importlib.util.spec_from_file_location("codexmax_candidate_dispatcher", path)
    if spec is None or spec.loader is None:
        raise CandidateError("adapter_evidence_unreadable", path.name)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        raise CandidateError("adapter_evidence_unreadable", path.name) from error
    return module, path


def _adapter_evidence(draft: dict[str, Any]) -> tuple[str, str]:
    dispatcher, path = _load_dispatcher()
    identity = {
        "provider": draft["provider"], "model": draft["exact_model"],
        "route": draft["route_id"], "runtime": draft["runtime"],
        "reasoning": draft["reasoning"], "billing": draft["billing_basis"],
    }
    try:
        adapter_id = dispatcher._adapter_id(draft["name"], identity)
        source_bytes = path.read_bytes()
    except Exception as error:
        raise CandidateError("adapter_identity_unresolved", draft["name"]) from error
    _text(adapter_id, "adapter_id", ID_RE)
    return adapter_id, "sha256:" + hashlib.sha256(source_bytes).hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False,
        separators=(",", ":"), sort_keys=True,
    )


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError("duplicate_json_key", key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise CandidateError("invalid_json_constant", value)


def load_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
            parse_constant=_reject_json_constant,
        )
    except CandidateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateError("candidate_input_unreadable", str(path)) from error


def _text(value: object, field: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CandidateError("candidate_field_invalid", field)
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CandidateError("candidate_field_invalid", field)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise CandidateError("candidate_field_invalid", field)
    return value


def _nonnegative_integer(value: object, field: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise CandidateError("candidate_field_invalid", field)
    return value


def _relative_output_path(value: object, field: str) -> str:
    text = _text(value, field)
    path = Path(text)
    if (
        path.is_absolute()
        or text.startswith("./")
        or ".." in path.parts
        or "\\" in text
        or text.endswith("/")
        or path.as_posix() in {"", "."}
    ):
        raise CandidateError("candidate_path_invalid", field)
    return path.as_posix()


def validate_draft(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateError("candidate_shape_invalid", "top level must be an object")
    forbidden = sorted(set(value) & OUTPUT_ONLY_KEYS)
    if forbidden:
        raise CandidateError("hand_authored_preflight_forbidden", ",".join(forbidden))
    if set(value) != DRAFT_KEYS:
        missing = sorted(DRAFT_KEYS - set(value))
        unknown = sorted(set(value) - DRAFT_KEYS)
        detail = canonical_json({"missing": missing, "unknown": unknown})
        raise CandidateError("candidate_shape_invalid", detail)
    _text(value["name"], "name", ID_RE)
    for field in (
        "provider", "exact_model", "route_id", "runtime", "runtime_host",
        "reasoning", "billing_basis", "independence_group",
    ):
        _text(value[field], field)
    _nonnegative_integer(value["concurrency_limit"], "concurrency_limit", positive=True)
    _nonnegative_integer(value["allowance_units"], "allowance_units")
    if value["token_reservation"] != "unknown":
        _nonnegative_integer(value["token_reservation"], "token_reservation")
    if not isinstance(value["cash_reservation_required"], bool):
        raise CandidateError("candidate_field_invalid", "cash_reservation_required")
    _relative_output_path(value["evidence_path"], "evidence_path")
    supplied_digest = _text(value["resolver_packet_sha256"], "resolver_packet_sha256")
    if SHA256_RE.fullmatch(supplied_digest) is None:
        raise CandidateError("candidate_field_invalid", "resolver_packet_sha256")
    if not isinstance(value["resolver_packet"], dict):
        raise CandidateError("candidate_field_invalid", "resolver_packet")
    if "adapter_evidence" in value["resolver_packet"]:
        raise CandidateError("hand_authored_adapter_identity_forbidden", "resolver_packet.adapter_evidence")
    try:
        actual_digest = digest(value["resolver_packet"])
    except (TypeError, ValueError) as error:
        raise CandidateError("candidate_field_invalid", "resolver_packet") from error
    if actual_digest != supplied_digest:
        raise CandidateError("resolver_packet_digest_mismatch")
    return value


def resolve_broker_state_path(repo_root: Path, broker_state: Path) -> tuple[Path, str]:
    try:
        root = repo_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise CandidateError("repo_root_invalid", str(repo_root)) from error
    if not root.is_dir():
        raise CandidateError("repo_root_invalid", str(repo_root))
    raw = os.fspath(broker_state)
    if (
        not isinstance(raw, str)
        or not raw
        or raw != raw.strip()
        or "\\" in raw
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise CandidateError("broker_state_path_invalid", str(raw))
    requested = Path(raw)
    if ".." in requested.parts:
        raise CandidateError("broker_state_path_invalid", raw)
    named = Path(os.path.abspath(raw)) if requested.is_absolute() else root / requested
    try:
        relative = named.relative_to(root)
    except ValueError as error:
        raise CandidateError("broker_state_outside_repo", raw) from error
    if not relative.parts:
        raise CandidateError("broker_state_path_invalid", raw)
    current = root
    final_stat: os.stat_result | None = None
    try:
        for index, part in enumerate(relative.parts):
            current = current / part
            current_stat = current.lstat()
            if stat.S_ISLNK(current_stat.st_mode):
                raise CandidateError("broker_state_path_unsafe", relative.as_posix())
            if index < len(relative.parts) - 1:
                if not stat.S_ISDIR(current_stat.st_mode):
                    raise CandidateError("broker_state_path_unsafe", relative.as_posix())
            else:
                final_stat = current_stat
    except CandidateError:
        raise
    except OSError as error:
        raise CandidateError("broker_state_unreadable", relative.as_posix()) from error
    assert final_stat is not None
    if not stat.S_ISREG(final_stat.st_mode) or final_stat.st_nlink != 1:
        raise CandidateError("broker_state_path_unsafe", relative.as_posix())
    return current, relative.as_posix()


def _preflight_key(draft: dict[str, Any]) -> dict[str, str]:
    return {
        "provider": draft["provider"],
        "exact_model": draft["exact_model"],
        "route_id": draft["route_id"],
        "runtime": draft["runtime"],
        "reasoning": draft["reasoning"],
        "proof_mode": PROOF_MODE,
    }


def compile_candidate(
    draft_value: object, *, repo_root: Path, broker_state: Path, now: str,
) -> dict[str, Any]:
    draft = validate_draft(draft_value)
    state_path, relative_state = resolve_broker_state_path(repo_root, broker_state)
    try:
        current = BROKER.read_current_observation(state_path, _preflight_key(draft), now=now)
    except BROKER.PreflightBrokerError as error:
        raise CandidateError(error.code) from error
    adapter_id, adapter_sha256 = _adapter_evidence(draft)
    result = dict(draft)
    result["adapter_id"] = adapter_id
    result["adapter_sha256"] = adapter_sha256
    raw_selection = draft["resolver_packet"].get("explicit_selection")
    if raw_selection is None:
        result["explicit_selection"] = None
        result["explicit_selection_sha256"] = None
    else:
        try:
            selection = EXPLICIT_SELECTION.validate_selection(raw_selection)
        except EXPLICIT_SELECTION.ExplicitSelectionError as error:
            raise CandidateError(error.code, error.detail) from error
        expected = {
            "route_name": draft["name"], "requested_model": draft["exact_model"],
            "route_id": draft["route_id"], "provider": draft["provider"],
            "runtime": draft["runtime"], "billing_basis": draft["billing_basis"],
            "adapter_type": adapter_id, "adapter_sha256": adapter_sha256,
        }
        for field, value in expected.items():
            if selection.get(field) != value:
                raise CandidateError("explicit_selection_candidate_mismatch", field)
        result["explicit_selection"] = selection
        result["explicit_selection_sha256"] = selection["selection_sha256"]
    result["preflight_key_sha256"] = current["key_sha256"]
    result["preflight_observation"] = current["observation"]
    result["preflight_binding"] = {
        "state_path": relative_state,
        "state_sha256": current["state_sha256"],
        "entry_sha256": current["entry_sha256"],
    }
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--broker-state", type=Path, required=True)
    parser.add_argument("--now", required=True, help="Injected ISO-8601 UTC timestamp")
    args = parser.parse_args(argv)
    try:
        result = compile_candidate(
            load_json(args.input), repo_root=args.repo_root,
            broker_state=args.broker_state, now=args.now,
        )
    except CandidateError as error:
        print(canonical_json({
            "schema_version": SCHEMA_VERSION,
            "status": "rejected",
            "error": error.code,
            "detail": error.detail,
        }), file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
