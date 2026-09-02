#!/usr/bin/env python3
"""Apply one persisted GitHub issue prepare receipt through a verified local gh identity."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping, Sequence


RECEIPT_TYPE = "orcastrata_github_issue_live_receipt_v1"
STATE_TYPE = "orcastrata_github_issue_live_state_v1"
ALLOWED_PERMISSIONS = {"WRITE", "ADMIN"}


def _module(name: str, filename: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise RuntimeError("github_runtime_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


effect = _module("orcastrata_github_issue_effect", "github_issue_effect.py")
github = _module("orcastrata_github_cli_read", "github_cli_read.py")
adapter = _module("orcastrata_workgraph_goalbuddy_adapter", "workgraph_goalbuddy_adapter.py")


def _load_prepare(path: Path) -> tuple[dict[str, Any], str]:
    raw = adapter._read_regular_bytes(path, label="prepare")
    if len(raw) > effect.MAX_INPUT_BYTES:
        raise effect.IssueEffectError("prepare_oversize")
    try:
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=effect._pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, effect.IssueEffectError) as exc:
        raise effect.IssueEffectError("prepare_invalid") from exc
    return effect._prepare_receipt(receipt), effect._digest(receipt)


def _load_state(path: Path, prepared: Mapping[str, Any], prepare_sha256: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        value = json.loads(
            adapter._read_regular_bytes(path, label="effect_state").decode("utf-8"),
            object_pairs_hook=effect._pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, effect.IssueEffectError) as exc:
        raise effect.IssueEffectError("effect_state_invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"artifact_type", "effect_id", "issue", "outcome", "prepare_receipt_sha256", "schema_version", "status"}
        or value["schema_version"] != 1
        or value["artifact_type"] != STATE_TYPE
        or value["effect_id"] != prepared["effect_id"]
        or value["prepare_receipt_sha256"] != prepare_sha256
        or value["status"] not in {"effect_started", "unknown", "bound"}
    ):
        raise effect.IssueEffectError("effect_state_invalid")
    return value


def _state(
    prepared: Mapping[str, Any], prepare_sha256: str, status: str,
    *, outcome: str | None = None, issue: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": STATE_TYPE,
        "effect_id": prepared["effect_id"],
        "prepare_receipt_sha256": prepare_sha256,
        "status": status,
        "outcome": outcome,
        "issue": dict(issue) if issue is not None else None,
    }


def _write_state(path: Path, value: Mapping[str, Any], *, initial: bool) -> None:
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink():
        raise effect.IssueEffectError("effect_state_path_invalid")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if initial:
        try:
            descriptor = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600
            )
        except FileExistsError as exc:
            raise effect.IssueEffectError("effect_state_raced") from exc
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    if path.is_symlink() or not path.is_file():
        raise effect.IssueEffectError("effect_state_path_invalid")
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, raw)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_command(
    argv: Sequence[str],
    runner: github.Runner,
    environment: Mapping[str, str],
) -> Any:
    raw = github._invoke(argv, runner, environment)
    return github._json_output(raw)


def _identity(
    executable: str,
    environment: Mapping[str, str],
    host: str,
    repository: str,
    runner: github.Runner,
) -> dict[str, str]:
    viewer = _json_command(
        (executable, "api", "--hostname", host, "--method", "GET", "user"),
        runner,
        environment,
    )
    if not isinstance(viewer, Mapping):
        raise effect.IssueEffectError("identity_response_invalid")
    username = github._text(viewer.get("login"), maximum=100)
    owner, name = repository.split("/", 1)
    raw_repo = _json_command(
        (executable, "api", "--hostname", host, "--method", "GET", f"repos/{owner}/{name}"),
        runner,
        environment,
    )
    if (
        not isinstance(raw_repo, Mapping)
        or raw_repo.get("archived") is not False
        or raw_repo.get("disabled") is not False
    ):
        raise effect.IssueEffectError("repository_inactive")
    repo = github._repository(raw_repo)
    if repo["name_with_owner"].lower() != repository.lower():
        raise effect.IssueEffectError("repository_identity_mismatch")
    return {"username": username, "permission": repo["viewer_permission"]}


def execute(
    prepare_path: Path,
    state_path: Path,
    *,
    expected_host: str,
    expected_repository: str,
    expected_user: str,
    resolver=github._resolve_gh,
    runner=github._run_command,
    environment_source=None,
) -> dict[str, Any]:
    command_count = 0
    mutation_attempted = False
    prepared = None
    prepare_receipt_sha256 = None
    try:
        prepared, prepare_receipt_sha256 = _load_prepare(prepare_path)
        if prepared["target"] != {
            "host": expected_host,
            "repository": expected_repository,
        }:
            raise effect.IssueEffectError("authority_target_mismatch")
        executable = resolver()
        environment = github._environment(
            github.os.environ if environment_source is None else environment_source
        )

        def counted_runner(
            argv: Sequence[str], environment: Mapping[str, str]
        ) -> Mapping[str, Any]:
            nonlocal command_count
            command_count += 1
            return runner(argv, environment)

        def live_runner(argv: Sequence[str]) -> Mapping[str, Any]:
            allowed = {
                tuple(effect._search_argv(prepared)),
                tuple(effect._create_argv(prepared)),
            }
            if tuple(argv) not in allowed:
                raise effect.IssueEffectError("command_shape_invalid")
            return counted_runner((executable, *argv[1:]), environment)

        facts = _identity(
            executable, environment, expected_host, expected_repository, counted_runner
        )
        if facts["username"] != expected_user:
            raise effect.IssueEffectError("identity_mismatch")
        if facts["permission"] not in ALLOWED_PERMISSIONS:
            raise effect.IssueEffectError("repository_write_permission_required")
        prior_state = _load_state(state_path, prepared, prepare_receipt_sha256)
        observed, issue = effect._observe(prepared, live_runner)
        if observed == "bound":
            _write_state(
                state_path,
                _state(prepared, prepare_receipt_sha256, "bound", outcome="reconciled_existing", issue=issue),
                initial=prior_state is None,
            )
            return _receipt(
                "bound", "reconciled_existing", prepared, prepare_receipt_sha256,
                facts, issue, command_count, github_mutated=False,
            )
        if prior_state is not None:
            if prior_state["status"] == "bound":
                raise effect.IssueEffectError("bound_issue_missing")
            return _unknown("prior_effect_requires_reconciliation", command_count)
        _write_state(
            state_path,
            _state(prepared, prepare_receipt_sha256, "effect_started"),
            initial=True,
        )
        mutation_attempted = True
        raw = effect._invoke(effect._create_argv(prepared), live_runner, effect=True)
        try:
            issue = effect._issue(effect._json(raw), prepared)
        except effect.IssueEffectError as exc:
            raise effect.IssueEffectError("effect_outcome_unknown") from exc
        try:
            _write_state(
                state_path,
                _state(prepared, prepare_receipt_sha256, "bound", outcome="created", issue=issue),
                initial=False,
            )
        except Exception as exc:
            raise effect.IssueEffectError("effect_outcome_unknown") from exc
        return _receipt(
            "bound", "created", prepared, prepare_receipt_sha256,
            facts, issue, command_count, github_mutated=True,
        )
    except (effect.IssueEffectError, github.GithubReadError) as error:
        code = error.code
        unknown = code == "effect_outcome_unknown"
        if unknown and prepared is not None and prepare_receipt_sha256 is not None:
            try:
                _write_state(
                    state_path,
                    _state(prepared, prepare_receipt_sha256, "unknown"),
                    initial=False,
                )
            except effect.IssueEffectError:
                code = "effect_outcome_and_state_unknown"
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "status": "unknown" if unknown else "error",
            "error": {"code": code},
            "command_count": command_count,
            "mutation_attempted": mutation_attempted,
            "reconcile_required": unknown,
            "effect_boundary": _boundary(
                github_called=command_count > 0,
                github_mutated="unknown" if unknown else False,
            ),
        }
    except Exception:
        return {
            "schema_version": 1,
            "artifact_type": RECEIPT_TYPE,
            "status": "error",
            "error": {"code": "live_issue_internal_error"},
            "command_count": command_count,
            "mutation_attempted": mutation_attempted,
            "reconcile_required": False,
            "effect_boundary": _boundary(
                github_called=command_count > 0, github_mutated=False
            ),
        }


def _boundary(*, github_called: bool, github_mutated: bool | str) -> dict[str, Any]:
    return {
        "acceptance_granted": False,
        "authority_granted": False,
        "credentials_read_by_orcastrata": False,
        "github_called": github_called,
        "github_mutated": github_mutated,
        "live_execution_available": True,
        "simulation_only": False,
    }


def _receipt(
    status: str,
    outcome: str,
    prepared: Mapping[str, Any],
    prepare_receipt_sha256: str,
    facts: Mapping[str, str],
    issue: Mapping[str, Any] | None,
    command_count: int,
    *,
    github_mutated: bool,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": RECEIPT_TYPE,
        "status": status,
        "outcome": outcome,
        "effect_id": prepared["effect_id"],
        "prepare_receipt_sha256": prepare_receipt_sha256,
        "target": dict(prepared["target"]),
        "verified_identity": dict(facts),
        "issue": dict(issue) if issue is not None else None,
        "command_count": command_count,
        "mutation_attempted": github_mutated,
        "reconcile_required": False,
        "effect_boundary": _boundary(github_called=True, github_mutated=github_mutated),
    }


def _unknown(code: str, command_count: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": RECEIPT_TYPE,
        "status": "unknown",
        "error": {"code": code},
        "command_count": command_count,
        "mutation_attempted": False,
        "reconcile_required": True,
        "effect_boundary": _boundary(github_called=True, github_mutated="unknown"),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-user", required=True)
    args = parser.parse_args(argv)
    receipt = execute(
        args.prepare,
        args.state,
        expected_host=args.expected_host,
        expected_repository=args.expected_repository,
        expected_user=args.expected_user,
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["status"] == "bound" else 2


if __name__ == "__main__":
    raise SystemExit(main())
