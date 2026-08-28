#!/usr/bin/env python3
"""Run a provider as a read-only patch author, then apply its patch safely."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


SCRIPT = Path(__file__).resolve()
SAFE_VALIDATORS = frozenset({"python", "python3", "node", "npm", "npx", "pytest", "cargo", "go", "ruby", "bundle"})


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PATCH = _load("orcastrata_provider_patch", SCRIPT.with_name("provider_patch_application.py"))
AUTO = _load("orcastrata_automatic_task", SCRIPT.with_name("run_automatic_provider_task.py"))
EXACT = AUTO.TASK


class ImplementationError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _assert_isolated(repo_root: Path, worktree: Path) -> None:
    repo = repo_root.resolve(strict=True)
    work = worktree.resolve(strict=True)
    if repo == work or work.is_relative_to(repo) or repo.is_relative_to(work):
        raise ImplementationError("isolated_worktree_required")
    source_git = repo / ".git"
    marker = work / ".git"
    if not source_git.is_dir() or source_git.is_symlink():
        raise ImplementationError("source_git_directory_required")
    try:
        info = marker.lstat()
        raw = marker.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ImplementationError("linked_worktree_marker_invalid") from exc
    if marker.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not raw.startswith("gitdir: "):
        raise ImplementationError("linked_worktree_marker_invalid")
    admin = Path(raw[8:])
    if not admin.is_absolute():
        admin = (work / admin).resolve(strict=True)
    else:
        admin = admin.resolve(strict=True)
    try:
        common = (admin / (admin / "commondir").read_text(encoding="utf-8").strip()).resolve(strict=True)
    except OSError as exc:
        raise ImplementationError("linked_worktree_marker_invalid") from exc
    if common != source_git.resolve(strict=True):
        raise ImplementationError("worktree_repository_mismatch")


def _authorized(worktree: Path, paths: Sequence[str], max_bytes: int) -> list[dict[str, Any]]:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 4 * 1024 * 1024:
        raise ImplementationError("max_file_bytes_invalid")
    if not isinstance(paths, (list, tuple)) or not paths:
        raise ImplementationError("authorized_files_invalid")
    result = []
    for value in paths:
        path = PATCH.relative_path(value)
        before = PATCH.read_existing(worktree, path)
        result.append({"path": path, "before_sha256": PATCH.sha256(before), "max_bytes": max_bytes})
    PATCH.validate_authorized_files(worktree, result)
    return result


def _extract_patch(content: Any) -> str:
    if not isinstance(content, str) or not content.strip():
        raise ImplementationError("provider_patch_missing")
    text = content.strip()
    if text.startswith("```diff\n") and text.endswith("\n```"):
        text = text[8:-4]
    elif text.startswith("```patch\n") and text.endswith("\n```"):
        text = text[9:-4]
    if not text.startswith("--- "):
        raise ImplementationError("provider_patch_not_unified_diff")
    return text + ("" if text.endswith("\n") else "\n")


def _validation_argv(value: Sequence[str]) -> list[str]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 64:
        raise ImplementationError("validation_command_invalid")
    argv: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip() or len(item) > 4096:
            raise ImplementationError("validation_command_invalid")
        if "\x00" in item or "\n" in item or "\r" in item:
            raise ImplementationError("validation_command_invalid")
        argv.append(item)
    if "/" in argv[0] or "\\" in argv[0] or argv[0] not in SAFE_VALIDATORS:
        raise ImplementationError("validation_executable_not_allowed", argv[0])
    if argv[0] in {"python", "python3", "node", "ruby"} and any(item in {"-c", "-e", "--eval"} for item in argv[1:]):
        raise ImplementationError("validation_inline_code_forbidden")
    return argv


def run_validation(
    *, worktree: Path, commands: Sequence[Sequence[str]], timeout_seconds: float,
    runner: Callable[..., Any] = subprocess.run,
) -> list[dict[str, Any]]:
    if not isinstance(commands, (list, tuple)) or len(commands) > 16:
        raise ImplementationError("validation_commands_invalid")
    results: list[dict[str, Any]] = []
    for raw in commands:
        argv = _validation_argv(raw)
        started = time.monotonic()
        try:
            completed = runner(
                argv, cwd=worktree, capture_output=True, text=False,
                timeout=timeout_seconds, check=False,
            )
            row = {
                "argv": argv,
                "execution_status": "completed",
                "result": "pass" if completed.returncode == 0 else "fail",
                "returncode": completed.returncode,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "stdout_sha256": PATCH.sha256(bytes(completed.stdout or b"")),
                "stderr_sha256": PATCH.sha256(bytes(completed.stderr or b"")),
            }
        except subprocess.TimeoutExpired as exc:
            row = {
                "argv": argv,
                "execution_status": "failed",
                "result": "fail",
                "returncode": None,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "failure": "timeout",
                "stdout_sha256": PATCH.sha256(bytes(exc.stdout or b"")),
                "stderr_sha256": PATCH.sha256(bytes(exc.stderr or b"")),
            }
        results.append(row)
        if row["result"] != "pass":
            break
    return results


def _provider_artifact(worktree: Path, relative: str) -> dict[str, Any]:
    path = worktree / PATCH.relative_path(relative)
    try:
        info = path.lstat()
        raw = path.read_bytes()
    except OSError as exc:
        raise ImplementationError("provider_artifact_missing", relative) from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or len(raw) > 1024 * 1024:
        raise ImplementationError("provider_artifact_invalid", relative)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImplementationError("provider_artifact_invalid", relative) from exc
    if not isinstance(value, dict):
        raise ImplementationError("provider_artifact_invalid", relative)
    return value


def _compact_provider(value: Mapping[str, Any]) -> dict[str, Any]:
    manifest = value.get("manifest") if isinstance(value.get("manifest"), Mapping) else {}
    attempts = manifest.get("attempts") if isinstance(manifest.get("attempts"), list) else []
    selection = value.get("selection") if isinstance(value.get("selection"), Mapping) else {}
    return {
        "configured": value.get("configured"),
        "selected": value.get("selected"),
        "called": value.get("called") is True,
        "completed": value.get("completed") is True,
        "rejected": value.get("rejected") is True,
        "reason": value.get("reason"),
        "selected_tool": value.get("selected_tool") or selection.get("tool"),
        "selected_model": value.get("selected_model") or selection.get("requested_model"),
        "usage": value.get("usage"),
        "dispatch": {
            "status": manifest.get("status"),
            "proof_mode": manifest.get("proof_mode"),
            "selected_route": manifest.get("selected_route"),
            "external_call_performed": manifest.get("external_call_performed"),
            "failure": manifest.get("failure"),
            "artifact": {
                key: manifest.get("artifact", {}).get(key)
                for key in ("sha256", "bytes")
                if isinstance(manifest.get("artifact"), Mapping) and key in manifest["artifact"]
            },
            "attempts": [
                {
                    key: attempt.get(key)
                    for key in (
                        "route_name", "outcome", "returncode", "timed_out",
                        "elapsed_time_ms", "response_identity_validated", "tokens", "cost", "quota",
                    )
                }
                for attempt in attempts if isinstance(attempt, Mapping)
            ],
        },
    }


def _write_rollback_bundle(
    *, evidence_root: Path, task_id: str, receipt: Mapping[str, Any], before: Mapping[str, bytes],
) -> dict[str, Any]:
    root = evidence_root.resolve(strict=True)
    bundle = root / ("rollback-" + task_id)
    try:
        bundle.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ImplementationError("rollback_bundle_exists", str(bundle)) from exc
    rows = []
    for index, row in enumerate(receipt["files"], start=1):
        path = row["path"]
        data = before[path]
        blob = bundle / f"{index:03d}.before.bin"
        fd = os.open(blob, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        rows.append({**row, "before_blob": str(blob)})
    manifest = {
        "schema_version": 1,
        "artifact_type": "OrcastrataImplementationRollback",
        "task_id": task_id,
        "worktree": str(receipt["worktree"]),
        "files": rows,
    }
    manifest_path = bundle / "manifest.json"
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"manifest": str(manifest_path), "manifest_sha256": PATCH.sha256(encoded)}


def _write_receipt(*, evidence_root: Path, task_id: str,
                   receipt: Mapping[str, Any]) -> dict[str, Any]:
    path = evidence_root / f"implementation-{task_id}.json"
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    try:
        fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise ImplementationError("implementation_receipt_exists", str(path)) from exc
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "sha256": PATCH.sha256(encoded)}


def rollback_implementation(*, manifest_path: Path, worktree: Path) -> dict[str, Any]:
    path = Path(manifest_path).resolve(strict=True)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ImplementationError("rollback_manifest_invalid")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "artifact_type", "task_id", "worktree", "files"}
        or value.get("schema_version") != 1
        or value.get("artifact_type") != "OrcastrataImplementationRollback"
        or not isinstance(value.get("task_id"), str)
        or EXACT.SERVICE.SAFE_ID.fullmatch(value["task_id"]) is None
        or value.get("worktree") != str(worktree.resolve(strict=True))
        or not isinstance(value.get("files"), list)
        or not 1 <= len(value["files"]) <= PATCH.MAX_FILES
    ):
        raise ImplementationError("rollback_manifest_invalid")
    before: dict[str, bytes] = {}
    receipt = {"files": []}
    for index, row in enumerate(value["files"], start=1):
        if not isinstance(row, dict) or set(row) != {
            "path", "before_sha256", "after_sha256", "before_bytes",
            "after_bytes", "before_blob",
        }:
            raise ImplementationError("rollback_manifest_invalid")
        relative = PATCH.relative_path(row["path"])
        if relative in before:
            raise ImplementationError("rollback_manifest_invalid")
        expected_blob = path.parent / f"{index:03d}.before.bin"
        try:
            blob = Path(row["before_blob"]).resolve(strict=True)
            info = blob.lstat()
        except OSError as exc:
            raise ImplementationError("rollback_blob_invalid", relative) from exc
        if (
            blob != expected_blob.resolve(strict=True)
            or blob.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > 4 * 1024 * 1024
        ):
            raise ImplementationError("rollback_blob_invalid", relative)
        data = blob.read_bytes()
        if PATCH.sha256(data) != row["before_sha256"]:
            raise ImplementationError("rollback_blob_invalid", row["path"])
        before[relative] = data
        receipt["files"].append({key: row[key] for key in ("path", "before_sha256", "after_sha256")})
    return PATCH.rollback(root=worktree, receipt=receipt, before_bytes=before)


def run_implementation(
    *, repo_root: Path, worktree: Path, task_id: str, prompt: str,
    authorized_files: Sequence[str], workspace_config: Path | None,
    evidence_root: Path, allow_provider_call: bool,
    exact_request: str | None = None, validation_commands: Sequence[Sequence[str]] = (),
    max_file_bytes: int = 262144, timeout_seconds: float = 120.0,
    role: str = "worker",
    probe_runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    if allow_provider_call is not True:
        return {"called": False, "completed": False, "rejected": True, "reason": "task_scoped_provider_call_not_authorized"}
    if not isinstance(task_id, str) or EXACT.SERVICE.SAFE_ID.fullmatch(task_id) is None:
        raise ImplementationError("task_id_invalid")
    repo_root = Path(repo_root).resolve(strict=True)
    worktree = Path(worktree).resolve(strict=True)
    _assert_isolated(repo_root, worktree)
    config = None if workspace_config is None else Path(workspace_config).resolve(strict=True)
    if config is not None and not config.is_relative_to(worktree):
        raise ImplementationError("workspace_config_outside_worktree")
    evidence_root = Path(evidence_root).resolve(strict=True)
    if evidence_root.is_relative_to(worktree):
        raise ImplementationError("evidence_must_be_outside_worktree")
    authorized = _authorized(worktree, authorized_files, max_file_bytes)
    scope_text = "\n".join(f"- {row['path']} ({row['before_sha256']})" for row in authorized)
    provider_prompt = (
        prompt
        + "\n\nReturn a minimal unified diff for only these existing files:\n"
        + scope_text
        + "\nDo not create, delete, or rename files. Do not modify files directly. "
          "The response JSON content field must contain only the unified diff."
    )
    raw_path = Path(tempfile.mkdtemp(prefix=".orcastrata-provider-", dir=worktree))
    raw_path.rmdir()
    try:
        relative = raw_path.relative_to(worktree).as_posix()
        artifact_relative = f"{relative}/result.json"
        common = {
            "repo_root": worktree,
            "task_id": task_id,
            "prompt": provider_prompt,
            "read_scope": ["."],
            "evidence_directory": relative,
            "expected_artifact": artifact_relative,
            "workspace_config": config,
            "allow_provider_call": True,
            "probe_runner": probe_runner,
            "timeout_seconds": timeout_seconds,
        }
        if exact_request is None:
            provider_result = AUTO.run_automatic_task(role=role, **common)
        else:
            provider_result = EXACT.run_task(request=exact_request, **common)
        if provider_result.get("completed") is not True:
            return {
                "called": provider_result.get("called") is True,
                "completed": False,
                "rejected": True,
                "reason": provider_result.get("reason", "provider_patch_generation_failed"),
                "provider": _compact_provider(provider_result),
            }
        artifact = _provider_artifact(worktree, artifact_relative)
        patch_text = _extract_patch(artifact.get("content"))
        change = PATCH.apply_patch(root=worktree, patch_text=patch_text, authorized_files=authorized)
    finally:
        shutil.rmtree(raw_path, ignore_errors=True)

    validation = run_validation(
        worktree=worktree, commands=validation_commands,
        timeout_seconds=min(float(timeout_seconds), 300.0),
    )
    validated = all(row["result"] == "pass" for row in validation)
    receipt = {
        "schema_version": 1,
        "artifact_type": "OrcastrataIsolatedImplementationReceipt",
        "task_id": task_id,
        "worktree": str(worktree),
        "selection_mode": "automatic" if exact_request is None else "exact",
        "called": provider_result.get("called") is True,
        "provider_completed": True,
        "patch_applied": True,
        "validation_passed": validated,
        "completed": validated,
        "rejected": not validated,
        "accepted_by_parent": False,
        "changed_paths": change["changed_paths"],
        "files": change["files"],
        "validation": validation,
        "provider": _compact_provider(provider_result),
        "no_provider_write_authority": True,
        "no_fallback_after_start": True,
    }
    receipt["rollback"] = _write_rollback_bundle(
        evidence_root=evidence_root, task_id=task_id, receipt=receipt,
        before=change["before_bytes"],
    )
    receipt["evidence"] = _write_receipt(
        evidence_root=evidence_root, task_id=task_id, receipt=receipt,
    )
    return receipt


def _json_command(value: str) -> list[str]:
    try:
        row = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError("validation command must be a JSON argv array") from exc
    try:
        return _validation_argv(row)
    except ImplementationError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--repo-root", type=Path, required=True)
    run.add_argument("--worktree", type=Path, required=True)
    run.add_argument("--task-id", required=True)
    run.add_argument("--prompt", required=True)
    run.add_argument("--authorized-file", dest="authorized_files", action="append", required=True)
    run.add_argument("--workspace-config", type=Path)
    run.add_argument("--evidence-root", type=Path, required=True)
    run.add_argument("--exact-request")
    run.add_argument("--role", choices=AUTO.ROLES, default="worker")
    run.add_argument("--validation-command", dest="validation_commands", type=_json_command, action="append", default=[])
    run.add_argument("--max-file-bytes", type=int, default=262144)
    run.add_argument("--timeout-seconds", type=float, default=120.0)
    run.add_argument("--allow-provider-call", action="store_true")
    rollback_parser = sub.add_parser("rollback")
    rollback_parser.add_argument("--manifest", dest="manifest_path", type=Path, required=True)
    rollback_parser.add_argument("--worktree", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "rollback":
            result = rollback_implementation(manifest_path=args.manifest_path, worktree=args.worktree)
        else:
            values = vars(args)
            values.pop("command")
            result = run_implementation(**values)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("completed", result.get("performed")) else 2
    except (ImplementationError, PATCH.PatchError, ValueError, OSError) as exc:
        print(json.dumps({"status": "rejected", "code": getattr(exc, "code", "implementation_rejected"), "detail": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
