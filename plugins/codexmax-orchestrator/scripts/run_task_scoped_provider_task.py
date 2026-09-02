#!/usr/bin/env python3
"""Run one bounded, read-only provider task from an exact model request."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

SCRIPT = Path(__file__).resolve()


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SESSION = _load("codexmax_task_scoped_session", SCRIPT.with_name("verify_configured_tool_session.py"))
DISPATCH = _load("codexmax_task_scoped_dispatch", SCRIPT.with_name("run_headless_provider_dispatch.py"))
CONFIG = _load("codexmax_task_scoped_config", SCRIPT.with_name("resolve_codexmax_config.py"))
SERVICE = _load("codexmax_provider_task_execution", SCRIPT.with_name("provider_task_execution.py"))

# Compatibility exports.  The lifecycle implementation is in SERVICE.
MAX_TEXT = SERVICE.MAX_TEXT
MAX_SCOPE_ITEMS = SERVICE.MAX_SCOPE_ITEMS
SAFE_ID = SERVICE.SAFE_ID
_now = SERVICE._now
_text = SERVICE._text
_relative_scope = SERVICE._relative_scope
_task_grant = SERVICE._task_grant


def _read_only_profile(route_name: str) -> dict[str, Any]:
    return SERVICE._read_only_profile(route_name, CONFIG)


def _preflight(task_id: str, route: dict[str, Any], probe: dict[str, Any], scope: list[str], now: str) -> dict[str, Any]:
    return SERVICE._preflight(task_id, route, probe, scope, now)


def build_assignment(**kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    kwargs.setdefault("session_module", SESSION)
    kwargs.setdefault("config_module", CONFIG)
    return SERVICE.build_assignment(**kwargs)


def run_task(*, repo_root: Path, request: str, task_id: str, prompt: str,
             read_scope: Sequence[str], evidence_directory: str,
             expected_artifact: str, workspace_config: Path | None,
             allow_provider_call: bool, probe_runner: Callable[..., Any],
             timeout_seconds: float = 60.0) -> dict[str, Any]:
    return SERVICE.execute_task(
        repo_root=repo_root, request=request, task_id=task_id, prompt=prompt,
        read_scope=read_scope, evidence_directory=evidence_directory,
        expected_artifact=expected_artifact, workspace_config=workspace_config,
        allow_provider_call=allow_provider_call, probe_runner=probe_runner,
        timeout_seconds=timeout_seconds, session_module=SESSION,
        dispatch_module=DISPATCH, config_module=CONFIG,
        assignment_builder=build_assignment, allow_task_local_binding=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--request", required=True, help="Use MODEL through Command Code or OpenCode")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--workspace-config", type=Path)
    parser.add_argument("--allow-provider-call", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--read-scope", action="append", required=True)
    parser.add_argument("--evidence-directory", default="reports/task-scoped")
    parser.add_argument("--expected-artifact", default="reports/task-scoped/result.json")
    args = parser.parse_args(argv)
    try:
        result = run_task(**vars(args), probe_runner=subprocess.run)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("completed") else 2
    except (ValueError, SESSION.ExplicitSelectionError, DISPATCH.DispatchError, OSError) as exc:
        print(json.dumps({"status": "rejected", "code": getattr(exc, "code", "task_scoped_rejected"), "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
