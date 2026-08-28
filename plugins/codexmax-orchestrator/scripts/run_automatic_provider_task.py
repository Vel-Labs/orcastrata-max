#!/usr/bin/env python3
"""Select and run one configured external Worker without an explicit model request."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SESSION = _load("automatic_provider_session", SCRIPT.with_name("verify_configured_tool_session.py"))
DISPATCH = _load("automatic_provider_dispatch", SCRIPT.with_name("run_headless_provider_dispatch.py"))
TASK = _load("automatic_provider_task", SCRIPT.with_name("run_task_scoped_provider_task.py"))

SUPPORTED = {"commandcode": "Command Code", "opencode_tool_loop": "OpenCode"}


def _public_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in row.items() if key not in {"sort_key", "binding", "route"}} for row in rows]


class _ProbeCache:
    def __init__(self, runner: Callable[..., Any]):
        self.runner = runner
        self.rows: dict[tuple[str, ...], Any] = {}

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> Any:
        key = tuple(argv)
        if key not in self.rows:
            self.rows[key] = self.runner(argv, **kwargs)
        return self.rows[key]


def _priority(effective: Mapping[str, Any]) -> dict[str, tuple[int, int, int]]:
    fields = tuple(f"route_{index:02d}" for index in range(1, 7))
    ordered = effective.get("headless_dispatch", {}).get("role_priorities", {}).get("worker", {})
    result: dict[str, tuple[int, int, int]] = {}
    for ordinal, field in enumerate(fields):
        route = ordered.get(field)
        if isinstance(route, str) and route != "none":
            result[route] = (ordinal, 0, ordinal)
    policy = effective.get("capability_model", {}).get("reasoning", {}).get("route_capability_policy", {}).get("routes", {})
    for route, row in policy.items():
        if route in result and isinstance(row, Mapping):
            ranks = []
            for field in ("cost_rank", "effort_rank"):
                value = row.get(field)
                ranks.append(value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 99)
            result[route] = (result[route][0], ranks[0], ranks[1])
    return result


def _candidates(effective: Mapping[str, Any]) -> list[dict[str, Any]]:
    registry = effective.get("adapter_registry", {}).get("bindings", {})
    routes = effective.get("route_registry", {}).get("routes", {})
    priority = _priority(effective)
    rows: list[dict[str, Any]] = []
    for binding_id, binding in registry.items() if isinstance(registry, Mapping) else ():
        route_ref = binding.get("route") if isinstance(binding, Mapping) else None
        route_name = route_ref.get("route_name") if isinstance(route_ref, Mapping) else None
        adapter = binding.get("adapter_type") if isinstance(binding, Mapping) else None
        route = routes.get(route_name) if isinstance(route_name, str) and isinstance(routes, Mapping) else None
        row = {"binding_id": binding_id, "route_name": route_name, "adapter_type": adapter,
               "exact_model": route_ref.get("exact_model") if isinstance(route_ref, Mapping) else None,
               "tool": SUPPORTED.get(adapter), "reason": "", "configured": False,
               "pre_probe_eligible": False,
               "probed": False, "selected": False, "called": False, "completed": False,
               "rejected": True}
        if adapter not in SUPPORTED:
            row["reason"] = "transport_not_supported_by_automatic_lane"
        elif not isinstance(route, Mapping) or route.get("route_kind") != "worker":
            row["reason"] = "not_enabled_worker_route"
        elif isinstance(row["exact_model"], str) and row["exact_model"]:
            row["configured"] = True
            if binding.get("enabled") is not True or route.get("enabled") is not True:
                row["reason"] = "binding_or_route_disabled"
            elif route_name not in priority:
                row["reason"] = "not_in_package_worker_priority"
            else:
                row["reason"] = "eligible_for_session_probe"
                row["pre_probe_eligible"] = True
                row["sort_key"] = (*priority[route_name], str(binding_id))
                row["binding"] = copy.deepcopy(dict(binding))
                row["route"] = copy.deepcopy(dict(route))
        else:
            row["reason"] = "exact_model_missing"
        rows.append(row)
    return sorted(rows, key=lambda row: row.get("sort_key", (999, 999, 999, str(row.get("binding_id", "")))))


def run_automatic_task(*, repo_root: Path, task_id: str, prompt: str, read_scope: Sequence[str],
                       evidence_directory: str, expected_artifact: str, workspace_config: Path,
                       allow_provider_call: bool, probe_runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    if allow_provider_call is not True:
        return {"configured": False, "selected": False, "called": False, "completed": False,
                "rejected": True, "reason": "task_scoped_provider_call_not_authorized", "considered": []}
    repo_root = Path(repo_root).resolve(strict=True)
    effective = DISPATCH._effective_config(repo_root, workspace_config)
    considered = _candidates(effective)
    cache = _ProbeCache(probe_runner)
    selected = None
    for row in considered:
        if row["reason"] != "eligible_for_session_probe":
            continue
        try:
            provider_id, token = SESSION._probe_identity(row["tool"], row["route"], row["exact_model"])
            probe = SESSION.probe_existing_session(row["tool"], provider_id, token, runner=cache)
            row.update({"reason": "session_probe_succeeded", "probed": True, "probe": probe})
            row["rejected"] = False
            selected = row
            break
        except (SESSION.ExplicitSelectionError, OSError) as exc:
            row.update({"reason": getattr(exc, "code", "session_probe_failed"), "probed": True})
    if selected is None:
        return {"configured": any(row["pre_probe_eligible"] for row in considered),
                "selected": False, "called": False, "completed": False, "rejected": True,
                "reason": "no_eligible_configured_worker", "considered": _public_rows(considered)}
    request = f"Use {selected['exact_model']} through {selected['tool']}"
    assignment, lifecycle = TASK.build_assignment(
        request=request, task_id=task_id, prompt=prompt, repo_root=repo_root,
        read_scope=read_scope, evidence_directory=evidence_directory,
        expected_artifact=expected_artifact, probe_runner=cache, effective=effective,
        allow_provider_call=True,
    )
    checked = DISPATCH._require_assignment(assignment, repo_root)
    packet = copy.deepcopy(checked["route_packet"])
    preview = DISPATCH._resolve_pre_dispatch(packet)
    considered = _public_rows(considered)
    lifecycle.update({"considered": considered, "selected": True, "selected_binding_id": selected["binding_id"],
                      "selected_tool": selected["tool"], "selected_model": selected["exact_model"],
                      "route_resolution": preview})
    if preview.get("status") != "dispatch_required":
        lifecycle.update({"called": False, "completed": False, "rejected": True, "reason": preview.get("stop_reason", "pre_dispatch_rejected")})
        return lifecycle
    result = DISPATCH.run_dispatch(checked, packet, repo_root, {}, effective=effective,
        allow_provider_call=True, allow_simulated_process=False, timeout=60.0,
        stdout_limit=1024 * 1024, stderr_limit=256 * 1024)
    attempts = result.get("attempts") or []
    called = any(attempt.get("returncode") is not None for attempt in attempts)
    completed = result.get("status") == "selected" and isinstance(result.get("artifact"), dict) and bool(attempts and attempts[-1].get("response_identity_validated") is True)
    for row in lifecycle["considered"]:
        if row.get("binding_id") == selected["binding_id"]:
            row.update({"selected": True, "called": called, "completed": completed, "rejected": not completed})
    lifecycle.update({"called": called, "completed": completed, "rejected": not completed,
                      "usage": result.get("usage"), "manifest": result})
    return lifecycle


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--workspace-config", type=Path, required=True)
    parser.add_argument("--allow-provider-call", action="store_true")
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--read-scope", action="append", required=True)
    parser.add_argument("--evidence-directory", default="reports/task-scoped")
    parser.add_argument("--expected-artifact", default="reports/task-scoped/result.json")
    args = parser.parse_args(argv)
    try:
        result = run_automatic_task(**vars(args))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("completed") else 2
    except (ValueError, SESSION.ExplicitSelectionError, DISPATCH.DispatchError, OSError) as exc:
        print(json.dumps({"status": "rejected", "code": getattr(exc, "code", "automatic_provider_rejected"), "detail": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
