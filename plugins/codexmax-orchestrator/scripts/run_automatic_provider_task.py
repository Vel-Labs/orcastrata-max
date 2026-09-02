#!/usr/bin/env python3
"""Select and run one configured external Worker without an explicit model request."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import re
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


TASK = _load("automatic_provider_task", SCRIPT.with_name("run_task_scoped_provider_task.py"))
SESSION = TASK.SESSION
DISPATCH = TASK.DISPATCH

SUPPORTED = {"commandcode": "Command Code", "opencode_tool_loop": "OpenCode"}
ROLES = ("planner", "architect", "worker", "tester", "documenter", "auditor")
COMMANDCODE_MODEL_ROW_RE = re.compile(
    r"^\s*([A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?)\s{2,}\S"
)


def _public_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [{
        key: value for key, value in row.items()
        if key not in {"sort_key", "binding", "route", "probe"}
    } for row in rows]


class _ProbeCache:
    def __init__(self, runner: Callable[..., Any]):
        self.runner = runner
        self.rows: dict[tuple[str, ...], Any] = {}

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> Any:
        key = tuple(argv)
        if key not in self.rows:
            self.rows[key] = self.runner(argv, **kwargs)
        return self.rows[key]


def _priority(effective: Mapping[str, Any], role: str = "worker") -> dict[str, tuple[int, int, int]]:
    fields = tuple(f"route_{index:02d}" for index in range(1, 7))
    if role not in ROLES:
        raise ValueError("role_invalid")
    ordered = effective.get("headless_dispatch", {}).get("role_priorities", {}).get(role, {})
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


def _candidates(effective: Mapping[str, Any], role: str = "worker") -> list[dict[str, Any]]:
    registry = effective.get("adapter_registry", {}).get("bindings", {})
    routes = effective.get("route_registry", {}).get("routes", {})
    priority = _priority(effective, role)
    rows: list[dict[str, Any]] = []
    for binding_id, binding in registry.items() if isinstance(registry, Mapping) else ():
        route_ref = binding.get("route") if isinstance(binding, Mapping) else None
        route_name = route_ref.get("route_name") if isinstance(route_ref, Mapping) else None
        adapter = binding.get("adapter_type") if isinstance(binding, Mapping) else None
        route = routes.get(route_name) if isinstance(route_name, str) and isinstance(routes, Mapping) else None
        row = {"binding_id": binding_id, "route_name": route_name, "adapter_type": adapter,
               "exact_model": route_ref.get("exact_model") if isinstance(route_ref, Mapping) else None,
               "tool": SUPPORTED.get(adapter), "reason": "", "configured": False,
               "pre_probe_eligible": False, "probed": False, "selected": False,
               "called": False, "completed": False, "rejected": True}
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


def _discover_commandcode_models(runner: Callable[..., Any]) -> list[str]:
    """Read the fixed Command Code model catalog without starting a model."""
    env = {key: os.environ[key] for key in SESSION.PROBE_ENV_KEYS if key in os.environ}
    try:
        completed = runner(
            list(SESSION.COMMANDCODE_MODELS_ARGV), input="", text=True,
            capture_output=True, check=False, timeout=15, env=env,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode != 0 or not SESSION._stderr_is_safe("Command Code", stderr):
        return []
    if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > 262144:
        return []
    cleaned = SESSION._clean_bounded_output(stdout, tool="Command Code")
    models: list[str] = []
    for line in cleaned.splitlines():
        match = COMMANDCODE_MODEL_ROW_RE.match(line)
        if match is None:
            continue
        model = match.group(1)
        if SESSION.MODEL_TOKEN_RE.fullmatch(model) is not None and model not in models:
            models.append(model)
    return models[:128]


def _model_preference(effective: Mapping[str, Any], model: str,
                      role: str) -> tuple[int, int, int, str]:
    """Rank a discovered model only from declared route metadata."""
    priorities = _priority(effective, role)
    routes = effective.get("route_registry", {}).get("routes", {})
    matches: list[tuple[int, int, int, str]] = []
    for route_name, route in routes.items() if isinstance(routes, Mapping) else ():
        if (
            isinstance(route_name, str)
            and isinstance(route, Mapping)
            and route.get("route_kind") == "worker"
            and route.get("exact_model") == model
            and route_name in priorities
        ):
            ordinal, cost, effort = priorities[route_name]
            matches.append((ordinal, cost, effort, route_name))
    return min(matches) if matches else (999, 999, 999, model)


def _with_discovered_candidates(effective: Mapping[str, Any], role: str,
                                runner: Callable[..., Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    overlay = copy.deepcopy(dict(effective))
    existing = overlay.get("adapter_registry", {}).get("bindings", {})
    blocked_models = {
        binding.get("route", {}).get("exact_model")
        for binding_id, binding in existing.items()
        if isinstance(binding_id, str) and not binding_id.startswith("example_")
        and isinstance(binding, Mapping) and binding.get("enabled") is False
    }
    rows: list[dict[str, Any]] = []
    ordered = sorted(
        _discover_commandcode_models(runner),
        key=lambda model: _model_preference(effective, model, role),
    )
    for ordinal, model in enumerate(ordered[:8]):
        if model in blocked_models:
            continue
        request = f"Use {model} through Command Code"
        try:
            overlay, created = TASK.SERVICE.task_local_exact_config(
                effective=overlay, request=request, session_module=SESSION,
                config_module=TASK.CONFIG,
            )
            binding_id, binding, route = SESSION._configured_binding(
                overlay, "Command Code", model,
            )
        except (SESSION.ExplicitSelectionError, ValueError):
            continue
        if not created:
            continue
        rows.append({
            "binding_id": binding_id, "route_name": binding["route"]["route_name"],
            "adapter_type": "commandcode", "exact_model": model,
            "tool": "Command Code", "reason": "eligible_for_session_probe",
            "configured": True, "pre_probe_eligible": True, "probed": False,
            "selected": False, "called": False, "completed": False,
            "rejected": True, "task_local_binding": True,
            "candidate_origin": "discovered_session_model",
            "sort_key": (100, *_model_preference(effective, model, role), ordinal, binding_id),
            "binding": copy.deepcopy(dict(binding)), "route": copy.deepcopy(dict(route)),
        })
    return overlay, rows


def run_automatic_task(*, repo_root: Path, task_id: str, prompt: str,
                       read_scope: Sequence[str], evidence_directory: str,
                       expected_artifact: str, workspace_config: Path,
                       allow_provider_call: bool,
                       role: str = "worker",
                       timeout_seconds: float = 60.0,
                       probe_runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    if allow_provider_call is not True:
        return {"configured": False, "selected": False, "called": False, "completed": False,
                "rejected": True, "reason": "task_scoped_provider_call_not_authorized", "considered": []}
    repo_root = Path(repo_root).resolve(strict=True)
    if role not in ROLES:
        raise ValueError("role_invalid")
    effective = DISPATCH._effective_config(repo_root, workspace_config)
    cache = _ProbeCache(probe_runner)
    considered = _candidates(effective, role)
    effective, discovered = _with_discovered_candidates(effective, role, cache)
    considered.extend(discovered)
    considered.sort(key=lambda row: row.get("sort_key", (999, 999, 999, str(row.get("binding_id", "")))))
    selected = None
    for row in considered:
        if row["reason"] != "eligible_for_session_probe":
            continue
        try:
            request = f"Use {row['exact_model']} through {row['tool']}"
            probe_service = TASK.SERVICE.ProviderTaskExecutionService(
                session_module=SESSION, dispatch_module=DISPATCH, config_module=TASK.CONFIG,
            )
            probe = probe_service.probe_exact(request, effective, cache)
            row.update({"reason": "session_probe_succeeded", "probed": True,
                        "selected": True, "probe": probe})
            row["rejected"] = False
            selected = row
            break
        except (SESSION.ExplicitSelectionError, OSError) as exc:
            row.update({"reason": getattr(exc, "code", "session_probe_failed"), "probed": True})
    if selected is None:
        return {"configured": any(row["pre_probe_eligible"] for row in considered),
                "selected": False, "called": False, "completed": False,
                "rejected": True, "reason": "no_eligible_configured_worker",
                "considered": _public_rows(considered)}
    request = f"Use {selected['exact_model']} through {selected['tool']}"
    # The service receives the already verified probe and the existing seams.
    # This keeps automatic selection to one route and one dispatch.
    lifecycle_extra = {
        "considered": _public_rows(considered), "selected_binding_id": selected["binding_id"],
        "selected_tool": selected["tool"], "selected_model": selected["exact_model"],
        "selected_role": role,
        "task_local_binding": selected.get("task_local_binding") is True,
    }
    return TASK.SERVICE.execute_task(
        repo_root=repo_root, request=request, task_id=task_id, prompt=prompt,
        read_scope=read_scope, evidence_directory=evidence_directory,
        expected_artifact=expected_artifact, workspace_config=workspace_config,
        allow_provider_call=True, probe_runner=cache, timeout_seconds=timeout_seconds,
        session_module=SESSION, dispatch_module=DISPATCH, config_module=TASK.CONFIG,
        assignment_builder=TASK.build_assignment, session_probe=probe,
        effective_config=effective,
        lifecycle_extra=lifecycle_extra,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--workspace-config", type=Path)
    parser.add_argument("--allow-provider-call", action="store_true")
    parser.add_argument("--role", choices=ROLES, default="worker")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
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
