#!/usr/bin/env python3
"""Verify one configured tool/model session and compile a task-local selection."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
from typing import Any, Callable, Mapping, Sequence


SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUEST_RE = re.compile(
    r"^\s*Use\s+(?P<model>\S(?:.*?\S)?)\s+through\s+"
    r"(?P<tool>OpenCode|Command\s+Code)(?P<suffix>(?:\s*[.!:]\s*|\s+).*)?$",
    re.IGNORECASE,
)
ROUTE_CLAUSE_RE = re.compile(
    r"\bUse\s+\S(?:.*?\S)?\s+through\s+(?:OpenCode|Command\s+Code)\b",
    re.IGNORECASE,
)
PERSISTENCE_REQUEST_RE = re.compile(
    r"(?:"
    r"\b(?:save|remember|persist)\s+(?:it|this|that|the\s+(?:pairing|route|selection|choice))\b"
    r"|\bmake\s+(?:it|this|that|the\s+(?:pairing|route|selection|choice))\s+(?:my\s+)?default\b"
    r"|\b(?:save|remember|persist)\s+(?:this\s+)?(?:tool|model)\s+(?:pairing|selection|choice)\b"
    r")",
    re.IGNORECASE,
)
MAX_EXPLICIT_REQUEST_CHARS = 4096
TOOL_ADAPTERS = {
    "OpenCode": frozenset({"opencode_tool_loop", "opencode_qwopus"}),
    "Command Code": frozenset({"commandcode"}),
}
BINDING_ROUTE_FIELDS = frozenset({
    "route_name", "provider", "exact_model", "route_id", "runtime",
    "reasoning", "billing_basis", "independence_group",
})
TRANSPORT_IDENTITY_FIELDS = BINDING_ROUTE_FIELDS - {"exact_model"}
COMMANDCODE_STATUS_ARGV = ("commandcode", "status", "--json")
COMMANDCODE_MODELS_ARGV = ("commandcode", "--list-models")
OPENCODE_PROVIDER_ARGV = ("opencode", "providers", "list")
OPENCODE_MODELS_ARGV = ("opencode", "models")
PROBE_ENV_KEYS = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE")
COMMANDCODE_STATUS_FIELDS = frozenset({
    "authenticated", "context_window", "model", "provider", "user", "version",
})
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MODEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._/-]+)?$")
PROVIDER_MODEL_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$")
CREDENTIAL_COUNT_RE = re.compile(
    r"^(?:└\s*)?(?P<count>[0-9]{1,4}) credentials?$", re.IGNORECASE
)
PROMPT_MARKERS = (
    "log in", "login required", "sign in", "please authenticate", "authentication required",
    "onboarding", "enter api key", "credential required",
)
ERROR_MARKERS = ("error", "fatal", "failed", "failure", "traceback", "exception")
SELECTION_FIELDS = {
    "schema_version", "artifact_type", "task_id", "task_grant_sha256", "tool",
    "requested_model", "route_name", "route_id", "provider", "runtime",
    "billing_basis", "adapter_type", "adapter_sha256", "binding_id",
    "binding_sha256", "effective_config_sha256", "session_probe", "persistence",
    "no_fallback", "no_tool_substitution", "no_model_substitution",
    "authority_source", "authority_granted", "previewed", "execution_started",
    "selection_sha256",
}
PROBE_FIELDS = {
    "schema_version", "artifact_type", "tool", "probe_argv", "provider_id",
    "existing_session_verified", "exact_model_verified", "observed_model_token",
    "output_sha256", "credential_material_accessed", "authentication_changed",
    "provider_execution_started",
}
OPTIONAL_PROBE_FIELDS = {"observed_tool_version"}


class ExplicitSelectionError(ValueError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical_json(value: object) -> str:
    return json.dumps(value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_request(text: str) -> tuple[str, str]:
    if not isinstance(text, str):
        raise ExplicitSelectionError("explicit_request_malformed")
    if len(text) > MAX_EXPLICIT_REQUEST_CHARS or any(
        ord(character) < 32 and character not in "\t\n\r" for character in text
    ):
        raise ExplicitSelectionError("explicit_request_malformed")
    if len(ROUTE_CLAUSE_RE.findall(text)) != 1 or len(
        re.findall(r"\bthrough\s+(?:OpenCode|Command\s+Code)\b", text, re.IGNORECASE)
    ) != 1:
        raise ExplicitSelectionError("explicit_request_malformed")
    if PERSISTENCE_REQUEST_RE.search(text):
        raise ExplicitSelectionError("persistence_approval_required")
    match = REQUEST_RE.fullmatch(text)
    if match is None:
        raise ExplicitSelectionError("explicit_request_malformed")
    tool = "Command Code" if re.sub(r"\s+", " ", match.group("tool").lower()) == "command code" else "OpenCode"
    model = match.group("model")
    if any(ord(character) < 32 or ord(character) == 127 for character in model):
        raise ExplicitSelectionError("requested_model_invalid")
    return tool, model


def _identity_failure(tool: str, stage: str) -> ExplicitSelectionError:
    """Return a fixed, non-secret probe stage without echoing tool output."""
    return ExplicitSelectionError("identity_unverifiable", f"{tool}:{stage}")


def _configured_binding(effective_config: Mapping[str, Any], tool: str, model: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
    registry = effective_config.get("adapter_registry")
    routes = effective_config.get("route_registry", {}).get("routes")
    if not isinstance(registry, Mapping) or not isinstance(routes, Mapping):
        raise ExplicitSelectionError("effective_config_invalid")
    matches: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    enabled_matches: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for binding_id, raw_binding in registry.get("bindings", {}).items():
        if not isinstance(binding_id, str) or not isinstance(raw_binding, Mapping):
            continue
        binding = copy.deepcopy(dict(raw_binding))
        route_ref = binding.get("route")
        if (
            binding.get("adapter_type") not in TOOL_ADAPTERS[tool]
            or not isinstance(route_ref, Mapping)
            or route_ref.get("exact_model") != model
        ):
            continue
        route_name = route_ref.get("route_name")
        route = routes.get(route_name)
        if isinstance(route_name, str) and isinstance(route, Mapping):
            match = (binding_id, binding, copy.deepcopy(dict(route)))
            matches.append(match)
            if binding.get("enabled") is True and route.get("enabled") is True:
                enabled_matches.append(match)
    if not matches:
        raise ExplicitSelectionError("requested_model_not_configured", f"{tool}:{model}")
    if not enabled_matches:
        raise ExplicitSelectionError("requested_binding_disabled", matches[0][0])
    if len(enabled_matches) != 1:
        raise ExplicitSelectionError("requested_model_ambiguous", f"{tool}:{model}")
    binding_id, binding, route = enabled_matches[0]
    if binding.get("adapter_binding_sha256") is None or binding.get("adapter_sha256") is None:
        raise ExplicitSelectionError("requested_binding_unverifiable", binding_id)
    identity = binding["route"]
    if set(identity) != BINDING_ROUTE_FIELDS:
        raise ExplicitSelectionError("requested_binding_route_mismatch", "shape")
    for field in sorted(TRANSPORT_IDENTITY_FIELDS):
        route_field = "route_name" if field == "route_name" else field
        expected = route_name if route_field == "route_name" else route.get(route_field)
        if identity.get(field) != expected:
            raise ExplicitSelectionError("requested_binding_route_mismatch", field)
    # The binding is the model declaration. Clone that exact model onto the
    # package-owned transport route without rewriting either source object.
    route["exact_model"] = identity["exact_model"]
    return binding_id, binding, route


def _probe_identity(tool: str, route: Mapping[str, Any], model: str) -> tuple[str, str]:
    if tool != "OpenCode":
        return "commandcode", model
    # OpenCode selects provider/model. The package-owned backend binding is the
    # only authority for translating the public exact model to that selector.
    if route.get("route_id") == "minimax-subscription-m3-opencode":
        return "minimax", "minimax/MiniMax-M3"
    if route.get("route_id") == "qwopus-opencode-local":
        return "llama-server", "llama-server/qwopus36-35b-a3b-coder-mtp-q5_k_m"
    raise ExplicitSelectionError("requested_model_probe_unavailable", model)


def _clean_bounded_output(value: str, *, tool: str) -> str:
    cleaned = ANSI_ESCAPE_RE.sub("", value)
    if any(character not in "\n\r\t" and not character.isprintable() for character in cleaned):
        raise ExplicitSelectionError("identity_unverifiable", tool)
    lines = cleaned.splitlines()
    if len(lines) > 512 or any(len(line) > 2048 for line in lines):
        raise ExplicitSelectionError("identity_unverifiable", tool)
    return cleaned


def _stderr_is_safe(tool: str, stderr: str) -> bool:
    if not stderr.strip():
        return True
    if tool != "OpenCode" or len(stderr.encode("utf-8")) > 2048:
        return False
    cleaned = _clean_bounded_output(stderr, tool=tool)
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    if not lines:
        return True
    lowered = "\n".join(lines).lower()
    return (
        len(lines) <= 4
        and all(len(line) <= 512 for line in lines)
        and not any(marker in lowered for marker in PROMPT_MARKERS + ERROR_MARKERS)
    )


def probe_existing_session(
    tool: str,
    provider_id: str,
    model_token: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout_seconds: int = 15,
) -> dict[str, Any]:
    """Run two fixed identity probes. They never request or change authentication."""
    model_argv = OPENCODE_MODELS_ARGV if tool == "OpenCode" else COMMANDCODE_MODELS_ARGV
    commands = (OPENCODE_PROVIDER_ARGV, model_argv) if tool == "OpenCode" else (COMMANDCODE_STATUS_ARGV, model_argv)
    completed_rows: list[subprocess.CompletedProcess[str]] = []
    probe_env = {key: os.environ[key] for key in PROBE_ENV_KEYS if key in os.environ}
    stages = ("providers", "models") if tool == "OpenCode" else ("status", "models")
    for stage, argv in zip(stages, commands):
        try:
            completed = runner(
                list(argv), input="", text=True, capture_output=True, check=False,
                timeout=timeout_seconds, env=probe_env,
            )
        except FileNotFoundError as exc:
            raise ExplicitSelectionError("configured_tool_unavailable", tool) from exc
        except subprocess.TimeoutExpired as exc:
            raise ExplicitSelectionError("tool_session_probe_timeout", tool) from exc
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")) > 262144:
            raise ExplicitSelectionError("tool_session_probe_oversized", tool)
        cleaned_stdout = _clean_bounded_output(stdout, tool=tool)
        cleaned_stderr = _clean_bounded_output(stderr, tool=tool)
        if any(marker in f"{cleaned_stdout}\n{cleaned_stderr}".lower() for marker in PROMPT_MARKERS):
            raise _identity_failure(tool, f"{stage}:authentication_prompt")
        if completed.returncode != 0:
            raise _identity_failure(tool, f"{stage}:nonzero_exit")
        if not _stderr_is_safe(tool, stderr):
            raise _identity_failure(tool, f"{stage}:stderr")
        completed_rows.append(completed)

    if tool == "Command Code":
        try:
            status = json.loads(completed_rows[0].stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise _identity_failure(tool, "status:json") from exc
        if (
            not isinstance(status, dict)
            or set(status) != COMMANDCODE_STATUS_FIELDS
            or status.get("authenticated") is not True
            or type(status.get("context_window")) is not int
            or status["context_window"] <= 0
            or any(
                not isinstance(status.get(field), str)
                or not status[field]
                or len(status[field]) > 512
                or any(not character.isprintable() for character in status[field])
                for field in ("model", "provider", "user", "version")
            )
        ):
            raise _identity_failure(tool, "status:shape")
        observed_tool_version = status["version"]
        model_output = _clean_bounded_output(completed_rows[1].stdout, tool=tool)
        first_columns = [line.split()[0] for line in model_output.splitlines() if line.split()]
        exact_model_verified = any(
            MODEL_TOKEN_RE.fullmatch(token) is not None and token == model_token
            for token in first_columns
        )
    else:
        provider_output = _clean_bounded_output(completed_rows[0].stdout, tool=tool)
        provider_lines = [line.strip() for line in provider_output.splitlines() if line.strip()]
        count_match = CREDENTIAL_COUNT_RE.fullmatch(provider_lines[-1]) if provider_lines else None
        if count_match is None or int(count_match.group("count")) <= 0:
            raise _identity_failure(tool, "providers:credential_count")
        model_output = _clean_bounded_output(completed_rows[1].stdout, tool=tool)
        model_lines = [line.strip() for line in model_output.splitlines() if line.strip()]
        if not model_lines or any(PROVIDER_MODEL_TOKEN_RE.fullmatch(line) is None for line in model_lines):
            raise _identity_failure(tool, "models:shape")
        exact_model_verified = model_token in model_lines and model_token.startswith(provider_id + "/")
        observed_tool_version = None
    if not exact_model_verified:
        raise ExplicitSelectionError("exact_model_unverifiable", model_token)
    combined = "\n".join((row.stdout or "") for row in completed_rows)
    probe = {
        "schema_version": 1,
        "artifact_type": "ConfiguredToolSessionProbe",
        "tool": tool,
        "probe_argv": [list(argv) for argv in commands],
        "provider_id": provider_id,
        "existing_session_verified": True,
        "exact_model_verified": True,
        "observed_model_token": model_token,
        "output_sha256": "sha256:" + hashlib.sha256(combined.encode("utf-8")).hexdigest(),
        "credential_material_accessed": False,
        "authentication_changed": False,
        "provider_execution_started": False,
    }
    if observed_tool_version is not None:
        probe["observed_tool_version"] = observed_tool_version
    return probe


def compile_selection(
    request: str,
    *,
    task_id: str,
    task_grant_sha256: str,
    effective_config: Mapping[str, Any],
    probe_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    timeout_seconds: int = 15,
    session_probe: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(task_id, str) or not task_id.strip():
        raise ExplicitSelectionError("task_id_invalid")
    if not isinstance(task_grant_sha256, str) or SHA256_RE.fullmatch(task_grant_sha256) is None:
        raise ExplicitSelectionError("task_grant_digest_invalid")
    tool, model = parse_request(request)
    binding_id, binding, route = _configured_binding(effective_config, tool, model)
    provider_id, model_token = _probe_identity(tool, route, model)
    probe = dict(session_probe) if session_probe is not None else probe_existing_session(
        tool, provider_id, model_token,
        runner=probe_runner, timeout_seconds=timeout_seconds,
    )
    selection = {
        "schema_version": 1,
        "artifact_type": "ExplicitToolModelSelection",
        "task_id": task_id,
        "task_grant_sha256": task_grant_sha256,
        "tool": tool,
        "requested_model": model,
        "route_name": binding["route"]["route_name"],
        "route_id": binding["route"]["route_id"],
        "provider": binding["route"]["provider"],
        "runtime": binding["route"]["runtime"],
        "billing_basis": binding["route"]["billing_basis"],
        "adapter_type": binding["adapter_type"],
        "adapter_sha256": binding["adapter_sha256"],
        "binding_id": binding_id,
        "binding_sha256": binding["adapter_binding_sha256"],
        "effective_config_sha256": digest(effective_config),
        "session_probe": probe,
        "persistence": "none",
        "no_fallback": True,
        "no_tool_substitution": True,
        "no_model_substitution": True,
        "authority_source": "task_grant_only",
        "authority_granted": False,
        "previewed": True,
        "execution_started": False,
    }
    selection["selection_sha256"] = digest(selection)
    return selection


def validate_selection(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExplicitSelectionError("explicit_selection_invalid")
    if set(value) != SELECTION_FIELDS:
        raise ExplicitSelectionError("explicit_selection_shape_invalid")
    supplied = value.get("selection_sha256")
    body = copy.deepcopy(value)
    body.pop("selection_sha256", None)
    if supplied != digest(body):
        raise ExplicitSelectionError("explicit_selection_digest_mismatch")
    required_true = (
        "no_fallback", "no_tool_substitution", "no_model_substitution", "previewed",
    )
    if (
        body.get("schema_version") != 1
        or body.get("artifact_type") != "ExplicitToolModelSelection"
        or body.get("persistence") != "none"
        or body.get("authority_source") != "task_grant_only"
        or body.get("authority_granted") is not False
        or body.get("execution_started") is not False
        or any(body.get(field) is not True for field in required_true)
    ):
        raise ExplicitSelectionError("explicit_selection_policy_invalid")
    probe = body.get("session_probe")
    provider_id = probe.get("provider_id") if isinstance(probe, dict) else None
    tool = body.get("tool")
    if tool not in TOOL_ADAPTERS or body.get("adapter_type") not in TOOL_ADAPTERS[tool]:
        raise ExplicitSelectionError("explicit_selection_tool_invalid")
    try:
        expected_provider_id, expected_model_token = _probe_identity(
            tool,
            {"route_id": body.get("route_id")},
            str(body.get("requested_model", "")),
        )
    except ExplicitSelectionError as exc:
        raise ExplicitSelectionError("explicit_selection_probe_invalid") from exc
    expected_commands = (
        [list(OPENCODE_PROVIDER_ARGV), list(OPENCODE_MODELS_ARGV)]
        if tool == "OpenCode" and isinstance(provider_id, str)
        else [list(COMMANDCODE_STATUS_ARGV), list(COMMANDCODE_MODELS_ARGV)]
    )
    if (
        not isinstance(probe, dict)
        or not PROBE_FIELDS.issubset(probe)
        or not set(probe).issubset(PROBE_FIELDS | OPTIONAL_PROBE_FIELDS)
        or probe.get("existing_session_verified") is not True
        or probe.get("exact_model_verified") is not True
        or probe.get("credential_material_accessed") is not False
        or probe.get("authentication_changed") is not False
        or probe.get("provider_execution_started") is not False
        or probe.get("tool") != tool
        or probe.get("probe_argv") != expected_commands
        or provider_id != expected_provider_id
        or probe.get("observed_model_token") != expected_model_token
    ):
        raise ExplicitSelectionError("explicit_selection_probe_invalid")
    observed_tool_version = probe.get("observed_tool_version")
    if observed_tool_version is not None and (
        tool != "Command Code"
        or not isinstance(observed_tool_version, str)
        or not observed_tool_version
        or len(observed_tool_version) > 512
        or any(not character.isprintable() for character in observed_tool_version)
    ):
        raise ExplicitSelectionError("explicit_selection_probe_invalid")
    if SHA256_RE.fullmatch(str(body.get("task_grant_sha256", ""))) is None:
        raise ExplicitSelectionError("task_grant_digest_invalid")
    body["selection_sha256"] = supplied
    return body


__all__ = [
    "ExplicitSelectionError", "compile_selection", "parse_request",
    "probe_existing_session", "validate_selection",
]
