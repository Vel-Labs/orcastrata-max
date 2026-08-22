#!/usr/bin/env python3
"""Compile admitted LoopRegistry matches into bounded WorkGraph references."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time
from typing import Any

import loop_registry
import workgraph
import loop_actions
import loop_run_trace


class CompilationError(Exception):
    def __init__(self, *codes: str):
        self.codes = sorted(set(codes or ("schema_invalid",)))
        super().__init__(",".join(self.codes))


def _create_or_verify_artifact(
    roots: dict[str, Path], locator: dict[str, str], raw: bytes,
) -> None:
    """Create one exact artifact, or accept only the same unique regular file."""
    root = roots[locator["root_id"]].resolve(strict=True)
    target = root / locator["path"]
    try:
        info = target.lstat()
        resolved = target.resolve(strict=True)
    except FileNotFoundError:
        loop_actions._safe_create(roots, locator, raw)  # noqa: SLF001
        return
    except OSError as exc:
        raise loop_actions.ActionError("reference_stale") from exc
    if resolved != target or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise loop_actions.ActionError("reference_stale")
    try:
        existing = target.read_bytes()
    except OSError as exc:
        raise loop_actions.ActionError("reference_stale") from exc
    if existing != raw:
        raise loop_actions.ActionError("reference_stale")


def _digest(value: object) -> str:
    raw = (loop_registry.canonical_json(value) + "\n").encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _locator_text(locator: dict[str, Any]) -> str:
    return f"{locator['root_id']}:{locator.get('path', locator.get('pattern'))}"


def _reference_evidence(evidence_id: str, locator: dict[str, Any], kind: str = "source_reference") -> dict[str, Any]:
    return {
        "id": evidence_id,
        "kind": kind,
        "locator": _locator_text(locator),
        "digest": locator["sha256"],
        "state": "observed",
        "claim_ids": [],
        "authority_effect": "none",
        "acceptance_effect": "none",
    }


def _load_workgraph(locator: dict[str, Any], roots: dict[str, Path]) -> None:
    errors: list[str] = []
    path = loop_registry._resolve(locator, roots, errors, require_digest=True)  # noqa: SLF001
    if errors or path is None:
        raise CompilationError(*(errors or ["reference_missing"]))
    try:
        document = loop_registry.load_json(path)
    except loop_registry.LoopContractError as error:
        raise CompilationError(*error.codes) from error
    receipt = workgraph.validate_document(document)
    if receipt["status"] != "valid":
        cycle = any(":cycle:" in row for row in receipt["errors"])
        raise CompilationError("static_cycle" if cycle else "schema_invalid")


def _graph(
    loop: dict[str, Any],
    event: dict[str, Any],
    registry_digest: str,
    event_digest: str,
    authority: dict[str, Any],
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    graph_ref = loop["graph"]["workgraph"]
    board_ref = loop["graph"]["goalbuddy_board"]
    evidence: list[dict[str, Any]] = [
        {
            "id": "EV-EVENT",
            "kind": "source_reference",
            "locator": f"loop-event:{event['event_id']}",
            "digest": event_digest,
            "state": "observed",
            "claim_ids": [],
            "authority_effect": "none",
            "acceptance_effect": "none",
        },
        {
            "id": "EV-REGISTRY",
            "kind": "source_reference",
            "locator": f"loop-registry:{loop['loop_id']}",
            "digest": registry_digest,
            "state": "observed",
            "claim_ids": [],
            "authority_effect": "none",
            "acceptance_effect": "none",
        },
        _reference_evidence("EV-AUTHORITY", authority, "receipt"),
    ]
    if graph_ref is not None:
        evidence.append(_reference_evidence("EV-WORKGRAPH", graph_ref))
    if board_ref is not None:
        evidence.append(_reference_evidence("EV-GOALBUDDY", board_ref))
    work_items: list[dict[str, Any]] = []
    prior: str | None = None
    for index, binding in enumerate(bindings, start=1):
        item_id = f"LOOP-ACTION-{index:03d}"
        output_id = f"EV-ACTION-OUTPUT-{index:03d}"
        evidence.append({
            "id": output_id,
            "kind": "command_result",
            "locator": f"loop-output:{binding['command_identity']}",
            "digest": "unknown",
            "state": "expected",
            "claim_ids": [],
            "authority_effect": "none",
            "acceptance_effect": "none",
        })
        reads = [_locator_text(row) for row in loop["scope"]["allowed_reads"]]
        writes = [_locator_text(row) for row in loop["scope"]["allowed_writes"]]
        work_items.append({
            "id": item_id,
            "kind": "task",
            "objective": f"Run fixed action profile {binding['profile_id']} under current bounded authority.",
            "status": "blocked" if prior else "active",
            "clarity_tier": "bounded",
            "scope": {"read": reads, "write": writes},
            "done_condition": "The fixed verifier completes and its LoopRunReceipt remains truthful.",
            "validation": [{
                "id": binding["validation_ids"][0],
                "kind": "command",
                "instruction": f"execute source-owned identity {binding['command_identity']}",
                "expected_result": "completed execution with exit status 0 and bounded evidence",
            }],
            "relationships": {
                "parent_of": [],
                "blocked_by": [prior] if prior else [],
                "related_to": [],
                "produces": [output_id],
                "consumes": ["EV-EVENT", "EV-REGISTRY", "EV-AUTHORITY"],
            },
            "owner_role": "Codexmax",
            "expected_artifacts": [output_id],
            "retry_policy": {
                "max_attempts": loop["budget"]["max_attempts"],
                "no_improvement_window": loop["budget"]["no_improvement_window"],
            },
            "stop_rule": "Stop on scope, authority, profile, budget, validation, or evidence failure.",
        })
        prior = item_id
    return {
        "schema_version": 1,
        "graph_id": f"loop-{loop['loop_id']}-v{loop['definition_version']}",
        "evidence": evidence,
        "work_items": work_items,
    }


def compile_loop(
    registry: dict[str, Any],
    event: dict[str, Any],
    *,
    evaluation_time: str,
    roots: dict[str, Path] | None = None,
    ledger: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a deterministic compilation; never execute or mutate references."""
    if roots is None or "workspace" not in roots or "codexmax_repo" not in roots:
        return {
            "schema_version": 1,
            "artifact_type": "LoopCompilation",
            "status": "rejected",
            "errors": ["path_invalid"],
            "compilation_id": None,
            "executed": False,
        }
    actual_roots = roots
    match = loop_registry.match_event(
        registry, event, evaluation_time=evaluation_time, roots=actual_roots,
        ledger=ledger, dry_run=False,
    )
    errors = list(match.get("errors", []))
    matched = match.get("matched_loop_ids", [])
    if len(matched) != 1:
        if not errors:
            errors.append("schema_invalid")
        return {
            "schema_version": 1,
            "artifact_type": "LoopCompilation",
            "status": "rejected",
            "errors": sorted(set(errors)),
            "compilation_id": None,
            "executed": False,
        }
    loop = next(row for row in registry["loops"] if row["loop_id"] == matched[0])
    authority = loop["contract_refs"]["authority_receipt"] or event["authority"]["receipt"]
    if authority is None or authority.get("sha256") == "unknown" or loop["lifecycle"]["state"] == "proposed":
        errors.append("authority_missing")
    graph_ref = loop["graph"]["workgraph"]
    board_ref = loop["graph"]["goalbuddy_board"]
    if event["subject"]["workgraph"] is not None and event["subject"]["workgraph"] != graph_ref:
        errors.append("reference_stale")
    if event["subject"]["goalbuddy_board"] is not None and event["subject"]["goalbuddy_board"] != board_ref:
        errors.append("reference_stale")
    if graph_ref is not None:
        try:
            _load_workgraph(graph_ref, actual_roots)
        except CompilationError as error:
            errors.extend(error.codes)
    bindings: list[dict[str, Any]] = []
    for profile_id in loop["action_profile_ids"]:
        try:
            profile = loop_actions.resolve_profile(profile_id, roots=actual_roots)
            binding = loop_actions.bind_profile(profile, loop)
            bindings.append(binding)
        except loop_actions.ActionError as error:
            errors.extend(error.codes)
    if errors:
        return {
            "schema_version": 1,
            "artifact_type": "LoopCompilation",
            "status": "rejected",
            "errors": sorted(set(errors)),
            "compilation_id": None,
            "executed": False,
        }
    registry_digest = _digest(registry)
    event_digest = _digest(event)
    compiled_graph = _graph(loop, event, registry_digest, event_digest, authority, bindings)
    graph_receipt = workgraph.validate_document(compiled_graph)
    if graph_receipt["status"] != "valid":
        return {
            "schema_version": 1,
            "artifact_type": "LoopCompilation",
            "status": "rejected",
            "errors": ["static_cycle" if any(":cycle:" in row for row in graph_receipt["errors"]) else "schema_invalid"],
            "compilation_id": None,
            "executed": False,
        }
    core = {
        "registry": {"registry_id": registry["registry_id"], "sha256": registry_digest},
        "event": {"event_id": event["event_id"], "sha256": event_digest},
        "loop": {
            "loop_id": loop["loop_id"],
            "definition_version": loop["definition_version"],
            "lifecycle": loop["lifecycle"]["state"],
        },
        "evaluation_time": evaluation_time,
        "authority": copy.deepcopy(authority),
        "references": {"workgraph": copy.deepcopy(graph_ref), "goalbuddy_board": copy.deepcopy(board_ref)},
        "action_bindings": bindings,
        "workgraph": compiled_graph,
    }
    compilation_id = "compile-" + _digest(core)[7:31]
    return {
        "schema_version": 1,
        "artifact_type": "LoopCompilation",
        "status": "candidate",
        "errors": [],
        "compilation_id": compilation_id,
        **core,
        "executed": False,
        "mutations": {"workgraph": False, "goalbuddy": False},
    }


def run_loop(
    registry: dict[str, Any],
    event: dict[str, Any],
    *,
    evaluation_time: str,
    roots: dict[str, Path] | None = None,
    ledger: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute only from raw inputs and caller-supplied logical roots."""
    def capture_fixed(profile: dict[str, Any], timeout: int, limit: int) -> dict[str, Any]:
        """Capture one already re-resolved source profile; not module-callable."""
        start = time.monotonic()
        process = subprocess.Popen(
            profile["argv"], cwd=profile["resolved_cwd"], env=loop_actions.FIXED_ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            shell=False, start_new_session=True,
        )
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        captured = bytearray()
        truncated = False
        timed_out = False
        deadline = start + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max(0, limit - len(captured))
                captured.extend(chunk[:room])
                truncated = truncated or len(chunk) > room
            if process.poll() is not None and not selector.get_map():
                break
        if timed_out:
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=1)
        else:
            process.wait()
        selector.close()
        process.stdout.close()
        duration_ms = max(0, int((time.monotonic() - start) * 1000))
        return {
            "returncode": process.returncode,
            "output": bytes(captured),
            "truncated": truncated,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
        }

    if roots is None or "workspace" not in roots or "codexmax_repo" not in roots:
        return [loop_actions.rejected_receipt(
            registry, event, ["path_invalid"], recorded_at=evaluation_time,
        )]
    actual_roots = roots
    compilation = compile_loop(
        registry, event, evaluation_time=evaluation_time,
        roots=actual_roots, ledger=ledger,
    )
    if compilation["status"] == "rejected":
        return [loop_actions.rejected_receipt(
            registry, event, compilation["errors"], recorded_at=evaluation_time,
        )]
    loop = next((row for row in registry["loops"] if row["loop_id"] == compilation["loop"]["loop_id"]), None)
    if loop is None:
        raise loop_actions.ActionError("reference_stale")
    receipts: list[dict[str, Any]] = []
    for binding in compilation["action_bindings"]:
        current_compilation = compile_loop(
            registry, event, evaluation_time=evaluation_time,
            roots=actual_roots, ledger=ledger,
        )
        if current_compilation["status"] == "rejected":
            return [loop_actions.rejected_receipt(
                registry, event, current_compilation["errors"],
                recorded_at=evaluation_time,
            )]
        if current_compilation != compilation:
            code = (
                "action_profile_unbound"
                if current_compilation.get("action_bindings") != compilation.get("action_bindings")
                else "reference_stale"
            )
            return [loop_actions.rejected_receipt(
                registry, event, [code],
                recorded_at=evaluation_time,
            )]
        profile = loop_actions.resolve_profile(binding["profile_id"], roots=actual_roots)
        current = loop_actions.bind_profile(profile, loop)
        if current != binding:
            return [loop_actions.rejected_receipt(
                registry, event, ["action_profile_unbound"],
                recorded_at=evaluation_time,
            )]
        current_errors = loop_registry.validate_registry(
            registry, roots=actual_roots, resolve_references=True,
        )
        if current_errors:
            return [loop_actions.rejected_receipt(
                registry, event, current_errors, recorded_at=evaluation_time,
            )]
        started = loop_actions._utc_now()  # noqa: SLF001
        captured = capture_fixed(
            profile, binding["effective_timeout_seconds"],
            binding["effective_max_output_bytes"],
        )
        finished = loop_actions._utc_now()  # noqa: SLF001
        receipt_id = "receipt-" + hashlib.sha256(
            f"{compilation['compilation_id']}:{binding['profile_id']}:1".encode()
        ).hexdigest()[:24]
        output_locator = loop_actions._sink_locator(loop, receipt_id, ".output.txt")  # noqa: SLF001
        loop_actions._safe_create(actual_roots, output_locator, captured["output"])  # noqa: SLF001
        receipt = loop_actions._receipt(  # noqa: SLF001
            compilation, registry, event, loop, binding, captured,
            started, finished, output_locator,
        )
        receipt_locator = loop_actions._sink_locator(loop, receipt["receipt_id"], ".json")  # noqa: SLF001
        trace_locator = loop_run_trace.adjacent_trace_locator(receipt_locator)
        loop_binding = {
            "loop_id": loop["loop_id"],
            "definition_version": loop["definition_version"],
        }
        trace = loop_run_trace.build_trace(
            receipt,
            event,
            receipt_locator=receipt_locator,
            output_locator=output_locator,
            roots=actual_roots,
        )
        trace_raw = loop_run_trace.trace_bytes(trace)
        receipt["artifacts"].append({
            "artifact_id": "loop-run-trace",
            "path": trace_locator,
            "sha256": loop_run_trace.digest_bytes(trace_raw),
            "state": "written",
        })
        errors = loop_registry.verify_receipt(receipt, roots=actual_roots)
        if errors:
            raise loop_actions.ActionError(*errors)
        _create_or_verify_artifact(actual_roots, trace_locator, trace_raw)
        loop_actions._safe_create(  # noqa: SLF001
            actual_roots, receipt_locator,
            (loop_registry.canonical_json(receipt) + "\n").encode("utf-8"),
        )
        receipts.append(receipt)
    return receipts
