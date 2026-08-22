#!/usr/bin/env python3
"""Source-local provider execution custody.

This backend proves restart, replay, and filesystem behavior. Its records are
explicitly non-authoritative. Production authority remains with the protected
receiver and its independently anchored records.
"""
from __future__ import annotations

import fcntl
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping


def _load(name: str) -> Any:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("codexmax_" + name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(name + "_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WORK = _load("provider_work_authority")
RECEIVER = _load("supported_host_protected_receiver_v1")


class BackendError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code + ((": " + detail) if detail else ""))


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _safe_regular(path: Path, root: Path, *, create: bool = False) -> int:
    root = root.resolve(strict=True)
    try:
        parent = path.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BackendError("path_escape", str(path)) from exc
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BackendError("descriptor_open_failed", str(path)) from exc
    info = os.fstat(fd)
    try:
        current = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise BackendError("descriptor_identity_invalid", str(path))
    except Exception:
        os.close(fd)
        raise
    return fd


def issue_source_local_authority(receiver_root: Path, card_value: Any, grant_value: Any,
                                 *, issued_at: str) -> dict[str, Any]:
    """Create a non-authoritative receiver fixture with absent-only publication."""
    card = WORK.validate_capability_card(card_value)
    grant = WORK.validate_task_grant(grant_value)
    WORK.effective_authority(card, grant, now=issued_at)
    root = receiver_root.resolve(strict=True)
    record = {
        "schema_version": 1,
        "artifact_type": "ProviderReceiverAuthorityRecord",
        "authority_mode": "source_local_non_authoritative",
        "issued_at": issued_at,
        "qualification_sha256": card["qualification_sha256"],
        "capability_sha256": card["capability_sha256"],
        "grant_sha256": grant["grant_sha256"],
        "task_id": grant["task_id"],
        "route_name": grant["route_name"],
        "lease_id": grant["lease_id"],
        "fencing_token": grant["fencing_token"],
        "expires_at": min(card["expires_at"], grant["expires_at"]),
    }
    record["record_sha256"] = WORK.canonical_digest(record)
    name = "authority-" + record["record_sha256"].split(":", 1)[1] + ".json"
    path = root / name
    raw = _canonical(record)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
    except FileExistsError:
        fd = _safe_regular(path, root)
        try:
            if os.pread(fd, os.fstat(fd).st_size, 0) != raw:
                raise BackendError("authority_collision", name)
        finally:
            os.close(fd)
    else:
        try:
            os.write(fd, raw); os.fsync(fd)
        finally:
            os.close(fd)
    return {"path": name, "sha256": _sha(raw), "record_sha256": record["record_sha256"]}


def load_source_local_authority(receiver_root: Path, reference: Mapping[str, Any],
                                card_value: Any, grant_value: Any, *, now: str) -> dict[str, Any]:
    if not isinstance(reference, Mapping) or set(reference) != {"path", "sha256", "record_sha256"}:
        raise BackendError("authority_reference_invalid")
    name = reference["path"]
    if not isinstance(name, str) or Path(name).name != name:
        raise BackendError("authority_reference_escape")
    root = receiver_root.resolve(strict=True)
    fd = _safe_regular(root / name, root)
    try:
        before = os.fstat(fd); raw = os.pread(fd, before.st_size, 0); after = os.fstat(fd)
    finally:
        os.close(fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise BackendError("authority_descriptor_mutation")
    if _sha(raw) != reference["sha256"]:
        raise BackendError("authority_file_digest_mismatch")
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendError("authority_record_invalid") from exc
    card = WORK.validate_capability_card(card_value); grant = WORK.validate_task_grant(grant_value)
    WORK.effective_authority(card, grant, now=now)
    expected = {
        "qualification_sha256": card["qualification_sha256"], "capability_sha256": card["capability_sha256"],
        "grant_sha256": grant["grant_sha256"], "task_id": grant["task_id"], "route_name": grant["route_name"],
        "lease_id": grant["lease_id"], "fencing_token": grant["fencing_token"],
    }
    if record.get("authority_mode") != "source_local_non_authoritative" or any(record.get(k) != v for k, v in expected.items()):
        raise BackendError("authority_binding_mismatch")
    payload = dict(record); supplied = payload.pop("record_sha256", None)
    if supplied != reference["record_sha256"] or WORK.canonical_digest(payload) != supplied:
        raise BackendError("authority_record_digest_mismatch")
    return record


def consume_source_local_authority_once(receiver_root: Path, record: Mapping[str, Any], *, attempt_id: str) -> Path:
    """Claim one simulated authority record once across every journal/worktree."""
    root = receiver_root.resolve(strict=True)
    if not isinstance(attempt_id, str) or Path(attempt_id).name != attempt_id:
        raise BackendError("attempt_id_invalid")
    marker = root / ("consumed-" + str(record["record_sha256"]).split(":", 1)[1] + ".json")
    raw = _canonical({"authority_record_sha256": record["record_sha256"], "attempt_id": attempt_id,
                      "authority_mode": "source_local_non_authoritative"})
    try: fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as exc: raise BackendError("authority_already_consumed") from exc
    try: os.write(fd, raw); os.fsync(fd)
    finally: os.close(fd)
    return marker


def begin_source_local_attempt(journal_path: Path, receiver_root: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    """Durably enter consuming. Any interrupted consuming state becomes unknown."""
    fd = _safe_regular(journal_path, receiver_root, create=True)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        data = os.pread(fd, os.fstat(fd).st_size, 0)
        state = RECEIVER.verify_journal(data)
        if state["state"] == "transaction_consuming":
            recovered = RECEIVER.recover_source_local_consuming(fd)
            raise BackendError("execution_unknown_no_retry", recovered["status"])
        if state["state"] is not None:
            raise BackendError("attempt_replay_forbidden", str(state["state"]))
        bindings = WORK.canonical_digest({k: record[k] for k in (
            "record_sha256", "qualification_sha256", "grant_sha256", "lease_id", "fencing_token")})
        for target in ("pending_host_facts", "generation_reserved", "launch_attested", "transaction_issued", "transaction_consuming"):
            event = RECEIVER.make_source_local_event(state, target, task_selector=record["task_id"], generation=1,
                                                     bindings_sha256=bindings)
            os.lseek(fd, 0, os.SEEK_END); os.write(fd, _canonical(event)); os.fsync(fd)
            state = RECEIVER.verify_journal(os.pread(fd, os.fstat(fd).st_size, 0))
        return state
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


def finish_source_local_attempt(journal_path: Path, receiver_root: Path, *, success: bool) -> dict[str, Any]:
    fd = _safe_regular(journal_path, receiver_root)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        state = RECEIVER.verify_journal(os.pread(fd, os.fstat(fd).st_size, 0))
        if state["state"] != "transaction_consuming":
            raise BackendError("attempt_not_consuming", str(state["state"]))
        target = "consumed_success" if success else "consumed_failure"
        event = RECEIVER.make_source_local_event(state, target, task_selector=state["task_selector"],
                                                 generation=state["generation"], bindings_sha256=state["bindings_sha256"])
        os.lseek(fd, 0, os.SEEK_END); os.write(fd, _canonical(event)); os.fsync(fd)
        return RECEIVER.verify_journal(os.pread(fd, os.fstat(fd).st_size, 0))
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


def reconcile_source_local_unknown(journal_path: Path, receiver_root: Path) -> dict[str, Any]:
    fd = _safe_regular(journal_path, receiver_root); fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        state = RECEIVER.verify_journal(os.pread(fd, os.fstat(fd).st_size, 0))
        if state["state"] == "execution_unknown": return state
        if state["state"] not in {"transaction_consuming", "consumed_success", "consumed_failure"}:
            raise BackendError("attempt_unknown_reconciliation_invalid", str(state["state"]))
        event = RECEIVER.make_source_local_event(state, "execution_unknown", task_selector=state["task_selector"],
            generation=state["generation"], bindings_sha256=state["bindings_sha256"])
        os.lseek(fd, 0, os.SEEK_END); os.write(fd, _canonical(event)); os.fsync(fd)
        return RECEIVER.verify_journal(os.pread(fd, os.fstat(fd).st_size, 0))
    finally: fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


def descriptor_snapshot(workspace: Path, scope_root: Path) -> tuple[dict[str, str], str]:
    root = scope_root.resolve(strict=True); workspace = workspace.resolve(strict=True)
    try: workspace.relative_to(root)
    except ValueError as exc: raise BackendError("workspace_escape") from exc
    files: dict[str, str] = {}
    for current, directories, names in os.walk(workspace, followlinks=False):
        base = Path(current)
        for name in [*directories, *names]:
            if (base / name).is_symlink(): raise BackendError("workspace_symlink_escape", str(base / name))
        for name in names:
            path = base / name; fd = _safe_regular(path, root)
            try:
                before = os.fstat(fd); raw = os.pread(fd, before.st_size, 0); after = os.fstat(fd)
            finally: os.close(fd)
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise BackendError("snapshot_descriptor_mutation", str(path))
            files[path.relative_to(workspace).as_posix()] = _sha(raw)
    return files, WORK.canonical_digest(files)


def create_source_local_worktree(source: Path, execution_root: Path, *, attempt_id: str,
                                 expected_base_sha256: str) -> Path:
    """Create an executor-owned copy. It is a non-authoritative test worktree."""
    root = execution_root.resolve(strict=True); source = source.resolve(strict=True)
    if source == root:
        raise BackendError("source_is_execution_root")
    before, tree = descriptor_snapshot(source, source.parent)
    if tree != expected_base_sha256:
        raise BackendError("stale_base_tree")
    if not isinstance(attempt_id, str) or not attempt_id or Path(attempt_id).name != attempt_id:
        raise BackendError("attempt_id_invalid")
    destination = root / attempt_id
    try: destination.mkdir(mode=0o700)
    except FileExistsError as exc: raise BackendError("worktree_collision") from exc
    try:
        for relative in sorted(before):
            source_path = source / relative; target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source_fd = _safe_regular(source_path, source.parent)
            try:
                info = os.fstat(source_fd); raw = os.pread(source_fd, info.st_size, 0)
                if _sha(raw) != before[relative]: raise BackendError("source_descriptor_mutation", relative)
            finally: os.close(source_fd)
            target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try: os.write(target_fd, raw); os.fsync(target_fd)
            finally: os.close(target_fd)
        copied, copied_tree = descriptor_snapshot(destination, root)
        if copied != before or copied_tree != tree: raise BackendError("worktree_copy_mismatch")
        return destination
    except Exception:
        # Preserve partial residue for review. Never overwrite or reuse it.
        raise


def canonical_change_inventory(before: Mapping[str, str], after: Mapping[str, str]) -> tuple[list[dict[str, Any]], bytes]:
    inventory = [{"path": path, "before_sha256": before.get(path), "after_sha256": after.get(path)}
                 for path in sorted(set(before) | set(after)) if before.get(path) != after.get(path)]
    return inventory, _canonical(inventory)


def read_changed_bytes(workspace: Path, relative_paths: list[str], scope_root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    workspace = workspace.resolve(strict=True); root = scope_root.resolve(strict=True)
    workspace.relative_to(root)
    for relative in relative_paths:
        path = workspace / relative
        if not path.exists(): result[relative] = {"state": "absent", "base64": None}; continue
        fd = _safe_regular(path, root)
        try:
            before = os.fstat(fd); raw = os.pread(fd, before.st_size, 0); after = os.fstat(fd)
        finally: os.close(fd)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise BackendError("changed_bytes_descriptor_mutation", relative)
        result[relative] = {"state": "present", "base64": base64.b64encode(raw).decode("ascii")}
    return result


class SourceLocalLeaseAdapter:
    """Durable non-authoritative scheduler lease state for simulated execution."""
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)

    def _path(self, binding: Mapping[str, Any]) -> Path:
        attempt = binding.get("attempt_id")
        if not isinstance(attempt, str) or Path(attempt).name != attempt:
            raise BackendError("attempt_id_invalid")
        return self.root / (attempt + ".lease.jsonl")

    def start(self, binding: Mapping[str, Any], now: str) -> None:
        WORK._time(now, "now")
        row = {"state": "started", "attempt_id": binding["attempt_id"], "lease_id": binding["lease_id"],
               "fencing_token": binding["fencing_token"], "at": now}
        path = self._path(binding)
        try: fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError as exc: raise BackendError("scheduler_lease_replay") from exc
        try: os.write(fd, _canonical(row)); os.fsync(fd)
        finally: os.close(fd)

    def finish(self, binding: Mapping[str, Any], state: str, now: str) -> None:
        if state not in {"succeeded", "failed", "execution_unknown"}: raise BackendError("lease_terminal_invalid")
        WORK._time(now, "now"); path = self._path(binding); fd = _safe_regular(path, self.root)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            raw = os.pread(fd, os.fstat(fd).st_size, 0); rows = [json.loads(line) for line in raw.splitlines()]
            if len(rows) != 1 or rows[0].get("state") != "started": raise BackendError("scheduler_lease_replay")
            if any(rows[0].get(k) != binding.get(k) for k in ("attempt_id", "lease_id", "fencing_token")):
                raise BackendError("scheduler_lease_fence_mismatch")
            os.lseek(fd, 0, os.SEEK_END); os.write(fd, _canonical({"state": state, "attempt_id": binding["attempt_id"],
                "lease_id": binding["lease_id"], "fencing_token": binding["fencing_token"], "at": now})); os.fsync(fd)
        finally: fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)

    def reconcile_unknown(self, binding: Mapping[str, Any], now: str) -> None:
        WORK._time(now, "now"); path = self._path(binding); fd = _safe_regular(path, self.root)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            rows = [json.loads(line) for line in os.pread(fd, os.fstat(fd).st_size, 0).splitlines()]
            if rows[-1]["state"] == "execution_unknown": return
            if rows[-1]["state"] not in {"started", "succeeded", "failed"}: raise BackendError("scheduler_reconcile_invalid")
            if any(rows[0].get(k) != binding.get(k) for k in ("attempt_id", "lease_id", "fencing_token")):
                raise BackendError("scheduler_lease_fence_mismatch")
            os.lseek(fd, 0, os.SEEK_END); os.write(fd, _canonical({"state": "execution_unknown",
                "attempt_id": binding["attempt_id"], "lease_id": binding["lease_id"],
                "fencing_token": binding["fencing_token"], "at": now})); os.fsync(fd)
        finally: fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


__all__ = ["BackendError", "begin_source_local_attempt", "canonical_change_inventory", "consume_source_local_authority_once", "create_source_local_worktree",
           "descriptor_snapshot", "finish_source_local_attempt", "issue_source_local_authority",
           "load_source_local_authority", "read_changed_bytes", "reconcile_source_local_unknown", "SourceLocalLeaseAdapter"]
