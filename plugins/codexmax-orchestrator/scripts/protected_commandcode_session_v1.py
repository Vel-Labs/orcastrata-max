#!/usr/bin/env python3
"""Pending-only protected Command Code subscription-session boundary."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping, Protocol


# Compatibility aliases for the original Pro-only caller. Preparation does not
# default to these values. Each request must carry one exact table binding.
TASK_ID = "T156"
ROUTE_NAME = "worker_deepseek_v4_pro"
MODEL = "deepseek/deepseek-v4-pro"
COMMANDCODE_VERSION = "1.23.2"
BILLING_BASIS = "subscription"
_POLICY_SPEC = importlib.util.spec_from_file_location(
    "commandcode_provider_execution_policy",
    Path(__file__).with_name("provider_execution_policy.py"),
)
if _POLICY_SPEC is None or _POLICY_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("provider execution policy is unavailable")
_POLICY = importlib.util.module_from_spec(_POLICY_SPEC)
_POLICY_SPEC.loader.exec_module(_POLICY)
# This protected historical surface owns its fixed version. The configured V1
# route map is version-neutral and must not inherit this compatibility value.
ROUTE_BINDINGS = MappingProxyType({
    "worker_deepseek_v4_flash": MappingProxyType({
        "route_id": "commandcode-subscription-deepseek-v4-flash",
        "model": "deepseek/deepseek-v4-flash",
        "commandcode_version": COMMANDCODE_VERSION,
        "billing_basis": BILLING_BASIS,
    }),
    "worker_deepseek_v4_pro": MappingProxyType({
        "route_id": "commandcode-subscription-deepseek-v4-pro",
        "model": "deepseek/deepseek-v4-pro",
        "commandcode_version": COMMANDCODE_VERSION,
        "billing_basis": BILLING_BASIS,
    }),
})
MODE_POLICY = {"read_only": "plan", "scoped_write": "pretooluse_guard"}
MAX_TURNS = 20
ISOLATION_FLAGS = ("--no-session", "--no-skills", "--skip-onboarding", "--no-auto-update")
ENVIRONMENT = (("LANG", "C"), ("LC_ALL", "C"))
REFERENCE = re.compile(r"\Aprotected-commandcode-[A-Za-z0-9_-]{16,80}\Z")
IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}\Z")
SHA = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
MAX_TTL_SECONDS = 300
PREPARE_FIELDS = {
    "schema_version", "task_id", "route_name", "route_id", "model", "mode",
    "billing_basis", "prompt", "credential_service_reference", "scoped_write_grant",
}
PUBLIC_FIELDS = {
    "schema_version", "capability_id", "sequence", "task_id", "route_name",
    "route_id", "model", "mode", "commandcode_version", "billing_basis",
    "command_link_identity_sha256", "package_identity_sha256",
    "entry_identity_sha256", "node_identity_sha256", "sandbox_identity_sha256",
    "worktree_identity_sha256", "argv_sha256", "environment_sha256",
    "credential_reference_sha256", "scoped_write_grant_sha256", "challenge_sha256",
    "issued_at", "expires_at",
    "writer_service_id", "writer_build_sha256", "writer_uid",
    "writer_session_sha256", "writer_receipt_sha256", "anchor_service_id",
    "anchor_build_sha256", "anchor_uid", "anchor_session_sha256",
    "anchor_receipt_sha256", "capability_checksum_sha256",
}


class ProtectedCommandCodeError(ValueError):
    def __init__(self, code: str, field_name: str = "") -> None:
        self.code = code
        self.field_name = field_name
        super().__init__(code + ((":" + field_name) if field_name else ""))


class ProtectedCapabilityService(Protocol):
    def consume_one_use_capability(
        self, *, capability_id: str, sequence: int, capability_checksum_sha256: str,
    ) -> object: ...


class DescriptorNativeLauncher(Protocol):
    def launch_bound_session(
        self, *, node_fd: int, entry_fd: int, sandbox_fd: int, worktree_fd: int,
        argv_sha256: str, environment_sha256: str, one_use_service_capability: object,
    ) -> object: ...


@dataclass(frozen=True)
class DescriptorIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str | None


@dataclass(frozen=True)
class PreparedCommandCodeSession:
    """Public, non-authoritative bindings. No raw auth reference or env value."""

    task_id: str
    route_name: str
    route_id: str
    model: str
    mode: str
    commandcode_version: str
    billing_basis: str
    command_link_fd: int
    package_fd: int
    entry_fd: int
    node_fd: int
    sandbox_fd: int
    worktree_fd: int
    command_link_identity_sha256: str
    package_identity_sha256: str
    entry_identity_sha256: str
    node_identity_sha256: str
    sandbox_identity_sha256: str
    worktree_identity_sha256: str
    argv_sha256: str
    environment_sha256: str
    credential_reference_sha256: str
    scoped_write_grant_sha256: str
    prepared_checksum_sha256: str


class SourceLocalOneUseJournal:
    """Non-authoritative state model for replay and recovery tests only."""

    def __init__(self) -> None:
        self.state = "issued"
        self.digest: str | None = None

    def begin(self, digest: str) -> None:
        if not isinstance(digest, str) or SHA.fullmatch(digest) is None:
            raise ProtectedCommandCodeError("commandcode_capability_digest_invalid")
        if self.state == "consuming":
            self.state = "execution_unknown"
            raise ProtectedCommandCodeError("commandcode_execution_unknown_no_retry")
        if self.state != "issued":
            raise ProtectedCommandCodeError("commandcode_capability_replay_forbidden")
        self.digest = digest
        self.state = "consuming"

    def finish(self, digest: str, *, success: bool) -> None:
        if self.state != "consuming" or digest != self.digest:
            raise ProtectedCommandCodeError("commandcode_capability_finalization_invalid")
        self.state = "consumed_success" if success else "consumed_failure"

    def recover(self) -> None:
        if self.state == "consuming":
            self.state = "execution_unknown"
        elif self.state not in {"consumed_success", "consumed_failure", "execution_unknown"}:
            raise ProtectedCommandCodeError("commandcode_capability_recovery_invalid")


class SourceLocalGuardSequence:
    """Non-authoritative one-session read-mutate-read state model."""

    def __init__(self, *, attempt_id: str, session_id: str, mutation_tool: str) -> None:
        if not attempt_id or not session_id or mutation_tool not in {"write_file", "edit_file"}:
            raise ProtectedCommandCodeError("commandcode_guard_sequence_binding_invalid")
        self.attempt_id = attempt_id
        self.session_id = session_id
        self.sequence = ("read_file", mutation_tool, "read_file")
        self.index = 0
        self.state = "issued"

    def admit(self, *, attempt_id: str, session_id: str, tool: str) -> None:
        if attempt_id != self.attempt_id or session_id != self.session_id:
            raise ProtectedCommandCodeError("commandcode_guard_session_attempt_substitution")
        if self.state in {"consuming", "execution_unknown", "consumed"}:
            raise ProtectedCommandCodeError("commandcode_guard_replay_forbidden")
        if self.index >= len(self.sequence) or tool != self.sequence[self.index]:
            raise ProtectedCommandCodeError("commandcode_guard_order_invalid")
        if self.index == 1:
            self.state = "consuming"
        self.index += 1
        if self.index == 1:
            self.state = "read_verified"
        elif self.index == 3:
            self.state = "consumed"

    def mutation_completed(self) -> None:
        if self.state != "consuming" or self.index != 2:
            raise ProtectedCommandCodeError("commandcode_guard_state_invalid")
        self.state = "mutated"

    def recover(self) -> None:
        if self.state in {"consuming", "mutated"}:
            self.state = "execution_unknown"
        elif self.state != "consumed":
            raise ProtectedCommandCodeError("commandcode_guard_state_reset_forbidden")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_fd(descriptor: int, size: int) -> bytes:
    if size < 0 or size > 256 * 1024 * 1024:
        raise ProtectedCommandCodeError("commandcode_descriptor_size_invalid")
    raw = b""
    while len(raw) < size:
        chunk = os.pread(descriptor, min(65536, size - len(raw)), len(raw))
        if not chunk:
            break
        raw += chunk
    if len(raw) != size:
        raise ProtectedCommandCodeError("commandcode_descriptor_read_incomplete")
    return raw


def _identity(descriptor: int, field_name: str, *, directory: bool = False) -> DescriptorIdentity:
    try:
        before = os.fstat(descriptor)
        if directory:
            if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o700:
                raise ProtectedCommandCodeError("commandcode_worktree_identity_invalid", field_name)
            if os.listdir(descriptor):
                raise ProtectedCommandCodeError("commandcode_worktree_not_empty", field_name)
            digest = None
        else:
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ProtectedCommandCodeError("commandcode_descriptor_identity_invalid", field_name)
            digest = _sha(_read_fd(descriptor, before.st_size))
        after = os.fstat(descriptor)
    except OSError as exc:
        raise ProtectedCommandCodeError("commandcode_descriptor_unavailable", field_name) from exc
    fields = lambda row: (
        row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid, row.st_nlink,
        row.st_size, row.st_mtime_ns, row.st_ctime_ns,
    )
    if fields(before) != fields(after):
        raise ProtectedCommandCodeError("commandcode_descriptor_identity_changed", field_name)
    return DescriptorIdentity(*fields(after), digest)


def _identity_sha(identity: DescriptorIdentity) -> str:
    return _sha(_canonical(asdict(identity)))


def _package_version(descriptor: int) -> str:
    identity = _identity(descriptor, "package_fd")
    try:
        value = json.loads(_read_fd(descriptor, identity.size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectedCommandCodeError("commandcode_package_invalid") from exc
    expected_bin = {
        "cmd": "dist/index.mjs", "cmdc": "dist/index.mjs",
        "command-code": "dist/index.mjs", "commandcode": "dist/index.mjs",
    }
    if not isinstance(value, dict) or value.get("name") != "command-code" or value.get("version") != COMMANDCODE_VERSION or value.get("bin") != expected_bin:
        raise ProtectedCommandCodeError("commandcode_package_binding_invalid")
    return COMMANDCODE_VERSION


def prepared_checksum_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("prepared_checksum_sha256", None)
    return _sha(_canonical(payload))


def capability_checksum_sha256(value: Mapping[str, Any]) -> str:
    payload = dict(value)
    payload.pop("capability_checksum_sha256", None)
    return _sha(_canonical(payload))


def prepare_session(
    value: Any, *, command_link_fd: int, package_fd: int, entry_fd: int,
    node_fd: int, sandbox_fd: int, worktree_fd: int,
) -> PreparedCommandCodeSession:
    if not isinstance(value, Mapping) or set(value) != PREPARE_FIELDS:
        raise ProtectedCommandCodeError("commandcode_prepare_shape_invalid")
    row = dict(value)
    if (
        row["schema_version"] != 1
        or not isinstance(row["task_id"], str)
        or IDENTIFIER.fullmatch(row["task_id"]) is None
        or row["mode"] not in MODE_POLICY
    ):
        raise ProtectedCommandCodeError("commandcode_task_route_model_mode_invalid")
    binding = ROUTE_BINDINGS.get(row["route_name"])
    if binding is None or any(
        row[field_name] != binding[field_name]
        for field_name in ("route_id", "model", "billing_basis")
    ):
        raise ProtectedCommandCodeError("commandcode_route_binding_invalid")
    prompt = row["prompt"]
    reference = row["credential_service_reference"]
    if not isinstance(prompt, str) or not prompt or "\x00" in prompt or len(prompt.encode()) > 131072:
        raise ProtectedCommandCodeError("commandcode_prompt_invalid")
    if not isinstance(reference, str) or REFERENCE.fullmatch(reference) is None:
        raise ProtectedCommandCodeError("commandcode_credential_reference_invalid")
    scoped_write_grant = row["scoped_write_grant"]
    if row["mode"] == "read_only":
        if scoped_write_grant is not None:
            raise ProtectedCommandCodeError("commandcode_read_only_guard_forbidden")
        scoped_write_grant_sha256 = _sha(_canonical({"mode": "read_only", "guard": None}))
    else:
        try:
            guarded = _POLICY.validate_commandcode_scoped_write_grant(
                scoped_write_grant,
                route_name=row["route_name"], model=row["model"], task_id=row["task_id"],
            )
        except _POLICY.ExecutionPolicyError as exc:
            raise ProtectedCommandCodeError("commandcode_scoped_write_guard_invalid", exc.path) from exc
        scoped_write_grant_sha256 = guarded["grant_sha256"]
    identities = {
        "command_link": _identity(command_link_fd, "command_link_fd"),
        "package": _identity(package_fd, "package_fd"),
        "entry": _identity(entry_fd, "entry_fd"),
        "node": _identity(node_fd, "node_fd"),
        "sandbox": _identity(sandbox_fd, "sandbox_fd"),
        "worktree": _identity(worktree_fd, "worktree_fd", directory=True),
    }
    if len({(item.device, item.inode) for item in identities.values()}) != len(identities):
        raise ProtectedCommandCodeError("commandcode_descriptor_alias_forbidden")
    version = _package_version(package_fd)
    argv = ["-p", prompt, "--model", row["model"], "--max-turns", str(MAX_TURNS)]
    if row["mode"] == "read_only":
        argv.extend(("--permission-mode", "plan"))
    else:
        argv.extend(("--yolo", "--tools-enable", ",".join(_POLICY.COMMANDCODE_FILE_TOOLS)))
    argv.extend(ISOLATION_FLAGS)
    payload = {
        "task_id": row["task_id"], "route_name": row["route_name"],
        "route_id": row["route_id"], "model": row["model"],
        "mode": row["mode"], "commandcode_version": version,
        "billing_basis": row["billing_basis"],
        "command_link_fd": command_link_fd, "package_fd": package_fd,
        "entry_fd": entry_fd, "node_fd": node_fd, "sandbox_fd": sandbox_fd,
        "worktree_fd": worktree_fd,
        "command_link_identity_sha256": _identity_sha(identities["command_link"]),
        "package_identity_sha256": _identity_sha(identities["package"]),
        "entry_identity_sha256": _identity_sha(identities["entry"]),
        "node_identity_sha256": _identity_sha(identities["node"]),
        "sandbox_identity_sha256": _identity_sha(identities["sandbox"]),
        "worktree_identity_sha256": _identity_sha(identities["worktree"]),
        "argv_sha256": _sha(_canonical(argv)),
        "environment_sha256": _sha(_canonical(ENVIRONMENT)),
        "credential_reference_sha256": _sha(reference.encode()),
        "scoped_write_grant_sha256": scoped_write_grant_sha256,
    }
    return PreparedCommandCodeSession(**payload, prepared_checksum_sha256=prepared_checksum_sha256(payload))


def _time(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProtectedCommandCodeError("commandcode_capability_time_invalid", field_name)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise ProtectedCommandCodeError("commandcode_capability_time_invalid", field_name) from exc


def _validate_prepared(prepared: PreparedCommandCodeSession) -> None:
    if not isinstance(prepared, PreparedCommandCodeSession):
        raise ProtectedCommandCodeError("commandcode_prepared_invalid")
    payload = asdict(prepared)
    if prepared.prepared_checksum_sha256 != prepared_checksum_sha256(payload):
        raise ProtectedCommandCodeError("commandcode_prepared_checksum_mismatch")
    binding = ROUTE_BINDINGS.get(prepared.route_name)
    if (
        not isinstance(prepared.task_id, str)
        or IDENTIFIER.fullmatch(prepared.task_id) is None
        or prepared.mode not in MODE_POLICY
        or binding is None
        or prepared.route_id != binding["route_id"]
        or prepared.model != binding["model"]
        or prepared.commandcode_version != binding["commandcode_version"]
        or prepared.billing_basis != binding["billing_basis"]
    ):
        raise ProtectedCommandCodeError("commandcode_prepared_route_binding_invalid")
    observed = {
        "command_link_identity_sha256": _identity_sha(_identity(prepared.command_link_fd, "command_link_fd")),
        "package_identity_sha256": _identity_sha(_identity(prepared.package_fd, "package_fd")),
        "entry_identity_sha256": _identity_sha(_identity(prepared.entry_fd, "entry_fd")),
        "node_identity_sha256": _identity_sha(_identity(prepared.node_fd, "node_fd")),
        "sandbox_identity_sha256": _identity_sha(_identity(prepared.sandbox_fd, "sandbox_fd")),
        "worktree_identity_sha256": _identity_sha(_identity(prepared.worktree_fd, "worktree_fd", directory=True)),
    }
    if any(getattr(prepared, key) != value for key, value in observed.items()) or _package_version(prepared.package_fd) != prepared.commandcode_version:
        raise ProtectedCommandCodeError("commandcode_descriptor_substitution_detected")


def validate_public_request(value: Any, *, prepared: PreparedCommandCodeSession, now: datetime) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != PUBLIC_FIELDS:
        raise ProtectedCommandCodeError("commandcode_capability_shape_invalid")
    row = dict(value)
    if row["schema_version"] != 1 or type(row["sequence"]) is not int or row["sequence"] < 1:
        raise ProtectedCommandCodeError("commandcode_capability_sequence_invalid")
    for field_name in ("capability_id", "task_id", "writer_service_id", "anchor_service_id"):
        if not isinstance(row[field_name], str) or IDENTIFIER.fullmatch(row[field_name]) is None:
            raise ProtectedCommandCodeError("commandcode_capability_identifier_invalid", field_name)
    digest_fields = {field for field in PUBLIC_FIELDS if field.endswith("_sha256")}
    for field_name in digest_fields:
        if not isinstance(row[field_name], str) or SHA.fullmatch(row[field_name]) is None:
            raise ProtectedCommandCodeError("commandcode_capability_digest_invalid", field_name)
    issued = _time(row["issued_at"], "issued_at")
    expires = _time(row["expires_at"], "expires_at")
    if issued > now or expires <= now or expires - issued > timedelta(seconds=MAX_TTL_SECONDS):
        raise ProtectedCommandCodeError("commandcode_capability_expired_or_future")
    expected = {
        key: getattr(prepared, key) for key in (
            "task_id", "route_name", "route_id", "model", "mode",
            "commandcode_version", "billing_basis",
            "command_link_identity_sha256", "package_identity_sha256",
            "entry_identity_sha256", "node_identity_sha256", "sandbox_identity_sha256",
            "worktree_identity_sha256", "argv_sha256", "environment_sha256",
            "credential_reference_sha256", "scoped_write_grant_sha256",
        )
    }
    if any(row[key] != expected[key] for key in expected):
        raise ProtectedCommandCodeError("commandcode_capability_binding_mismatch")
    if type(row["writer_uid"]) is not int or type(row["anchor_uid"]) is not int:
        raise ProtectedCommandCodeError("commandcode_capability_service_uid_invalid")
    if (
        row["writer_service_id"] == row["anchor_service_id"]
        or row["writer_uid"] == row["anchor_uid"]
        or row["writer_uid"] == os.geteuid() or row["anchor_uid"] == os.geteuid()
        or row["writer_build_sha256"] == row["anchor_build_sha256"]
        or row["writer_session_sha256"] == row["anchor_session_sha256"]
        or row["writer_receipt_sha256"] == row["anchor_receipt_sha256"]
    ):
        raise ProtectedCommandCodeError("commandcode_capability_distinct_service_binding_invalid")
    if row["capability_checksum_sha256"] != capability_checksum_sha256(row):
        raise ProtectedCommandCodeError("commandcode_capability_checksum_mismatch")
    return row


def inspect_pending(
    value: Any, *, prepared: PreparedCommandCodeSession, now: datetime,
    launcher: DescriptorNativeLauncher, capability_service: ProtectedCapabilityService,
) -> dict[str, Any]:
    _validate_prepared(prepared)
    row = validate_public_request(value, prepared=prepared, now=now)
    return {
        "status": "pending_distinct_uid_service_capability",
        "reason": "protected_subscription_service_and_descriptor_launcher_required",
        "task_id": prepared.task_id,
        "route_name": prepared.route_name,
        "route_id": prepared.route_id,
        "model": prepared.model,
        "mode": prepared.mode,
        "billing_basis": prepared.billing_basis,
        "capability_checksum_sha256": row["capability_checksum_sha256"],
        "capability_checksum_authoritative": False,
        "capability_service_called": False,
        "launcher_called": False,
        "provider_called": False,
        "retry_allowed": False,
        "route_qualified": False,
    }


__all__ = [
    "ROUTE_BINDINGS",
    "PreparedCommandCodeSession", "ProtectedCommandCodeError",
    "ProtectedCapabilityService", "DescriptorNativeLauncher",
    "SourceLocalOneUseJournal", "SourceLocalGuardSequence", "prepare_session", "prepared_checksum_sha256",
    "capability_checksum_sha256", "validate_public_request", "inspect_pending",
]
