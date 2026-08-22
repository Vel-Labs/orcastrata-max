#!/usr/bin/env python3
"""Pending-only public seam for protected provider qualification.

Positive authority exists only as a one-use transaction inside the future
OS-bound protected-service dispatch channel. No Python mapping, class, token,
receipt, constructor, or registry mutation can represent that authority.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import socket
import stat
import sys
from typing import Any, Mapping, Sequence

MAX_TTL_SECONDS = 300
ROUTE_CARDS = {
    "worker_deepseek_v4_pro": ("commandcode", "Command Code", "deepseek/deepseek-v4-pro", "commandcode-subscription-deepseek-v4-pro", "Command Code 1.23.2", "subscription"),
    "worker_deepseek_v4_flash": ("commandcode", "Command Code", "deepseek/deepseek-v4-flash", "commandcode-subscription-deepseek-v4-flash", "Command Code 1.23.2", "subscription"),
    "worker_claude_code_sonnet_5": ("claude_cli", "Anthropic", "claude-sonnet-5", "claude-code-subscription-sonnet-5", "Claude Code 2.1.231", "subscription"),
    "worker_minimax_m3": ("minimax_mmx", "MiniMax", "MiniMax-M3", "minimax-subscription-m3", "mmx 1.0.16", "subscription"),
    "worker_minimax_m3_tool_loop": ("minimax_mmx_tool_loop", "MiniMax", "MiniMax-M3", "minimax-subscription-m3-tool-loop", "mmx 1.0.16", "subscription"),
    "worker_minimax_m3_opencode": ("opencode_tool_loop", "MiniMax", "MiniMax-M3", "minimax-subscription-m3-opencode", "OpenCode with MiniMax provider-managed subscription", "subscription"),
    "worker_grok_4_5": ("grok_cli", "Grok", "grok-4.5", "grok-subscription-4-5", "Grok CLI 1.0.3", "subscription"),
    "worker_grok_4_6": ("grok_cli", "Grok", "grok-4.6", "grok-subscription-4-6", "Grok CLI 1.0.3", "subscription"),
}
QUALIFICATION_VARIANTS = {
    "worker_deepseek_v4_pro": ("Command Code 1.23.2", "commandcode", "subscription"),
    "worker_deepseek_v4_flash": ("Command Code 1.23.2", "commandcode", "subscription"),
    "worker_claude_code_sonnet_5": ("Claude Code 2.1.231", "claude_code", "subscription"),
    "worker_minimax_m3": ("mmx 1.0.16", "minimax_message", "subscription"),
    "worker_minimax_m3_tool_loop": ("mmx 1.0.16", "minimax_codexmax_json_text_file_tool_loop", "subscription"),
    "worker_minimax_m3_opencode": ("OpenCode 1.14.39", "minimax_subscription", "subscription"),
    "worker_grok_4_5": ("Grok CLI 1.0.3", "grok_cli", "subscription"),
    "worker_grok_4_6": ("Grok CLI 1.0.3", "grok_cli", "subscription"),
}
_REQUEST_FIELDS = frozenset({
    "schema_version", "task_id", "route_name", "binding_id", "adapter_binding_sha256",
    "challenge", "challenge_sha256", "authority_sha256", "issued_at", "expires_at",
    "ttl_seconds", "task_profile_sha256", "source_delivery", "command_capability",
    "reasoning", "token_limit", "local_file_access", "write_access", "read_scope",
    "write_scope", "authority_scope", "consequence_floor", "independence_group",
    "executable_sha256", "receiver_service_id", "receiver_build_sha256",
    "receiver_uid", "receiver_gid",
    "adapter_build", "backend_variant", "credential_reference_sha256",
    "billing_observation",
})
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{1,127}$")


class QualificationError(ValueError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code; self.path = path
        super().__init__(f"{code}: {path}")


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _time(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"): raise QualificationError("timestamp_invalid", path)
    try: return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc: raise QualificationError("timestamp_invalid", path) from exc


def _descriptor_identity(fd: int) -> dict[str, Any]:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o111 == 0: raise QualificationError("executable_descriptor_invalid")
        data = bytearray(); offset = 0
        while True:
            chunk = os.pread(fd, 65536, offset)
            if not chunk: break
            data.extend(chunk); offset += len(chunk)
        after = os.fstat(fd)
    except OSError as exc: raise QualificationError("executable_descriptor_invalid") from exc
    fields = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid, row.st_size, row.st_mtime_ns, row.st_nlink)
    if fields(before) != fields(after): raise QualificationError("executable_descriptor_changed")
    return {"device": before.st_dev, "inode": before.st_ino, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid, "gid": before.st_gid, "size": before.st_size, "mtime_ns": before.st_mtime_ns, "sha256": _digest_bytes(bytes(data))}


def _socket_peer(fd: int) -> dict[str, Any]:
    try:
        info = os.fstat(fd)
        if not stat.S_ISSOCK(info.st_mode): raise QualificationError("receiver_descriptor_invalid")
        duplicate = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if hasattr(duplicate, "getpeereid"): uid, gid = duplicate.getpeereid()
            elif hasattr(socket, "SO_PEERCRED"):
                import struct
                _, uid, gid = struct.unpack("3i", duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            elif hasattr(socket, "LOCAL_PEERCRED"):
                import ctypes
                class XUCred(ctypes.Structure):
                    _fields_ = [("version", ctypes.c_uint), ("uid", ctypes.c_uint), ("ngroups", ctypes.c_short), ("groups", ctypes.c_uint * 16)]
                credential = XUCred.from_buffer_copy(duplicate.getsockopt(0, socket.LOCAL_PEERCRED, ctypes.sizeof(XUCred)))
                uid, gid = int(credential.uid), int(credential.groups[0])
            else: raise QualificationError("kernel_peer_witness_unavailable")
        finally: duplicate.close()
    except OSError as exc: raise QualificationError("receiver_descriptor_invalid") from exc
    return {"device": info.st_dev, "inode": info.st_ino, "peer_uid": uid, "peer_gid": gid}


def validate_request(value: Any, registry: Mapping[str, Any], *, now: datetime) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != _REQUEST_FIELDS: raise QualificationError("request_shape_invalid")
    request = dict(value)
    if request["schema_version"] != 1 or request["route_name"] not in ROUTE_CARDS: raise QualificationError("route_unconfigured")
    issued = _time(request["issued_at"], "$.issued_at"); expires = _time(request["expires_at"], "$.expires_at")
    if type(request["ttl_seconds"]) is not int or not 1 <= request["ttl_seconds"] <= MAX_TTL_SECONDS or expires - issued != timedelta(seconds=request["ttl_seconds"]): raise QualificationError("request_ttl_invalid")
    if issued > now: raise QualificationError("request_from_future")
    if expires <= now: raise QualificationError("request_stale")
    if request["challenge_sha256"] != _digest_bytes(str(request["challenge"]).encode()): raise QualificationError("challenge_digest_mismatch")
    for field in ("adapter_binding_sha256", "authority_sha256", "task_profile_sha256", "challenge_sha256", "executable_sha256", "receiver_build_sha256"):
        if not isinstance(request[field], str) or _SHA.fullmatch(request[field]) is None: raise QualificationError("request_digest_invalid", f"$.{field}")
    for field in ("task_id", "binding_id", "receiver_service_id"):
        if not isinstance(request[field], str) or _ID.fullmatch(request[field]) is None: raise QualificationError("request_identifier_invalid", f"$.{field}")
    binding = registry.get("bindings", {}).get(request["binding_id"])
    if not isinstance(binding, Mapping): raise QualificationError("binding_unconfigured")
    card = ROUTE_CARDS[request["route_name"]]; route = binding.get("route", {})
    if not binding.get("enabled"): raise QualificationError("binding_unavailable")
    if binding.get("task_profile_sha256") != request["task_profile_sha256"]: raise QualificationError("task_profile_mismatch")
    if binding.get("adapter_type") != card[0] or binding.get("adapter_binding_sha256") != request["adapter_binding_sha256"] or route.get("route_name") != request["route_name"]: raise QualificationError("binding_route_mismatch")
    for field, expected in zip(("provider", "exact_model", "route_id", "runtime", "billing_basis"), card[1:]):
        if route.get(field) != expected: raise QualificationError("binding_identity_mismatch", f"$.binding.route.{field}")
    adapter_build, backend_variant, billing = QUALIFICATION_VARIANTS[request["route_name"]]
    if request["adapter_build"] != adapter_build: raise QualificationError("adapter_build_mismatch")
    if request["backend_variant"] != backend_variant or backend_variant == "unknown": raise QualificationError("backend_variant_mismatch")
    if request["billing_observation"] != billing or billing == "unknown": raise QualificationError("billing_observation_mismatch")
    reference_sha256 = binding.get("credential_reference", {}).get("reference_sha256")
    if request["credential_reference_sha256"] != reference_sha256: raise QualificationError("credential_reference_mismatch")
    return request, dict(binding)


def qualification_status_projection(request: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    return {"artifact_type": "codexmax_provider_qualification_status_v1", "status": "pending_receiver_owned_qualification", "task_id": request["task_id"], "route_name": request["route_name"], "adapter_binding_sha256": binding["adapter_binding_sha256"], "task_profile_sha256": request["task_profile_sha256"], "authority_sha256": request["authority_sha256"], "challenge_sha256": request["challenge_sha256"], "issued_at": request["issued_at"], "expires_at": request["expires_at"], "availability": "unknown", "health": "unknown", "callability": "unknown", "authorization_granted": False, "serializable_authority": False}


def inspect_pending(request_value: Any, registry: Mapping[str, Any], *, executable_fd: int, receiver_fd: int, now: datetime) -> dict[str, Any]:
    request, binding = validate_request(request_value, registry, now=now)
    executable_before = _descriptor_identity(executable_fd); peer_before = _socket_peer(receiver_fd)
    if executable_before["sha256"] != request["executable_sha256"]: raise QualificationError("executable_digest_mismatch")
    if peer_before["peer_uid"] != request["receiver_uid"] or peer_before["peer_gid"] != request["receiver_gid"]: raise QualificationError("receiver_kernel_peer_mismatch")
    executable_after = _descriptor_identity(executable_fd); peer_after = _socket_peer(receiver_fd)
    if executable_after != executable_before: raise QualificationError("executable_descriptor_changed")
    if peer_after != peer_before: raise QualificationError("receiver_peer_substituted")
    projection = qualification_status_projection(request, binding)
    return {"status": "pending_receiver_owned_qualification", "status_projection": projection, "protected_transaction_created": False, "qualified_registry_receipt": None, "preflight_observation": None, "provider_call_performed": False, "reason": "os_bound_protected_transaction_required"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-json", required=True); parser.add_argument("--registry-json", required=True)
    parser.add_argument("--executable-fd", type=int, required=True); parser.add_argument("--receiver-fd", type=int, required=True); parser.add_argument("--now", required=True)
    args = parser.parse_args(argv)
    try: result = inspect_pending(json.loads(args.request_json), json.loads(args.registry_json), executable_fd=args.executable_fd, receiver_fd=args.receiver_fd, now=_time(args.now, "$.now"))
    except (QualificationError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "rejected", "error": {"code": getattr(exc, "code", "input_invalid")}, "provider_call_performed": False}, sort_keys=True, separators=(",", ":")), file=sys.stderr); return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":"))); return 4


if __name__ == "__main__": raise SystemExit(main())

__all__ = ["QUALIFICATION_VARIANTS", "ROUTE_CARDS", "QualificationError", "validate_request", "qualification_status_projection", "inspect_pending", "main"]
