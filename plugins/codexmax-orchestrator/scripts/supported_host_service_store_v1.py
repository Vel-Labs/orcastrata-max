#!/usr/bin/env python3
"""Service-owned writer and independent-anchor persistence for supported hosts.

The stores in this module are executable product implementations.  A
``create_source_local`` store is intentionally non-authoritative.  A later
service process can use ``create_service_owned`` only when its effective UID
and GID match the configured service account.  Store classification never
promotes a fact.  Live authority additionally requires the OS-authenticated
service channels in ``supported_host_protected_service_v1``.
"""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
import errno
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
from types import MappingProxyType
from typing import Any, Mapping

import supported_host_durable_store_v1 as t082


WRITER_MANIFEST_TYPE = "supported_host_service_writer_manifest_v1"
ANCHOR_MANIFEST_TYPE = "supported_host_service_anchor_manifest_v1"
WRITER_HEAD_TYPE = "supported_host_service_writer_head_v1"
ANCHOR_HEAD_TYPE = "supported_host_service_anchor_head_v1"
PENDING_TYPE = "supported_host_service_writer_pending_v1"
SOURCE_LOCAL_SCOPE = "source_local_temp_root_non_production"
SERVICE_OWNED_SCOPE = "service_account_owned_candidate"


class ServiceStoreError(ValueError):
    """Stable fail-closed service-store error."""

    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return t082.canonical_bytes(value)
    except (TypeError, ValueError, t082.DurableStoreError) as exc:
        raise ServiceStoreError("service_store_json_invalid") from exc


def _digest(value: Mapping[str, Any]) -> str:
    return t082._digest(_canonical(value))


def _seal(value: Mapping[str, Any], field: str) -> dict[str, Any]:
    row = deepcopy(dict(value))
    row[field] = ""
    row[field] = _digest(row)
    return row


def _read(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceStoreError("service_store_file_invalid", str(path)) from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise ServiceStoreError("service_store_file_type_invalid", str(path))
    try:
        parent_info = path.parent.lstat()
    except OSError as exc:
        raise ServiceStoreError("service_store_directory_missing", str(path.parent)) from exc
    if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != parent_info.st_uid:
        raise ServiceStoreError("service_store_file_mode_invalid", str(path))
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise ServiceStoreError("service_store_file_not_canonical", str(path))
    return value


def _check_directory(path: Path, expected_uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ServiceStoreError("service_store_directory_missing", str(path)) from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ServiceStoreError("service_store_directory_type_invalid", str(path))
    if stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != expected_uid:
        raise ServiceStoreError("service_store_directory_owner_invalid", str(path))


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_absent(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise ServiceStoreError("service_store_publication_collision", str(path))
    temporary = path.parent / (".pending-publication-" + secrets.token_hex(16))
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(_canonical(value))
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise ServiceStoreError("service_store_write_incomplete", str(path))
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
    except FileExistsError as exc:
        raise ServiceStoreError("service_store_publication_collision", str(path)) from exc
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise ServiceStoreError("service_store_publication_collision", str(path)) from exc
        raise ServiceStoreError("service_store_publication_failed", str(path)) from exc
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    _fsync_directory(path.parent)


def _replace(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.parent / (".pending-replacement-" + secrets.token_hex(16))
    _write_absent(temporary, value)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


def _validate_identity(value: Mapping[str, Any], *, role: str) -> dict[str, Any]:
    fields = {
        "service_id", "service_build_sha256", "service_uid", "service_gid",
        "service_start_id", "service_session_id", "session_expires_at",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ServiceStoreError("service_store_identity_shape_invalid", "$.identity")
    row = dict(value)
    try:
        t082._identifier(row["service_id"], "service_id_invalid", "$.identity.service_id")
        t082._sha(row["service_build_sha256"], "service_build_invalid", "$.identity.service_build_sha256")
        t082._identifier(row["service_start_id"], "service_start_invalid", "$.identity.service_start_id")
        t082._identifier(row["service_session_id"], "service_session_invalid", "$.identity.service_session_id")
        t082._time(row["session_expires_at"], "service_session_expiry_invalid", "$.identity.session_expires_at")
    except t082.DurableStoreError as exc:
        raise ServiceStoreError(exc.code, exc.location) from exc
    if type(row["service_uid"]) is not int or row["service_uid"] < 1:
        raise ServiceStoreError("service_store_uid_invalid", "$.identity.service_uid")
    if type(row["service_gid"]) is not int or row["service_gid"] < 1:
        raise ServiceStoreError("service_store_gid_invalid", "$.identity.service_gid")
    row["role"] = role
    return row


def _validate_operation_owners(value: Mapping[str, Mapping[str, str]]) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != set(t082.OPERATIONS):
        raise ServiceStoreError("service_store_operation_owners_invalid", "$.operation_owners")
    result: dict[str, dict[str, str]] = {}
    for operation in t082.OPERATIONS:
        owner = value[operation]
        if not isinstance(owner, Mapping) or set(owner) != {"namespace", "canonical_source_id", "producer_principal_id"}:
            raise ServiceStoreError("service_store_operation_owner_invalid", "$.operation_owners." + operation)
        if owner["namespace"] not in t082.NAMESPACES:
            raise ServiceStoreError("namespace_invalid", "$.operation_owners." + operation + ".namespace")
        try:
            result[operation] = {
                "namespace": owner["namespace"],
                "canonical_source_id": t082._identifier(owner["canonical_source_id"], "canonical_source_id_invalid", "$.owners"),
                "producer_principal_id": t082._identifier(owner["producer_principal_id"], "producer_principal_id_invalid", "$.owners"),
            }
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
    return result


def _head(store_id: str, namespace: str, *, anchor: bool = False) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": ANCHOR_HEAD_TYPE if anchor else WRITER_HEAD_TYPE,
        "store_id": store_id,
        "namespace": namespace,
        "sequence": 0,
        "generation": 0,
        "head_sha256": t082.EMPTY_SHA256,
        "anchor_sha256": t082.EMPTY_SHA256,
        "last_receipt_sha256": t082.EMPTY_SHA256,
        "last_anchor_receipt_sha256": t082.EMPTY_SHA256,
    }


class _Root:
    __slots__ = ("root", "manifest", "expected_uid", "source_local")

    def _open_root(self, root: Path, manifest_type: str) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise ServiceStoreError("service_store_root_invalid", "$.root")
        manifest = _read(root / "manifest.json")
        if manifest.get("schema_version") != 1 or manifest.get("artifact_type") != manifest_type:
            raise ServiceStoreError("service_store_manifest_identity_invalid", "$.manifest")
        if manifest.get("manifest_sha256") != _seal(manifest, "manifest_sha256")["manifest_sha256"]:
            raise ServiceStoreError("service_store_manifest_digest_mismatch", "$.manifest")
        source_local = manifest.get("execution_scope") == SOURCE_LOCAL_SCOPE
        if not source_local and manifest.get("execution_scope") != SERVICE_OWNED_SCOPE:
            raise ServiceStoreError("service_store_scope_invalid", "$.manifest.execution_scope")
        expected_uid = os.geteuid() if source_local else manifest.get("service_uid")
        if type(expected_uid) is not int:
            raise ServiceStoreError("service_store_uid_invalid", "$.manifest.service_uid")
        _check_directory(root, expected_uid)
        if not source_local and (os.geteuid() != manifest.get("service_uid") or os.getegid() != manifest.get("service_gid")):
            raise ServiceStoreError("service_store_process_identity_mismatch", "$.manifest")
        self.root = root
        self.manifest = MappingProxyType(manifest)
        self.expected_uid = expected_uid
        self.source_local = source_local

    @staticmethod
    def _create_root(
        root: Path, manifest: Mapping[str, Any], *, source_local: bool,
        service_uid: int, service_gid: int,
    ) -> None:
        if not isinstance(root, Path) or not root.is_absolute() or root.exists() or root.is_symlink():
            raise ServiceStoreError("service_store_root_invalid", "$.root")
        if not source_local and (os.geteuid() != service_uid or os.getegid() != service_gid):
            raise ServiceStoreError("service_store_process_identity_mismatch", "$.identity")
        root.mkdir(mode=0o700)
        _write_absent(root / "manifest.json", manifest)


class ServiceOwnedAnchorStore(_Root):
    """Independent append-only retention of exact T082 anchor triples."""

    __slots__ = ()

    def __init__(self, root: Path) -> None:
        self._open_root(root, ANCHOR_MANIFEST_TYPE)
        self.recover_all()

    @classmethod
    def create_source_local(
        cls, root: Path, *, store_id: str, identity: Mapping[str, Any], created_at: str,
    ) -> "ServiceOwnedAnchorStore":
        return cls._create(root, store_id=store_id, identity=identity, created_at=created_at, source_local=True)

    @classmethod
    def create_service_owned(
        cls, root: Path, *, store_id: str, identity: Mapping[str, Any], created_at: str,
    ) -> "ServiceOwnedAnchorStore":
        return cls._create(root, store_id=store_id, identity=identity, created_at=created_at, source_local=False)

    @classmethod
    def _create(
        cls, root: Path, *, store_id: str, identity: Mapping[str, Any], created_at: str,
        source_local: bool,
    ) -> "ServiceOwnedAnchorStore":
        identity_row = _validate_identity(identity, role="independent_anchor")
        try:
            t082._identifier(store_id, "store_id_invalid", "$.store_id")
            t082._time(created_at, "created_at_invalid", "$.created_at")
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
        manifest = _seal({
            "schema_version": 1, "artifact_type": ANCHOR_MANIFEST_TYPE,
            "execution_scope": SOURCE_LOCAL_SCOPE if source_local else SERVICE_OWNED_SCOPE,
            "store_id": store_id, "created_at": created_at,
            "service_id": identity_row["service_id"],
            "service_build_sha256": identity_row["service_build_sha256"],
            "service_uid": identity_row["service_uid"], "service_gid": identity_row["service_gid"],
            "manifest_sha256": "",
        }, "manifest_sha256")
        cls._create_root(root, manifest, source_local=source_local,
                         service_uid=identity_row["service_uid"], service_gid=identity_row["service_gid"])
        for namespace in t082.NAMESPACES:
            folder = root / namespace
            folder.mkdir(mode=0o700)
            (folder / "anchors").mkdir(mode=0o700)
            _write_absent(folder / "head.json", _head(store_id, namespace, anchor=True))
        return cls(root)

    @property
    def store_id(self) -> str:
        return self.manifest["store_id"]

    def _recover(self, namespace: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if namespace not in t082.NAMESPACES:
            raise ServiceStoreError("namespace_invalid", "$.namespace")
        folder = self.root / namespace
        _check_directory(folder, self.expected_uid)
        _check_directory(folder / "anchors", self.expected_uid)
        head = _read(folder / "head.json")
        if set(head) != set(_head(self.store_id, namespace, anchor=True)) or head["artifact_type"] != ANCHOR_HEAD_TYPE:
            raise ServiceStoreError("anchor_head_shape_invalid", "$.head")
        sequence = head["sequence"]
        if type(sequence) is not int or sequence < 0 or head["generation"] != sequence:
            raise ServiceStoreError("anchor_head_sequence_invalid", "$.head")
        names = sorted(path.name for path in (folder / "anchors").iterdir())
        expected = [f"{index:020d}.json" for index in range(1, sequence + 1)]
        if names != expected:
            pending_path = folder / ".pending-retain.json"
            if not (pending_path.exists() and names == expected + [f"{sequence + 1:020d}.json"]):
                raise ServiceStoreError("anchor_truncation_or_residue", "$.anchors")
        rows: list[dict[str, Any]] = []
        prior_head = prior_anchor = prior_writer = prior_anchor_receipt = t082.EMPTY_SHA256
        seen_requests: set[str] = set()
        for index, name in enumerate(names[:sequence], 1):
            row = _read(folder / "anchors" / name)
            if set(row) != {"request", "writer_receipt", "anchor_receipt"}:
                raise ServiceStoreError("anchor_record_shape_invalid", "$.anchor")
            try:
                triple = t082.validate_protected_record(row["request"], row["writer_receipt"], row["anchor_receipt"])
            except t082.DurableStoreError as exc:
                raise ServiceStoreError(exc.code, exc.location) from exc
            request = triple["request"]; writer = triple["writer_receipt"]; anchor = triple["anchor_receipt"]
            if request["store_id"] != self.store_id or request["namespace"] != namespace:
                raise ServiceStoreError("anchor_store_identity_mismatch", "$.anchor")
            if request["request_sha256"] in seen_requests:
                raise ServiceStoreError("anchor_replay", "$.anchor.request")
            if writer["prior_sequence"] != index - 1 or writer["prior_head_sha256"] != prior_head:
                raise ServiceStoreError("anchor_fork", "$.anchor.writer_receipt")
            if anchor["previous_anchor_receipt_sha256"] != prior_anchor_receipt:
                raise ServiceStoreError("anchor_receipt_fork", "$.anchor.anchor_receipt")
            seen_requests.add(request["request_sha256"]); rows.append(deepcopy(dict(triple)))
            prior_head = writer["successor_head_sha256"]; prior_anchor = writer["anchor_sha256"]
            prior_writer = writer["receipt_sha256"]; prior_anchor_receipt = anchor["receipt_sha256"]
        expected_head = {
            **_head(self.store_id, namespace, anchor=True), "sequence": sequence, "generation": sequence,
            "head_sha256": prior_head, "anchor_sha256": prior_anchor,
            "last_receipt_sha256": prior_writer,
            "last_anchor_receipt_sha256": prior_anchor_receipt,
        }
        if head != expected_head:
            raise ServiceStoreError("anchor_head_rollback_or_fork", "$.head")
        return head, rows

    def recover_all(self) -> Mapping[str, Mapping[str, Any]]:
        for namespace in t082.NAMESPACES:
            if (self.root / namespace / ".pending-retain.json").exists():
                self._commit_pending(namespace)
        return MappingProxyType({namespace: MappingProxyType(self._recover(namespace)[0]) for namespace in t082.NAMESPACES})

    def read(self, namespace: str, anchor_receipt_sha256: str | None = None) -> tuple[Mapping[str, Any], ...]:
        _head_row, rows = self._recover(namespace)
        if anchor_receipt_sha256 is not None:
            rows = [row for row in rows if row["anchor_receipt"]["receipt_sha256"] == anchor_receipt_sha256]
        return tuple(MappingProxyType(deepcopy(row)) for row in rows)

    def retain(self, request: Mapping[str, Any], writer_statement: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._retain(request, writer_statement, test_fault=None)

    def retain_with_test_fault(
        self, request: Mapping[str, Any], writer_statement: Mapping[str, Any], stage: str,
    ) -> Mapping[str, Any]:
        if not self.source_local:
            raise ServiceStoreError("service_store_test_fault_forbidden", "$.stage")
        if stage not in {"after_pending", "after_anchor", "after_head"}:
            raise ServiceStoreError("service_store_test_fault_invalid", "$.stage")
        return self._retain(request, writer_statement, test_fault=stage)

    def _retain(
        self, request: Mapping[str, Any], writer_statement: Mapping[str, Any], *,
        test_fault: str | None,
    ) -> Mapping[str, Any]:
        try:
            request_row = t082._validate_request(request)
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
        namespace = request_row["namespace"]
        head, rows = self._recover(namespace)
        existing = next((row for row in rows if row["request"]["request_sha256"] == request_row["request_sha256"]), None)
        if existing is not None:
            if existing["writer_receipt"]["writer_receipt_sha256"] != writer_statement.get("writer_receipt_sha256"):
                raise ServiceStoreError("anchor_request_collision", "$.request")
            return existing["anchor_receipt"]
        if request_row["expected_sequence"] != head["sequence"] or request_row["expected_generation"] != head["generation"] or request_row["expected_head_sha256"] != head["head_sha256"]:
            raise ServiceStoreError("anchor_expected_head_cas_failed", "$.request")
        statement = deepcopy(dict(writer_statement))
        required = set(t082._RECEIPT_FIELDS)
        if set(statement) != required or statement["receipt_sha256"] or statement["anchor_receipt_sha256"]:
            raise ServiceStoreError("writer_statement_shape_invalid", "$.writer_statement")
        if statement["writer_receipt_sha256"] != t082._writer_statement_digest(statement):
            raise ServiceStoreError("writer_statement_digest_mismatch", "$.writer_statement")
        bindings = {
            "request_sha256": request_row["request_sha256"], "store_id": request_row["store_id"],
            "namespace": namespace, "nonce": request_row["nonce"],
            "prior_sequence": head["sequence"], "prior_generation": head["generation"],
            "prior_head_sha256": head["head_sha256"],
            "previous_receipt_sha256": head["last_receipt_sha256"],
            "anchor_authority_id": self.manifest["service_id"],
            "anchor_authority_build_sha256": self.manifest["service_build_sha256"],
        }
        if any(statement.get(field) != expected for field, expected in bindings.items()):
            raise ServiceStoreError("writer_statement_binding_mismatch", "$.writer_statement")
        anchor = _seal({
            "schema_version": 1, "artifact_type": t082.ANCHOR_RECEIPT_TYPE,
            "anchor_authority_id": self.manifest["service_id"],
            "anchor_authority_build_sha256": self.manifest["service_build_sha256"],
            "anchor_receipt_id": f"anchor-{namespace}-{head['sequence'] + 1:020d}",
            "request_sha256": request_row["request_sha256"], "nonce": request_row["nonce"],
            "prior_sequence": statement["prior_sequence"], "successor_sequence": statement["successor_sequence"],
            "prior_head_sha256": statement["prior_head_sha256"], "successor_head_sha256": statement["successor_head_sha256"],
            "prior_generation": statement["prior_generation"], "successor_generation": statement["successor_generation"],
            "event_sha256": statement["event_sha256"], "writer_receipt_sha256": statement["writer_receipt_sha256"],
            "anchor_sha256": statement["anchor_sha256"],
            "previous_anchor_receipt_sha256": head["last_anchor_receipt_sha256"],
            "retained_at": request_row["occurred_at"], "expires_at": statement["expires_at"],
            "receipt_sha256": "",
        }, "receipt_sha256")
        final_writer = deepcopy(statement)
        final_writer["anchor_receipt_sha256"] = anchor["receipt_sha256"]
        final_writer = t082._seal(final_writer, "receipt_sha256")
        try:
            triple = t082.validate_protected_record(request_row, final_writer, anchor)
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
        successor = head["sequence"] + 1
        pending_path = self.root / namespace / ".pending-retain.json"
        _write_absent(pending_path, _seal({
            "schema_version": 1, "artifact_type": "supported_host_service_anchor_pending_v1",
            "triple": triple, "pending_sha256": "",
        }, "pending_sha256"))
        if test_fault == "after_pending":
            raise ServiceStoreError("injected_anchor_after_pending", "$.stage")
        return self._commit_pending(namespace, test_fault=test_fault)

    def _commit_pending(self, namespace: str, *, test_fault: str | None = None) -> Mapping[str, Any]:
        pending_path = self.root / namespace / ".pending-retain.json"
        pending = _read(pending_path)
        if set(pending) != {"schema_version", "artifact_type", "triple", "pending_sha256"} or pending["artifact_type"] != "supported_host_service_anchor_pending_v1" or pending["pending_sha256"] != _seal(pending, "pending_sha256")["pending_sha256"]:
            raise ServiceStoreError("anchor_pending_invalid", "$.pending")
        triple_value = pending["triple"]
        try:
            triple = t082.validate_protected_record(
                triple_value["request"], triple_value["writer_receipt"], triple_value["anchor_receipt"],
            )
        except (KeyError, t082.DurableStoreError) as exc:
            raise ServiceStoreError(getattr(exc, "code", "anchor_pending_invalid"), "$.pending") from exc
        head, _rows = self._recover(namespace)
        writer = triple["writer_receipt"]; anchor = triple["anchor_receipt"]
        successor = writer["successor_sequence"]
        if head["sequence"] == successor:
            completed = (
                head["head_sha256"] == writer["successor_head_sha256"]
                and head["anchor_sha256"] == writer["anchor_sha256"]
                and head["last_receipt_sha256"] == writer["receipt_sha256"]
                and head["last_anchor_receipt_sha256"] == anchor["receipt_sha256"]
            )
            if not completed:
                raise ServiceStoreError("anchor_pending_head_mismatch", "$.pending")
            _unlink(pending_path); self._recover(namespace)
            return MappingProxyType(deepcopy(anchor))
        if successor != head["sequence"] + 1 or writer["prior_head_sha256"] != head["head_sha256"] or anchor["previous_anchor_receipt_sha256"] != head["last_anchor_receipt_sha256"]:
            raise ServiceStoreError("anchor_pending_head_mismatch", "$.pending")
        event_path = self.root / namespace / "anchors" / f"{successor:020d}.json"
        if not event_path.exists():
            _write_absent(event_path, triple)
        elif _read(event_path) != triple:
            raise ServiceStoreError("anchor_event_collision", "$.anchor")
        if test_fault == "after_anchor":
            raise ServiceStoreError("injected_anchor_after_anchor", "$.stage")
        _replace(self.root / namespace / "head.json", {
            **_head(self.store_id, namespace, anchor=True), "sequence": successor, "generation": successor,
            "head_sha256": writer["successor_head_sha256"], "anchor_sha256": writer["anchor_sha256"],
            "last_receipt_sha256": writer["receipt_sha256"],
            "last_anchor_receipt_sha256": anchor["receipt_sha256"],
        })
        if test_fault == "after_head":
            raise ServiceStoreError("injected_anchor_after_head", "$.stage")
        _unlink(pending_path)
        self._recover(namespace)
        return MappingProxyType(deepcopy(anchor))


class ServiceOwnedWriterStore(_Root):
    """Append-only exact T082 writer with restart-safe anchor reconciliation."""

    __slots__ = ("identity",)

    def __init__(self, root: Path, identity: Mapping[str, Any]) -> None:
        self._open_root(root, WRITER_MANIFEST_TYPE)
        self.identity = MappingProxyType(_validate_identity(identity, role="protected_writer"))
        if self.identity["service_id"] != self.manifest["service_id"] or self.identity["service_build_sha256"] != self.manifest["service_build_sha256"]:
            raise ServiceStoreError("writer_runtime_identity_mismatch", "$.identity")
        self._recover_committed_all()

    @classmethod
    def create_source_local(
        cls, root: Path, *, store_id: str, operation_owners: Mapping[str, Mapping[str, str]],
        writer_identity: Mapping[str, Any], anchor_identity: Mapping[str, Any], created_at: str,
    ) -> "ServiceOwnedWriterStore":
        return cls._create(root, store_id=store_id, operation_owners=operation_owners, writer_identity=writer_identity,
                           anchor_identity=anchor_identity, created_at=created_at, source_local=True)

    @classmethod
    def create_service_owned(
        cls, root: Path, *, store_id: str, operation_owners: Mapping[str, Mapping[str, str]],
        writer_identity: Mapping[str, Any], anchor_identity: Mapping[str, Any], created_at: str,
    ) -> "ServiceOwnedWriterStore":
        return cls._create(root, store_id=store_id, operation_owners=operation_owners, writer_identity=writer_identity,
                           anchor_identity=anchor_identity, created_at=created_at, source_local=False)

    @classmethod
    def _create(
        cls, root: Path, *, store_id: str, operation_owners: Mapping[str, Mapping[str, str]],
        writer_identity: Mapping[str, Any], anchor_identity: Mapping[str, Any], created_at: str,
        source_local: bool,
    ) -> "ServiceOwnedWriterStore":
        writer = _validate_identity(writer_identity, role="protected_writer")
        anchor = _validate_identity(anchor_identity, role="independent_anchor")
        if writer["service_uid"] == anchor["service_uid"] or writer["service_gid"] == anchor["service_gid"] or writer["service_id"] == anchor["service_id"]:
            raise ServiceStoreError("service_store_identity_collision", "$.identity")
        normalized_owners = _validate_operation_owners(operation_owners)
        try:
            t082._identifier(store_id, "store_id_invalid", "$.store_id")
            t082._time(created_at, "created_at_invalid", "$.created_at")
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
        manifest = _seal({
            "schema_version": 1, "artifact_type": WRITER_MANIFEST_TYPE,
            "execution_scope": SOURCE_LOCAL_SCOPE if source_local else SERVICE_OWNED_SCOPE,
            "store_id": store_id, "created_at": created_at, "operation_owners": normalized_owners,
            "service_id": writer["service_id"], "service_build_sha256": writer["service_build_sha256"],
            "service_uid": writer["service_uid"], "service_gid": writer["service_gid"],
            "anchor_service_id": anchor["service_id"],
            "anchor_service_build_sha256": anchor["service_build_sha256"],
            "manifest_sha256": "",
        }, "manifest_sha256")
        cls._create_root(root, manifest, source_local=source_local,
                         service_uid=writer["service_uid"], service_gid=writer["service_gid"])
        for namespace in t082.NAMESPACES:
            folder = root / namespace
            folder.mkdir(mode=0o700); (folder / "events").mkdir(mode=0o700)
            _write_absent(folder / ".namespace.lock", {"schema_version": 1, "namespace": namespace})
            _write_absent(folder / "head.json", _head(store_id, namespace))
        return cls(root, writer_identity)

    @property
    def store_id(self) -> str:
        return self.manifest["store_id"]

    def _recover_committed(self, namespace: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        if namespace not in t082.NAMESPACES:
            raise ServiceStoreError("namespace_invalid", "$.namespace")
        folder = self.root / namespace
        _check_directory(folder, self.expected_uid); _check_directory(folder / "events", self.expected_uid)
        residue = [p.name for p in folder.iterdir() if p.name.startswith(".pending-") and p.name != ".pending-append.json"]
        if residue:
            raise ServiceStoreError("writer_publication_residue", "$.namespace")
        head = _read(folder / "head.json")
        if set(head) != set(_head(self.store_id, namespace)) or head["artifact_type"] != WRITER_HEAD_TYPE:
            raise ServiceStoreError("writer_head_shape_invalid", "$.head")
        sequence = head["sequence"]
        if type(sequence) is not int or sequence < 0 or head["generation"] != sequence:
            raise ServiceStoreError("writer_head_sequence_invalid", "$.head")
        names = sorted(path.name for path in (folder / "events").iterdir())
        # One extra event is recoverable only when the exact pending intent exists.
        pending_path = folder / ".pending-append.json"
        expected = [f"{index:020d}.json" for index in range(1, sequence + 1)]
        if names != expected:
            if not (pending_path.exists() and names == expected + [f"{sequence + 1:020d}.json"]):
                raise ServiceStoreError("writer_truncation_or_residue", "$.events")
        rows: list[dict[str, Any]] = []
        prior_head = prior_anchor = prior_writer = prior_anchor_receipt = t082.EMPTY_SHA256
        nonces: set[str] = set(); record_ids: dict[str, str] = {}; transitioned: set[str] = set()
        for index, name in enumerate(names[:sequence], 1):
            row = _read(folder / "events" / name)
            try:
                triple = t082.validate_protected_record(row["request"], row["writer_receipt"], row["anchor_receipt"])
            except (KeyError, t082.DurableStoreError) as exc:
                raise ServiceStoreError(getattr(exc, "code", "writer_record_invalid"), "$.event") from exc
            request = triple["request"]; writer = triple["writer_receipt"]; anchor = triple["anchor_receipt"]
            owner = self.manifest["operation_owners"].get(request["operation"])
            if owner is None or request["store_id"] != self.store_id or request["namespace"] != namespace or owner["namespace"] != namespace or request["canonical_source_id"] != owner["canonical_source_id"] or request["producer_principal_id"] != owner["producer_principal_id"]:
                raise ServiceStoreError("writer_owner_mismatch", "$.event.request")
            if request["expected_sequence"] != index - 1 or request["expected_generation"] != index - 1 or request["expected_head_sha256"] != prior_head:
                raise ServiceStoreError("writer_fork", "$.event.request")
            if writer["previous_receipt_sha256"] != prior_writer or anchor["previous_anchor_receipt_sha256"] != prior_anchor_receipt:
                raise ServiceStoreError("writer_anchor_fork", "$.event")
            if request["nonce"] in nonces:
                raise ServiceStoreError("writer_nonce_replay", "$.event.request.nonce")
            if request["record_id"] in record_ids:
                code = "writer_record_replay" if record_ids[request["record_id"]] == request["payload_sha256"] else "writer_record_collision"
                raise ServiceStoreError(code, "$.event.request.record_id")
            if request["event_kind"] != "fact":
                target = request["target_event_sha256"]
                if target in transitioned or not any(item["writer_receipt"]["event_sha256"] == target and item["request"]["event_kind"] == "fact" for item in rows):
                    raise ServiceStoreError("writer_transition_replay_or_missing", "$.event.request.target_event_sha256")
                transitioned.add(target)
            nonces.add(request["nonce"]); record_ids[request["record_id"]] = request["payload_sha256"]
            rows.append(deepcopy(dict(triple)))
            prior_head = writer["successor_head_sha256"]; prior_anchor = writer["anchor_sha256"]
            prior_writer = writer["receipt_sha256"]; prior_anchor_receipt = anchor["receipt_sha256"]
        expected_head = {
            **_head(self.store_id, namespace), "sequence": sequence, "generation": sequence,
            "head_sha256": prior_head, "anchor_sha256": prior_anchor,
            "last_receipt_sha256": prior_writer, "last_anchor_receipt_sha256": prior_anchor_receipt,
        }
        if head != expected_head:
            raise ServiceStoreError("writer_head_rollback_or_fork", "$.head")
        return head, rows

    def _recover_committed_all(self) -> Mapping[str, Mapping[str, Any]]:
        return MappingProxyType({namespace: MappingProxyType(self._recover_committed(namespace)[0]) for namespace in t082.NAMESPACES})

    def head(self, namespace: str) -> Mapping[str, Any]:
        return MappingProxyType(self._recover_committed(namespace)[0])

    def records(self, namespace: str) -> tuple[Mapping[str, Any], ...]:
        return tuple(MappingProxyType(deepcopy(row)) for row in self._recover_committed(namespace)[1])

    def _statement(self, request: Mapping[str, Any], head: Mapping[str, Any]) -> dict[str, Any]:
        successor = head["sequence"] + 1
        event_sha = t082._event_digest(request, successor, successor)
        anchor_sha = t082._anchor_digest(request, event_sha, head["last_receipt_sha256"])
        row = {
            "schema_version": 1, "artifact_type": t082.RECEIPT_TYPE,
            "state": t082.PROTECTED_RECEIPT_STATE, "request_sha256": request["request_sha256"],
            "store_id": self.store_id, "namespace": request["namespace"],
            "canonical_source_id": request["canonical_source_id"],
            "producer_principal_id": request["producer_principal_id"], "operation": request["operation"],
            "candidate_sha256": request["candidate_sha256"], "profile_sha256": request["profile_sha256"],
            "nonce": request["nonce"], "prior_sequence": head["sequence"], "successor_sequence": successor,
            "prior_head_sha256": head["head_sha256"], "successor_head_sha256": event_sha,
            "prior_generation": head["generation"], "successor_generation": successor,
            "event_sha256": event_sha, "anchor_sha256": anchor_sha,
            "previous_receipt_sha256": head["last_receipt_sha256"],
            "writer_id": self.manifest["service_id"],
            "writer_build_sha256": self.manifest["service_build_sha256"],
            "protected_session_id": self.identity["service_session_id"],
            "protected_session_binding_sha256": _digest({
                "service_id": self.identity["service_id"], "service_start_id": self.identity["service_start_id"],
                "service_session_id": self.identity["service_session_id"], "request_sha256": request["request_sha256"],
            }),
            "witnessed_at": request["occurred_at"], "expires_at": self.identity["session_expires_at"],
            "anchor_authority_id": self.manifest["anchor_service_id"],
            "anchor_authority_build_sha256": self.manifest["anchor_service_build_sha256"],
            "anchor_receipt_sha256": "", "writer_receipt_sha256": "", "receipt_sha256": "",
        }
        row["writer_receipt_sha256"] = t082._writer_statement_digest(row)
        return row

    @contextmanager
    def namespace_lock(self, namespace: str):
        if namespace not in t082.NAMESPACES:
            raise ServiceStoreError("namespace_invalid", "$.namespace")
        path = self.root / namespace / ".namespace.lock"
        _read(path)
        before = path.lstat()
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        try:
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ServiceStoreError("writer_namespace_lock_replaced", "$.namespace")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def begin_append(self, request: Mapping[str, Any], *, test_fault: str | None = None) -> Mapping[str, Any]:
        try:
            request_row = t082._validate_request(request)
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
        namespace = request_row["namespace"]
        head, records = self._recover_committed(namespace)
        owner = self.manifest["operation_owners"].get(request_row["operation"])
        if owner is None or request_row["store_id"] != self.store_id or owner["namespace"] != namespace or request_row["canonical_source_id"] != owner["canonical_source_id"] or request_row["producer_principal_id"] != owner["producer_principal_id"]:
            raise ServiceStoreError("writer_owner_mismatch", "$.request")
        if request_row["expected_sequence"] != head["sequence"] or request_row["expected_generation"] != head["generation"] or request_row["expected_head_sha256"] != head["head_sha256"]:
            raise ServiceStoreError("writer_expected_head_cas_failed", "$.request")
        if any(row["request"]["nonce"] == request_row["nonce"] for row in records):
            raise ServiceStoreError("writer_nonce_replay", "$.request.nonce")
        same = next((row for row in records if row["request"]["record_id"] == request_row["record_id"]), None)
        if same is not None:
            code = "writer_record_replay" if same["request"]["payload_sha256"] == request_row["payload_sha256"] else "writer_record_collision"
            raise ServiceStoreError(code, "$.request.record_id")
        if request_row["event_kind"] != "fact":
            target = request_row["target_event_sha256"]
            target_record = next((row for row in records if row["writer_receipt"]["event_sha256"] == target and row["request"]["event_kind"] == "fact"), None)
            already = any(row["request"]["target_event_sha256"] == target for row in records)
            if target_record is None:
                raise ServiceStoreError("writer_transition_target_missing", "$.request.target_event_sha256")
            if already:
                raise ServiceStoreError("writer_transition_replay", "$.request.target_event_sha256")
        pending_path = self.root / namespace / ".pending-append.json"
        if pending_path.exists():
            raise ServiceStoreError("writer_pending_recovery_required", "$.pending")
        statement = self._statement(request_row, head)
        pending = _seal({
            "schema_version": 1, "artifact_type": PENDING_TYPE, "request": request_row,
            "writer_statement": statement, "pending_sha256": "",
        }, "pending_sha256")
        _write_absent(pending_path, pending)
        if test_fault == "after_pending":
            raise ServiceStoreError("injected_after_pending", "$.fault")
        return MappingProxyType({"request": MappingProxyType(request_row), "writer_statement": MappingProxyType(statement)})

    def commit_append(
        self, namespace: str, anchor: Mapping[str, Any], *, test_fault: str | None = None,
    ) -> Mapping[str, Mapping[str, Any]]:
        pending_path = self.root / namespace / ".pending-append.json"
        pending = _read(pending_path)
        if set(pending) != {"schema_version", "artifact_type", "request", "writer_statement", "pending_sha256"} or pending["artifact_type"] != PENDING_TYPE or pending["pending_sha256"] != _seal(pending, "pending_sha256")["pending_sha256"]:
            raise ServiceStoreError("writer_pending_invalid", "$.pending")
        request = t082._validate_request(pending["request"])
        statement = pending["writer_statement"]
        if not isinstance(anchor, Mapping):
            raise ServiceStoreError("writer_pending_anchor_missing", "$.pending")
        final_writer = deepcopy(dict(statement)); final_writer["anchor_receipt_sha256"] = anchor["receipt_sha256"]
        final_writer = t082._seal(final_writer, "receipt_sha256")
        try:
            triple = t082.validate_protected_record(request, final_writer, anchor)
        except t082.DurableStoreError as exc:
            raise ServiceStoreError(exc.code, exc.location) from exc
        successor = final_writer["successor_sequence"]
        event_path = self.root / namespace / "events" / f"{successor:020d}.json"
        if not event_path.exists():
            _write_absent(event_path, triple)
        elif _read(event_path) != triple:
            raise ServiceStoreError("writer_event_collision", "$.event")
        if test_fault == "after_event":
            raise ServiceStoreError("injected_after_event", "$.fault")
        _replace(self.root / namespace / "head.json", {
            **_head(self.store_id, namespace), "sequence": successor, "generation": successor,
            "head_sha256": final_writer["successor_head_sha256"], "anchor_sha256": final_writer["anchor_sha256"],
            "last_receipt_sha256": final_writer["receipt_sha256"],
            "last_anchor_receipt_sha256": anchor["receipt_sha256"],
        })
        if test_fault == "after_head":
            raise ServiceStoreError("injected_after_head", "$.fault")
        _unlink(pending_path)
        self._recover_committed(namespace)
        return MappingProxyType({"writer_receipt": MappingProxyType(final_writer), "anchor_receipt": MappingProxyType(deepcopy(dict(anchor)))})

    def pending_append(self, namespace: str) -> Mapping[str, Any] | None:
        path = self.root / namespace / ".pending-append.json"
        return None if not path.exists() else MappingProxyType(_read(path))


class SourceLocalInProcessAnchorGateway:
    """Explicitly non-production writer-to-anchor gateway for temp-root tests."""

    __slots__ = ("_anchor",)

    def __init__(self, anchor: ServiceOwnedAnchorStore) -> None:
        if type(anchor) is not ServiceOwnedAnchorStore or not anchor.source_local:
            raise ServiceStoreError("source_local_anchor_gateway_invalid", "$.anchor")
        self._anchor = anchor

    def append(
        self, writer: ServiceOwnedWriterStore, request: Mapping[str, Any], *,
        test_fault: str | None = None,
    ) -> Mapping[str, Mapping[str, Any]]:
        if type(writer) is not ServiceOwnedWriterStore or not writer.source_local:
            raise ServiceStoreError("source_local_writer_gateway_invalid", "$.writer")
        namespace = request.get("namespace") if isinstance(request, Mapping) else None
        with writer.namespace_lock(namespace):
            prepared = writer.begin_append(request, test_fault=test_fault)
            anchor = self._anchor.retain(prepared["request"], prepared["writer_statement"])
            if test_fault == "after_anchor":
                raise ServiceStoreError("injected_after_anchor", "$.fault")
            return writer.commit_append(namespace, anchor, test_fault=test_fault)

    def recover(self, writer: ServiceOwnedWriterStore) -> Mapping[str, Mapping[str, Any]]:
        if type(writer) is not ServiceOwnedWriterStore or not writer.source_local:
            raise ServiceStoreError("source_local_writer_gateway_invalid", "$.writer")
        for namespace in t082.NAMESPACES:
            with writer.namespace_lock(namespace):
                pending = writer.pending_append(namespace)
                if pending is not None:
                    anchor = self._anchor.retain(pending["request"], pending["writer_statement"])
                    writer.commit_append(namespace, anchor)
        return writer._recover_committed_all()


__all__ = [
    "ANCHOR_HEAD_TYPE", "ANCHOR_MANIFEST_TYPE", "PENDING_TYPE", "SERVICE_OWNED_SCOPE",
    "SOURCE_LOCAL_SCOPE", "ServiceOwnedAnchorStore", "ServiceOwnedWriterStore", "SourceLocalInProcessAnchorGateway",
    "ServiceStoreError", "WRITER_HEAD_TYPE", "WRITER_MANIFEST_TYPE",
]
