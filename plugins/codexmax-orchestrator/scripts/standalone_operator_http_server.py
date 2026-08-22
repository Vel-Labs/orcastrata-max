#!/usr/bin/env python3
"""One admitted numeric-loopback HTTP origin for the standalone operator."""

from __future__ import annotations

from datetime import datetime, timezone
from datetime import timedelta
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import threading
from typing import Any

import standalone_operator_local_binding as binding
import standalone_runtime_service as service


HOST = "127.0.0.1"
PREFIX = "/operator/v1/"
HISTORICAL_PORT = 41785
MAX_BODY_BYTES = 64 * 1024
PAGE_HEADER = "X-Codexmax-Operator-Page-Nonce"
STATUS_DOMAIN = b"codexmax-operator-browser-status-v1\0"
TRANSPORT_DOMAIN = b"codexmax-operator-browser-transport-v1\0"
STATUS_LIFETIME_SECONDS = 5
ASSET_ROOT = Path(__file__).resolve().parents[1] / "assets/operator/standalone-runtime"
ASSETS = {
    "/operator/v1/": ("index.html", "text/html; charset=utf-8"),
    "/operator/v1/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/operator/v1/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


class OperatorHTTPError(RuntimeError):
    def __init__(self, code: str, path: str = "$") -> None:
        self.code = code
        self.path = path
        super().__init__(f"{code}: {path}")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _bytes_sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


class _BrowserSessions:
    def __init__(self, admission: dict[str, Any]) -> None:
        self.listener_id = "listener-" + secrets.token_hex(12)
        self.listener_nonce = bytearray(secrets.token_bytes(32))
        self.key = bytearray(secrets.token_bytes(32))
        self.admission_expires = _parse_time(admission["expires_at"])
        self.pages: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()

    def bootstrap(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = min(now + timedelta(seconds=60), self.admission_expires)
        if expires <= now:
            raise OperatorHTTPError("operator_page_session_unavailable", "$.admission")
        page_nonce = _b64(secrets.token_bytes(32))
        value = {
            "schema_version": 1, "artifact_type": "standalone_operator_browser_bootstrap_v1",
            "listener_id": self.listener_id, "listener_nonce": _b64(bytes(self.listener_nonce)),
            "page_nonce": page_nonce, "hmac_key_b64": _b64(bytes(self.key)),
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with self.lock:
            self.pages[page_nonce] = {"expires": expires, "sequence": 0, "previous": None}
        return value

    def page(self, headers: Any) -> tuple[str, dict[str, Any]]:
        values = headers.get_all(PAGE_HEADER, failobj=[])
        if len(values) != 1:
            raise OperatorHTTPError("operator_page_session_invalid", "$.headers")
        nonce = values[0]
        with self.lock:
            session = self.pages.get(nonce)
            if session is None or session["expires"] <= datetime.now(timezone.utc):
                raise OperatorHTTPError("operator_page_session_invalid", "$.headers")
            return nonce, session

    def _mac(self, domain: bytes, receipt: dict[str, Any]) -> str:
        return _b64(hmac.new(bytes(self.key), domain + _canonical(receipt), hashlib.sha256).digest())

    def status(self, page_nonce: str, session: dict[str, Any], projection: Any) -> dict[str, Any]:
        raw = _canonical(projection)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = min(now + timedelta(seconds=STATUS_LIFETIME_SECONDS), session["expires"])
        with self.lock:
            sequence = session["sequence"] + 1
            previous = session["previous"]
            receipt = {
                "schema_version": 1, "artifact_type": "standalone_operator_browser_status_receipt_v1",
                "listener_id": self.listener_id, "listener_nonce": _b64(bytes(self.listener_nonce)),
                "page_nonce": page_nonce, "status_sequence": sequence,
                "previous_status_receipt_sha256": previous,
                "projection_encoding": "base64url-canonical-json-v1",
                "projection_bytes_b64": _b64(raw), "projection_sha256": _bytes_sha(raw),
                "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "receipt_sha256": "", "mac_algorithm": "HMAC-SHA-256", "mac_b64": "",
            }
            receipt["receipt_sha256"] = _digest({key: item for key, item in receipt.items() if key not in {"receipt_sha256", "mac_b64"}})
            receipt["mac_b64"] = self._mac(STATUS_DOMAIN, {key: item for key, item in receipt.items() if key != "mac_b64"})
            session["sequence"], session["previous"] = sequence, receipt["receipt_sha256"]
        return receipt

    def transport(self, page_nonce: str, submission: dict[str, Any], payload: Any) -> dict[str, Any]:
        raw = _canonical(payload)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        receipt = {
            "schema_version": 1, "artifact_type": "standalone_operator_browser_transport_receipt_v1",
            "listener_id": self.listener_id, "listener_nonce": _b64(bytes(self.listener_nonce)),
            "page_nonce": page_nonce, "submission_id": submission["submission_id"],
            "submission_sha256": _digest(submission), "payload_encoding": "base64url-canonical-json-v1",
            "payload_bytes_b64": _b64(raw), "payload_sha256": _bytes_sha(raw),
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": min(now + timedelta(seconds=STATUS_LIFETIME_SECONDS), self.pages[page_nonce]["expires"]).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "receipt_sha256": "", "mac_algorithm": "HMAC-SHA-256", "mac_b64": "",
        }
        receipt["receipt_sha256"] = _digest({key: item for key, item in receipt.items() if key not in {"receipt_sha256", "mac_b64"}})
        receipt["mac_b64"] = self._mac(TRANSPORT_DOMAIN, {key: item for key, item in receipt.items() if key != "mac_b64"})
        return receipt

    def destroy(self) -> None:
        with self.lock:
            for index in range(len(self.key)):
                self.key[index] = 0
            for index in range(len(self.listener_nonce)):
                self.listener_nonce[index] = 0
            self.pages.clear()


def _validated_assets() -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    for route, (filename, _) in ASSETS.items():
        path = ASSET_ROOT / filename
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise OperatorHTTPError("operator_asset_unsafe", filename)
            values[route] = path.read_bytes()
        except OSError as exc:
            raise OperatorHTTPError("operator_asset_unavailable", filename) from exc
    return values


def _handler(workspace: Path, assets: dict[str, bytes], sessions: _BrowserSessions):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send(self, status_code: int, content_type: str, payload: bytes) -> None:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def _error(self, code: str, status_code: int = 404) -> None:
            payload = json.dumps({"error": code}, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self._send(status_code, "application/json", payload)

        def do_GET(self) -> None:
            if self.path == "/operator/v1/":
                try:
                    bootstrap = _canonical(sessions.bootstrap()).decode("utf-8").replace("<", "\\u003c")
                    payload = assets[self.path].replace(b"__CODEXMAX_BOOTSTRAP__", bootstrap.encode("utf-8"))
                    self._send(200, ASSETS[self.path][1], payload)
                except OperatorHTTPError as exc:
                    self._error(exc.code, 409)
                return
            if self.path in assets:
                _, content_type = ASSETS[self.path]
                self._send(200, content_type, assets[self.path])
                return
            if self.path != "/operator/v1/status":
                self._error("operator_route_not_found")
                return
            try:
                page_nonce, page = sessions.page(self.headers)
                value = service.handle_operator_request(workspace, "GET", self.path)
                payload = _canonical(sessions.status(page_nonce, page, value))
                self._send(200, "application/json", payload)
            except (OperatorHTTPError, service.RuntimeServiceError, TypeError, ValueError) as exc:
                self._error(getattr(exc, "code", "operator_status_failed"), 409)

        def do_POST(self) -> None:
            if self.path != "/operator/v1/submit" or self.headers.get("Content-Type") != "application/json":
                self._error("operator_request_invalid", 400)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 2 or length > MAX_BODY_BYTES:
                self._error("operator_request_invalid", 400)
                return
            try:
                page_nonce, _ = sessions.page(self.headers)
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                value = service.handle_operator_request(workspace, "POST", self.path, body)
                payload = _canonical(sessions.transport(page_nonce, body, value))
                self._send(202, "application/json", payload)
            except (OperatorHTTPError, UnicodeError, json.JSONDecodeError, service.RuntimeServiceError, TypeError, ValueError) as exc:
                self._error(getattr(exc, "code", "operator_request_invalid"), 409)

        def do_OPTIONS(self) -> None:
            self._error("operator_route_not_found")

    return Handler


class OperatorHTTPListener:
    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread, admission: dict[str, Any], readiness: dict[str, Any], sessions: _BrowserSessions) -> None:
        self._server = server
        self._thread = thread
        self._admission = admission
        self._sessions = sessions
        self.readiness_receipt = readiness

    @property
    def origin(self) -> str:
        return f"http://{HOST}:{self.readiness_receipt['port']}{PREFIX}"

    def shutdown(self) -> dict[str, Any]:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(5)
        if self._thread.is_alive():
            raise OperatorHTTPError("operator_shutdown_incomplete", "$.thread")
        self._sessions.destroy()
        port = self.readiness_receipt["port"]
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            absent = probe.connect_ex((HOST, port)) != 0
        finally:
            probe.close()
        receipt = {
            "schema_version": 1,
            "artifact_type": "standalone_operator_listener_shutdown_receipt_v1",
            "listener_id": self.readiness_receipt["listener_id"],
            "admission_id": self._admission["admission_id"],
            "readiness_receipt_sha256": self.readiness_receipt["receipt_sha256"],
            "shutdown": True, "thread_joined": True, "port_absent": absent,
            "shutdown_at": _now(), "receipt_sha256": "",
        }
        receipt["receipt_sha256"] = _digest({key: item for key, item in receipt.items() if key != "receipt_sha256"})
        if not absent:
            raise OperatorHTTPError("operator_shutdown_incomplete", "$.port")
        return receipt


def start_operator_http_server(workspace: str | Path) -> OperatorHTTPListener:
    """Admit first, validate fixed assets, then bind one OS-assigned loopback port."""
    workspace_path = Path(workspace).resolve()
    try:
        admission = service.start_operator_listener(workspace_path)
    except service.RuntimeServiceError as exc:
        raise OperatorHTTPError(exc.code, exc.path) from exc
    assets = _validated_assets()
    sessions = _BrowserSessions(admission)
    try:
        server = ThreadingHTTPServer((HOST, 0), _handler(workspace_path, assets, sessions))
    except Exception:
        sessions.destroy()
        raise
    server.daemon_threads = False
    port = server.server_address[1]
    if server.server_address[0] != HOST or port == HISTORICAL_PORT:
        server.server_close()
        sessions.destroy()
        raise OperatorHTTPError("operator_listener_binding_invalid", "$.listener")
    thread = threading.Thread(target=server.serve_forever, name="codexmax-operator-loopback", daemon=False)
    try:
        thread.start()
    except Exception:
        server.server_close()
        sessions.destroy()
        raise
    readiness = {
        "schema_version": 1,
        "artifact_type": "standalone_operator_listener_readiness_receipt_v1",
        "listener_id": sessions.listener_id,
        "admission_id": admission["admission_id"],
        "workspace_id": admission["workspace_id"],
        "source_sha256": admission["source_sha256"],
        "candidate_sha256": admission["candidate_sha256"],
        "service_instance_id": admission["service_instance_id"],
        "route_table_sha256": admission["route_table_sha256"],
        "host": HOST, "port": port, "path_prefix": PREFIX,
        "ownership_nonce": secrets.token_hex(32), "ready": True,
        "issued_at": _now(), "receipt_sha256": "",
    }
    readiness["receipt_sha256"] = _digest({key: item for key, item in readiness.items() if key != "receipt_sha256"})
    return OperatorHTTPListener(server, thread, admission, readiness, sessions)
