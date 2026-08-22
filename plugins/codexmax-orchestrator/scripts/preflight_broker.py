#!/usr/bin/env python3
"""Local deterministic singleflight cache for exact-route preflight evidence."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, Iterator, Sequence

sys.dont_write_bytecode = True

SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 60
MAX_TTL_SECONDS = 300
KEY_FIELDS = ("provider", "exact_model", "route_id", "runtime", "reasoning", "proof_mode")
KEY_KEYS = set(KEY_FIELDS)
OBSERVATION_INPUT_KEYS = {
    "schema_version", "availability", "health", "callability",
    "receipt_descriptor", "receipt_digest",
}
OBSERVATION_KEYS = OBSERVATION_INPUT_KEYS | {"key", "observed_at", "expires_at"}
LEASE_KEYS = {"owner_token", "acquired_at", "expires_at"}
ENTRY_KEYS = {"key", "lease", "observation"}
STATE_KEYS = {"schema_version", "entries", "history", "state_sha256"}
EVENT_KEYS = {"sequence", "kind", "key_sha256", "at", "owner_token", "previous_event_sha256", "event_sha256"}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$")
STATUS = {
    "availability": {"available", "unavailable", "unknown"},
    "health": {"healthy", "unhealthy", "unknown"},
    "callability": {"callable", "not_callable", "unknown"},
}


class PreflightBrokerError(Exception):
    def __init__(self, code: str, details: object | None = None):
        super().__init__(code)
        self.code = code
        self.details = details


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _strict_text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise PreflightBrokerError(code)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise PreflightBrokerError(code)
    return value


def _timestamp(value: object, code: str) -> datetime:
    text = _strict_text(value, code)
    if TIME_RE.fullmatch(text) is None:
        raise PreflightBrokerError(code)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise PreflightBrokerError(code) from error
    return parsed.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(".000000+00:00", "Z").replace("+00:00", "Z")


def _duration(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_TTL_SECONDS:
        raise PreflightBrokerError(code)
    return value


def normalize_key(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != KEY_KEYS:
        raise PreflightBrokerError("preflight_key_shape_invalid")
    return {field: _strict_text(value[field], f"preflight_key_{field}_invalid") for field in KEY_FIELDS}


def key_sha256(value: object) -> str:
    return _digest(normalize_key(value))


def _empty_state() -> dict[str, Any]:
    state: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "entries": {}, "history": []}
    state["state_sha256"] = _digest(state)
    return state


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {key: event[key] for key in EVENT_KEYS - {"event_sha256"}}


def _verify_observation(value: object, expected_key: dict[str, str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != OBSERVATION_KEYS:
        raise PreflightBrokerError("preflight_observation_shape_invalid")
    if value["schema_version"] != SCHEMA_VERSION or isinstance(value["schema_version"], bool):
        raise PreflightBrokerError("preflight_observation_version_invalid")
    if normalize_key(value["key"]) != expected_key:
        raise PreflightBrokerError("preflight_observation_key_mismatch")
    for field, allowed in STATUS.items():
        if value[field] not in allowed:
            raise PreflightBrokerError(f"preflight_observation_{field}_invalid")
    _strict_text(value["receipt_descriptor"], "preflight_receipt_descriptor_invalid")
    if not isinstance(value["receipt_digest"], str) or SHA256_RE.fullmatch(value["receipt_digest"]) is None:
        raise PreflightBrokerError("preflight_receipt_digest_invalid")
    observed = _timestamp(value["observed_at"], "preflight_observed_at_invalid")
    expires = _timestamp(value["expires_at"], "preflight_expires_at_invalid")
    if expires <= observed or expires - observed > timedelta(seconds=MAX_TTL_SECONDS):
        raise PreflightBrokerError("preflight_observation_expiry_invalid")
    return value


def verify_state(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise PreflightBrokerError("preflight_state_shape_invalid")
    if value["schema_version"] != SCHEMA_VERSION or isinstance(value["schema_version"], bool):
        raise PreflightBrokerError("preflight_state_version_invalid")
    supplied_digest = value["state_sha256"]
    if not isinstance(supplied_digest, str) or SHA256_RE.fullmatch(supplied_digest) is None:
        raise PreflightBrokerError("preflight_state_digest_invalid")
    payload = {key: value[key] for key in STATE_KEYS - {"state_sha256"}}
    if _digest(payload) != supplied_digest:
        raise PreflightBrokerError("preflight_state_digest_mismatch")
    if not isinstance(value["entries"], dict) or not isinstance(value["history"], list):
        raise PreflightBrokerError("preflight_state_shape_invalid")
    previous: str | None = None
    for index, event in enumerate(value["history"], start=1):
        if not isinstance(event, dict) or set(event) != EVENT_KEYS:
            raise PreflightBrokerError("preflight_history_event_shape_invalid")
        if event["sequence"] != index or isinstance(event["sequence"], bool):
            raise PreflightBrokerError("preflight_history_sequence_invalid")
        if event["kind"] not in {"probe_claimed", "probe_recovered", "observation_recorded"}:
            raise PreflightBrokerError("preflight_history_kind_invalid")
        if not isinstance(event["key_sha256"], str) or SHA256_RE.fullmatch(event["key_sha256"]) is None:
            raise PreflightBrokerError("preflight_history_key_digest_invalid")
        _timestamp(event["at"], "preflight_history_timestamp_invalid")
        _strict_text(event["owner_token"], "preflight_owner_token_invalid")
        if event["previous_event_sha256"] != previous:
            raise PreflightBrokerError("preflight_history_chain_invalid")
        if event["event_sha256"] != _digest(_event_payload(event)):
            raise PreflightBrokerError("preflight_history_digest_mismatch")
        previous = event["event_sha256"]
    for digest, entry in value["entries"].items():
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise PreflightBrokerError("preflight_entry_digest_invalid")
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise PreflightBrokerError("preflight_entry_shape_invalid")
        key = normalize_key(entry["key"])
        if _digest(key) != digest:
            raise PreflightBrokerError("preflight_entry_key_digest_mismatch")
        lease = entry["lease"]
        if lease is not None:
            if not isinstance(lease, dict) or set(lease) != LEASE_KEYS:
                raise PreflightBrokerError("preflight_lease_shape_invalid")
            _strict_text(lease["owner_token"], "preflight_owner_token_invalid")
            acquired = _timestamp(lease["acquired_at"], "preflight_lease_acquired_at_invalid")
            expires = _timestamp(lease["expires_at"], "preflight_lease_expires_at_invalid")
            if expires <= acquired or expires - acquired > timedelta(seconds=MAX_TTL_SECONDS):
                raise PreflightBrokerError("preflight_lease_expiry_invalid")
        if entry["observation"] is not None:
            _verify_observation(entry["observation"], key)
    return value


def read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreflightBrokerError("preflight_state_unreadable") from error
    return verify_state(value)


def _read_existing_regular_state(path: Path) -> dict[str, Any]:
    """Read one existing state file without following a final symlink."""
    try:
        named = path.lstat()
    except OSError as error:
        raise PreflightBrokerError("preflight_state_unreadable") from error
    if stat.S_ISLNK(named.st_mode) or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1:
        raise PreflightBrokerError("preflight_state_unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PreflightBrokerError("preflight_state_unreadable") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PreflightBrokerError("preflight_state_unsafe")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise PreflightBrokerError("preflight_state_unreadable") from error
    finally:
        os.close(descriptor)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_nlink)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink):
        raise PreflightBrokerError("preflight_state_changed")
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreflightBrokerError("preflight_state_unreadable") from error
    return verify_state(value)


def read_current_observation(
    path: Path, key_value: object, *, now: str,
) -> dict[str, Any]:
    """Return one exact, current observation and its locked state bindings."""
    key = normalize_key(key_value)
    instant = _timestamp(now, "preflight_read_timestamp_invalid")
    digest = _digest(key)
    with _locked(path):
        state = _read_existing_regular_state(path)
        entry = state["entries"].get(digest)
        if entry is None:
            raise PreflightBrokerError("preflight_entry_missing")
        observation = entry["observation"]
        if observation is None:
            raise PreflightBrokerError("preflight_observation_missing")
        observed = _timestamp(observation["observed_at"], "preflight_observed_at_invalid")
        expires = _timestamp(observation["expires_at"], "preflight_expires_at_invalid")
        if observed > instant:
            raise PreflightBrokerError("preflight_observation_from_future")
        if expires <= instant:
            raise PreflightBrokerError("preflight_observation_expired")
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "current",
            "key_sha256": digest,
            "observation": json.loads(canonical_json(observation)),
            "state_sha256": state["state_sha256"],
            "entry_sha256": _digest(entry),
        }
    return result


def _seal(state: dict[str, Any]) -> None:
    state["state_sha256"] = _digest({key: state[key] for key in STATE_KEYS - {"state_sha256"}})


def _append_event(state: dict[str, Any], kind: str, digest: str, at: str, owner_token: str) -> None:
    previous = state["history"][-1]["event_sha256"] if state["history"] else None
    event = {
        "sequence": len(state["history"]) + 1, "kind": kind, "key_sha256": digest,
        "at": at, "owner_token": owner_token, "previous_event_sha256": previous,
    }
    event["event_sha256"] = _digest(event)
    state["history"].append(event)


def _atomic_write(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _seal(state)
    verify_state(state)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(canonical_json(state) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def request_probe(path: Path, key_value: object, *, owner_token: str, now: str, lease_seconds: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
    key = normalize_key(key_value)
    owner = _strict_text(owner_token, "preflight_owner_token_invalid")
    instant = _timestamp(now, "preflight_request_timestamp_invalid")
    seconds = _duration(lease_seconds, "preflight_lease_duration_invalid")
    digest = _digest(key)
    with _locked(path):
        state = read_state(path)
        entry = state["entries"].get(digest)
        if entry is not None and entry["observation"] is not None:
            observation = entry["observation"]
            if _timestamp(observation["expires_at"], "preflight_expires_at_invalid") > instant:
                return {"schema_version": 1, "decision": "cache_hit", "key_sha256": digest, "observation": observation}
        if entry is not None and entry["lease"] is not None:
            lease = entry["lease"]
            if _timestamp(lease["expires_at"], "preflight_lease_expires_at_invalid") > instant:
                decision = "probe_required" if lease["owner_token"] == owner else "probe_in_flight"
                return {"schema_version": 1, "decision": decision, "key_sha256": digest, "lease": lease, "recovered_abandoned_lease": False}
        recovered = entry is not None and entry["lease"] is not None
        lease = {"owner_token": owner, "acquired_at": now, "expires_at": _time_text(instant + timedelta(seconds=seconds))}
        state["entries"][digest] = {"key": key, "lease": lease, "observation": None}
        _append_event(state, "probe_recovered" if recovered else "probe_claimed", digest, now, owner)
        _atomic_write(path, state)
        return {"schema_version": 1, "decision": "probe_required", "key_sha256": digest, "lease": lease, "recovered_abandoned_lease": recovered}


def record_observation(path: Path, key_value: object, observation_value: object, *, owner_token: str, now: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
    key = normalize_key(key_value)
    owner = _strict_text(owner_token, "preflight_owner_token_invalid")
    instant = _timestamp(now, "preflight_record_timestamp_invalid")
    seconds = _duration(ttl_seconds, "preflight_ttl_invalid")
    if not isinstance(observation_value, dict) or set(observation_value) != OBSERVATION_INPUT_KEYS:
        raise PreflightBrokerError("preflight_observation_input_shape_invalid")
    if observation_value["schema_version"] != SCHEMA_VERSION or isinstance(observation_value["schema_version"], bool):
        raise PreflightBrokerError("preflight_observation_version_invalid")
    digest = _digest(key)
    observation = {
        **observation_value, "key": key, "observed_at": now,
        "expires_at": _time_text(instant + timedelta(seconds=seconds)),
    }
    _verify_observation(observation, key)
    with _locked(path):
        state = read_state(path)
        entry = state["entries"].get(digest)
        if entry is None or entry["lease"] is None:
            raise PreflightBrokerError("preflight_probe_lease_missing")
        lease = entry["lease"]
        if lease["owner_token"] != owner:
            raise PreflightBrokerError("preflight_probe_owner_mismatch")
        if _timestamp(lease["expires_at"], "preflight_lease_expires_at_invalid") <= instant:
            raise PreflightBrokerError("preflight_probe_lease_expired")
        entry["lease"] = None
        entry["observation"] = observation
        _append_event(state, "observation_recorded", digest, now, owner)
        _atomic_write(path, state)
    return {"schema_version": 1, "status": "recorded", "key_sha256": digest, "observation": observation}


def inspect(path: Path) -> dict[str, Any]:
    with _locked(path):
        state = read_state(path)
    return {
        "schema_version": 1, "status": "valid", "entry_count": len(state["entries"]),
        "event_count": len(state["history"]), "state_sha256": state["state_sha256"],
        "entries": [state["entries"][key] for key in sorted(state["entries"])],
    }


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PreflightBrokerError("preflight_input_unreadable") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    request_parser = subparsers.add_parser("request")
    request_parser.add_argument("state", type=Path); request_parser.add_argument("key", type=Path)
    request_parser.add_argument("--owner-token", required=True); request_parser.add_argument("--now", required=True)
    request_parser.add_argument("--lease-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("state", type=Path); record_parser.add_argument("key", type=Path); record_parser.add_argument("observation", type=Path)
    record_parser.add_argument("--owner-token", required=True); record_parser.add_argument("--now", required=True)
    record_parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    current_parser = subparsers.add_parser("current")
    current_parser.add_argument("state", type=Path); current_parser.add_argument("key", type=Path)
    current_parser.add_argument("--now", required=True)
    inspect_parser = subparsers.add_parser("inspect"); inspect_parser.add_argument("state", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "request":
            result = request_probe(args.state, _load_json(args.key), owner_token=args.owner_token, now=args.now, lease_seconds=args.lease_seconds)
        elif args.command == "record":
            result = record_observation(args.state, _load_json(args.key), _load_json(args.observation), owner_token=args.owner_token, now=args.now, ttl_seconds=args.ttl_seconds)
        elif args.command == "current":
            result = read_current_observation(args.state, _load_json(args.key), now=args.now)
        else:
            result = inspect(args.state)
    except PreflightBrokerError as error:
        print(canonical_json({"schema_version": 1, "status": "error", "code": error.code, "details": error.details}), file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
