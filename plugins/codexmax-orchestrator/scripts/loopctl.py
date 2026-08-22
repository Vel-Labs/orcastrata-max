#!/usr/bin/env python3
"""Non-executing LoopRegistry v1 inspection and dry-run CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import loop_registry as core


def emit(payload: object) -> None:
    print(core.canonical_json(payload))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Inspect LoopRegistry v1 without executing actions.")
    sub = result.add_subparsers(dest="operation", required=True)
    for name in ("list", "validate"):
        command = sub.add_parser(name)
        command.add_argument("--workspace-root", required=True)
        command.add_argument("--registry", required=True)
        command.add_argument("--json", action="store_true")
    for name in ("show", "status"):
        command = sub.add_parser(name)
        command.add_argument("loop_id")
        command.add_argument("--workspace-root", required=True)
        command.add_argument("--registry", required=True)
        command.add_argument("--json", action="store_true")
    for name in ("match", "dry-run"):
        command = sub.add_parser(name)
        command.add_argument("--workspace-root", required=True)
        command.add_argument("--registry", required=True)
        command.add_argument("--event", required=True)
        command.add_argument("--evaluation-time", required=True)
        command.add_argument("--json", action="store_true")
    command = sub.add_parser("verify-receipt")
    command.add_argument("receipt")
    command.add_argument("--workspace-root", required=True)
    command.add_argument("--json", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        roots = core.default_roots(workspace_root=Path(args.workspace_root))
        if args.operation == "verify-receipt":
            value = core.load_json(Path(args.receipt), receipt=True)
            errors = core.verify_receipt(value, roots=roots)
            emit({"schema_version": 1, "operation": args.operation, "valid": not errors, "errors": errors, "executed": False})
            return 0 if not errors else 2
        path = Path(args.registry)
        value = core.load_yaml(path)
        errors = core.validate_registry(value, roots=roots)
        if args.operation == "validate":
            emit({"schema_version": 1, "operation": "validate", "registry": str(path), "valid": not errors, "errors": errors, "executed": False})
            return 0 if not errors else 2
        if errors:
            raise core.LoopContractError(*errors)
        assert isinstance(value, dict)
        loops = sorted(value["loops"], key=lambda row: row["loop_id"])
        if args.operation == "list":
            emit({"schema_version": 1, "operation": "list", "loops": [{"loop_id": row["loop_id"], "lifecycle": row["lifecycle"]["state"]} for row in loops], "executed": False})
            return 0
        if args.operation in {"show", "status"}:
            found = next((row for row in loops if row["loop_id"] == args.loop_id), None)
            if found is None:
                emit({"schema_version": 1, "operation": args.operation, "valid": False, "errors": ["loop_unknown"], "executed": False})
                return 2
            payload = found if args.operation == "show" else {"loop_id": found["loop_id"], "lifecycle": found["lifecycle"]["state"], "action_profile_ids": found["action_profile_ids"]}
            emit({"schema_version": 1, "operation": args.operation, "valid": True, "loop": payload, "executed": False})
            return 0
        event = core.load_json(Path(args.event))
        assert isinstance(event, dict)
        result = core.match_event(
            value,
            event,
            evaluation_time=args.evaluation_time,
            roots=roots,
            dry_run=True,
        )
        result["operation"] = args.operation
        emit(result)
        return 0 if result["valid"] else 2
    except (OSError, core.LoopContractError) as error:
        codes = error.codes if isinstance(error, core.LoopContractError) else ["input_unavailable"]
        emit({"schema_version": 1, "operation": args.operation, "valid": False, "errors": codes, "executed": False})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
