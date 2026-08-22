#!/usr/bin/env python3
"""Build one explicit public repository stage from an approved allowlist."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys

from validate_public_release import (
    MANIFEST_RELATIVE,
    PLUGIN_RELATIVE,
    ROOT_PUBLIC_FILES,
    PublicReleaseError,
    validate_manifest_source,
    validate_stage,
)


def _copy_file(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise PublicReleaseError(f"source_file_invalid:{source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def build_public_release(source_root: Path, destination: Path) -> dict[str, object]:
    source_root = source_root.resolve()
    destination = destination.absolute()
    if not source_root.is_dir() or source_root.is_symlink():
        raise PublicReleaseError("source_root_invalid")
    if destination.exists():
        raise PublicReleaseError("destination_exists")
    plugin_root = source_root / PLUGIN_RELATIVE
    rows = validate_manifest_source(plugin_root)
    for relative in ROOT_PUBLIC_FILES:
        if not (source_root / relative).is_file():
            raise PublicReleaseError(f"required_public_file_missing:{relative}")

    destination.mkdir(parents=True, exist_ok=False)
    try:
        for relative in ROOT_PUBLIC_FILES:
            _copy_file(source_root / relative, destination / relative)
        for row in rows:
            relative = Path(row["path"])
            _copy_file(
                plugin_root / relative,
                destination / PLUGIN_RELATIVE / relative,
            )
        _copy_file(
            plugin_root / MANIFEST_RELATIVE,
            destination / PLUGIN_RELATIVE / MANIFEST_RELATIVE,
        )
        receipt = validate_stage(destination)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return {
        **receipt,
        "stage": str(destination),
        "source": str(source_root),
        "git_staging_performed": False,
        "archive_created": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = build_public_release(args.source_root, args.destination)
    except PublicReleaseError as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

