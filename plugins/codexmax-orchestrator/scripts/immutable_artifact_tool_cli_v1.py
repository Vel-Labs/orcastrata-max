#!/usr/bin/env python3
"""Argument gate for successor immutable builder, verifier, and stager tools."""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence


def run_guarded_tool(argv: Sequence[str] | None, *, description: str,
                     action: Callable[[], int]) -> int:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--execute", action="store_true", help="run the one immutable action")
    args = parser.parse_args(argv)
    if not args.execute:
        parser.error("--execute is required")
    return action()


__all__ = ["run_guarded_tool"]
