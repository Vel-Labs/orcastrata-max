#!/usr/bin/env python3
"""V3 Darwin launch-proof gate over the unchanged R3 commit boundary.

The gate performs source-local rejection only. It does not launch, inspect the
host, reopen a pathname, write the R3 ledger, or issue deployment admission.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Collection, Mapping

import supported_host_darwin_launch_authority_v1 as darwin


PROTOCOL_VERSION = "supported_host_deployment_bootstrap_v3"
SOURCE_ID = "codexmax-supported-host-deployment-bootstrap-v3"

def assess_darwin_launch_proof_for_r3(
    value: Any,
    *,
    expected_bindings: Mapping[str, Any],
    previous_committed_generation: int,
    now: datetime,
    seen_proof_sha256s: Collection[str] = (),
    seen_nonce_sha256s: Collection[str] = (),
) -> darwin.LaunchProofV3Assessment:
    """Assess evidence without advancing or opening the R3 ledger."""

    return darwin.assess_launch_proof_v3(
        value,
        expected_bindings=expected_bindings,
        previous_committed_generation=previous_committed_generation,
        now=now,
        seen_proof_sha256s=seen_proof_sha256s,
        seen_nonce_sha256s=seen_nonce_sha256s,
    )


def source_local_validation_boundary() -> darwin.LaunchProofV3Assessment:
    """Return a pending-only boundary with no production effects."""

    return darwin.source_local_validation_boundary()


__all__ = [
    "PROTOCOL_VERSION",
    "SOURCE_ID",
    "assess_darwin_launch_proof_for_r3",
    "source_local_validation_boundary",
]
