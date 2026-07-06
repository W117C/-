"""Tool function: scan_secret_leaks (spec §3.2 ⑤).

Wires GitleaksAdapter through ComplianceGate. Scans git repos for leaked
credentials. Data minimization (spec §4.3): secrets are redacted in the adapter.
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.gitleaks import GitleaksAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="scan_secret_leaks", target_field=["scope", "target"])
def scan_secret_leaks(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    target = params.get("scope", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(
            field="scope",
            reason="must be a non-empty string (local repo path or repo URL)",
        )
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = GitleaksAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
