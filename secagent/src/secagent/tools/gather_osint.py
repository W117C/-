"""Tool function: gather_osint (spec §3.2 ④).

Wires TheHarvesterAdapter through ComplianceGate. OSINT gathering only collects
public data — no intrusion — so this is a low-risk tool.
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.theharvester import TheHarvesterAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="gather_osint", target_field="target")
def gather_osint(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    target = params.get("target", "")
    if not target:
        raise InvalidInputError(field="target", reason="must be a non-empty string")
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = TheHarvesterAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
