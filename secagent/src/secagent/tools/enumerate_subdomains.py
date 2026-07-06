"""Tool function: enumerate_subdomains (spec §3.2 ①).

Wires SubfinderAdapter through ComplianceGate. The MCP server (M2b) will
expose this as a tool; tests call it directly.
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.subfinder import SubfinderAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="enumerate_subdomains", target_field="target_domain")
def enumerate_subdomains(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    target_domain = params.get("target_domain", "")
    if not target_domain or not isinstance(target_domain, str):
        raise InvalidInputError(
            field="target_domain", reason="must be a non-empty string"
        )
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = SubfinderAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
