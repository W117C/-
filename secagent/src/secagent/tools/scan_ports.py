"""Tool function: scan_ports (设计文档 §2).

Wires NaabuAdapter through ComplianceGate. Performs port scanning on authorized
targets using naabu (ProjectDiscovery port scanner).
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.naabu import NaabuAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="scan_ports", target_field="target")
def scan_ports(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty string")
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = NaabuAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
