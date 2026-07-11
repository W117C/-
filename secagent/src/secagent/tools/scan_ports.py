"""Tool function: scan_ports (spec §3.2 ②) — port scanning.

Naabu performs port scanning on authorized targets. Wired through
ComplianceGate with IP whitelist/blacklist enforcement."""
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
    """Run naabu port scanner through the compliance gate.

    Validates target, constructs NaabuAdapter. The decorator handles
    gate.check, commit_findings, and the return dict encoding.
    """
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty string")
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = NaabuAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120),
                          proxy_manager=gate.proxy_manager),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
