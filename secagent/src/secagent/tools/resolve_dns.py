"""Tool function: resolve_dns — DNS resolution with wildcard detection.

Wires DnsxAdapter through ComplianceGate. Resolves subdomains/domains,
detects wildcard DNS configurations, and extracts A/CNAME/MX records.
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.dnsx import DnsxAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="resolve_dns", target_field="targets")
def resolve_dns(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    targets = params.get("targets", [])
    if isinstance(targets, str):
        targets = [targets]
    if not targets or not isinstance(targets, list):
        raise InvalidInputError(field="targets", reason="must be a non-empty list")

    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = DnsxAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120),
                          proxy_manager=gate.proxy_manager),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
