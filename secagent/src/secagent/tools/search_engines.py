"""Tool function: search_engines — multi-engine host discovery.

Wires UncoverAdapter through ComplianceGate. Queries Shodan/Censys/Fofa
simultaneously for hosts matching a query. Passive-only, no target probes.
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.uncover import UncoverAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="search_engines", target_field=["query", "target"])
def search_engines(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    query = params.get("query", "") or params.get("target", "")
    if not query or not isinstance(query, str):
        raise InvalidInputError(field="query", reason="must be a non-empty string")

    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = UncoverAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120),
                          proxy_manager=gate.proxy_manager),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
