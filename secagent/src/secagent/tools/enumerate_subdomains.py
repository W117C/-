"""Tool function: enumerate_subdomains (spec §3.2 ①).

Wires SubfinderAdapter through ComplianceGate. The MCP server (M2b) will
expose this as a tool; tests call it directly.

Contract:
  - caller MUST call this with a valid authz_token for the target.
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after adapter returns.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from secagent.adapters.subfinder import SubfinderAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.gate import ComplianceGate


def enumerate_subdomains(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run subfinder subdomain enumeration through the compliance gate.

    Returns the unified output structure (spec §3.1):
    { engagement_id, tool, findings, summary, quota_used }
    """
    target_domain = params.get("target_domain", "")
    tool_name = "enumerate_subdomains"

    # Pre-flight: compliance gate check (authz + blocklist)
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=target_domain,
        caller_id=caller_id,
    )

    # Execute: adapter
    adapter = SubfinderAdapter(launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)))
    findings = adapter.run(params)

    # Post-run: commit findings + decrement quota
    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=target_domain,
        scope_value=scope.value,
    )

    # Build response
    return {
        "engagement_id": f"eng_{uuid.uuid4().hex[:8]}",
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": {"info": len(findings)},
            "by_type": {"subdomain": len(findings)},
        },
        "quota_used": 1,
    }
