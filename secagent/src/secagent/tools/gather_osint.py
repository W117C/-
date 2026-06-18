"""Tool function: gather_osint (spec §3.2 ④).

Wires TheHarvesterAdapter through ComplianceGate. OSINT gathering only collects
public data — no intrusion — so this is a low-risk tool. MVP still routes through
the standard gate for consistency with the other tools; spec §4.5 notes B-direction
rules may be relaxed later.

Contract:
  - caller MUST call this with a valid authz_token for the target.
  - target may be a domain (DOMAIN scope) or an email (EMAIL scope); the scope
    type is decided at token issuance and enforced by gate.check().
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after the adapter returns — even on empty
    results, one quota unit is consumed.
"""
from __future__ import annotations

import uuid
from typing import Any

from secagent.adapters.theharvester import TheHarvesterAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def gather_osint(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run theHarvester OSINT gathering through the compliance gate.

    Returns the unified output structure (spec §3.1):
    { engagement_id, tool, findings, summary, quota_used }
    """
    target = params.get("target", "")
    if not target:
        raise InvalidInputError(field="target", reason="must be a non-empty string")

    tool_name = "gather_osint"

    # Pre-flight: compliance gate check (authz + blocklist)
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=target,
        caller_id=caller_id,
    )

    # Execute: adapter
    adapter = TheHarvesterAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120))
    )
    findings = adapter.run(params)

    # Post-run: commit findings + decrement quota
    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=target,
        scope_value=scope.value,
    )

    # Build response
    return {
        "engagement_id": f"eng_{uuid.uuid4().hex[:8]}",
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": Finding.summary(findings),
        "quota_used": 1,
    }
