"""Tool function: probe_services (spec §3.2 ②).

Wires HttpxAdapter through ComplianceGate. Performs live probe + service
identification on a list of authorized targets.

Contract:
  - caller MUST call this with a valid authz_token covering ALL targets.
  - the compliance gate checks authorization + blocklist per target.
  - if ANY target is out of scope, the entire call is refused before any
    probe runs (no partial execution).
  - adapter runs only after every target passes gate.check().
  - gate.commit_findings() is called once after the adapter returns.
"""
from __future__ import annotations

import uuid
from typing import Any

from secagent.adapters.httpx_adapter import HttpxAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def probe_services(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run httpx live probe through the compliance gate.

    Returns the unified output structure (spec §3.1):
    { engagement_id, tool, findings, summary, quota_used }
    """
    targets = params.get("targets", [])
    if not targets or not isinstance(targets, list):
        raise InvalidInputError(field="targets", reason="must be a non-empty list")

    tool_name = "probe_services"

    # Pre-flight: compliance gate check for EVERY target (authz + blocklist).
    # If any target is out of scope, refuse the entire call before running
    # the adapter — no partial probing.
    last_scope = None
    for target in targets:
        last_scope = gate.check(
            token=authz_token,
            tool=tool_name,
            target=target,
            caller_id=caller_id,
        )

    # Execute: adapter
    adapter = HttpxAdapter(launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)))
    findings = adapter.run(params)

    # Post-run: commit findings + decrement quota (one unit per call)
    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=",".join(targets),
        scope_value=last_scope.value if last_scope else None,
    )

    return {
        "engagement_id": f"eng_{uuid.uuid4().hex[:8]}",
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": Finding.summary(findings),
        "quota_used": 1,
    }
