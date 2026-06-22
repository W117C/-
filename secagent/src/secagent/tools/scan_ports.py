"""Tool function: scan_ports (设计文档 §2).

Wires NaabuAdapter through ComplianceGate. Performs port scanning on authorized
targets using naabu (ProjectDiscovery port scanner).

Contract:
  - caller MUST supply a valid authz_token whose scope covers the target.
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after the adapter returns.
"""
from __future__ import annotations

import os
import uuid
from typing import Any

from secagent.adapters.naabu import NaabuAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def scan_ports(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run naabu port scan through the compliance gate.

    Returns the unified output structure (spec §3.1):
      { engagement_id, tool, findings, summary, quota_used }
    """
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty string")

    tool_name = "scan_ports"

    # Pre-flight: compliance gate check (authz + blocklist + DNS IP check)
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=target,
        caller_id=caller_id,
    )

    # Execute: adapter
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = NaabuAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    findings = adapter.run(params)

    # Build response
    engagement_id = f"eng_{uuid.uuid4().hex}"
    findings_dicts = [f.to_dict() for f in findings]
    for fd in findings_dicts:
        fd["engagement_id"] = engagement_id

    # Post-run: commit findings + decrement quota
    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=target,
        scope_value=scope.value,
        findings=findings_dicts,
    )

    return {
        "engagement_id": engagement_id,
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": Finding.summary(findings),
        "quota_used": 1,
    }
