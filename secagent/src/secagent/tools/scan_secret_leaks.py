"""Tool function: scan_secret_leaks (spec §3.2 ⑤).

Wires GitleaksAdapter through ComplianceGate. The MCP server (M2b) exposes this
as a tool; tests call it directly.

Contract:
  - caller MUST call this with a valid authz_token for the target repo.
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after adapter returns.
  - data minimization (spec §4.3): the adapter is responsible for redacting
    secrets before they reach a Finding; this function trusts that contract
    and does not re-emit plaintext.
"""
from __future__ import annotations

import os
import uuid
from typing import Any

from secagent.adapters.gitleaks import GitleaksAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.errors import InvalidInputError
from secagent.core.gate import ComplianceGate
from secagent.core.finding import Finding


def scan_secret_leaks(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run gitleaks secret-leak scan through the compliance gate.

    Returns the unified output structure (spec §3.1):
    { engagement_id, tool, findings, summary, quota_used }
    """
    target = params.get("scope", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="scope", reason="must be a non-empty string (local repo path or repo URL)")
    tool_name = "scan_secret_leaks"

    # Pre-flight: compliance gate check (authz + blocklist)
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=target,
        caller_id=caller_id,
    )

    # Execute: adapter
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = GitleaksAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    findings = adapter.run(params)

    # Build response
    engagement_id = f"eng_{uuid.uuid4().hex}"
    findings_dicts = [f.to_dict() for f in findings]
    for fd in findings_dicts:
        fd["engagement_id"] = engagement_id

    # Post-run: commit findings + decrement quota (also persists to findings table)
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
