"""Tool function: discover_paths (设计文档 §3).

Wires FfufAdapter through ComplianceGate. Performs directory/file fuzzing on
authorized targets.

Contract:
  - caller MUST supply a valid authz_token whose scope covers the target URL's host.
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after the adapter returns.
"""
from __future__ import annotations

import os
import uuid
from typing import Any
from urllib.parse import urlparse

from secagent.adapters.ffuf import FfufAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def _host_of(target: str) -> str:
    """Extract the hostname from a target URL for scope/blocklist checks."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def discover_paths(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run ffuf directory/file fuzzing through the compliance gate.

    Returns the unified output structure (spec §3.1):
      { engagement_id, tool, findings, summary, quota_used }
    """
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty string")

    tool_name = "discover_paths"

    # Extract host for scope/blocklist checks
    host = _host_of(target)

    # Pre-flight: compliance gate check (authz + blocklist + DNS IP check)
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=host,
        caller_id=caller_id,
    )

    # Safety: cap recursive depth at 3
    recursive_depth = min(int(params.get("recursive_depth", 1)), 3)

    # Execute: adapter
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    wordlists_dir = os.environ.get("SECAGENT_WORDLISTS_DIR", "./wordlists")
    adapter = FfufAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
        wordlists_dir=wordlists_dir,
    )

    safe_params = dict(params)
    safe_params["recursive_depth"] = recursive_depth
    findings = adapter.run(safe_params)

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
