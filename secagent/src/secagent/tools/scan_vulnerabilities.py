"""Tool function: scan_vulnerabilities (spec §3.2 ③) — HIGHEST RISK TOOL.

Nuclei sends ACTIVE probe packets. This tool function implements the
three-layer compliance guard required by spec §3.2 ③:

  Layer 1 (gate.check)      — token verified + target within scope
  Layer 2 (blocklist.check) — re-validated per-target immediately before
                              nuclei runs (defense in depth: even if the
                              gate passed, a .gov target must NEVER reach
                              nuclei's -u list)
  Layer 3 (rate_limit)      — nuclei -rate-limit enforced per subprocess

The blocklist re-check is non-trivial: between gate.check and adapter.run the
only thing that could change is the target list itself (a caller might pass
mixed targets). We therefore iterate every target through the blocklist a
SECOND time right before handing off to the adapter, and refuse the whole
call if any target is blocked.

Contract (same as every other tool function):
  - caller supplies a verified authz_token covering ALL targets
  - gate.check runs per-target (one out-of-scope target refuses the call)
  - blocklist re-checked per-target right before nuclei runs
  - quota_used = 1 per call (not per target — keeps billing simple in MVP)
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from secagent.adapters.nuclei import NucleiAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.blocklist import Blocklist
from secagent.core.errors import ComplianceBlockError, InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def _host_of(target: str) -> str:
    """Extract the hostname from a target for scope/blocklist checks.

    Nuclei accepts both bare hosts ('sub.acme.com') and URLs
    ('https://sub.acme.com/path'). The authz scope and blocklist are defined
    on hostnames, so we strip the scheme/path here. Non-URL targets are
    returned unchanged (covers IP literals and bare domains).
    """
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def scan_vulnerabilities(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run nuclei vulnerability scan through the three-layer compliance guard.

    Returns the unified output structure (spec §3.1).
    Raises NotAuthorizedError / ComplianceBlockError / InvalidInputError /
    ToolFailedError / ToolTimeoutError as appropriate.
    """
    targets: list[str] = params.get("targets", [])
    if not targets:
        raise InvalidInputError(
            field="targets", reason="must be a non-empty list"
        )
    tool_name = "scan_vulnerabilities"

    # --- Layer 1: gate.check per target (authz + blocklist + audit) --------
    # Every target is checked; the first failure refuses the whole call and
    # is recorded in the audit log by the gate itself. Scope/blocklist are
    # evaluated on the hostname (targets may be URLs).
    scopes = []
    for t in targets:
        host = _host_of(t)
        scope = gate.check(
            token=authz_token, tool=tool_name, target=host, caller_id=caller_id
        )
        scopes.append(scope)

    # --- Layer 2: blocklist re-check immediately before nuclei runs --------
    # Defense in depth (spec §3.2 ③ 三层防护 layer 2). The gate already
    # checked the blocklist, but we re-assert here so that even a future bug
    # in gate wiring can never let a .gov/private-IP reach nuclei's -l list.
    blocklist = gate.blocklist or Blocklist()
    for t in targets:
        host = _host_of(t)
        blocked, reason = blocklist.is_blocked(host)
        if blocked:
            raise ComplianceBlockError(target=host, reason=reason or "blocklist match")

    # --- Layer 3: rate limit is passed through to the adapter -------------
    # The adapter forwards rate_limit to nuclei's -rate-limit flag. We cap it
    # at a sane maximum to prevent accidental DoS even if the caller asks for
    # something absurd.
    safe_params = dict(params)
    requested_rate = int(params.get("rate_limit", 150))
    safe_params["rate_limit"] = max(1, min(requested_rate, 500))

    # --- Execute: adapter -------------------------------------------------
    adapter = NucleiAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 600))
    )
    findings = adapter.run(safe_params)

    # --- Post-run: commit findings + decrement quota ----------------------
    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=",".join(targets),
        scope_value=scopes[0].value if scopes else None,
    )

    return {
        "engagement_id": f"eng_{uuid.uuid4().hex[:8]}",
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": Finding.summary(findings),
        "quota_used": 1,
    }
