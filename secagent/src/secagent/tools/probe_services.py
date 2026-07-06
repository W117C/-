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

import os
from typing import Any

from secagent.adapters.httpx_adapter import HttpxAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="probe_services", target_field="targets")
def probe_services(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    """Run httpx live probe through the compliance gate.

    Returns list[Finding] — the @gated_tool decorator handles the rest.
    """
    targets = params.get("targets", [])
    if not targets or not isinstance(targets, list):
        raise InvalidInputError(field="targets", reason="must be a non-empty list")

    # Pre-flight: compliance gate check for EVERY target. If any target is out
    # of scope, the first gate.check() call raises before any probe runs.
    for target in targets:
        gate.check(
            token=authz_token,
            tool="probe_services",
            target=target,
            caller_id=caller_id,
        )

    # Execute: adapter
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = HttpxAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
    )
    findings = adapter.run(params)

    # The decorator wraps this return value with the standard boilerplate
    return findings
