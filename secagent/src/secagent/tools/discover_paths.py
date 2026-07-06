"""Tool function: discover_paths (设计文档 §3).

Wires FfufAdapter through ComplianceGate. Performs directory/file fuzzing on
authorized targets.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from secagent.adapters.ffuf import FfufAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def _host_of(target: str) -> str:
    """Extract the hostname from a target URL for scope/blocklist checks."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


@gated_tool(tool_name="discover_paths", target_field="target")
def discover_paths(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    """Run ffuf directory/file fuzzing through the compliance gate.

    The @gated_tool decorator handles gate.check, commit_findings, and the
    return dict. This function only validates params and creates the adapter.
    """
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty string")

    # Safety: cap recursive depth at 3
    safe_params = dict(params)
    safe_params["recursive_depth"] = min(int(params.get("recursive_depth", 1)), 3)

    binaries_dir = __import__("os").environ.get("SECAGENT_BINARIES_DIR", "./bin")
    wordlists_dir = __import__("os").environ.get("SECAGENT_WORDLISTS_DIR", "./wordlists")
    adapter = FfufAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
        binaries_dir=binaries_dir,
        wordlists_dir=wordlists_dir,
    )
    findings = adapter.run(safe_params)
    return findings
