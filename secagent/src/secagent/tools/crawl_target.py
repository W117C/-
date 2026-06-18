"""Tool function: crawl_target (spec §3.2 ⑥).

Wires SimpleCrawlerAdapter through ComplianceGate. The MCP server exposes this
as a tool; tests call it directly.

Contract:
  - caller MUST supply a valid authz_token whose scope covers the URL's host.
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after the adapter returns.

Scope handling:
  - `target` is a URL like "https://acme.com/path".
  - The ComplianceGate checks scope against the host (e.g. "acme.com"), so we
    extract the hostname via urllib.parse.urlparse before calling gate.check().
"""
from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from secagent.adapters.simple_crawler import SimpleCrawlerAdapter
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


def crawl_target(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run the built-in single-page HTTP crawler through the compliance gate.

    Returns the unified output structure (spec §3.1):
      { engagement_id, tool, findings, summary, quota_used }
    """
    target = params.get("target", "")
    tool_name = "crawl_target"

    # The scope is domain-based; gate.check compares against the host, not the
    # full URL. urlparse(...).hostname lowercases and strips the port.
    host = urlparse(target).hostname or target
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=host,
        caller_id=caller_id,
    )

    adapter = SimpleCrawlerAdapter(timeout_sec=params.get("timeout_sec", 30))
    findings: list[Finding] = adapter.run(params)

    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=target,
        scope_value=scope.value,
    )

    return {
        "engagement_id": f"eng_{uuid.uuid4().hex[:8]}",
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": Finding.summary(findings),
        "quota_used": 1,
    }
