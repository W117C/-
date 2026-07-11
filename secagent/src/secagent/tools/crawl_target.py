"""Tool function: crawl_target (spec §3.2 ⑥).

Wires SimpleCrawlerAdapter through ComplianceGate. Crawls a single URL and
extracts exposure signals (forms, JS endpoints, emails, comments).
"""
from __future__ import annotations

from typing import Any

from secagent.adapters.simple_crawler import SimpleCrawlerAdapter
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="crawl_target", target_field="target")
def crawl_target(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    """Run the built-in single-page HTTP crawler through the compliance gate.

    The @gated_tool decorator handles gate.check, commit_findings,
    engagement_id, and the return dict. This function only needs to
    create the adapter and run it.
    """
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty URL")
    if not (target.startswith("http://") or target.startswith("https://")):
        raise InvalidInputError(field="target", reason="must be http/https URL")

    adapter = SimpleCrawlerAdapter(
        timeout_sec=params.get("timeout_sec", 30),
        proxy_manager=gate.proxy_manager,
    )
    findings = adapter.run(params)
    return findings
