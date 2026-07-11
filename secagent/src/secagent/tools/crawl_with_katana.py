"""Tool function: crawl_with_katana — production-grade crawling.

Wires KatanaAdapter through ComplianceGate. Replaces SimpleCrawlerAdapter
for deep crawling with headless browser, JS rendering, and depth control.
"""
from __future__ import annotations

import os
from typing import Any

from secagent.adapters.katana import KatanaAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate


@gated_tool(tool_name="crawl_with_katana", target_field="target")
def crawl_with_katana(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty URL")
    if not (target.startswith("http://") or target.startswith("https://")):
        raise InvalidInputError(field="target", reason="must be an http/https URL")

    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    adapter = KatanaAdapter(
        launcher=Launcher(timeout_sec=params.get("timeout_sec", 300),
                          proxy_manager=gate.proxy_manager),
        binaries_dir=binaries_dir,
    )
    return adapter.run(params)
