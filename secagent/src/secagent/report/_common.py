"""Shared report utility functions (_normalize, _aggregate)."""
from __future__ import annotations

from collections import Counter
from typing import Any


def _normalize(engagements: Any) -> list[dict]:
    """Accept a single engagement dict or a list of them; return a list."""
    if isinstance(engagements, dict):
        return [engagements]
    return list(engagements)


def _aggregate(engagements: list[dict]) -> tuple[Counter, Counter, Counter, list[str], int]:
    """Return (sev_counter, type_counter, tool_counter, tools_used, total)."""
    sev: Counter = Counter()
    typ: Counter = Counter()
    tool: Counter = Counter()
    tools_used: list[str] = []
    total = 0

    for eng in engagements:
        tool_name = eng.get("tool", "")
        if tool_name and tool_name not in tools_used:
            tools_used.append(tool_name)
        findings = eng.get("findings", []) or []
        total += len(findings)
        tool[tool_name] += len(findings)
        for f in findings:
            sev[f.get("severity", "info")] += 1
            typ[f.get("type", "")] += 1

    return sev, typ, tool, tools_used, total
