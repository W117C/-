"""JSON report renderer (spec §M4).

Renders one or more engagement dicts into a single human-readable JSON
report with cross-engagement summary aggregation.
"""
from __future__ import annotations

import datetime as dt
import json
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


def render_json(engagements: Any) -> str:
    """Render one or more engagements as a complete JSON report string.

    Accepts a single engagement dict or a list of dicts. Returns a
    pretty-printed JSON string (ensure_ascii=False, indent=2).
    """
    engs = _normalize(engagements)
    sev, typ, tool, tools_used, total = _aggregate(engs)

    report = {
        "report_metadata": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "engagement_count": len(engs),
            "total_findings": total,
            "tools_used": tools_used,
        },
        "summary": {
            "by_severity": dict(sev),
            "by_type": dict(typ),
            "by_tool": dict(tool),
        },
        "engagements": engs,
    }

    return json.dumps(report, ensure_ascii=False, indent=2)
