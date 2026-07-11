"""JSON report renderer (spec §M4).

Renders one or more engagement dicts into a single human-readable JSON
report with cross-engagement summary aggregation.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from secagent.report._common import _aggregate, _normalize


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
