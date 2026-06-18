"""Markdown report renderer (spec §M4).

Renders one or more engagement dicts as a human-readable Markdown report
with summary tables and per-engagement detail sections grouped by severity.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any

# Severity order, highest first. Mirrors core.finding._SEVERITY_RANK but
# kept local to avoid depending on a private name.
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]


def _normalize(engagements: Any) -> list[dict]:
    if isinstance(engagements, dict):
        return [engagements]
    return list(engagements)


def _render_evidence(ev: dict) -> str:
    """Render an evidence dict as `key=value, key=value`."""
    if not ev:
        return ""
    return ", ".join(f"{k}={v}" for k, v in ev.items())


def _aggregate(engagements: list[dict]) -> tuple[Counter, Counter, Counter, list[str], int]:
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


def render_markdown(engagements: Any) -> str:
    """Render one or more engagements as a Markdown report string."""
    engs = _normalize(engagements)
    sev, typ, tool, tools_used, total = _aggregate(engs)

    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append("# SecAgent 扫描报告")
    lines.append("")
    lines.append(
        f"> 生成时间: {generated_at} | 会话数: {len(engs)} | 发现总数: {total}"
    )
    lines.append("")

    # ----- Summary -----
    lines.append("## 摘要")
    lines.append("")

    lines.append("### 按严重度")
    lines.append("| 严重度 | 数量 |")
    lines.append("|---|---|")
    for s in SEVERITY_ORDER:
        lines.append(f"| {s.capitalize()} | {sev.get(s, 0)} |")
    lines.append("")

    lines.append("### 按类型")
    lines.append("| 类型 | 数量 |")
    lines.append("|---|---|")
    for t in sorted(typ.keys()):
        lines.append(f"| {t} | {typ[t]} |")
    lines.append("")

    lines.append("### 按工具")
    lines.append("| 工具 | 发现数 |")
    lines.append("|---|---|")
    for t in sorted(tool.keys()):
        lines.append(f"| {t} | {tool[t]} |")
    lines.append("")

    # ----- Details -----
    lines.append("## 详情")
    lines.append("")

    for eng in engs:
        tool_name = eng.get("tool", "")
        eng_id = eng.get("engagement_id", "")
        findings = eng.get("findings", []) or []
        quota = eng.get("quota_used", 0)

        lines.append(f"### {tool_name} ({eng_id})")
        lines.append("")
        lines.append(f"发现 {len(findings)} 项，配额消耗 {quota}。")
        lines.append("")

        if not findings:
            lines.append("未发现")
            lines.append("")
            continue

        # Group findings by severity.
        by_sev: dict[str, list[dict]] = {}
        for f in findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)

        # Emit severity groups in fixed descending order; skip empty ones.
        for s in SEVERITY_ORDER:
            group = by_sev.get(s)
            if not group:
                continue
            lines.append(f"#### {s.capitalize()} ({len(group)})")
            lines.append("")
            for f in group:
                target = f.get("target", "")
                title = f.get("title", "")
                lines.append(f"- **{target}** — {title}")
                ev = f.get("evidence", {})
                if ev:
                    lines.append(f"  - 证据: {_render_evidence(ev)}")
            lines.append("")

    # ----- Appendix -----
    lines.append("## 附录")
    lines.append("")
    lines.append("报告由 SecAgent 生成。所有扫描均经授权校验。")
    lines.append("")

    return "\n".join(lines)
