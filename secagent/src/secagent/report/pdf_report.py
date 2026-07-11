"""PDF report renderer (spec §M8).

Renders one or more engagement dicts as a professional PDF deliverable using
ReportLab's Platypus layout engine. The content mirrors ``render_markdown``
(summary tables + per-severity detail + appendix) so both output formats stay
consistent, but the PDF is built directly from the engagement data rather than
by parsing Markdown — keeping the layout robust and styleable.

Requires the optional ``reportlab`` dependency:
    pip install reportlab
"""

from __future__ import annotations

import datetime as dt
import sys
from typing import Any

# Defensive: the Hermes agent harness may inject its own venv (python3.11) onto
# sys.path ahead of our venv, which breaks binary extension imports such as
# Pillow's `_imaging` that reportlab depends on. Import reportlab with those
# foreign paths temporarily stripped, then restore sys.path unchanged so we
# never leak this workaround into the global interpreter state.
_FOREIGN = ("hermes-agent", "python3.11", "python3.12")
_saved_path = list(sys.path)
_clean_path = [p for p in sys.path if not any(f in p for f in _FOREIGN)]
sys.path[:] = _clean_path
try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    # Register a built-in CJK font so Chinese findings render correctly
    # (the default Helvetica has no CJK glyphs).
    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        _CJK_FONT = "STSong-Light"
    except Exception:
        _CJK_FONT = "Helvetica"
finally:
    sys.path[:] = _saved_path

from secagent.report._common import _aggregate, _normalize

SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]
_SEV_COLOR = {
    "critical": colors.HexColor("#b00020"),
    "high": colors.HexColor("#e65100"),
    "medium": colors.HexColor("#f9a825"),
    "low": colors.HexColor("#1565c0"),
    "info": colors.HexColor("#546e7a"),
}
_CONF_LABEL = {
    "validated": "已验证",
    "likely": "疑似",
    "unvalidated": "未确认",
    "false_positive": "误报",
}


def _render_evidence(ev: dict) -> str:
    if not ev:
        return ""
    return ", ".join(f"{k}={v}" for k, v in ev.items())


def render_pdf(engagements: Any, path: str) -> str:
    """Render engagements to a PDF file at *path*.

    Returns *path* on success. Requires the ``reportlab`` package
    (``pip install reportlab``).
    """
    engs = _normalize(engagements)
    sev, typ, tool, tools_used, total = _aggregate(engs)
    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=22, spaceAfter=6,
                        fontName=_CJK_FONT)
    subtitle = ParagraphStyle(
        "sub", parent=styles["Normal"], fontSize=10, textColor=colors.grey,
        fontName=_CJK_FONT,
    )
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=15,
                        spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1a237e"),
                        fontName=_CJK_FONT)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=12,
                        spaceBefore=8, spaceAfter=4, fontName=_CJK_FONT)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5,
                          leading=13, alignment=TA_LEFT, fontName=_CJK_FONT)
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8,
                           leading=10, textColor=colors.grey, fontName=_CJK_FONT)

    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=1.8 * cm, bottomMargin=1.8 * cm,
        title="SecAgent 安全扫描报告", author="SecAgent",
    )
    flow: list[Any] = []

    # --- Cover / header ---
    flow.append(Paragraph("SecAgent 安全扫描报告", h1))
    flow.append(Paragraph(
        f"生成时间: {generated_at} &nbsp;|&nbsp; 会话数: {len(engs)} "
        f"&nbsp;|&nbsp; 发现总数: {total}", subtitle))
    flow.append(HRFlowable(width="100%", thickness=1.2,
                           color=colors.HexColor("#1a237e"), spaceBefore=6, spaceAfter=10))

    # --- Summary: by severity ---
    flow.append(Paragraph("摘要 — 按严重度", h2))
    sev_rows = [["严重度", "数量"]]
    for s in SEVERITY_ORDER:
        if sev.get(s, 0) or True:
            sev_rows.append([s.capitalize(), str(sev.get(s, 0))])
    t_sev = Table(sev_rows, colWidths=[4 * cm, 3 * cm])
    t_sev.setStyle(_table_style())
    flow.append(t_sev)

    # --- Summary: by type ---
    flow.append(Paragraph("摘要 — 按类型", h2))
    typ_rows = [["类型", "数量"]] + [[k, str(v)] for k, v in sorted(typ.items())]
    t_typ = Table(typ_rows, colWidths=[8 * cm, 3 * cm])
    t_typ.setStyle(_table_style())
    flow.append(t_typ)

    # --- Summary: by tool ---
    flow.append(Paragraph("摘要 — 按工具", h2))
    tool_rows = [["工具", "发现数"]] + [[k or "-", str(v)] for k, v in sorted(tool.items())]
    t_tool = Table(tool_rows, colWidths=[8 * cm, 3 * cm])
    t_tool.setStyle(_table_style())
    flow.append(t_tool)

    # --- Details, grouped by severity per engagement ---
    flow.append(Paragraph("漏洞详情", h2))
    for eng in engs:
        tool_name = eng.get("tool", "")
        eng_id = eng.get("engagement_id", "")
        findings = eng.get("findings", []) or []
        quota = eng.get("quota_used", 0)
        flow.append(Paragraph(f"{tool_name} ({eng_id})", h3))
        flow.append(Paragraph(
            f"发现 {len(findings)} 项，配额消耗 {quota}。", body))
        if not findings:
            flow.append(Paragraph("未发现漏洞。", small))
            continue

        by_sev: dict[str, list[dict]] = {}
        for f in findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)

        for s in SEVERITY_ORDER:
            group = by_sev.get(s)
            if not group:
                continue
            flow.append(_severity_badge(s, len(group)))
            for f in group:
                flow.append(_finding_block(f, body, small))

    # --- Appendix ---
    flow.append(Spacer(1, 0.4 * cm))
    flow.append(HRFlowable(width="100%", thickness=0.6, color=colors.grey))
    flow.append(Paragraph(
        "附录：本报告由 SecAgent 自动生成。所有扫描均经过授权校验与合规闸门，"
        "漏洞结论基于自动化探测证据，修复前建议人工复核。", small))

    doc.build(flow)
    return path


def _table_style() -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b0bec5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ])


def _severity_badge(sev: str, count: int) -> Any:
    style = ParagraphStyle(
        f"sev_{sev}", parent=getSampleStyleSheet()["Heading4"],
        fontSize=11, textColor=_SEV_COLOR.get(sev, colors.black),
        spaceBefore=8, spaceAfter=2, fontName=_CJK_FONT,
    )
    return Paragraph(f"{sev.capitalize()} ({count})", style)


def _finding_block(f: dict, body: Any, small: Any) -> Any:
    target = f.get("target", "")
    title = f.get("title", "")
    confidence = f.get("confidence", "")
    remediation = f.get("remediation", "")
    ev = f.get("evidence", {}) or {}

    conf_txt = _CONF_LABEL.get(confidence, confidence)
    head = Paragraph(f"<b>{target}</b> — {title} &nbsp;[{conf_txt}]", body)
    parts: list[Any] = [head]
    if ev:
        parts.append(Paragraph(f"证据: {_render_evidence(ev)}", small))
    if remediation:
        parts.append(Paragraph(f"修复建议: {remediation}", small))
    # Keep each finding together so it never splits across pages awkwardly.
    return KeepTogether(parts + [Spacer(1, 0.25 * cm)])
