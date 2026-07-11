"""Client-facing security report renderer (spec §M5).

Extends the internal Markdown report with the fields a paying customer
needs: an executive summary, a CVSS-based severity score per finding, a
reproducible proof-of-concept (PoC) step list, and a prioritized
remediation roadmap.

It deliberately reuses the existing ``_common._normalize`` / ``_aggregate``
helpers so the aggregation logic stays in one place. The only new logic is
the rendering layer that turns raw findings into a deliverable document.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from secagent.report._common import _aggregate, _normalize
from secagent.report.compliance_map import map_engagements

# Severity → CVSS v3.1 base score band (lower bound used for sorting/scoring).
_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
    "info": 0.0,
}

# Ordered highest-first; mirrors core.finding._SEVERITY_RANK but kept local
# to avoid depending on a private name.
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

# Mapping from finding type → remediation guidance shown to the client.
_REMEDIATION_GUIDANCE: dict[str, str] = {
    "sqli_error": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    "sqli_blind_time": "Use parameterized queries. Disable verbose error output and add WAF rules for time-based payloads.",
    "sqli_blind_boolean": "Use parameterized queries. Validate and whitelist expected input shapes.",
    "xss_reflected": "Context-aware output encoding (HTML-encode in body, attribute-encode in attributes). Set CSP header.",
    "ssrf_internal": "Validate and allowlist outbound target hosts. Block requests to internal/link-local ranges (RFC1918, 169.254.169.254).",
    "ssrf_oob": "Validate and allowlist outbound target hosts. Block metadata endpoints and internal IP ranges.",
    "lfi_traversal": "Never pass user input to filesystem path APIs. Map to an allowlisted identifier; strip '../' and null bytes.",
}


def _cvss_for(finding: dict[str, Any]) -> float:
    """Derive a CVSS v3.1 base score estimate from severity + evidence.

    This is a conservative band estimate for client reporting, not a
    full vector calculation. The 'confidence' field downgrades the score
    for unconfirmed findings.
    """
    sev = finding.get("severity", "info")
    base = _SEVERITY_CVSS.get(sev, 0.0)
    if finding.get("confidence") in ("likely", "unvalidated"):
        base = max(0.0, base - 1.5)  # downgrade uncertain findings
    return round(base, 1)


def _poc_steps(finding: dict[str, Any]) -> list[str]:
    """Build a reproducible PoC step list from the finding evidence."""
    ev = finding.get("evidence", {}) or {}
    target = finding.get("target", "")
    steps: list[str] = []
    param = ev.get("parameter", "")
    payload = ev.get("payload", ev.get("callback_url", ""))
    if param and payload:
        steps.append(f"1. Send a request to {target} with parameter '{param}' set to the payload below.")
        steps.append(f"2. Payload: {payload[:200]}")
        if ev.get("bypass_technique"):
            steps.append(f"3. Bypass technique used: {ev['bypass_technique']}")
        match = ev.get("match")
        if match:
            steps.append(f"4. Observe the following confirmation in the response: {match[:120]}")
    elif ev.get("callback_url"):
        steps.append(f"1. Trigger an outbound request from {target} to the callback URL: {ev['callback_url']}")
        steps.append("2. Confirm the callback arrived at the listener (out-of-band).")
    else:
        steps.append(f"1. Inspect {target} — see evidence block for technical detail.")
    return steps


def render_client_report(
    engagements: Any,
    *,
    client_name: str = "",
    engagement_ref: str = "",
    authorized_by: str = "",
    compliance: bool = True,
) -> str:
    """Render one or more engagements as a client-deliverable Markdown report.

    Args:
        engagements: single engagement dict or list of them (same shape as
            the internal report: ``{tool, engagement_id, findings, quota_used}``).
        client_name: customer / recipient name for the cover page.
        engagement_ref: your contract or engagement reference id.
        authorized_by: scope note shown in the cover (e.g. 'Authorized by
            ACME Corp per PO #123, 2026-07-10').
        compliance: if True (default), append a "Compliance Impact" section
            mapping findings to OWASP 2021 / PCI-DSS v4.0 / SOC 2 clauses.

    Returns the report as a Markdown string.
    """
    engs = _normalize(engagements)
    sev, typ, tool, tools_used, total = _aggregate(engs)

    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Flatten all findings for per-item scoring + sorting.
    flat: list[dict[str, Any]] = []
    for eng in engs:
        for f in (eng.get("findings", []) or []):
            fd = dict(f)
            fd["_eng_tool"] = eng.get("tool", "")
            fd["_eng_id"] = eng.get("engagement_id", "")
            flat.append(fd)

    flat.sort(
        key=lambda f: _SEVERITY_CVSS.get(f.get("severity", "info"), 0.0),
        reverse=True,
    )

    risk_score = round(sum(_cvss_for(f) for f in flat), 1)

    lines: list[str] = []
    # ---- Cover ----
    lines.append("# 安全渗透测试报告 / Security Assessment Report")
    lines.append("")
    lines.append(f"> 生成时间: {generated_at}")
    if client_name:
        lines.append(f"> 客户: {client_name}")
    if engagement_ref:
        lines.append(f"> 委托编号: {engagement_ref}")
    if authorized_by:
        lines.append(f"> 授权范围: {authorized_by}")
    lines.append(f"> 综合风险评分 (CVSS 估算累计): {risk_score}")
    lines.append("")

    # ---- Executive Summary ----
    lines.append("## 执行摘要 / Executive Summary")
    lines.append("")
    if total == 0:
        lines.append("本次评估**未发现**高危或以上的安全漏洞。建议保持现有安全控制措施并定期复测。")
    else:
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        med = sev.get("medium", 0)
        low = sev.get("low", 0)
        lines.append(
            f"本次评估共发现 **{total}** 项问题："
            f"严重 {crit}、高危 {high}、中危 {med}、低危 {low}。"
        )
        if crit or high:
            lines.append("")
            lines.append(
                "⚠️ 存在可被远程利用的高危/严重漏洞，建议**在 7 日内**优先修复并复测，"
                "避免被攻击者利用导致数据泄露或服务中断。"
            )
    lines.append("")

    # ---- Severity summary table ----
    lines.append("### 按严重度统计")
    lines.append("")
    lines.append("| 严重度 | 数量 | CVSS 估算区间 |")
    lines.append("|---|---|---|")
    for s in SEVERITY_ORDER:
        if sev.get(s, 0) == 0 and s in ("info",):
            continue
        band = {
            "critical": "9.0–10.0",
            "high": "7.0–8.9",
            "medium": "4.0–6.9",
            "low": "0.1–3.9",
            "info": "0.0",
        }.get(s, "")
        lines.append(f"| {s.capitalize()} | {sev.get(s, 0)} | {band} |")
    lines.append("")

    # ---- Detailed findings ----
    lines.append("## 详细发现 / Detailed Findings")
    lines.append("")
    if not flat:
        lines.append("未发现。")
    for i, f in enumerate(flat, 1):
        sev_label = f.get("severity", "info").capitalize()
        cvss = _cvss_for(f)
        conf = f.get("confidence", "unvalidated")
        lines.append(f"### {i}. [{sev_label}] {f.get('title', 'Untitled')}")
        lines.append("")
        lines.append(f"- **目标**: {f.get('target', '')}")
        lines.append(f"- **类型**: {f.get('type', '')}")
        lines.append(f"- **CVSS v3.1 估算**: {cvss}")
        lines.append(f"- **置信度**: {conf}")
        lines.append(f"- **来源工具**: {f.get('_eng_tool', f.get('source_tool', ''))}")
        lines.append("")
        # PoC
        lines.append("**复现步骤 / Proof of Concept**:")
        lines.append("")
        for step in _poc_steps(f):
            lines.append(f"{step}")
        lines.append("")
        # Evidence
        ev = f.get("evidence", {}) or {}
        if ev:
            lines.append("**技术证据 / Evidence**:")
            lines.append("")
            for k, v in ev.items():
                lines.append(f"- `{k}`: `{v}`")
            lines.append("")
        # Remediation
        guidance = _REMEDIATION_GUIDANCE.get(
            f.get("type", ""),
            f.get("remediation", "") or "请联系安全团队获取针对性修复建议。",
        )
        lines.append("**修复建议 / Remediation**:")
        lines.append("")
        lines.append(f"- {guidance}")
        lines.append("")

    # ---- Remediation roadmap ----
    lines.append("## 修复优先级 / Remediation Roadmap")
    lines.append("")
    lines.append("| 优先级 | 动作 | 时限建议 |")
    lines.append("|---|---|---|")
    if sev.get("critical", 0):
        lines.append(f"| P0 | 修复 {sev['critical']} 项严重漏洞 | 24–72 小时 |")
    if sev.get("high", 0):
        lines.append(f"| P1 | 修复 {sev['high']} 项高危漏洞 | 7 天 |")
    if sev.get("medium", 0):
        lines.append(f"| P2 | 修复 {sev['medium']} 项中危漏洞 | 30 天 |")
    if sev.get("low", 0):
        lines.append(f"| P3 | 修复 {sev['low']} 项低危问题 | 90 天 |")
    if total == 0:
        lines.append("| — | 无需立即修复 | — |")
    lines.append("")

    # ---- Compliance Impact (optional) ----
    if compliance:
        impact = map_engagements(engs)
        lines.append("## 合规影响 / Compliance Impact")
        lines.append("")
        lines.append(
            "以下映射帮助客户评估本次发现对其审计义务的影响。"
            "该映射为**参考性**建议，不构成正式合规认证。"
        )
        lines.append("")
        any_impact = False
        for fw in ("OWASP 2021", "PCI-DSS v4.0", "SOC 2"):
            clauses = sorted(impact.get(fw, set()))
            if not clauses:
                continue
            any_impact = True
            lines.append(f"### {fw}")
            lines.append("")
            for c in clauses:
                lines.append(f"- {c}")
            lines.append("")
        if not any_impact:
            lines.append("本次评估未发现映射到所列合规框架的漏洞类型。")
            lines.append("")

    # ---- Footer ----
    lines.append("---")
    lines.append("")
    lines.append(
        "本报告由 SecAgent 生成。所有测试均在客户书面授权范围内进行。"
        "PoC 步骤仅用于验证漏洞存在，请勿用于未授权目标。"
    )
    lines.append("")

    return "\n".join(lines)
