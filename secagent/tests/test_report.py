"""Tests for secagent.report (M4)."""
from __future__ import annotations

import json
from collections import Counter

import pytest

from secagent.report import render_json, render_markdown


def _make_finding(
    fid: str,
    type_: str,
    severity: str,
    target: str,
    title: str,
    evidence: dict | None = None,
    source_tool: str = "subfinder",
    remediation: str = "",
) -> dict:
    return {
        "id": fid,
        "type": type_,
        "severity": severity,
        "target": target,
        "title": title,
        "evidence": evidence or {},
        "source_tool": source_tool,
        "remediation": remediation,
        "raw": {},
        "timestamp": "2026-06-18T14:30:00+00:00",
    }


def _make_engagement(
    eng_id: str, tool: str, findings: list[dict], quota_used: int = 1
) -> dict:
    sev = Counter(f["severity"] for f in findings)
    typ = Counter(f["type"] for f in findings)
    return {
        "engagement_id": eng_id,
        "tool": tool,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": dict(sev),
            "by_type": dict(typ),
        },
        "quota_used": quota_used,
    }


@pytest.fixture()
def sample_engagements() -> list[dict]:
    eng1 = _make_engagement(
        "eng_abc123",
        "enumerate_subdomains",
        [
            _make_finding(
                "fnd_1",
                "subdomain",
                "info",
                "sub.acme.com",
                "Subdomain: sub.acme.com",
                {"source": "crtsh", "domain_queried": "acme.com"},
            ),
        ],
        quota_used=1,
    )
    eng2 = _make_engagement(
        "eng_def456",
        "scan_vulnerabilities",
        [
            _make_finding(
                "fnd_2",
                "vulnerability",
                "critical",
                "acme.com",
                "RCE in /api",
                {"cvss": 9.8},
                source_tool="nuclei",
            ),
            _make_finding(
                "fnd_3",
                "vulnerability",
                "high",
                "acme.com",
                "SQLi in /login",
                {"param": "user"},
                source_tool="nuclei",
            ),
            _make_finding(
                "fnd_4",
                "vulnerability",
                "medium",
                "acme.com",
                "XSS in /search",
                {},
                source_tool="nuclei",
            ),
        ],
        quota_used=2,
    )
    return [eng1, eng2]


# ---------- render_json ----------


def test_render_json_returns_valid_json(sample_engagements):
    out = render_json(sample_engagements)
    assert isinstance(out, str)
    # Must parse without error.
    json.loads(out)


def test_render_json_top_level_structure(sample_engagements):
    data = json.loads(render_json(sample_engagements))
    assert "report_metadata" in data
    assert "summary" in data
    assert "engagements" in data


def test_render_json_metadata_counts(sample_engagements):
    data = json.loads(render_json(sample_engagements))
    md = data["report_metadata"]
    assert md["engagement_count"] == 2
    assert md["total_findings"] == 4
    assert "generated_at" in md and md["generated_at"]


def test_render_json_tools_used(sample_engagements):
    data = json.loads(render_json(sample_engagements))
    tools = data["report_metadata"]["tools_used"]
    assert "enumerate_subdomains" in tools
    assert "scan_vulnerabilities" in tools
    # No duplicates.
    assert len(tools) == len(set(tools))


def test_render_json_summary_aggregation(sample_engagements):
    data = json.loads(render_json(sample_engagements))
    sev = data["summary"]["by_severity"]
    assert sev["info"] == 1
    assert sev["critical"] == 1
    assert sev["high"] == 1
    assert sev["medium"] == 1

    typ = data["summary"]["by_type"]
    assert typ["subdomain"] == 1
    assert typ["vulnerability"] == 3

    by_tool = data["summary"]["by_tool"]
    assert by_tool["enumerate_subdomains"] == 1
    assert by_tool["scan_vulnerabilities"] == 3


def test_render_json_engagements_preserved(sample_engagements):
    data = json.loads(render_json(sample_engagements))
    assert data["engagements"] == sample_engagements


def test_render_json_single_dict_input(sample_engagements):
    data = json.loads(render_json(sample_engagements[0]))
    assert data["report_metadata"]["engagement_count"] == 1
    assert data["report_metadata"]["total_findings"] == 1
    assert len(data["engagements"]) == 1


def test_render_json_empty_findings():
    eng = _make_engagement("eng_empty", "enumerate_subdomains", [])
    data = json.loads(render_json(eng))
    assert data["report_metadata"]["total_findings"] == 0
    assert data["engagements"][0]["findings"] == []
    assert data["summary"]["by_severity"] == {}


def test_render_json_unicode_passthrough():
    eng = _make_engagement(
        "eng_uni",
        "enumerate_subdomains",
        [
            _make_finding(
                "fnd_u",
                "subdomain",
                "info",
                "中文.例子.com",
                "子域名: 中文.例子.com",
            )
        ],
    )
    out = render_json(eng)
    # ensure_ascii=False -> no \uXXXX escapes for our chars.
    assert "中文.例子.com" in out
    assert "子域名" in out


# ---------- render_markdown ----------


def test_render_markdown_has_main_headers(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "# SecAgent 扫描报告" in out
    assert "## 摘要" in out
    assert "## 详情" in out


def test_render_markdown_engagement_headers(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "enumerate_subdomains" in out
    assert "eng_abc123" in out
    assert "scan_vulnerabilities" in out
    assert "eng_def456" in out


def test_render_markdown_finding_titles(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "RCE in /api" in out
    assert "Subdomain: sub.acme.com" in out
    assert "SQLi in /login" in out


def test_render_markdown_severity_descending_order(sample_engagements):
    out = render_markdown(sample_engagements)
    pos_critical = out.find("#### Critical")
    pos_high = out.find("#### High")
    pos_medium = out.find("#### Medium")
    assert pos_critical != -1
    assert pos_high != -1
    assert pos_medium != -1
    assert pos_critical < pos_high < pos_medium


def test_render_markdown_quota_used(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "配额消耗 1" in out
    assert "配额消耗 2" in out


def test_render_markdown_evidence_rendered(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "source=crtsh" in out
    assert "domain_queried=acme.com" in out
    assert "cvss=9.8" in out


def test_render_markdown_single_dict_input(sample_engagements):
    out = render_markdown(sample_engagements[0])
    assert "enumerate_subdomains" in out
    assert "eng_abc123" in out
    assert "Subdomain: sub.acme.com" in out


def test_render_markdown_empty_findings_shows_not_found():
    eng = _make_engagement("eng_empty", "enumerate_subdomains", [])
    out = render_markdown(eng)
    assert "eng_empty" in out
    assert "未发现" in out
    # Should not crash and should still have main sections.
    assert "## 详情" in out
    assert "## 附录" in out


def test_render_markdown_summary_tables(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "| 严重度 | 数量 |" in out
    assert "| 类型 | 数量 |" in out
    assert "| 工具 | 发现数 |" in out
    # Fixed severity order in summary table (all five rows present).
    assert "| Critical | 1 |" in out
    assert "| High | 1 |" in out
    assert "| Medium | 1 |" in out
    assert "| Low | 0 |" in out
    assert "| Info | 1 |" in out


def test_render_markdown_appendix(sample_engagements):
    out = render_markdown(sample_engagements)
    assert "## 附录" in out
    assert "SecAgent" in out


def test_render_markdown_multi_engagement_aggregation():
    eng1 = _make_engagement(
        "eng_a",
        "enumerate_subdomains",
        [
            _make_finding("f1", "subdomain", "info", "a.com", "A"),
            _make_finding("f2", "subdomain", "low", "b.com", "B"),
        ],
    )
    eng2 = _make_engagement(
        "eng_b",
        "scan_vulnerabilities",
        [
            _make_finding("f3", "vulnerability", "critical", "c.com", "C"),
            _make_finding("f4", "vulnerability", "critical", "d.com", "D"),
            _make_finding("f5", "vulnerability", "high", "e.com", "E"),
        ],
    )
    out = render_markdown([eng1, eng2])
    # Cross-engagement aggregation in summary table.
    assert "| Critical | 2 |" in out
    assert "| High | 1 |" in out
    assert "| Low | 1 |" in out
    assert "| Info | 1 |" in out
    assert "| enumerate_subdomains | 2 |" in out
    assert "| scan_vulnerabilities | 3 |" in out
    # Total in header line.
    assert "发现总数: 5" in out


def test_render_markdown_total_findings_zero():
    eng = _make_engagement("eng_empty", "enumerate_subdomains", [])
    out = render_markdown(eng)
    assert "发现总数: 0" in out


# ===========================================================================
# PDF renderer (spec §M8)
# ===========================================================================


def test_render_pdf_produces_valid_pdf(tmp_path):
    from secagent.report import render_pdf

    engagements = [
        _make_engagement(
            "eng_pdf", "web_vuln_scan",
            [_make_finding("f1", "sqli", "high", "http://x/", "SQLi via id",
                           {"parameter": "id", "method": "error"}, remediation="Use prepared statements")],
        )
    ]
    out = tmp_path / "report.pdf"
    returned = render_pdf(engagements, str(out))
    assert returned == str(out)
    assert out.exists()
    # PDF magic header.
    assert out.read_bytes()[:5] == b"%PDF-"
    # ReportLab wrote more than just a header.
    assert out.stat().st_size > 500


def test_render_pdf_empty_findings(tmp_path):
    from secagent.report import render_pdf

    eng = _make_engagement("eng_empty", "web_vuln_scan", [])
    out = tmp_path / "empty.pdf"
    render_pdf(eng, str(out))
    assert out.read_bytes()[:5] == b"%PDF-"
