"""Tests for the client-facing report renderer (spec §M5)."""

from __future__ import annotations

from secagent.report.client_report import render_client_report, _cvss_for, _poc_steps


def _sample_engagement() -> dict:
    return {
        "tool": "web_vuln_scan",
        "engagement_id": "eng_test",
        "quota_used": 1,
        "findings": [
            {
                "id": "fnd_1",
                "type": "sqli_error",
                "severity": "high",
                "target": "https://acme.com/?id=1",
                "title": "SQL Injection (MySQL) via 'id' (error-based)",
                "confidence": "validated",
                "evidence": {
                    "parameter": "id",
                    "payload": "'",
                    "db_type": "MySQL",
                    "match": "You have an error in your SQL syntax",
                },
            },
            {
                "id": "fnd_2",
                "type": "lfi_traversal",
                "severity": "critical",
                "target": "https://acme.com/?file=report.pdf",
                "title": "Local File Inclusion via 'file' (basic_../)",
                "confidence": "validated",
                "evidence": {
                    "parameter": "file",
                    "payload": "../../../../../../etc/passwd",
                    "bypass_technique": "basic_../",
                    "match": "root:x:0:0:",
                },
            },
        ],
    }


class TestClientReportRendering:
    def test_executive_summary_counts(self):
        md = render_client_report(
            _sample_engagement(),
            client_name="ACME Corp",
            engagement_ref="PO-2026-001",
            authorized_by="Authorized by ACME per PO-2026-001",
        )
        assert "执行摘要" in md
        assert "ACME Corp" in md
        assert "PO-2026-001" in md
        # critical + high = 2 findings total
        assert "共发现 **2**" in md

    def test_cvss_present_and_sorted_critical_first(self):
        md = render_client_report(_sample_engagement())
        # Critical LFI should appear before high SQLi in the detailed section.
        idx_crit = md.find("Local File Inclusion")
        idx_high = md.find("SQL Injection")
        assert idx_crit != -1 and idx_high != -1
        assert idx_crit < idx_high
        assert "CVSS v3.1 估算" in md

    def test_poc_steps_generated(self):
        md = render_client_report(_sample_engagement())
        assert "复现步骤" in md or "Proof of Concept" in md
        assert "../../../../../../etc/passwd" in md

    def test_remediation_guidance_present(self):
        md = render_client_report(_sample_engagement())
        assert "修复建议" in md
        # SQLi guidance should mention parameterized queries
        assert "parameterized" in md.lower() or "参数化" in md

    def test_empty_findings_no_vuln_message(self):
        eng = {"tool": "web_vuln_scan", "engagement_id": "e", "findings": []}
        md = render_client_report(eng)
        assert "未发现" in md

    def test_risk_score_is_sum_of_cvss(self):
        # 2 findings: critical(9.0) + high(7.0) = 16.0
        md = render_client_report(_sample_engagement())
        assert "16.0" in md


class TestCvssHelper:
    def test_validated_high_is_7(self):
        assert _cvss_for({"severity": "high", "confidence": "validated"}) == 7.0

    def test_likely_downgraded(self):
        # high(7.0) - 1.5 = 5.5 for unconfirmed
        assert _cvss_for({"severity": "high", "confidence": "likely"}) == 5.5

    def test_unknown_severity_zero(self):
        assert _cvss_for({"severity": "nonsense"}) == 0.0


class TestPocSteps:
    def test_param_payload_poc(self):
        steps = _poc_steps({
            "target": "https://x/?id=1",
            "evidence": {"parameter": "id", "payload": "'", "match": "sql error"},
        })
        assert any("id" in s for s in steps)
        assert any("'" in s for s in steps)

    def test_callback_poc(self):
        steps = _poc_steps({
            "target": "https://x/",
            "evidence": {"callback_url": "https://cb.example.com/x"},
        })
        assert any("callback" in s.lower() for s in steps)


# ===========================================================================
# Compliance mapping (spec §M9)
# ===========================================================================


from secagent.report.compliance_map import map_finding, map_engagements  # noqa: E402


class TestComplianceMap:
    def test_exact_match(self):
        m = map_finding("sqli_error")
        assert m["OWASP 2021"].startswith("A03")
        assert "6.5.1" in m["PCI-DSS v4.0"]
        assert "CC6.1" in m["SOC 2"]

    def test_family_prefix_fallback(self):
        # An unseen sqli variant still maps via the sqli_ prefix.
        m = map_finding("sqli_novel_variant")
        assert m["OWASP 2021"].startswith("A03")

    def test_xss_and_ssrf_and_lfi(self):
        assert map_finding("xss_reflected")["OWASP 2021"].startswith("A03")
        assert map_finding("ssrf_oob")["OWASP 2021"].startswith("A10")
        assert "A01" in map_finding("lfi_traversal")["OWASP 2021"]

    def test_no_match_returns_empty(self):
        assert map_finding("unknown_class") == {}

    def test_map_engagements_aggregates(self):
        eng = {
            "tool": "web_vuln_scan", "engagement_id": "e",
            "quota_used": 1,
            "findings": [
                {"type": "sqli_error", "evidence": {"vuln_class": "sqli_error"}},
                {"type": "xss_reflected", "evidence": {"vuln_class": "xss_reflected"}},
            ],
        }
        impact = map_engagements(eng)
        # Both sqli and xss fall under OWASP A03 (Injection) but carry
        # distinct clause strings, so both appear.
        assert "A03:2021 – Injection" in impact["OWASP 2021"]
        assert "A03:2021 – Injection (XSS)" in impact["OWASP 2021"]
        # PCI-DSS has distinct clauses per type.
        assert any("6.5.1" in c for c in impact["PCI-DSS v4.0"])
        assert any("6.5.7" in c for c in impact["PCI-DSS v4.0"])


class TestClientReportCompliance:
    def test_compliance_section_present_by_default(self):
        md = render_client_report(_sample_engagement())
        assert "合规影响" in md
        assert "OWASP 2021" in md
        assert "PCI-DSS v4.0" in md
        assert "A03" in md  # sqli + lfi both map, A03 from sqli

    def test_compliance_section_disabled(self):
        md = render_client_report(_sample_engagement(), compliance=False)
        assert "合规影响" not in md

    def test_compliance_maps_sample_findings(self):
        md = render_client_report(_sample_engagement())
        # sqli_error → A03, lfi_traversal → A01
        assert "A03" in md and "A01" in md
        assert "SOC 2" in md
