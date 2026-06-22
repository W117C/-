"""Tests for NucleiAdapter + scan_vulnerabilities tool (spec §3.2 ③).

Covers the three-layer compliance guard:
  L1 gate.check (authz + blocklist + audit)
  L2 blocklist re-check before nuclei runs
  L3 rate-limit clamping

Plus adapter output parsing (nuclei JSONL → Finding[VULNERABILITY]).
"""
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from secagent.adapters.nuclei import NucleiAdapter
from secagent.core.errors import (
    ComplianceBlockError,
    InvalidInputError,
    NotAuthorizedError,
    ToolFailedError,
)
from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.finding import FindingType, Severity
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore
from secagent.tools.scan_vulnerabilities import scan_vulnerabilities
from helper import setup_gate_and_token


def _mock_launcher(stdout_lines, returncode=0):
    mock_result = MagicMock()
    mock_result.returncode = returncode
    mock_result.stdout = "\n".join(stdout_lines)
    mock_result.stderr = ""
    mock_result.json_output = None
    return mock_result


def _nuclei_line(template_id="CVE-2021-44228", name="Log4Shell",
                 severity="critical", host="https://sub.acme.com",
                 matched_at=None, curl="curl -X GET 'https://sub.acme.com'"):
    return json.dumps({
        "template-id": template_id,
        "info": {"name": name, "severity": severity, "tags": ["cve", "rce"]},
        "host": host,
        "matched-at": matched_at or host,
        "curl-command": curl,
        "type": "http",
    })


# ===========================================================================
# NucleiAdapter unit tests
# ===========================================================================

class TestNucleiAdapter:
    def test_parses_one_finding_per_jsonl_line(self):
        adapter = NucleiAdapter()
        lines = [
            _nuclei_line(template_id="CVE-2021-44228", severity="critical"),
            _nuclei_line(template_id="CVE-2023-1234", name="XSS", severity="high",
                         host="https://blog.acme.com"),
        ]
        with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
            findings = adapter.run({"targets": ["https://sub.acme.com"]})
        assert len(findings) == 2
        for f in findings:
            assert f.type == FindingType.VULNERABILITY
            assert f.source_tool == "nuclei"

    def test_severity_mapping(self):
        adapter = NucleiAdapter()
        for sev_str, expected in [("critical", Severity.CRITICAL),
                                  ("high", Severity.HIGH),
                                  ("medium", Severity.MEDIUM),
                                  ("low", Severity.LOW),
                                  ("info", Severity.INFO),
                                  ("unknown", Severity.INFO)]:
            lines = [_nuclei_line(severity=sev_str)]
            with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
                findings = adapter.run({"targets": ["https://sub.acme.com"]})
            assert findings[0].severity == expected, sev_str

    def test_evidence_includes_template_and_curl(self):
        adapter = NucleiAdapter()
        lines = [_nuclei_line(template_id="CVE-2021-44228", curl="curl -X GET 'x'")]
        with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
            findings = adapter.run({"targets": ["https://sub.acme.com"]})
        f = findings[0]
        assert f.evidence["template_id"] == "CVE-2021-44228"
        assert f.evidence["curl_repro"] == "curl -X GET 'x'"
        assert f.evidence["matched_at"] == "https://sub.acme.com"
        assert "cve" in f.evidence["tags"]

    def test_empty_output_returns_empty_list(self):
        adapter = NucleiAdapter()
        with patch.object(adapter, "_launch", return_value=_mock_launcher([])):
            findings = adapter.run({"targets": ["https://sub.acme.com"]})
        assert findings == []

    def test_skips_non_json_lines(self):
        adapter = NucleiAdapter()
        lines = ["not json", _nuclei_line(), ""]
        with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
            findings = adapter.run({"targets": ["https://sub.acme.com"]})
        assert len(findings) == 1

    def test_missing_targets_raises(self):
        adapter = NucleiAdapter()
        with pytest.raises(InvalidInputError):
            adapter.run({})

    def test_nonzero_exit_raises_tool_failed(self):
        adapter = NucleiAdapter()
        with patch.object(adapter, "_launch",
                          return_value=_mock_launcher([], returncode=1)):
            with pytest.raises(ToolFailedError):
                adapter.run({"targets": ["https://sub.acme.com"]})

    def test_rate_limit_passed_to_command(self):
        adapter = NucleiAdapter()
        cmd_captured = {}

        def capture(cmd, **kw):
            cmd_captured["cmd"] = cmd
            return _mock_launcher([])

        with patch.object(adapter, "_launch", capture):
            adapter.run({"targets": ["https://sub.acme.com"], "rate_limit": 42})
        assert "-rate-limit" in cmd_captured["cmd"]
        idx = cmd_captured["cmd"].index("-rate-limit")
        assert cmd_captured["cmd"][idx + 1] == "42"

    def test_templates_filter_passed_to_command(self):
        adapter = NucleiAdapter()
        cmd_captured = {}

        def capture(cmd, **kw):
            cmd_captured["cmd"] = cmd
            return _mock_launcher([])

        with patch.object(adapter, "_launch", capture):
            adapter.run({"targets": ["https://sub.acme.com"],
                         "templates": ["cves", "exposures"]})
        assert "-t" in cmd_captured["cmd"]
        idx = cmd_captured["cmd"].index("-t")
        assert "cves,exposures" == cmd_captured["cmd"][idx + 1]


# ===========================================================================
# scan_vulnerabilities tool function tests (three-layer guard)
# ===========================================================================

class TestScanVulnerabilitiesTool:
    def test_authorized_target_returns_findings(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        def _mk(target, i):
            m = MagicMock()
            m.target = target
            m.to_dict.return_value = {"id": f"fnd_{i}", "type": "vulnerability", "severity": "medium",
                "target": target, "title": target, "evidence": {}, "source_tool": "nuclei",
                "raw": {}, "timestamp": "2025-01-01"}
            return m
        with patch("secagent.tools.scan_vulnerabilities.NucleiAdapter") as MockAd:
            MockAd.return_value.run.return_value = [
                _mk("https://sub.acme.com", 0),
                _mk("https://blog.acme.com", 1),
            ]
            result = scan_vulnerabilities(
                gate=gate, params={"targets": ["https://sub.acme.com"]},
                authz_token=token, caller_id="test",
            )
        assert result["tool"] == "scan_vulnerabilities"
        assert result["summary"]["total"] == 2
        assert result["quota_used"] == 1

    def test_out_of_scope_target_refused(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
        with pytest.raises(NotAuthorizedError):
            scan_vulnerabilities(
                gate=gate, params={"targets": ["https://evil.com"]},
                authz_token=token, caller_id="test",
            )

    def test_one_out_of_scope_target_refuses_whole_call(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
        with pytest.raises(NotAuthorizedError):
            scan_vulnerabilities(
                gate=gate,
                params={"targets": ["https://sub.acme.com", "https://evil.com"]},
                authz_token=token, caller_id="test",
            )

    def test_empty_targets_raises_invalid_input(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        with pytest.raises(InvalidInputError):
            scan_vulnerabilities(
                gate=gate, params={"targets": []},
                authz_token=token, caller_id="test",
            )

    def test_missing_targets_raises_invalid_input(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        with pytest.raises(InvalidInputError):
            scan_vulnerabilities(
                gate=gate, params={},
                authz_token=token, caller_id="test",
            )

    def test_layer2_blocklist_recheck_refuses_gov_even_if_in_scope(self, tmp_db):
        """Defense in depth: even if a .gov target is somehow authorized,
        the layer-2 blocklist re-check must refuse it before nuclei runs."""
        gate, token = setup_gate_and_token(tmp_db, scope_value="example.gov")
        with pytest.raises(ComplianceBlockError):
            scan_vulnerabilities(
                gate=gate, params={"targets": ["https://example.gov"]},
                authz_token=token, caller_id="test",
            )

    def test_layer2_blocklist_recheck_refuses_private_ip(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
        # 192.168.x is private — even though we authorize acme.com, an
        # authorized-domain scan should not somehow include private IPs.
        # We authorize a private-IP scope to simulate the edge case.
        store = SQLiteStore(tmp_db)
        reg2 = AuthorizationRegistry(store, default_quota=100)
        ip_token = reg2.issue(scope=AuthorizationScope(ScopeType.IP, "192.168.1.1"))
        reg2.mark_verified(ip_token, method="dns_txt")
        gate2 = ComplianceGate(store, reg2.quota, default_quota=100)
        with pytest.raises(ComplianceBlockError):
            scan_vulnerabilities(
                gate=gate2, params={"targets": ["192.168.1.1"]},
                authz_token=ip_token, caller_id="test",
            )

    def test_rate_limit_clamped_to_safe_max(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        captured = {}

        def fake_run(params):
            captured["rate_limit"] = params.get("rate_limit")
            return []

        with patch("secagent.tools.scan_vulnerabilities.NucleiAdapter") as MockAd:
            MockAd.return_value.run.side_effect = fake_run
            scan_vulnerabilities(
                gate=gate, params={"targets": ["https://sub.acme.com"],
                                   "rate_limit": 99999},
                authz_token=token, caller_id="test",
            )
        assert captured["rate_limit"] == 500  # clamped

    def test_rate_limit_clamped_to_min_1(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        captured = {}

        def fake_run(params):
            captured["rate_limit"] = params.get("rate_limit")
            return []

        with patch("secagent.tools.scan_vulnerabilities.NucleiAdapter") as MockAd:
            MockAd.return_value.run.side_effect = fake_run
            scan_vulnerabilities(
                gate=gate, params={"targets": ["https://sub.acme.com"],
                                   "rate_limit": 0},
                authz_token=token, caller_id="test",
            )
        assert captured["rate_limit"] == 1  # floor

    def test_empty_result_still_commits_quota(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        with patch("secagent.tools.scan_vulnerabilities.NucleiAdapter") as MockAd:
            MockAd.return_value.run.return_value = []
            result = scan_vulnerabilities(
                gate=gate, params={"targets": ["https://sub.acme.com"]},
                authz_token=token, caller_id="test",
            )
        assert result["summary"]["total"] == 0
        assert result["quota_used"] == 1

    def test_tool_failure_propagates(self, tmp_db):
        gate, token = setup_gate_and_token(tmp_db)
        with patch("secagent.tools.scan_vulnerabilities.NucleiAdapter") as MockAd:
            MockAd.return_value.run.side_effect = ToolFailedError(
                tool="nuclei", detail="binary not found"
            )
            with pytest.raises(ToolFailedError):
                scan_vulnerabilities(
                    gate=gate, params={"targets": ["https://sub.acme.com"]},
                    authz_token=token, caller_id="test",
                )
