"""Tests for scripts/batch_scan.py (spec §M6 batch orchestration)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Make scripts/ importable in the test process.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from batch_scan import run_batch, _read_targets  # noqa: E402


def _write_targets(tmp_path: Path, lines: list[str]) -> str:
    p = tmp_path / "targets.txt"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


class TestReadTargets:
    def test_skips_comments_and_blanks(self, tmp_path):
        path = _write_targets(tmp_path, [
            "# comment", "", "https://a.com/?id=1", "  ", "https://b.com/?x=2",
        ])
        assert _read_targets(path) == ["https://a.com/?id=1", "https://b.com/?x=2"]

    def test_empty_file(self, tmp_path):
        path = _write_targets(tmp_path, ["# only comment", ""])
        assert _read_targets(path) == []


class TestRunBatch:
    def _gate_token(self, tmp_path):
        from helper import setup_gate_and_token
        return setup_gate_and_token(str(tmp_path / "batch.db"), scope_value="acme.com")

    def test_aggregates_two_targets_into_report(self, tmp_path):
        gate, token = self._gate_token(tmp_path)

        def fake_scan(*, gate, params, authz_token, caller_id="batch_scan"):
            t = params["target"]
            return {
                "tool": "web_vuln_scan",
                "engagement_id": f"eng_{t}",
                "quota_used": 1,
                "findings": [{
                    "id": "fnd_x",
                    "type": "sqli_error",
                    "severity": "high",
                    "target": t,
                    "title": f"SQLi on {t}",
                    "confidence": "validated",
                    "evidence": {"parameter": "id", "payload": "'", "match": "sql"},
                }],
                "summary": {"total": 1},
            }

        with patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = []
            with patch("secagent.tools.web_vuln_scan.web_vuln_scan", side_effect=fake_scan):
                report = run_batch(
                    ["https://acme.com/?id=1", "https://acme.com/?page=2"],
                    token,
                    client_name="ACME",
                )

        assert "ACME" in report
        assert "SQLi on https://acme.com/?id=1" in report
        assert "SQLi on https://acme.com/?page=2" in report
        # two engagements → 2 findings
        assert "共发现 **2**" in report

    def test_out_of_scope_target_refused(self, tmp_path):
        gate, token = self._gate_token(tmp_path)  # scope = acme.com only

        with patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = []
            report = run_batch(
                ["https://other.com/?id=1"],  # out of scope
                token,
                client_name="ACME",
            )

        # The refusal is recorded as an info-level finding in the report.
        assert "Scan refused" in report
        assert "other.com" in report

    def test_empty_target_list_returns_valid_report(self, tmp_path):
        gate, token = self._gate_token(tmp_path)
        with patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = []
            report = run_batch([], token)
        assert "执行摘要" in report
