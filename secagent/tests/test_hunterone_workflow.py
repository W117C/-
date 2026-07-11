"""Tests for HackerOne workflow engine (recon pipeline + BBP profile).

Focus:
  - Architecture identification works on a real HTTP response shape
  - Endpoint discovery extracts /api/ routes from JS
  - TikTok BBP profile enforces --h1-username requirement
  - _run_vuln_scan dispatches all 6 modules (sqli/xss/ssrf/lfi/idor/xxe)
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from helper import setup_gate_and_token

from secagent.workflow.hunterone import (
    HackerOneWorkflow,
    _identify_architecture,
    _extract_js_endpoints,
)


# ── Architecture identification ─────────────────────────────────────────────

class TestArchitectureIdentification:
    def test_spa_catch_all_detection(self):
        """A Next.js SPA shell with catch-all returns identical hash for random path."""
        target = "https://app.example.com"
        spa_html = (
            '<html><body><div id="root">loading...</div></body></html>'
        )
        with patch("secagent.workflow.hunterone.httpx.Client") as MockClient:
            resp = MagicMock()
            resp.status_code = 200
            resp.text = spa_html
            resp.content = spa_html.encode()
            MockClient.return_value.__enter__.return_value.get.return_value = resp
            info = _identify_architecture(target)
        assert info.framework == "spa"
        assert info.catch_all is True
        assert "example.com" in info.evidence

    def test_target_unreachable(self):
        import httpx
        with patch("secagent.workflow.hunterone.httpx.Client") as MockClient:
            MockClient.return_value.__enter__.return_value.get.side_effect = (
                httpx.RequestError("conn refused")
            )
            info = _identify_architecture("https://dead.example.com")
        assert info.framework == "unknown"
        assert "unreachable" in info.evidence.lower()


# ── Endpoint discovery ──────────────────────────────────────────────────────

class TestEndpointDiscovery:
    def test_extracts_api_routes_from_js(self):
        js_body = '''
        fetch("/api/user/profile")
        const baseURL = "https://api.example.com"
        url: "/graphql"
        '''
        with patch("secagent.workflow.hunterone.httpx.Client") as MockClient:
            resp = MagicMock()
            resp.status_code = 200
            resp.text = js_body
            MockClient.return_value.__enter__.return_value.get.return_value = resp
            endpoints = _extract_js_endpoints(
                MockClient.return_value.__enter__.return_value,
                ["https://app.example.com/main.js"],
                "https://app.example.com",
            )
        urls = {e.url for e in endpoints}
        assert "https://app.example.com/api/user/profile" in urls
        assert "https://app.example.com/graphql" in urls


# ── TikTok BBP profile enforcement ──────────────────────────────────────────

class TestTiktokBBPProfile:
    def test_missing_h1_username_appends_error(self, tmp_path):
        wf = HackerOneWorkflow(
            target="https://www.tiktok.com",
            bbp_profile="tiktok",
            output_dir=str(tmp_path),
        )
        # _identify_architecture with unreachable target → no crash,
        # TikTok profile should still flag missing --h1-username
        import httpx
        with patch("secagent.workflow.hunterone.httpx.Client") as MockClient:
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html><body>ok</body></html>"
            resp.content = b"<html><body>ok</body></html>"
            MockClient.return_value.__enter__.return_value.get.return_value = resp
            report_path = wf.run()
        assert report_path
        report = open(report_path, encoding="utf-8").read()
        assert "TikTok" in report
        assert "--h1-username" in report or "H1 username" in report

    def test_h1_username_present_no_warning(self, tmp_path):
        wf = HackerOneWorkflow(
            target="https://www.tiktok.com",
            bbp_profile="tiktok",
            h1_username="W117C",
            output_dir=str(tmp_path),
        )
        import httpx
        with patch("secagent.workflow.hunterone.httpx.Client") as MockClient:
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "<html><body>ok</body></html>"
            resp.content = b"<html><body>ok</body></html>"
            MockClient.return_value.__enter__.return_value.get.return_value = resp
            report_path = wf.run()
        report = open(report_path, encoding="utf-8").read()
        assert "W117C" in report


# ── Vuln scan module dispatch ───────────────────────────────────────────────

class TestVulnScanDispatch:
    def test_all_six_modules_dispatched(self, tmp_path):
        """_run_vuln_scan must call web_vuln_scan for sqli/xss/ssrf/lfi/idor/xxe."""
        from secagent.workflow.hunterone import _run_vuln_scan

        calls: list[dict] = []

        def fake_scan(*, gate, params, authz_token, caller_id):
            calls.append(dict(params))
            return {"findings": [], "summary": {}}

        with patch("secagent.workflow.hunterone._SDK_AVAILABLE", True), \
             patch("secagent.tools.web_vuln_scan.web_vuln_scan", side_effect=fake_scan):
            results = _run_vuln_scan(
                "https://app.example.com",
                "tok_xyz",
                bbp_profile="",
                cookie="session=abc",
                post_body_params=["id"],
            )

        dispatched = {c["modules"][0] for c in calls}
        assert dispatched == {"sqli", "xss", "ssrf", "lfi", "idor", "xxe"}
        # cookie + post_body_params must be forwarded to web_vuln_scan
        assert all(c.get("cookie") == "session=abc" for c in calls)
        assert all(c.get("post_body_params") == ["id"] for c in calls)
        # 6 modules + 1 secret_leaks note
        assert len(results) == 7

    def test_tiktok_skips_ssrf(self, tmp_path):
        from secagent.workflow.hunterone import _run_vuln_scan

        calls: list[dict] = []

        def fake_scan(*, gate, params, authz_token, caller_id):
            calls.append(dict(params))
            return {"findings": [], "summary": {}}

        with patch("secagent.workflow.hunterone._SDK_AVAILABLE", True), \
             patch("secagent.tools.web_vuln_scan.web_vuln_scan", side_effect=fake_scan):
            _run_vuln_scan(
                "https://www.tiktok.com",
                "tok_xyz",
                bbp_profile="tiktok",
            )

        dispatched = {c["modules"][0] for c in calls}
        assert "ssrf" not in dispatched
        assert dispatched == {"sqli", "xss", "lfi", "idor", "xxe"}
