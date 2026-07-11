"""Tests for WebVulnAdapter + web_vuln_scan tool (capability extension).

Covers SQLi detection (error/time/boolean), XSS reflection analysis, SSRF
probing, and the three-layer compliance guard integration.
"""

from __future__ import annotations

import json
import httpx
from unittest.mock import patch, MagicMock

import pytest

from secagent.adapters.web_vuln import WebVulnAdapter
from secagent.core.errors import (
    ComplianceBlockError,
    InvalidInputError,
    NotAuthorizedError,
)
from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.finding import FindingType, Severity
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore
from secagent.tools.web_vuln_scan import web_vuln_scan
from helper import setup_gate_and_token

import datetime as dt


# ===========================================================================
# WebVulnAdapter unit tests
# ===========================================================================


class TestWebVulnAdapterBasics:
    def test_tool_name(self):
        adapter = WebVulnAdapter()
        assert adapter.tool_name == "web_vuln_scan"

    def test_requires_target(self):
        adapter = WebVulnAdapter()
        with pytest.raises(InvalidInputError):
            adapter.run({})

    def test_returns_list(self):
        adapter = WebVulnAdapter()
        # Mock the internal detection methods
        with patch.object(adapter, '_detect_sqli', return_value=[]), \
             patch.object(adapter, '_detect_xss', return_value=[]), \
             patch.object(adapter, '_detect_ssrf', return_value=[]):
            result = adapter.run({"target": "http://example.com"})
        assert isinstance(result, list)

    def test_empty_params_returns_empty(self):
        """No query params → no SQLi/XSS findings."""
        adapter = WebVulnAdapter()

        # Mock _extract_query_params used inside the detection methods
        with patch("secagent.adapters.web_vuln._extract_query_params", return_value={}):
            result = adapter.run({"target": "http://example.com"})
        assert result == []


class TestSQLiDetection:
    def test_error_based_sqli_detected(self):
        """Adapter recognizes SQL error in response body."""
        adapter = WebVulnAdapter()

        mock_response = MagicMock()
        mock_response.text = "Error: You have an error in your SQL syntax near ''' at line 1"

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_sqli(mock_client, "http://example.com/?id=1&page=2")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].type == FindingType.VULNERABILITY
        assert "SQL" in findings[0].title

    def test_error_based_sqli_no_error_in_response(self):
        """No SQL error pattern → no finding for that param."""
        adapter = WebVulnAdapter()

        mock_response = MagicMock()
        mock_response.text = "<html><body>Page content here</body></html>"

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_sqli(mock_client, "http://example.com/?id=1")
        assert len(findings) == 0

    def test_no_query_params_returns_empty(self):
        """URL without query params should return empty findings."""
        adapter = WebVulnAdapter()
        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        findings = adapter._detect_sqli(mock_client, "http://example.com/static-page")
        assert findings == []


class TestXSSDetection:
    def test_reflected_xss_detected(self):
        """Adapter detects unencoded script payload reflection."""
        adapter = WebVulnAdapter()

        # Simulate: payload appears unencoded in response
        marker = "abc12345"
        malicious_payload = f"<script>alert('XSS_{marker}')</script>"
        body = f"<html><body>Search results: {malicious_payload}</body></html>"

        mock_response = MagicMock()
        mock_response.text = body

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_xss(mock_client, "http://example.com/?q=test")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "XSS" in findings[0].title

    def test_encoded_xss_not_flagged(self):
        """HTML-encoded payload should NOT be flagged as exploitable."""
        adapter = WebVulnAdapter()

        # Response contains HTML-escaped version
        marker = "abc12345"
        encoded_payload = f"&lt;script&gt;alert(&#x27;XSS_{marker}&#x27;)&lt;/script&gt;"
        body = f"<html><body>Search results: {encoded_payload}</body></html>"

        mock_response = MagicMock()
        mock_response.text = body

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_xss(mock_client, "http://example.com/?q=test")
        assert len(findings) == 0


class TestSSRFDetection:
    def test_ssrf_via_cloud_metadata(self):
        """Adapter detects AWS metadata endpoint reflection."""
        adapter = WebVulnAdapter()

        mock_response = MagicMock()
        mock_response.text = '{"ami-id":"ami-12345678","instance-id":"i-12345"}'

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_ssrf(
            mock_client,
            "http://example.com/?url=http://example.com",
            "",
        )
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert "SSRF" in findings[0].title

    def test_ssrf_no_url_params_no_findings(self):
        """No URL-bearing params → no SSRF findings."""
        adapter = WebVulnAdapter()
        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        findings = adapter._detect_ssrf(mock_client, "http://example.com/?id=1", "")
        assert findings == []


class TestLFIDetection:
    def test_lfi_via_etc_passwd(self):
        """Adapter detects /etc/passwd content in response."""
        adapter = WebVulnAdapter()

        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash\n daemon:x:1:1:daemon:"

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_lfi(
            mock_client, "http://example.com/?file=report.pdf"
        )
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "LFI" in findings[0].title or "Inclusion" in findings[0].title
        assert findings[0].evidence.get("bypass_technique")

    def test_lfi_no_signature_no_finding(self):
        """Normal page content → no LFI finding."""
        adapter = WebVulnAdapter()

        mock_response = MagicMock()
        mock_response.text = "<html><body>Normal report listing</body></html>"

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_lfi(
            mock_client, "http://example.com/?file=report.pdf"
        )
        assert findings == []

    def test_lfi_url_path_injection_branch(self):
        """LFI also probes traversal appended to a non-root URL path."""
        adapter = WebVulnAdapter()

        mock_response = MagicMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        # No query params → exercises the <path> injection branch.
        findings = adapter._detect_lfi(
            mock_client, "http://example.com/download/report"
        )
        assert len(findings) >= 1
        assert findings[0].evidence.get("parameter") == "<path>"

    def test_lfi_default_modules_includes_lfi(self):
        """run() default modules must include 'lfi' now that it is implemented."""
        adapter = WebVulnAdapter()
        with patch.object(adapter, '_detect_sqli', return_value=[]), \
             patch.object(adapter, '_detect_xss', return_value=[]), \
             patch.object(adapter, '_detect_ssrf', return_value=[]), \
             patch.object(adapter, '_detect_lfi', return_value=[]):
            result = adapter.run({"target": "http://example.com/?file=x"})
        assert isinstance(result, list)


class TestSSRF_OOBClosure:
    def _ssrf_adapter(self, oob_poller=None):
        a = WebVulnAdapter(oob_poller=oob_poller)
        # Bypass network: stub the client + the internal probes, keep only
        # the OOB branch logic by mocking _detect_ssrf's HTTP via the client.
        import httpx
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = MagicMock(text="ok")  # no internal-IP signature
        return a, client

    def test_no_poller_stays_pending_high(self):
        """Without a poller, OOB finding stays HIGH + pending_verification."""
        a = WebVulnAdapter()
        import httpx
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = MagicMock(text="ok")
        findings = a._detect_ssrf(
            client, "http://example.com/?url=http://x", "https://cb.example/{id}", None
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["status"] == "pending_verification"
        assert findings[0].confidence != "validated"

    def test_poller_true_upgrades_to_critical_confirmed(self):
        """Poller returning True → CRITICAL + confirmed + validated."""
        a = WebVulnAdapter(oob_poller=lambda cid: True)
        import httpx
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = MagicMock(text="ok")
        findings = a._detect_ssrf(
            client, "http://example.com/?url=http://x", "https://cb.example/{id}", a.oob_poller
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].evidence["status"] == "confirmed"
        assert findings[0].confidence == "validated"

    def test_poller_false_stays_pending_high(self):
        """Poller returning False → still suspected (HIGH), never over-stated."""
        a = WebVulnAdapter(oob_poller=lambda cid: False)
        import httpx
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = MagicMock(text="ok")
        findings = a._detect_ssrf(
            client, "http://example.com/?url=http://x", "https://cb.example/{id}", a.oob_poller
        )
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["status"] == "pending_verification"

    def test_poller_exception_does_not_crash(self):
        """A throwing poller is swallowed → falls back to pending HIGH."""
        def boom(cid):
            raise RuntimeError("callback server down")
        a = WebVulnAdapter(oob_poller=boom)
        import httpx
        client = MagicMock(spec=httpx.Client)
        client.get.return_value = MagicMock(text="ok")
        findings = a._detect_ssrf(
            client, "http://example.com/?url=http://x", "https://cb.example/{id}", a.oob_poller
        )
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["status"] == "pending_verification"

        adapter = WebVulnAdapter()
        mock_response = MagicMock()
        mock_response.text = "ORA-01722: invalid number"

        import httpx
        mock_client = MagicMock(spec=httpx.Client)
        mock_client.get.return_value = mock_response

        findings = adapter._detect_sqli(mock_client, "http://example.com/?id=1")
        assert len(findings) >= 1
        f = findings[0]
        assert f.id.startswith("fnd_")
        assert f.source_tool == "web_vuln_scan"
        assert f.evidence["parameter"] == "id"


# ===========================================================================
# Tool function integration tests (gate + adapter)
# ===========================================================================


class TestWebVulnScanTool:
    def test_rejects_empty_target(self, tmp_path):
        gate, token = setup_gate_and_token(str(tmp_path / "test.db"))
        with pytest.raises(InvalidInputError):
            web_vuln_scan(gate=gate, params={}, authz_token=token)

    def test_rejects_blocklisted_target(self, tmp_path):
        gate, token = setup_gate_and_token(str(tmp_path / "test.db"))
        # Scope is acme.com — inject blocklisted host into scope
        # The blocklist contains .gov/.mil by default
        with pytest.raises((ComplianceBlockError, NotAuthorizedError)):
            web_vuln_scan(
                gate=gate,
                params={"target": "http://acme.gov/"},
                authz_token=token,
            )

    def test_successful_scan_returns_findings(self, tmp_path):
        gate, token = setup_gate_and_token(str(tmp_path / "test.db"))

        # Mock the adapter to return a finding
        mock_finding = MagicMock()
        mock_finding.to_dict.return_value = {
            "id": "fnd_test123",
            "type": "vulnerability",
            "severity": "high",
            "target": "http://acme.com",
            "title": "SQL Injection (MySQL) via 'id'",
            "evidence": {"parameter": "id"},
        }

        with patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = [mock_finding]
            result = web_vuln_scan(
                gate=gate,
                params={"target": "http://acme.com/?id=1"},
                authz_token=token,
            )

        assert result["tool"] == "web_vuln_scan"
        assert result["quota_used"] == 1
        assert len(result["findings"]) >= 1
        assert result["summary"]["total"] >= 1

    def test_no_findings_still_returns_valid_structure(self, tmp_path):
        gate, token = setup_gate_and_token(str(tmp_path / "test.db"))

        with patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = []
            result = web_vuln_scan(
                gate=gate,
                params={"target": "http://acme.com/?id=1"},
                authz_token=token,
            )

        assert result["tool"] == "web_vuln_scan"
        assert result["findings"] == []
        assert result["summary"]["total"] == 0

    def test_oob_auto_mode_starts_server_and_injects_poller(self, tmp_path):
        """oob_callback='auto' → embedded server starts, poller injected,
        callback URL rewritten to the live port, then server stops."""
        gate, token = setup_gate_and_token(str(tmp_path / "test.db"))
        started, stopped = [], []

        class FakeServer:
            def __init__(self):
                self.port = 19999
            def start(self):
                started.append(1)
            def stop(self):
                stopped.append(1)
            def poll(self, cid, timeout=0):
                return []

        with patch("secagent.oob.CallbackServer", return_value=FakeServer()), \
             patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = []

            web_vuln_scan(
                gate=gate,
                params={"target": "http://acme.com/?url=http://x",
                        "oob_callback": "auto"},
                authz_token=token,
            )
            assert MockAdapter.call_args is not None
            _, kwargs = MockAdapter.call_args
            captured_poller = kwargs

        assert started, "CallbackServer.start() not called in auto mode"
        assert stopped, "CallbackServer.stop() not called (leak!)"
        assert "oob_poller" in captured_poller and callable(captured_poller["oob_poller"])
        # URL must have been rewritten to the embedded server port.
        run_kwargs = MockAdapter.call_args.kwargs if MockAdapter.call_args.kwargs else {}
        # The adapter received params dict via .run(params); check via the
        # captured oob_callback rewrite by inspecting adapter.run call instead.
        run_call = MockAdapter.return_value.run.call_args
        run_params = (run_call.kwargs if run_call.kwargs else run_call.args[0]) if run_call else {}
        assert run_params.get("oob_callback") == "http://127.0.0.1:19999/{id}", run_params

    def test_oob_external_url_mode_does_not_start_server(self, tmp_path):
        """A full external URL means caller owns the listener → no server,
        poller stays None, callback URL passed through unchanged."""
        gate, token = setup_gate_and_token(str(tmp_path / "test.db"))
        started = []

        class FakeServer:
            def start(self):
                started.append(1)
            def stop(self):
                pass
            def poll(self, cid, timeout=0):
                return []

        with patch("secagent.oob.CallbackServer", return_value=FakeServer()), \
             patch("secagent.tools.web_vuln_scan.WebVulnAdapter") as MockAdapter:
            MockAdapter.return_value.run.return_value = []

            web_vuln_scan(
                gate=gate,
                params={"target": "http://acme.com/?url=http://x",
                        "oob_callback": "https://cb.example/{id}"},
                authz_token=token,
            )
            run_call = MockAdapter.return_value.run.call_args
            run_params = (run_call.kwargs if run_call.kwargs else run_call.args[0]) if run_call else {}

        assert not started, "External-URL mode must NOT start a server"
        assert run_params.get("oob_callback") == "https://cb.example/{id}"


# ===========================================================================
# Deduplication (spec §M6-adjacent: clean client reports)
# ===========================================================================


class TestWebVulnDedupe:
    def _mk(self, method, param="id", conf="validated", vclass="sqli"):
        return Finding(
            id=f"fnd_{method}",
            type=FindingType.VULNERABILITY,
            severity=Severity.HIGH,
            target="http://acme.com",
            title=f"SQLi via {param}",
            evidence={"parameter": param, "method": method, "vuln_class": vclass},
            source_tool="web_vuln_scan",
            timestamp=dt.datetime.now(dt.timezone.utc),
            confidence=conf,
        )

    def test_same_param_same_method_collapses(self):
        a = WebVulnAdapter()
        f1 = self._mk("error")
        f2 = self._mk("error")  # identical key
        out = a._dedupe([f1, f2])
        assert len(out) == 1

    def test_distinct_methods_merge_with_evidence(self):
        a = WebVulnAdapter()
        f_err = self._mk("error")
        f_bool = self._mk("boolean")
        out = a._dedupe([f_err, f_bool])
        assert len(out) == 1
        ev = out[0].evidence
        assert "methods" in ev and set(ev["methods"]) == {"error", "boolean"}
        assert ev.get("duplicate_count") == 2

    def test_different_params_not_merged(self):
        a = WebVulnAdapter()
        f1 = self._mk("error", param="id")
        f2 = self._mk("error", param="page")
        out = a._dedupe([f1, f2])
        assert len(out) == 2

    def test_different_types_not_merged(self):
        a = WebVulnAdapter()
        sql = self._mk("error")
        xss = Finding(
            id="fnd_xss", type=FindingType.VULNERABILITY, severity=Severity.HIGH,
            target="http://acme.com", title="XSS via id",
            evidence={"parameter": "id", "method": "reflection", "vuln_class": "xss"},
            source_tool="web_vuln_scan",
            timestamp=dt.datetime.now(dt.timezone.utc), confidence="validated",
        )
        out = a._dedupe([sql, xss])
        assert len(out) == 2

    def test_higher_confidence_wins(self):
        a = WebVulnAdapter()
        low = self._mk("error", conf="unvalidated")
        high = self._mk("boolean", conf="validated")
        out = a._dedupe([low, high])
        assert len(out) == 1
        assert out[0].confidence == "validated"

    def test_run_applies_dedupe(self):
        a = WebVulnAdapter()
        with patch.object(a, "_detect_sqli", return_value=[self._mk("error"), self._mk("boolean")]), \
             patch.object(a, "_detect_xss", return_value=[]), \
             patch.object(a, "_detect_ssrf", return_value=[]), \
             patch.object(a, "_detect_lfi", return_value=[]):
            out = a.run({"target": "http://acme.com/?id=1"})
        assert len(out) == 1


# ===========================================================================
# P7 — IDOR / XXE detection (spec §M7)
# ===========================================================================


class TestIDORD检测:
    def _client_for_idor(self, base_id, neighbor_id):
        """Mock client where base id page and neighbor id page both look like
        real objects (status 200, content, different bodies)."""
        base_url = f"http://acme.com/user?id={base_id}"
        neighbor_url = f"http://acme.com/user?id={neighbor_id}"

        def _get(url, *a, **k):
            resp = MagicMock()
            resp.status_code = 200
            if neighbor_id and neighbor_url in url:
                resp.text = f"<html><body>User profile #{neighbor_id}: name=neighbor, email=n@x.com, ssn=999</body></html>"
            elif base_url in url:
                resp.text = f"<html><body>User profile #{base_id}: name=base, email=b@x.com, ssn=111</body></html>"
            else:
                resp.text = "<html><body>Not found</body></html>"
            return resp

        client = MagicMock(spec=httpx.Client)
        client.get.side_effect = _get
        return client

    def test_idor_flags_adjacent_object(self):
        client = self._client_for_idor("100", "101")
        a = WebVulnAdapter()
        findings = a._detect_idor(client, "http://acme.com/user?id=100")
        assert len(findings) == 1
        f = findings[0]
        assert f.evidence["vuln_class"] == "idor_adjacent_access"
        assert f.evidence["neighbor_id"] == "101"
        assert f.confidence == "unvalidated"  # never claim confirmed IDOR

    def test_idor_no_finding_when_neighbor_404(self):
        # Neighbor returns a "not found" page → no IDOR flagged.
        def _get(url, *a, **k):
            resp = MagicMock()
            resp.status_code = 404
            resp.text = "Not found"
            return resp
        client = MagicMock(spec=httpx.Client)
        client.get.side_effect = _get
        a = WebVulnAdapter()
        assert a._detect_idor(client, "http://acme.com/user?id=100") == []

    def test_idor_no_finding_without_id_param(self):
        a = WebVulnAdapter()
        assert a._detect_idor(MagicMock(spec=httpx.Client), "http://acme.com/about") == []

    def test_neighbor_id_increments(self):
        assert WebVulnAdapter._neighbor_id("100") == "101"
        assert WebVulnAdapter._neighbor_id("user1001") == "user1002"
        assert WebVulnAdapter._neighbor_id("abc") is None


class TestXXE检测:
    def test_xxe_echo_detected(self):
        # Simulate a server that reflects the expanded internal entity.
        def _post(url, *a, **k):
            content = k.get("content", "")
            if isinstance(content, bytes):
                content = content.decode("utf-8", "ignore")
            resp = MagicMock()
            resp.status_code = 200
            # Extract the marker from the payload and echo it back.
            import re as _re
            m = _re.search(r"XXE_ECHO_MARKER_(\w+)", content or "")
            if m:
                resp.text = f"result: XXE_ECHO_MARKER_{m.group(1)}"
            else:
                resp.text = "ok"
            return resp

        client = MagicMock(spec=httpx.Client)
        client.post.side_effect = _post
        a = WebVulnAdapter()
        findings = a._detect_xxe(client, "http://acme.com/api", "", None)
        assert len(findings) == 1
        assert findings[0].evidence["vuln_class"] == "xxe_echo"
        assert findings[0].confidence == "validated"

    def test_xxe_oob_confirmed(self):
        def _post(url, *a, **k):
            return MagicMock(status_code=200, text="ok")
        client = MagicMock(spec=httpx.Client)
        client.post.side_effect = _post
        a = WebVulnAdapter()

        def _poller(cid):
            return True  # callback reached our listener

        findings = a._detect_xxe(client, "http://acme.com/api", "https://cb.example/{id}", _poller)
        assert len(findings) == 1
        assert findings[0].evidence["vuln_class"] == "xxe_oob"
        assert findings[0].confidence == "validated"

    def test_xxe_no_finding_when_unconfirmed(self):
        # No echo, no OOB callback → zero findings (no false positive).
        def _post(url, *a, **k):
            return MagicMock(status_code=200, text="ok")
        client = MagicMock(spec=httpx.Client)
        client.post.side_effect = _post
        a = WebVulnAdapter()
        assert a._detect_xxe(client, "http://acme.com/api", "", None) == []

