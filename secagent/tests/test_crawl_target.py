"""Tests for SimpleCrawlerAdapter and the crawl_target tool function (spec §3.2 ⑥)."""
from __future__ import annotations

import pytest

from secagent.adapters.simple_crawler import SimpleCrawlerAdapter
from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.errors import InvalidInputError, NotAuthorizedError, ToolFailedError
from secagent.core.finding import FindingType, Severity
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore
from secagent.tools.crawl_target import crawl_target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_gate_and_token(tmp_db, scope_domain="acme.com"):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=100)
    return gate, token


def _make_adapter(html: str, timeout_sec: int = 5) -> SimpleCrawlerAdapter:
    """Build an adapter with a fetcher that returns the supplied HTML."""
    def fake_fetcher(url, timeout):
        return html
    return SimpleCrawlerAdapter(timeout_sec=timeout_sec, fetcher=fake_fetcher)


# ---------------------------------------------------------------------------
# Adapter: forms
# ---------------------------------------------------------------------------

def test_adapter_extracts_form():
    html = '<html><body><form action="/login" method="post"><input></form></body></html>'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})

    forms = [f for f in findings if f.evidence.get("form_action") is not None]
    assert len(forms) == 1
    f = forms[0]
    assert f.type == FindingType.EXPOSURE
    assert f.severity == Severity.INFO
    assert f.source_tool == "simple_crawler"
    assert f.target == "https://acme.com"
    assert f.evidence["form_action"] == "/login"
    assert f.evidence["form_method"] == "post"
    assert f.evidence["url"] == "https://acme.com"


def test_adapter_form_default_method_when_missing():
    html = '<form action="/search"></form>'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    forms = [f for f in findings if "form_action" in f.evidence]
    assert len(forms) == 1
    assert forms[0].evidence["form_method"] == "get"


# ---------------------------------------------------------------------------
# Adapter: js_endpoints
# ---------------------------------------------------------------------------

def test_adapter_extracts_js_endpoint():
    html = '<script>fetch("/api/users").then(r=>r.json())</script>'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})

    eps = [f for f in findings if "js_api" in f.evidence]
    assert len(eps) == 1
    assert eps[0].evidence["js_api"] == "/api/users"
    assert eps[0].type == FindingType.EXPOSURE
    assert eps[0].source_tool == "simple_crawler"


def test_adapter_js_endpoints_deduplicated():
    html = '<script>fetch("/api/users"); fetch("/api/users"); axios("/api/users")</script>'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    eps = [f for f in findings if "js_api" in f.evidence]
    assert len(eps) == 1


def test_adapter_js_endpoint_v1_path():
    html = 'axios("/v1/orders/42")'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    eps = [f for f in findings if "js_api" in f.evidence]
    assert len(eps) == 1
    assert eps[0].evidence["js_api"] == "/v1/orders/42"


# ---------------------------------------------------------------------------
# Adapter: emails
# ---------------------------------------------------------------------------

def test_adapter_extracts_email():
    html = '<a href="mailto:admin@acme.com">admin@acme.com</a>'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})

    emails = [f for f in findings if "email" in f.evidence]
    assert len(emails) == 1
    assert emails[0].evidence["email"] == "admin@acme.com"
    assert emails[0].type == FindingType.EXPOSURE
    assert emails[0].source_tool == "simple_crawler"


def test_adapter_emails_deduplicated():
    html = 'contact: a@b.com; also a@b.com again'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    emails = [f for f in findings if "email" in f.evidence]
    assert len(emails) == 1


# ---------------------------------------------------------------------------
# Adapter: comments / secret leaks
# ---------------------------------------------------------------------------

def test_adapter_comment_with_aws_key_high_severity():
    html = '<!-- backup key: AKIAIOSFODNN7EXAMPLE do not commit -->'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})

    secrets = [f for f in findings if "leaked_secret_hint" in f.evidence]
    assert len(secrets) == 1
    assert secrets[0].severity == Severity.HIGH
    assert secrets[0].type == FindingType.EXPOSURE
    assert "AKIA" in secrets[0].evidence["leaked_secret_hint"]
    assert secrets[0].source_tool == "simple_crawler"


def test_adapter_comment_with_private_key_block_high_severity():
    html = '<!-- -----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY----- -->'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    secrets = [f for f in findings if "leaked_secret_hint" in f.evidence]
    assert len(secrets) == 1
    assert secrets[0].severity == Severity.HIGH


def test_adapter_comment_with_token_equals_high_severity():
    html = '<!-- access token=abc123secret -->'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    secrets = [f for f in findings if "leaked_secret_hint" in f.evidence]
    assert len(secrets) == 1
    assert secrets[0].severity == Severity.HIGH


def test_adapter_benign_comment_no_finding():
    html = '<!-- TODO: refactor this module before Q3 launch -->'
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    secrets = [f for f in findings if "leaked_secret_hint" in f.evidence]
    assert len(secrets) == 0


# ---------------------------------------------------------------------------
# Adapter: empty / error / input validation
# ---------------------------------------------------------------------------

def test_adapter_empty_page_returns_no_findings():
    adapter = _make_adapter("")
    findings = adapter.run({"target": "https://acme.com"})
    assert findings == []


def test_adapter_missing_target_raises_invalid_input():
    adapter = _make_adapter("<html></html>")
    with pytest.raises(InvalidInputError):
        adapter.run({})


def test_adapter_non_http_target_raises_invalid_input():
    adapter = _make_adapter("<html></html>")
    with pytest.raises(InvalidInputError):
        adapter.run({"target": "ftp://acme.com"})


def test_adapter_fetcher_failure_raises_tool_failed():
    def boom(url, timeout):
        raise RuntimeError("network down")
    adapter = SimpleCrawlerAdapter(timeout_sec=5, fetcher=boom)
    with pytest.raises(ToolFailedError):
        adapter.run({"target": "https://acme.com"})


# ---------------------------------------------------------------------------
# Adapter: extract filter
# ---------------------------------------------------------------------------

def test_adapter_extract_filter_forms_only_skips_emails():
    html = (
        '<form action="/login" method="post"></form>'
        '<a href="mailto:admin@acme.com">admin@acme.com</a>'
        '<script>fetch("/api/users")</script>'
    )
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com", "extract": ["forms"]})

    assert len(findings) == 1
    assert "form_action" in findings[0].evidence
    assert all("email" not in f.evidence for f in findings)
    assert all("js_api" not in f.evidence for f in findings)
    assert all("leaked_secret_hint" not in f.evidence for f in findings)


def test_adapter_extract_filter_emails_only():
    html = (
        '<form action="/login" method="post"></form>'
        '<a href="mailto:admin@acme.com">admin@acme.com</a>'
    )
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com", "extract": ["emails"]})
    assert len(findings) == 1
    assert findings[0].evidence["email"] == "admin@acme.com"


def test_adapter_extract_unknown_type_raises():
    adapter = _make_adapter("<html></html>")
    with pytest.raises(InvalidInputError):
        adapter.run({"target": "https://acme.com", "extract": ["nonsense"]})


# ---------------------------------------------------------------------------
# Adapter: source_tool / type invariants on a mixed page
# ---------------------------------------------------------------------------

def test_adapter_all_findings_are_exposure_from_simple_crawler():
    html = """
    <html>
      <body>
        <form action="/login" method="post"></form>
        <script>fetch("/api/users"); axios("/v1/orders")</script>
        <a href="mailto:admin@acme.com">admin@acme.com</a>
        <!-- AKIAIOSFODNN7EXAMPLE -->
        <!-- just a note -->
      </body>
    </html>
    """
    adapter = _make_adapter(html)
    findings = adapter.run({"target": "https://acme.com"})
    assert len(findings) >= 5  # 1 form + 2 js + 1 email + 1 secret
    for f in findings:
        assert f.type == FindingType.EXPOSURE
        assert f.source_tool == "simple_crawler"


# ---------------------------------------------------------------------------
# Tool function
# ---------------------------------------------------------------------------

def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")

    from unittest.mock import patch, MagicMock
    from secagent.core.finding import Finding
    fake_finding = Finding(
        id="fnd_1",
        type=FindingType.EXPOSURE,
        severity=Severity.INFO,
        target="https://acme.com",
        title="Form: action=/login method=post",
        evidence={"url": "https://acme.com", "form_action": "/login", "form_method": "post"},
        source_tool="simple_crawler",
    )
    with patch("secagent.tools.crawl_target.SimpleCrawlerAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [fake_finding]
        MockAdapter.return_value = mock_instance

        result = crawl_target(
            gate=gate,
            params={"target": "https://acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "crawl_target"
    assert result["quota_used"] == 1
    assert "engagement_id" in result
    assert isinstance(result["engagement_id"], str)
    assert result["engagement_id"].startswith("eng_")
    assert result["summary"]["total"] == 1
    assert result["summary"]["by_severity"]["info"] == 1
    assert result["summary"]["by_type"]["exposure"] == 1
    assert result["findings"][0]["source_tool"] == "simple_crawler"


def test_tool_rejects_unauthorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")
    with pytest.raises(NotAuthorizedError):
        crawl_target(
            gate=gate,
            params={"target": "https://evil.com"},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_missing_target_raises_invalid_input(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")
    # The tool extracts host = "" (urlparse of empty), gate.check on "" is
    # not in scope "acme.com" -> NotAuthorizedError fires before adapter
    # validation. To exercise InvalidInputError we need an in-scope host but
    # an empty/invalid target string passed to the adapter. Use a target
    # whose host matches scope but is not a valid http URL — gate.check
    # passes (host is in scope), then adapter.run raises InvalidInputError.
    with pytest.raises(InvalidInputError):
        crawl_target(
            gate=gate,
            params={"target": "acme.com"},  # in scope, but not http(s)
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_end_to_end_with_real_adapter(tmp_db):
    """End-to-end: real adapter with a mock fetcher, real gate, real findings."""
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")
    html = (
        '<form action="/login" method="post"></form>'
        '<script>fetch("/api/users")</script>'
        '<a href="mailto:admin@acme.com">admin@acme.com</a>'
        '<!-- AKIAIOSFODNN7EXAMPLE -->'
    )

    from unittest.mock import patch
    def fake_fetcher(url, timeout):
        return html

    with patch("secagent.tools.crawl_target.SimpleCrawlerAdapter") as MockAdapter:
        # Wire the mock to actually use the real adapter logic with our fetcher.
        from unittest.mock import MagicMock
        real_adapter = SimpleCrawlerAdapter(timeout_sec=5, fetcher=fake_fetcher)
        mock_instance = MagicMock(wraps=real_adapter)
        MockAdapter.return_value = mock_instance

        result = crawl_target(
            gate=gate,
            params={"target": "https://acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "crawl_target"
    assert result["quota_used"] == 1
    assert result["summary"]["total"] >= 4
    # One HIGH (secret), the rest INFO.
    assert result["summary"]["by_severity"].get("high") == 1
    assert result["summary"]["by_severity"].get("info", 0) >= 3
    assert result["summary"]["by_type"]["exposure"] == result["summary"]["total"]
    for f in result["findings"]:
        assert f["type"] == "exposure"
        assert f["source_tool"] == "simple_crawler"
