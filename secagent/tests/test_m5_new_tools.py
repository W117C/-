"""Smoke tests for 4 new penetration tools — validate gate + params + envelope.

Strategy: patch each adapter's `run` method directly to return list[Finding].
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from secagent.core.finding import Finding
from secagent.core.proxy import ProxyConfig, ProxyManager
from secagent.tools.crawl_with_katana import crawl_with_katana
from secagent.tools.fingerprint_tls import fingerprint_tls
from secagent.tools.resolve_dns import resolve_dns
from secagent.tools.search_engines import search_engines


def _gate():
    from secagent.core.authz import AuthorizationScope, ScopeType
    g = MagicMock()
    g.check.return_value = AuthorizationScope(ScopeType.DOMAIN, "example.com")
    g.audit = MagicMock()
    g.proxy_manager = ProxyManager(config=ProxyConfig(pool=[]))
    return g


def _ok_finding(tool: str) -> Finding:
    from secagent.core.finding import FindingType, Severity
    return Finding(
        id=f"{tool}-001",
        type=FindingType.EXPOSURE,
        severity=Severity.INFO,
        target="example.com",
        title=f"{tool} smoke test",
        evidence={},
        confidence="validated",
        source_tool="test",
    )


# ── crawl_with_katana ────────────────────────────────────────────────────

def test_katana_http_target_required():
    from secagent.adapters.katana import KatanaAdapter
    fake = lambda params: [_ok_finding("katana")]
    with patch.object(KatanaAdapter, "run", side_effect=fake):
        r = crawl_with_katana(
            gate=_gate(),
            params={"target": "https://example.com", "depth": 2},
            authz_token="t",
            caller_id="tester",
        )
    # gated_tool wraps list[Finding] into a dict envelope
    assert isinstance(r, dict)
    assert "findings" in r and len(r["findings"]) == 1
    assert r["findings"][0]["confidence"] == "validated"


def test_katana_rejects_non_url():
    with pytest.raises(Exception):
        crawl_with_katana(
            gate=_gate(), params={"target": "not-a-url"},
            authz_token="t", caller_id="tester",
        )


def test_katana_rejects_empty_target():
    with pytest.raises(Exception):
        crawl_with_katana(
            gate=_gate(), params={"target": ""},
            authz_token="t", caller_id="tester",
        )


# ── resolve_dns ──────────────────────────────────────────────────────────

def test_dns_targets_required():
    from secagent.adapters.dnsx import DnsxAdapter
    with patch.object(DnsxAdapter, "run", return_value=[_ok_finding("dnsx")]):
        r = resolve_dns(
            gate=_gate(),
            params={"targets": ["a.example.com"]},
            authz_token="t", caller_id="tester",
        )
    assert isinstance(r, dict) and len(r["findings"]) == 1


def test_dns_empty_rejected():
    with pytest.raises(Exception):
        resolve_dns(gate=_gate(), params={"targets": []}, authz_token="t", caller_id="tester")


# ── fingerprint_tls ──────────────────────────────────────────────────────

def test_tls_targets_required():
    from secagent.adapters.tlsx import TlsxAdapter
    with patch.object(TlsxAdapter, "run", return_value=[_ok_finding("tlsx")]):
        r = fingerprint_tls(
            gate=_gate(),
            params={"targets": ["example.com"]},
            authz_token="t", caller_id="tester",
        )
    assert isinstance(r, dict) and len(r["findings"]) == 1


# ── search_engines ──────────────────────────────────────────────────────

def test_uncover_query_required():
    from secagent.adapters.uncover import UncoverAdapter
    with patch.object(UncoverAdapter, "run", return_value=[_ok_finding("uncover")]):
        r = search_engines(
            gate=_gate(),
            params={"query": "example.com", "engines": ["shodan"]},
            authz_token="t", caller_id="tester",
        )
    assert isinstance(r, dict) and len(r["findings"]) == 1


def test_uncover_empty_query_rejected():
    with pytest.raises(Exception):
        search_engines(gate=_gate(), params={"query": ""}, authz_token="t", caller_id="tester")


# ── Registry + proxy matrix ───────────────────────────────────────────────

def test_all_four_tools_registered_in_registry():
    from secagent.server.tools_registry import all_tools

    names = {t.name for t in all_tools()}
    assert "crawl_with_katana" in names
    assert "resolve_dns" in names
    assert "fingerprint_tls" in names
    assert "search_engines" in names
    assert "web_vuln_scan" in names
    assert "attack_surface_scan" in names


def test_proxy_matrix_covers_all_four_tools():
    from secagent.core.proxy import PROXY_FLAG_TOOLS, ENV_PROXY_TOOLS

    coverage = set(PROXY_FLAG_TOOLS.keys()) | ENV_PROXY_TOOLS
    for t in ("katana", "dnsx", "tlsx", "uncover"):
        assert t in coverage, f"{t} missing from proxy matrix"


# ── attack_surface_scan ──────────────────────────────────────────────────

def test_attack_surface_scan_rejects_empty_domain():
    from secagent.tools.attack_surface_scan import attack_surface_scan

    with pytest.raises(Exception):
        attack_surface_scan(
            gate=_gate(), params={}, authz_token="t", caller_id="tester",
        )


def test_attack_surface_scan_requires_auth():
    from secagent.core.authz import AuthorizationScope, ScopeType
    from secagent.core.errors import NotAuthorizedError
    from secagent.tools.attack_surface_scan import attack_surface_scan

    g = MagicMock()
    g.check.side_effect = NotAuthorizedError(target="example.com", scope_domain=None)

    with pytest.raises(NotAuthorizedError):
        attack_surface_scan(
            gate=g, params={"target_domain": "example.com"}, authz_token="bad", caller_id="tester",
        )
