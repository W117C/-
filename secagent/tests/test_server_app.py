"""Unit tests for `SecAgentServer` — the MCP application core (M2b).

These tests exercise the dispatch + error-mapping layer WITHOUT importing the
MCP SDK. The SDK transport (`__main__.py`) is just thin glue over
`SecAgentServer.call_tool`, so covering `call_tool` here gives us full
confidence in the dispatch contract.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock


from secagent.config import Config
from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.errors import ToolFailedError
from secagent.server import SecAgentServer, ToolDefinition


def _make_server(tmp_db: str) -> SecAgentServer:
    return SecAgentServer(config=Config(db_path=tmp_db))


def _issue_verified_token(server: SecAgentServer, scope_domain: str = "acme.com") -> str:
    token = server.registry.issue(
        scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain)
    )
    server.registry.mark_verified(token, method="dns_txt")
    return token


# --- tool listing -----------------------------------------------------------

def test_server_lists_enumerate_subdomains_tool(tmp_db):
    server = _make_server(tmp_db)
    tools = server.list_tools()
    names = [t.name for t in tools]
    assert "enumerate_subdomains" in names

    td = next(t for t in tools if t.name == "enumerate_subdomains")
    assert isinstance(td, ToolDefinition)
    props = td.input_schema["properties"]
    assert "target_domain" in props
    assert callable(td.handler)


# --- happy path -------------------------------------------------------------

def test_server_dispatches_authorized_target(tmp_db):
    server = _make_server(tmp_db)
    token = _issue_verified_token(server, "acme.com")

    def _mk(target, i):
        m = MagicMock()
        m.target = target
        m.to_dict.return_value = {"id": f"fnd_{i}", "type": "subdomain", "severity": "info",
            "target": target, "title": f"Subdomain: {target}", "evidence": {}, "source_tool": "subfinder",
            "raw": {}, "timestamp": "2025-01-01"}
        return m
    fake_findings = [_mk("sub.acme.com", 0), _mk("blog.acme.com", 1)]
    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        MockAdapter.return_value.run.return_value = fake_findings
        result = server.call_tool("enumerate_subdomains", {
            "target_domain": "acme.com",
            "authz_token": token,
        })

    assert "error" not in result
    assert result["tool"] == "enumerate_subdomains"
    assert result["summary"]["total"] == 2
    assert result["quota_used"] == 1
    assert result["engagement_id"].startswith("eng_")


def test_server_empty_result_still_returns_summary(tmp_db):
    server = _make_server(tmp_db)
    token = _issue_verified_token(server, "acme.com")

    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        MockAdapter.return_value.run.return_value = []
        result = server.call_tool("enumerate_subdomains", {
            "target_domain": "acme.com",
            "authz_token": token,
        })

    assert result["summary"]["total"] == 0
    assert result["quota_used"] == 1


# --- authorization / compliance errors -------------------------------------

def test_server_rejects_unauthorized_target(tmp_db):
    server = _make_server(tmp_db)
    token = _issue_verified_token(server, "acme.com")

    result = server.call_tool("enumerate_subdomains", {
        "target_domain": "evil.com",
        "authz_token": token,
    })
    assert result["error"]["code"] == "NOT_AUTHORIZED"
    assert result["error"]["retryable"] is False
    assert "evil.com" in result["error"]["message"]


def test_server_rejects_unknown_token(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("enumerate_subdomains", {
        "target_domain": "acme.com",
        "authz_token": "auth_doesnotexist",
    })
    assert result["error"]["code"] == "NOT_AUTHORIZED"


def test_server_rejects_unverified_token(tmp_db):
    """Token issued but ownership never proven → must be refused (spec §4.1)."""
    server = _make_server(tmp_db)
    token = server.registry.issue(
        scope=AuthorizationScope(ScopeType.DOMAIN, "acme.com")
    )
    # intentionally skip mark_verified

    result = server.call_tool("enumerate_subdomains", {
        "target_domain": "acme.com",
        "authz_token": token,
    })
    assert result["error"]["code"] == "NOT_AUTHORIZED"


def test_server_blocks_compliance_violation(tmp_db):
    """Defense line 2: even an authorized .gov target is refused (spec §4.2)."""
    server = _make_server(tmp_db)
    # Authorize a government domain — scope check passes, blocklist must fire.
    token = _issue_verified_token(server, "example.gov")

    result = server.call_tool("enumerate_subdomains", {
        "target_domain": "example.gov",
        "authz_token": token,
    })
    assert result["error"]["code"] == "COMPLIANCE_BLOCK"
    assert result["error"]["retryable"] is False


# --- input validation -------------------------------------------------------

def test_server_rejects_unknown_tool(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("nonexistent_tool", {})
    assert result["error"]["code"] == "INVALID_INPUT"
    assert "nonexistent_tool" in result["error"]["message"]


def test_server_validates_required_target_domain(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("enumerate_subdomains", {"authz_token": "auth_x"})
    assert result["error"]["code"] == "INVALID_INPUT"
    assert "target_domain" in result["error"]["message"]


def test_server_validates_required_authz_token(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("enumerate_subdomains", {"target_domain": "acme.com"})
    assert result["error"]["code"] == "NOT_AUTHORIZED"


def test_server_rejects_empty_string_required_arg(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("enumerate_subdomains", {
        "target_domain": "",
        "authz_token": "auth_x",
    })
    assert result["error"]["code"] == "INVALID_INPUT"


def test_server_validates_argument_type(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("submit_scan", {
        "tool": "probe_services",
        "params": [],
        "authz_token": "auth_x",
    })
    assert result["error"]["code"] == "INVALID_INPUT"
    assert "params" in result["error"]["message"]
    assert "object" in result["error"]["message"]


def test_server_validates_integer_argument_type(tmp_db):
    server = _make_server(tmp_db)
    result = server.call_tool("enumerate_subdomains", {
        "target_domain": "acme.com",
        "authz_token": "auth_x",
        "timeout_sec": "120",
    })
    assert result["error"]["code"] == "INVALID_INPUT"
    assert "timeout_sec" in result["error"]["message"]
    assert "integer" in result["error"]["message"]


# --- tool execution errors --------------------------------------------------

def test_server_catches_tool_failure(tmp_db):
    server = _make_server(tmp_db)
    token = _issue_verified_token(server, "acme.com")

    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        MockAdapter.return_value.run.side_effect = ToolFailedError(
            tool="subfinder", detail="binary not found"
        )
        result = server.call_tool("enumerate_subdomains", {
            "target_domain": "acme.com",
            "authz_token": token,
        })
    assert result["error"]["code"] == "TOOL_FAILED"
    assert result["error"]["retryable"] is True
    assert "binary not found" in result["error"]["message"]


def test_server_catches_unexpected_exception(tmp_db):
    """Non-SecAgentError exceptions become TOOL_FAILED (last-resort guard)."""
    server = _make_server(tmp_db)
    token = _issue_verified_token(server, "acme.com")

    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        MockAdapter.return_value.run.side_effect = RuntimeError("kaboom")
        result = server.call_tool("enumerate_subdomains", {
            "target_domain": "acme.com",
            "authz_token": token,
        })
    assert result["error"]["code"] == "TOOL_FAILED"
    assert "kaboom" in result["error"]["message"]
