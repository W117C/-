"""Tests for TheHarvesterAdapter and the gather_osint tool function (spec §3.2 ④)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from secagent.adapters.theharvester import TheHarvesterAdapter
from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.errors import InvalidInputError, NotAuthorizedError, ToolFailedError
from secagent.core.finding import FindingType, Severity
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore
from secagent.tools.gather_osint import gather_osint


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_launcher(stdout: str, returncode: int = 0):
    """Build a LaunchResult-like mock with canned stdout/returncode."""
    mock_result = MagicMock()
    mock_result.returncode = returncode
    mock_result.stdout = stdout
    mock_result.stderr = ""
    mock_result.json_output = None  # adapter doesn't use this; launcher sets it
    return mock_result


def _canned_output() -> str:
    return json.dumps(
        {
            "emails": ["admin@acme.com", "info@acme.com"],
            "subdomains": ["mail.acme.com", "vpn.acme.com"],
            "hosts": ["acme.com:1.2.3.4"],
            "usernames": [],
        }
    )


def _setup_gate_and_token(tmp_db, scope_domain="acme.com"):
    """Bootstrap a real ComplianceGate + verified token for DOMAIN scope."""
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=100)
    return gate, token


# ---------------------------------------------------------------------------
# Adapter tests
# ---------------------------------------------------------------------------


def test_adapter_parses_emails_subdomains_hosts_into_findings():
    adapter = TheHarvesterAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher(_canned_output())):
        findings = adapter.run({"target": "acme.com"})

    # 2 emails + 2 subdomains + 1 host + 0 usernames = 5 findings
    assert len(findings) == 5
    for f in findings:
        assert f.type == FindingType.INTEL
        assert f.severity == Severity.INFO
        assert f.source_tool == "theharvester"


def test_adapter_evidence_has_category_source_value():
    adapter = TheHarvesterAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher(_canned_output())):
        findings = adapter.run({"target": "acme.com"})

    by_category: dict[str, list] = {}
    for f in findings:
        assert f.evidence["source"] == "theHarvester"
        assert f.evidence["value"] == f.target
        assert f.evidence["category"] in {"emails", "subdomains", "hosts", "usernames"}
        by_category.setdefault(f.evidence["category"], []).append(f)

    assert set(by_category.keys()) == {"emails", "subdomains", "hosts"}
    assert len(by_category["emails"]) == 2
    assert len(by_category["subdomains"]) == 2
    assert len(by_category["hosts"]) == 1
    # Titles are human-readable singular labels.
    assert findings[0].title.startswith(("Email:", "Subdomain:", "Host:"))


def test_adapter_handles_empty_results():
    adapter = TheHarvesterAdapter()
    empty = json.dumps({"emails": [], "subdomains": [], "hosts": [], "usernames": []})
    with patch.object(adapter, "_launch", return_value=_mock_launcher(empty)):
        findings = adapter.run({"target": "acme.com"})
    assert findings == []


def test_adapter_handles_empty_stdout():
    adapter = TheHarvesterAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher("")):
        findings = adapter.run({"target": "acme.com"})
    assert findings == []


def test_adapter_handles_non_json_stdout_with_zero_exit():
    adapter = TheHarvesterAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher("not json at all")):
        findings = adapter.run({"target": "acme.com"})
    # Non-JSON stdout with returncode 0 is treated as no findings (not an error).
    assert findings == []


def test_adapter_command_includes_d_flag_and_target():
    adapter = TheHarvesterAdapter()
    cmd_used: list[str] | None = None

    def capture_launch(cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher("{}")

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"target": "acme.com"})

    assert cmd_used is not None
    assert any("theHarvester" in part for part in cmd_used)
    assert "-d" in cmd_used
    assert "acme.com" in cmd_used
    assert "-b" in cmd_used and "all" in cmd_used
    assert "-f" in cmd_used and "json" in cmd_used


def test_adapter_raises_tool_failed_on_nonzero_exit():
    adapter = TheHarvesterAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher("", returncode=2)):
        with pytest.raises(ToolFailedError):
            adapter.run({"target": "acme.com"})


def test_adapter_raises_invalid_input_when_target_missing():
    adapter = TheHarvesterAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({})


def test_adapter_respects_data_types_filter():
    adapter = TheHarvesterAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher(_canned_output())):
        findings = adapter.run({"target": "acme.com", "data_types": ["emails"]})

    assert len(findings) == 2
    for f in findings:
        assert f.evidence["category"] == "emails"


# ---------------------------------------------------------------------------
# Tool function tests
# ---------------------------------------------------------------------------


def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with patch("secagent.tools.gather_osint.TheHarvesterAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [
            MagicMock(target="admin@acme.com"),
            MagicMock(target="mail.acme.com"),
        ]
        MockAdapter.return_value = mock_instance

        result = gather_osint(
            gate=gate,
            params={"target": "acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "gather_osint"
    assert result["summary"]["total"] == 2
    assert result["quota_used"] == 1
    assert "engagement_id" in result and result["engagement_id"].startswith("eng_")


def test_tool_rejects_unauthorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")
    with pytest.raises(NotAuthorizedError):
        gather_osint(
            gate=gate,
            params={"target": "evil.com"},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_raises_invalid_input_when_target_missing(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with pytest.raises(InvalidInputError):
        gather_osint(
            gate=gate,
            params={},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_empty_result_still_commits_quota(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with patch("secagent.tools.gather_osint.TheHarvesterAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        MockAdapter.return_value = mock_instance

        result = gather_osint(
            gate=gate,
            params={"target": "acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 0
    assert result["quota_used"] == 1
