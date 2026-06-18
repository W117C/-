from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.gate import ComplianceGate
from secagent.core.errors import NotAuthorizedError
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore
from secagent.tools.enumerate_subdomains import enumerate_subdomains


def _setup_gate_and_token(tmp_db, scope_domain="acme.com"):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=100)
    return gate, token


def _mock_subfinder_lines():
    return [
        json.dumps({"host": "sub.acme.com", "source": "crtsh"}),
        json.dumps({"host": "blog.acme.com", "source": "virustotal"}),
    ]


def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [
            MagicMock(target="sub.acme.com"),
            MagicMock(target="blog.acme.com"),
        ]
        MockAdapter.return_value = mock_instance

        result = enumerate_subdomains(
            gate=gate,
            params={"target_domain": "acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "enumerate_subdomains"
    assert result["summary"]["total"] == 2
    assert result["quota_used"] == 1


def test_tool_rejects_unauthorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")
    with pytest.raises(NotAuthorizedError):
        enumerate_subdomains(
            gate=gate,
            params={"target_domain": "evil.com"},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_empty_result_still_commits(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        MockAdapter.return_value = mock_instance

        result = enumerate_subdomains(
            gate=gate,
            params={"target_domain": "acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 0
    assert result["quota_used"] == 1
