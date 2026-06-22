from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from secagent.core.errors import NotAuthorizedError
from secagent.tools.enumerate_subdomains import enumerate_subdomains
from helper import setup_gate_and_token


def _mock_subfinder_lines():
    return [
        json.dumps({"host": "sub.acme.com", "source": "crtsh"}),
        json.dumps({"host": "blog.acme.com", "source": "virustotal"}),
    ]


def _make_mock_finding(target, id_suffix="0"):
    """Return a MagicMock that quacks like a Finding for to_dict()."""
    m = MagicMock()
    m.target = target
    m.to_dict.return_value = {
        "id": f"fnd_test_{id_suffix}",
        "type": "subdomain",
        "severity": "info",
        "target": target,
        "title": f"Subdomain: {target}",
        "evidence": {"source": "crtsh"},
        "source_tool": "subfinder",
        "raw": {},
        "timestamp": "2025-01-01T00:00:00+00:00",
    }
    return m


def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [
            _make_mock_finding("sub.acme.com", "a"),
            _make_mock_finding("blog.acme.com", "b"),
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
    gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
    with pytest.raises(NotAuthorizedError):
        enumerate_subdomains(
            gate=gate,
            params={"target_domain": "evil.com"},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_empty_result_still_commits(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
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
