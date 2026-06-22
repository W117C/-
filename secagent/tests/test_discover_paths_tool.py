"""Tool function tests for discover_paths."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from secagent.core.errors import InvalidInputError, NotAuthorizedError
from secagent.tools.discover_paths import discover_paths
from helper import setup_gate_and_token


def _mock_finding(url, status_code=200, severity="low"):
    m = MagicMock()
    m.to_dict.return_value = {
        "id": "fnd_test_path",
        "type": "exposed_path",
        "severity": severity,
        "target": url,
        "title": f"{url} ({status_code})",
        "evidence": {"url": url, "status_code": status_code},
        "source_tool": "ffuf",
        "raw": {},
        "timestamp": "2026-06-22T00:00:00+00:00",
    }
    return m


def test_discover_paths_success(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    mock_finding = _mock_finding("https://acme.com/admin", 200, "high")

    with patch("secagent.tools.discover_paths.FfufAdapter") as MockAd:
        instance = MockAd.return_value
        instance.run.return_value = [mock_finding]

        result = discover_paths(
            gate=gate,
            params={"target": "https://acme.com/FUZZ"},
            authz_token=token,
        )

    assert result["tool"] == "discover_paths"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "exposed_path"
    assert result["quota_used"] == 1


def test_discover_paths_empty_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with pytest.raises(InvalidInputError):
        discover_paths(
            gate=gate,
            params={"target": ""},
            authz_token=token,
        )


def test_discover_paths_no_results(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.discover_paths.FfufAdapter") as MockAd:
        instance = MockAd.return_value
        instance.run.return_value = []

        result = discover_paths(
            gate=gate,
            params={"target": "https://acme.com/FUZZ"},
            authz_token=token,
        )

    assert result["tool"] == "discover_paths"
    assert len(result["findings"]) == 0


def test_discover_paths_unauthorized(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_value="other.com")
    with pytest.raises(NotAuthorizedError):
        discover_paths(
            gate=gate,
            params={"target": "https://acme.com/FUZZ"},
            authz_token=token,
        )
