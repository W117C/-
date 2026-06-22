"""Tool function tests for scan_ports."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from secagent.core.errors import InvalidInputError, NotAuthorizedError
from secagent.tools.scan_ports import scan_ports
from helper import setup_gate_and_token


def _mock_finding(target, port, service="https"):
    m = MagicMock()
    m.to_dict.return_value = {
        "id": "fnd_test_port",
        "type": "open_port",
        "severity": "info",
        "target": target,
        "title": f"Open port {port}/tcp ({service})",
        "evidence": {"port": port, "protocol": "tcp", "service": service},
        "source_tool": "naabu",
        "raw": {},
        "timestamp": "2026-06-22T00:00:00+00:00",
    }
    return m


def test_scan_ports_success(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    mock_finding = _mock_finding("acme.com", 443, "https")

    with patch("secagent.tools.scan_ports.NaabuAdapter") as MockAd:
        instance = MockAd.return_value
        instance.run.return_value = [mock_finding]

        result = scan_ports(
            gate=gate,
            params={"target": "acme.com"},
            authz_token=token,
        )

    assert result["tool"] == "scan_ports"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "open_port"
    assert result["quota_used"] == 1
    assert "engagement_id" in result


def test_scan_ports_empty_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with pytest.raises(InvalidInputError):
        scan_ports(
            gate=gate,
            params={"target": ""},
            authz_token=token,
        )


def test_scan_ports_no_results(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.scan_ports.NaabuAdapter") as MockAd:
        instance = MockAd.return_value
        instance.run.return_value = []

        result = scan_ports(
            gate=gate,
            params={"target": "acme.com"},
            authz_token=token,
        )

    assert result["tool"] == "scan_ports"
    assert len(result["findings"]) == 0
    assert result["summary"]["total"] == 0


def test_scan_ports_unauthorized(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_value="other.com")
    with pytest.raises(NotAuthorizedError):
        scan_ports(
            gate=gate,
            params={"target": "acme.com"},
            authz_token=token,
        )
