"""Unit tests for NaabuAdapter."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from secagent.adapters.naabu import NaabuAdapter
from secagent.core.errors import InvalidInputError, ToolFailedError


def _mock_launcher_result(stdout_lines: list[str], returncode: int = 0):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = "\n".join(stdout_lines)
    m.stderr = ""
    return m


def test_naabu_adapter_missing_target():
    adapter = NaabuAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({"target": ""})


def test_naabu_adapter_parse_open_ports():
    lines = [
        json.dumps({"host": "acme.com", "port": 80, "protocol": "tcp", "service": "http"}),
        json.dumps({"host": "acme.com", "port": 443, "protocol": "tcp", "service": "https"}),
        json.dumps({"host": "acme.com", "port": 22, "protocol": "tcp", "service": "ssh"}),
    ]
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result(lines)):
        findings = adapter.run({"target": "acme.com"})

    assert len(findings) == 3
    assert findings[0].type.value == "open_port"
    assert findings[0].severity.value == "info"
    assert findings[0].target == "acme.com"
    assert findings[0].evidence["port"] == 80
    assert findings[0].evidence["service"] == "http"
    assert findings[2].evidence["port"] == 22


def test_naabu_adapter_empty_output():
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])):
        findings = adapter.run({"target": "acme.com"})
    assert len(findings) == 0


def test_naabu_adapter_nonzero_exit():
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([], returncode=1)):
        with pytest.raises(ToolFailedError):
            adapter.run({"target": "acme.com"})


def test_naabu_adapter_params():
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])) as mock_launch:
        adapter.run({
            "target": "test.com",
            "ports": "80,443",
            "scan_type": "syn",
            "rate": "1000",
        })
    cmd = mock_launch.call_args[0][0]
    assert "-host" in cmd
    assert "test.com" in cmd
    assert "80,443" in cmd
    assert "syn" in cmd
    assert "1000" in cmd


def test_naabu_adapter_rate_clamp():
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])) as mock_launch:
        adapter.run({"target": "test.com", "rate": "9999"})
    cmd = mock_launch.call_args[0][0]
    rate_idx = cmd.index("-rate") + 1
    assert int(cmd[rate_idx]) == 2000  # capped


def test_naabu_adapter_ip_output():
    lines = [
        json.dumps({"host": "10.0.0.1", "port": 8080, "protocol": "tcp", "service": ""}),
    ]
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result(lines)):
        findings = adapter.run({"target": "10.0.0.1"})
    assert len(findings) == 1
    assert findings[0].target == "10.0.0.1"
    assert findings[0].title == "Open port 8080/tcp"


def test_naabu_adapter_skips_invalid_json():
    lines = [
        "not json",
        json.dumps({"host": "acme.com", "port": 443, "protocol": "tcp", "service": "https"}),
        "",
    ]
    adapter = NaabuAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result(lines)):
        findings = adapter.run({"target": "acme.com"})
    assert len(findings) == 1
    assert findings[0].target == "acme.com"
