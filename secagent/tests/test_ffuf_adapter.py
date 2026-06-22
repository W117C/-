"""Unit tests for FfufAdapter."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from secagent.adapters.ffuf import FfufAdapter, _classify_severity
from secagent.core.errors import InvalidInputError, ToolFailedError
from secagent.core.finding import Severity


def _mock_launcher_result(stdout_lines: list[str], returncode: int = 0):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = "\n".join(stdout_lines)
    m.stderr = ""
    return m


# --- _classify_severity tests ---

class TestClassifySeverity:
    def test_critical_config(self):
        assert _classify_severity(200, "/admin/.env") == Severity.CRITICAL

    def test_critical_git_config(self):
        assert _classify_severity(200, "/.git/config") == Severity.CRITICAL

    def test_critical_backup_sql(self):
        assert _classify_severity(200, "/backup.sql") == Severity.CRITICAL

    def test_high_admin(self):
        assert _classify_severity(200, "/admin/") == Severity.HIGH

    def test_high_api(self):
        assert _classify_severity(200, "/api/users") == Severity.HIGH

    def test_high_api_403(self):
        assert _classify_severity(403, "/admin") == Severity.MEDIUM

    def test_medium_phpmyadmin(self):
        assert _classify_severity(200, "/phpmyadmin/") == Severity.MEDIUM

    def test_low_known_url(self):
        assert _classify_severity(200, "/about") == Severity.LOW

    def test_low_redirect(self):
        assert _classify_severity(301, "/old-page") == Severity.LOW

    def test_info_not_found(self):
        assert _classify_severity(404, "/nothing") == Severity.INFO


# --- FfufAdapter tests ---

def test_ffuf_adapter_missing_target():
    adapter = FfufAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({"target": ""})


def test_ffuf_adapter_parse_output():
    lines = [
        json.dumps({"url": "https://acme.com/admin", "status": 200, "content_length": 1500, "content_type": "text/html"}),
        json.dumps({"url": "https://acme.com/.env", "status": 200, "content_length": 500, "content_type": "text/plain"}),
        json.dumps({"url": "https://acme.com/backup", "status": 301, "content_length": 0, "content_type": ""}),
    ]
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result(lines)):
        with patch("secagent.adapters.ffuf._resolve_wordlist", return_value="/tmp/builtin.txt"):
            findings = adapter.run({"target": "https://acme.com/FUZZ"})

    assert len(findings) == 3
    # .env should be critical
    assert findings[1].type.value == "exposed_path"
    assert findings[1].severity == Severity.CRITICAL
    assert findings[1].evidence["status_code"] == 200

    # admin should be high
    assert findings[0].severity == Severity.HIGH


def test_ffuf_adapter_empty_output():
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])):
        with patch("secagent.adapters.ffuf._resolve_wordlist", return_value="/tmp/builtin.txt"):
            findings = adapter.run({"target": "https://acme.com/FUZZ"})
    assert len(findings) == 0


def test_ffuf_adapter_nonzero_exit():
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([], returncode=1)):
        with pytest.raises(ToolFailedError):
            adapter.run({"target": "https://acme.com/FUZZ"})


def test_ffuf_adapter_params():
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])) as mock_launch:
        with patch("secagent.adapters.ffuf._resolve_wordlist", return_value="/tmp/common.txt"):
            adapter.run({
                "target": "https://acme.com/FUZZ",
                "wordlist": "common",
                "extensions": "php,asp",
                "rate": "200",
                "threads": "50",
            })
    cmd = mock_launch.call_args[0][0]
    assert "-u" in cmd
    assert "https://acme.com/FUZZ" in cmd
    assert "-w" in cmd
    assert "/tmp/common.txt" in cmd or "common.txt" in str(cmd)
    assert "php,asp" in cmd


def test_ffuf_adapter_rate_clamp():
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])) as mock_launch:
        with patch("secagent.adapters.ffuf._resolve_wordlist", return_value="/tmp/builtin.txt"):
            adapter.run({"target": "https://acme.com/FUZZ", "rate": "9999"})
    cmd = mock_launch.call_args[0][0]
    rate_idx = cmd.index("-rate") + 1
    assert int(cmd[rate_idx]) == 500


def test_ffuf_adapter_depth_clamp():
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result([])) as mock_launch:
        with patch("secagent.adapters.ffuf._resolve_wordlist", return_value="/tmp/builtin.txt"):
            adapter.run({"target": "https://acme.com/FUZZ", "recursive_depth": "10"})
    cmd = mock_launch.call_args[0][0]
    depth_idx = cmd.index("-recursion-depth") + 1
    assert int(cmd[depth_idx]) == 3


def test_ffuf_adapter_skips_invalid_json():
    lines = [
        "not json",
        json.dumps({"url": "https://acme.com/admin", "status": 200}),
        "",
    ]
    adapter = FfufAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher_result(lines)):
        with patch("secagent.adapters.ffuf._resolve_wordlist", return_value="/tmp/builtin.txt"):
            findings = adapter.run({"target": "https://acme.com/FUZZ"})
    assert len(findings) == 1
