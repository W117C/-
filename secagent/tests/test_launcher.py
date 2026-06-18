from __future__ import annotations

import json
import pytest
import subprocess
from unittest.mock import patch, MagicMock

from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.core.errors import ToolFailedError, ToolTimeoutError


def test_launcher_runs_command_and_parses_json():
    fake_output = json.dumps({"host": "sub.example.com", "source": "crtsh"})
    with patch("secagent.binmgmt.launcher.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (fake_output.encode(), b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        launcher = Launcher(timeout_sec=10)
        result = launcher.run(["subfinder", "-d", "acme.com", "-json"])

    assert result.returncode == 0
    assert result.stdout == fake_output
    assert result.json_output == {"host": "sub.example.com", "source": "crtsh"}


def test_launcher_returns_empty_json_on_non_json_output():
    with patch("secagent.binmgmt.launcher.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"plain text output", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        launcher = Launcher(timeout_sec=10)
        result = launcher.run(["subfinder", "-d", "acme.com"])

    assert result.json_output is None


def test_launcher_raises_tool_timeout_on_timeout():
    with patch("secagent.binmgmt.launcher.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd="subfinder", timeout=1)
        mock_popen.return_value = mock_proc

        launcher = Launcher(timeout_sec=1)
        with pytest.raises(ToolTimeoutError):
            launcher.run(["subfinder", "-d", "acme.com"])


def test_launcher_raises_tool_failed_on_missing_binary():
    with patch("secagent.binmgmt.launcher.subprocess.Popen") as mock_popen:
        mock_popen.side_effect = FileNotFoundError("[Errno 2] No such file or directory: 'subfinder'")

        launcher = Launcher(timeout_sec=10)
        with pytest.raises(ToolFailedError) as exc_info:
            launcher.run(["subfinder", "-d", "acme.com"])
        assert "No such file" in str(exc_info.value)


def test_launcher_passes_timeout_to_communicate():
    with patch("secagent.binmgmt.launcher.subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"{}", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        launcher = Launcher(timeout_sec=5)
        launcher.run(["subfinder", "-d", "acme.com"])

    # communicate must be called with the launcher's timeout
    mock_proc.communicate.assert_called_once_with(timeout=5)
