"""Smoke + edge-case tests for check_health diagnostic tool."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from secagent.tools.check_health import check_health, _check_binary


# ── _check_binary unit tests ──────────────────────────────────────────

def test_check_binary_ok_when_binary_exists(tmp_path):
    """When the binary file exists on disk, status should be 'ok'."""
    bin_dir = str(tmp_path)
    binary = tmp_path / "subfinder"
    binary.write_text("fake")
    result = _check_binary("subfinder", bin_dir)
    assert result["status"] == "ok"
    assert result["name"] == "subfinder"


def test_check_binary_missing_when_not_found(tmp_path):
    bin_dir = str(tmp_path)
    result = _check_binary("subfinder", bin_dir)
    assert result["status"] == "missing"
    assert "hint" in result


def test_check_binary_unknown_tool_returns_question_mark():
    result = _check_binary("nonexistent_tool", "/tmp")
    assert result["status"] == "missing"
    assert result["version"] == "?"


# ── check_health integration ───────────────────────────────────────────

def test_check_health_returns_dict_with_all_keys():
    """No gate, no params — still returns a valid dict with the base keys."""
    result = check_health(gate=None, params=None)
    assert isinstance(result, dict)
    assert result["tool"] == "check_health"
    assert "python" in result
    assert "binaries" in result
    assert isinstance(result["binaries"], list)
    assert "binaries_all_ok" in result
    assert "wordlists" in result
    assert "database" in result
    assert "nuclei_templates" in result
    assert "summary" in result


def test_check_health_with_wordlists_dir(tmp_path):
    wl_dir = tmp_path / "wordlists"
    wl_dir.mkdir()
    (wl_dir / "paths_builtin.txt").write_text("/admin\n")
    (wl_dir / "common.txt").write_text("password\n")
    result = check_health(gate=None, params={"wordlists_dir": str(wl_dir)})
    assert result["wordlists"]["paths_builtin"] is True
    assert result["wordlists"]["common"] is True


def test_check_health_missing_wordlists():
    result = check_health(gate=None, params={"wordlists_dir": "/nonexistent/path"})
    assert result["wordlists"]["paths_builtin"] is False
    assert result["wordlists"]["common"] is False


def test_check_health_database_gate_with_store():
    gate = MagicMock()
    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = (1,)
    gate.store._connect.return_value.__enter__ = MagicMock(return_value=conn)
    gate.store._connect.return_value.__exit__ = MagicMock(return_value=None)
    # Simpler: just mock _connect to return a MagicMock
    gate.store._connect.return_value = MagicMock()
    gate.store._connect.return_value.execute.return_value.fetchone.return_value = (1,)

    result = check_health(gate=gate, params=None)
    assert result["database"] == "ok"


def test_check_health_database_no_gate():
    result = check_health(gate=None, params=None)
    assert result["database"] == "not checked"


def test_check_health_database_error():
    gate = MagicMock()
    gate.store._connect.side_effect = RuntimeError("db down")
    result = check_health(gate=gate, params=None)
    assert "error" in str(result["database"])


def test_check_health_summary_all_ok():
    """When all binaries are ok and db is not checked, summary should be green."""
    gate = None
    with patch("secagent.tools.check_health._check_binary",
               return_value={"name": "x", "status": "ok", "version": "1.0"}):
        result = check_health(gate=gate, params={"wordlists_dir": "/nonexistent"})
    assert result["binaries_all_ok"] is True
    assert "✅" in result["summary"]


def test_check_health_summary_one_missing():
    with patch("secagent.tools.check_health._check_binary",
               return_value={"name": "x", "status": "missing", "version": "?"}):
        result = check_health(gate=None, params={"wordlists_dir": "/nonexistent"})
    assert result["binaries_all_ok"] is False
    assert "⚠️" in result["summary"]
