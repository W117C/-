from __future__ import annotations

import json
import datetime as dt
from unittest.mock import patch, MagicMock

import pytest

from secagent.adapters.subfinder import SubfinderAdapter
from secagent.core.finding import Finding, FindingType, Severity


def _mock_launcher(stdout_lines: list[str], returncode: int = 0):
    """Patch Launcher.run to return canned output lines joined by newline."""
    stdout = "\n".join(stdout_lines)
    mock_result = MagicMock()
    mock_result.returncode = returncode
    mock_result.stdout = stdout
    mock_result.stderr = ""
    mock_result.json_output = None  # launcher will try json.loads
    return mock_result


def test_adapter_returns_one_finding_per_host():
    adapter = SubfinderAdapter()
    lines = [
        json.dumps({"host": "sub.acme.com", "source": "crtsh"}),
        json.dumps({"host": "blog.acme.com", "source": "virustotal"}),
        json.dumps({"host": "api.acme.com", "source": "crtsh"}),
    ]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"target_domain": "acme.com"})

    assert len(findings) == 3
    for f in findings:
        assert f.type == FindingType.SUBDOMAIN
        assert f.severity == Severity.INFO
        assert f.source_tool == "subfinder"


def test_adapter_includes_evidence():
    adapter = SubfinderAdapter()
    lines = [json.dumps({"host": "sub.acme.com", "source": "crtsh"})]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"target_domain": "acme.com"})

    f = findings[0]
    assert f.target == "sub.acme.com"
    assert f.title == "Subdomain: sub.acme.com"
    assert f.evidence["source"] == "crtsh"


def test_adapter_handles_empty_output():
    adapter = SubfinderAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher([])):
        findings = adapter.run({"target_domain": "acme.com"})
    assert findings == []


def test_adapter_handles_non_json_lines():
    adapter = SubfinderAdapter()
    lines = ["not json at all", json.dumps({"host": "sub.acme.com", "source": "crtsh"})]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"target_domain": "acme.com"})
    # Bad lines are silently skipped; only valid JSON lines become findings.
    assert len(findings) == 1
    assert findings[0].target == "sub.acme.com"


def test_adapter_uses_target_domain_in_command():
    adapter = SubfinderAdapter()
    cmd_used = None

    def capture_launch(cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher([])

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"target_domain": "acme.com"})

    assert any("subfinder" in part for part in cmd_used)
    assert "-d" in cmd_used
    assert "acme.com" in cmd_used


def test_adapter_supports_sources_param():
    adapter = SubfinderAdapter()
    cmd_used = None

    def capture_launch(cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher([])

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"target_domain": "acme.com", "sources": ["crtsh", "virustotal"]})

    assert "-sources" in cmd_used  # subfinder flag
