from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from secagent.adapters.httpx_adapter import HttpxAdapter
from secagent.core.errors import InvalidInputError, NotAuthorizedError
from secagent.core.finding import Finding, FindingType, Severity
from secagent.tools.probe_services import probe_services
from helper import setup_gate_and_token


# ---------- helpers ----------

def _mock_launcher(stdout_lines: list[str], returncode: int = 0):
    """Patch Launcher.run to return canned output lines joined by newline."""
    stdout = "\n".join(stdout_lines)
    mock_result = MagicMock()
    mock_result.returncode = returncode
    mock_result.stdout = stdout
    mock_result.stderr = ""
    mock_result.json_output = None  # launcher will try json.loads
    return mock_result


def _httpx_line(**overrides):
    obj = {
        "host": "sub.acme.com",
        "port": "443",
        "scheme": "https",
        "url": "https://sub.acme.com",
        "input": "sub.acme.com",
        "title": "Welcome",
        "status_code": 200,
        "tech": ["Nginx", "PHP"],
        "webserver": "nginx",
    }
    obj.update(overrides)
    return json.dumps(obj)


# ==================== Adapter tests ====================

def test_adapter_returns_one_finding_per_service():
    adapter = HttpxAdapter()
    lines = [
        _httpx_line(host="sub.acme.com", port="443"),
        _httpx_line(host="api.acme.com", port="80", scheme="http",
                    url="http://api.acme.com", status_code=301, tech=[]),
    ]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"targets": ["sub.acme.com", "api.acme.com"]})

    assert len(findings) == 2
    for f in findings:
        assert f.type == FindingType.SERVICE
        assert f.severity == Severity.INFO
        assert f.source_tool == "httpx"


def test_adapter_includes_evidence():
    adapter = HttpxAdapter()
    lines = [_httpx_line()]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"targets": ["sub.acme.com"]})

    f = findings[0]
    assert f.target == "sub.acme.com"
    assert f.title == "Service: sub.acme.com:443"
    assert f.evidence["port"] == "443"
    assert f.evidence["protocol"] == "https"
    assert f.evidence["service"] == "nginx"
    assert f.evidence["title"] == "Welcome"
    assert f.evidence["tech_stack"] == ["Nginx", "PHP"]
    assert f.evidence["status_code"] == 200


def test_adapter_handles_empty_output():
    adapter = HttpxAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher([])):
        findings = adapter.run({"targets": ["sub.acme.com"]})
    assert findings == []


def test_adapter_handles_non_json_lines():
    adapter = HttpxAdapter()
    lines = ["not json at all", _httpx_line()]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"targets": ["sub.acme.com"]})
    # Bad lines are silently skipped; only valid JSON lines become findings.
    assert len(findings) == 1
    assert findings[0].target == "sub.acme.com"


def test_adapter_command_uses_targets_and_flags():
    adapter = HttpxAdapter()
    cmd_used = None

    def capture_launch(cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher([])

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"targets": ["sub.acme.com", "api.acme.com"], "ports": "80,443"})

    assert any("httpx" in part for part in cmd_used)
    assert "-l" in cmd_used
    assert "-json" in cmd_used
    assert "-silent" in cmd_used
    assert "-p" in cmd_used
    assert "80,443" in cmd_used


def test_adapter_threads_param_passed():
    adapter = HttpxAdapter()
    cmd_used = None

    def capture_launch(cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher([])

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"targets": ["sub.acme.com"], "threads": 25})

    assert "-threads" in cmd_used
    assert "25" in cmd_used


def test_adapter_rejects_empty_targets():
    adapter = HttpxAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({})


def test_adapter_rejects_non_list_targets():
    adapter = HttpxAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({"targets": "sub.acme.com"})


# ==================== Tool function tests ====================

def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.probe_services.HttpxAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [
            Finding(id="fnd_a", type=FindingType.SERVICE, severity=Severity.INFO,
                    target="sub.acme.com", title="Service: sub.acme.com:443"),
        ]
        MockAdapter.return_value = mock_instance

        result = probe_services(
            gate=gate,
            params={"targets": ["sub.acme.com"]},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "probe_services"
    assert result["summary"]["total"] == 1
    assert result["summary"]["by_severity"] == {"info": 1}
    assert result["summary"]["by_type"] == {"service": 1}
    assert result["quota_used"] == 1


def test_tool_rejects_unauthorized_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
    with pytest.raises(NotAuthorizedError):
        probe_services(
            gate=gate,
            params={"targets": ["evil.com"]},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_rejects_empty_targets(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with pytest.raises(InvalidInputError):
        probe_services(
            gate=gate,
            params={"targets": []},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_rejects_when_any_target_out_of_scope(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
    # sub.acme.com is in scope, evil.com is not — entire call must refuse
    # before the adapter runs.
    with patch("secagent.tools.probe_services.HttpxAdapter") as MockAdapter:
        with pytest.raises(NotAuthorizedError):
            probe_services(
                gate=gate,
                params={"targets": ["sub.acme.com", "evil.com"]},
                authz_token=token,
                caller_id="test_user",
            )
        # adapter.run() must not have been called at all
        MockAdapter.return_value.run.assert_not_called()


def test_tool_empty_result_still_commits(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.probe_services.HttpxAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        MockAdapter.return_value = mock_instance

        result = probe_services(
            gate=gate,
            params={"targets": ["acme.com"]},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 0
    assert result["quota_used"] == 1


def test_tool_multiple_in_scope_targets_all_pass(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_value="acme.com")
    with patch("secagent.tools.probe_services.HttpxAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [
            Finding(id="fnd_a", type=FindingType.SERVICE, severity=Severity.INFO,
                    target="sub.acme.com", title="Service: sub.acme.com:443"),
            Finding(id="fnd_b", type=FindingType.SERVICE, severity=Severity.INFO,
                    target="api.acme.com", title="Service: api.acme.com:80"),
        ]
        MockAdapter.return_value = mock_instance

        result = probe_services(
            gate=gate,
            params={"targets": ["sub.acme.com", "api.acme.com"]},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 2
    assert result["quota_used"] == 1
