from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from secagent.adapters.gitleaks import GitleaksAdapter, _redact
from secagent.core.authz import ScopeType
from secagent.core.errors import InvalidInputError, NotAuthorizedError, ToolFailedError
from secagent.core.finding import Finding, FindingType, Severity
from secagent.tools.scan_secret_leaks import scan_secret_leaks
from helper import setup_gate_and_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_launcher(stdout: str, returncode: int = 0):
    """Patch Launcher.run-style result with given stdout (already a string)."""
    mock_result = MagicMock()
    mock_result.returncode = returncode
    mock_result.stdout = stdout
    mock_result.stderr = ""
    mock_result.json_output = None
    return mock_result


def _canned_gitleaks_json() -> list[dict]:
    return [
        {
            "Description": "AWS Access Key",
            "StartLine": 10,
            "EndLine": 10,
            "StartColumn": 15,
            "EndColumn": 34,
            "Match": "AKIAIOSFODNN7EXAMPLE",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
            "File": "config.py",
            "Repo": "acme/webapp",
            "RuleID": "aws-access-key",
            "Tags": ["aws", "key"],
        },
        {
            "Description": "Generic API Token",
            "StartLine": 42,
            "EndLine": 42,
            "StartColumn": 1,
            "EndColumn": 40,
            "Match": "ghp_abcdefghijklmnopqrstuvwx",
            "Secret": "ghp_abcdefghijklmnopqrstuvwx",
            "File": "src/api.py",
            "Repo": "acme/webapp",
            "RuleID": "generic-api-token",
            "Tags": ["token"],
        },
    ]


_PLAINTEXTS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_abcdefghijklmnopqrstuvwx",
]


# ---------------------------------------------------------------------------
# _redact unit tests
# ---------------------------------------------------------------------------

def test_redact_long_secret_keeps_prefix_and_suffix():
    assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIA****MPLE"


def test_redact_short_secret_fully_masked():
    assert _redact("short") == "****"
    assert _redact("12345678") == "****"  # exactly 8 chars → fully masked


def test_redact_empty():
    assert _redact("") == "****"


# ---------------------------------------------------------------------------
# Adapter tests
# ---------------------------------------------------------------------------

def test_adapter_parses_json_array_into_findings():
    adapter = GitleaksAdapter()
    stdout = json.dumps(_canned_gitleaks_json())
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    assert len(findings) == 2
    for f in findings:
        assert f.type == FindingType.SECRET_LEAK
        assert f.source_tool == "gitleaks"
        assert isinstance(f, Finding)


def test_adapter_finding_titles_follow_spec():
    adapter = GitleaksAdapter()
    stdout = json.dumps([_canned_gitleaks_json()[0]])
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    f = findings[0]
    assert f.title == "Secret leak: aws-access-key in config.py:10"


def test_adapter_severity_mapping_aws_is_critical():
    adapter = GitleaksAdapter()
    stdout = json.dumps([_canned_gitleaks_json()[0]])  # aws-access-key
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    assert findings[0].severity == Severity.CRITICAL


def test_adapter_severity_mapping_generic_is_high():
    adapter = GitleaksAdapter()
    stdout = json.dumps([_canned_gitleaks_json()[1]])  # generic-api-token
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    assert findings[0].severity == Severity.HIGH


def test_adapter_redacts_secret_in_evidence():
    adapter = GitleaksAdapter()
    stdout = json.dumps(_canned_gitleaks_json())
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    for f in findings:
        assert "redacted_secret" in f.evidence
        redacted = f.evidence["redacted_secret"]
        # Redacted form has **** in the middle.
        assert "****" in redacted
        # No full plaintext appears anywhere in evidence.
        for plain in _PLAINTEXTS:
            assert plain not in json.dumps(f.evidence), \
                f"plaintext leaked into evidence: {f.evidence}"


def test_adapter_no_plaintext_in_raw():
    adapter = GitleaksAdapter()
    stdout = json.dumps(_canned_gitleaks_json())
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    for f in findings:
        raw_json = json.dumps(f.raw)
        for plain in _PLAINTEXTS:
            assert plain not in raw_json, f"plaintext leaked into raw: {f.raw}"
        # raw must NOT have raw 'Secret' / 'Match' keys holding plaintext.
        assert "Secret" not in f.raw
        assert "Match" not in f.raw
        # but should have redacted forms
        assert "redacted_secret" in f.raw


def test_adapter_redacted_form_is_prefix_suffix():
    adapter = GitleaksAdapter()
    stdout = json.dumps([_canned_gitleaks_json()[0]])
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    # AKIAIOSFODNN7EXAMPLE -> AKIA****MPLE
    assert findings[0].evidence["redacted_secret"] == "AKIA****MPLE"


def test_adapter_evidence_has_required_fields():
    adapter = GitleaksAdapter()
    stdout = json.dumps([_canned_gitleaks_json()[0]])
    with patch.object(adapter, "_launch", return_value=_mock_launcher(stdout)):
        findings = adapter.run({"scope": "github.com/acme/webapp"})

    ev = findings[0].evidence
    assert ev["repo"] == "acme/webapp"
    assert ev["file"] == "config.py"
    assert ev["line"] == 10
    assert ev["rule_id"] == "aws-access-key"
    assert ev["secret_type"] == "AWS Access Key"
    assert "redacted_secret" in ev


def test_adapter_empty_array_returns_no_findings():
    adapter = GitleaksAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher("[]")):
        findings = adapter.run({"scope": "github.com/acme/webapp"})
    assert findings == []


def test_adapter_empty_stdout_returns_no_findings():
    adapter = GitleaksAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher("")):
        findings = adapter.run({"scope": "github.com/acme/webapp"})
    assert findings == []


def test_adapter_nonzero_returncode_raises_tool_failed():
    adapter = GitleaksAdapter()
    err = "gitleaks: error: not a git repository"
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stdout = ""
    mock_result.stderr = err
    mock_result.json_output = None
    with patch.object(adapter, "_launch", return_value=mock_result):
        with pytest.raises(ToolFailedError):
            adapter.run({"scope": "github.com/acme/webapp"})


def test_adapter_exit_one_with_findings_is_success():
    """gitleaks exits 1 when it finds leaks — that is a normal result, not a
    failure. The adapter must return the parsed findings rather than raise."""
    adapter = GitleaksAdapter()
    stdout = json.dumps([_canned_gitleaks_json()[0]])
    mock_result = MagicMock()
    mock_result.returncode = 1  # leaks found
    mock_result.stdout = stdout
    mock_result.stderr = ""
    mock_result.json_output = None
    with patch.object(adapter, "_launch", return_value=mock_result):
        findings = adapter.run({"scope": "github.com/acme/webapp"})
    assert len(findings) == 1
    assert findings[0].type == FindingType.SECRET_LEAK


def test_adapter_command_includes_detect_and_source():
    adapter = GitleaksAdapter()
    cmd_used = None

    def capture_launch(cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher("[]")

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"scope": "/tmp/repos/acme-webapp"})

    assert "detect" in cmd_used
    assert "--source" in cmd_used
    assert "/tmp/repos/acme-webapp" in cmd_used
    assert "--report-format" in cmd_used
    assert "json" in cmd_used
    assert "--report-path" in cmd_used
    assert "-" in cmd_used
    assert "--no-banner" in cmd_used
    # binary name should appear
    assert any("gitleaks" in part for part in cmd_used)


def test_adapter_missing_scope_raises_invalid_input():
    adapter = GitleaksAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({})


def test_adapter_empty_scope_raises_invalid_input():
    adapter = GitleaksAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({"scope": ""})


def test_adapter_unsupported_mode_raises_invalid_input():
    adapter = GitleaksAdapter()
    with pytest.raises(InvalidInputError):
        adapter.run({"scope": "/tmp/repo", "mode": "gitlab"})


def test_adapter_default_mode_is_github():
    """No `mode` supplied should default to 'github' and not raise."""
    adapter = GitleaksAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher("[]")):
        findings = adapter.run({"scope": "/tmp/repo"})
    assert findings == []


# ---------------------------------------------------------------------------
# Tool function tests
# ---------------------------------------------------------------------------

def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_type=ScopeType.REPO, scope_value="github.com/acme/webapp")
    with patch("secagent.tools.scan_secret_leaks.GitleaksAdapter") as MockAdapter:
        mock_instance = MagicMock()
        # Build real Finding objects so .to_dict() works in the tool function.
        mock_instance.run.return_value = [
            Finding(
                id="fnd_aabbccdd",
                type=FindingType.SECRET_LEAK,
                severity=Severity.CRITICAL,
                target="github.com/acme/webapp",
                title="Secret leak: aws-access-key in config.py:10",
                evidence={"repo": "acme/webapp", "file": "config.py", "line": 10,
                          "rule_id": "aws-access-key", "secret_type": "AWS Access Key",
                          "redacted_secret": "AKIA****MPLE"},
                source_tool="gitleaks",
                raw={"rule_id": "aws-access-key", "redacted_secret": "AKIA****MPLE"},
            )
        ]
        MockAdapter.return_value = mock_instance

        result = scan_secret_leaks(
            gate=gate,
            params={"scope": "github.com/acme/webapp"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "scan_secret_leaks"
    assert result["summary"]["total"] == 1
    assert result["quota_used"] == 1
    assert result["summary"]["by_severity"]["critical"] == 1
    assert result["summary"]["by_type"]["secret_leak"] == 1
    assert result["engagement_id"].startswith("eng_")


def test_tool_rejects_unauthorized_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_type=ScopeType.REPO, scope_value="github.com/acme/webapp")
    with pytest.raises(NotAuthorizedError):
        scan_secret_leaks(
            gate=gate,
            params={"scope": "github.com/evil/repo"},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_missing_scope_raises_invalid_input(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_type=ScopeType.REPO, scope_value="github.com/acme/webapp")
    # The tool function validates scope presence before calling the gate, so
    # no authorization is consumed and no adapter runs.
    with pytest.raises(InvalidInputError):
        scan_secret_leaks(
            gate=gate,
            params={"mode": "github"},  # no scope key
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_redaction_propagates_to_output(tmp_db):
    """End-to-end: real adapter with mocked launch → tool output has no plaintext."""
    gate, token = setup_gate_and_token(tmp_db, scope_type=ScopeType.REPO, scope_value="github.com/acme/webapp")
    stdout = json.dumps(_canned_gitleaks_json())
    # Patch the Launcher the tool function constructs (imported into the tools
    # module), not the one in the adapter module.
    with patch("secagent.tools.scan_secret_leaks.Launcher") as MockLauncher:
        MockLauncher.return_value.run.return_value = _mock_launcher(stdout)
        result = scan_secret_leaks(
            gate=gate,
            params={"scope": "github.com/acme/webapp"},
            authz_token=token,
            caller_id="test_user",
        )

    serialized = json.dumps(result)
    for plain in _PLAINTEXTS:
        assert plain not in serialized, \
            f"plaintext leaked into tool output: {plain}"

    # Spot-check the redacted form is present.
    assert "AKIA****MPLE" in serialized
    # Findings array has the expected count.
    assert len(result["findings"]) == 2
    # Each finding's evidence has redacted_secret with ****.
    for f in result["findings"]:
        assert "****" in f["evidence"]["redacted_secret"]
        assert "Secret" not in f["raw"]
        assert "Match" not in f["raw"]


def test_tool_empty_result_still_commits(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_type=ScopeType.REPO, scope_value="github.com/acme/webapp")
    with patch("secagent.tools.scan_secret_leaks.GitleaksAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        MockAdapter.return_value = mock_instance

        result = scan_secret_leaks(
            gate=gate,
            params={"scope": "github.com/acme/webapp"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 0
    assert result["quota_used"] == 1


def test_tool_target_subpath_under_scope_is_authorized(tmp_db):
    """REPO scope check allows target == scope.value/<anything>."""
    gate, token = setup_gate_and_token(tmp_db, scope_type=ScopeType.REPO, scope_value="github.com/acme/webapp")
    with patch("secagent.tools.scan_secret_leaks.GitleaksAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        MockAdapter.return_value = mock_instance

        result = scan_secret_leaks(
            gate=gate,
            params={"scope": "github.com/acme/webapp/subdir"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 0
