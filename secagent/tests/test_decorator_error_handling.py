"""Tests for error-handling paths added to decorators.py and gate.py.

These cover the three critical issues from the code review:
1. decorators.py — gated_tool / standard_adapter_tool must catch exceptions
2. gate.py — commit_findings must wrap DB errors
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from secagent.core.decorators import gated_tool, standard_adapter_tool
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.gate import ComplianceGate


# ── Helpers ──────────────────────────────────────────────────────────────

def _mock_gate(raise_on_commit=False, raise_on_check=False):
    """Return a mock ComplianceGate with controlled failure points."""
    gate = MagicMock(spec=ComplianceGate)
    scope = MagicMock()
    scope.value = "example.com"
    gate.check.return_value = scope

    if raise_on_commit:
        def boom(*args, **kwargs):
            raise RuntimeError("simulated DB failure")
        gate.commit_findings.side_effect = boom
    else:
        gate.commit_findings.return_value = None

    gate.proxy_manager = MagicMock()
    gate.proxy_manager.is_enabled.return_value = False
    return gate


def _ok_finding(tool="test"):
    return Finding(
        id=f"{tool}-001",
        type=FindingType.EXPOSURE,
        severity=Severity.INFO,
        target="example.com",
        title=f"{tool} finding",
        evidence={"detail": "test"},
        confidence="validated",
        source_tool=tool,
    )


# ── gated_tool error paths ──────────────────────────────────────────────

class TestGatedToolErrorHandling:
    """Each phase of gated_tool must be wrapped in try/except."""

    def test_resolve_target_failure_propagates(self):
        """When _resolve_target raises InvalidInputError, it propagates (SecAgentError)."""
        from secagent.core.errors import InvalidInputError

        @gated_tool("test_tool", "nonexistent_field")
        def tool_fn(*, gate, params, authz_token, caller_id):
            return [_ok_finding()]

        with pytest.raises(InvalidInputError, match="nonexistent_field"):
            tool_fn(
                gate=_mock_gate(),
                params={"wrong_key": "value"},
                authz_token="tok",
                caller_id="u",
            )

    def test_gate_check_raises_returns_error_envelope(self):
        """When gate.check raises an unexpected non-SecAgentError, wrapper catches it."""
        @gated_tool("test_tool", "target")
        def tool_fn(*, gate, params, authz_token, caller_id):
            return [_ok_finding()]

        mock_gate = _mock_gate()
        mock_gate.check.side_effect = PermissionError("denied")

        result = tool_fn(
            gate=mock_gate,
            params={"target": "example.com"},
            authz_token="tok",
            caller_id="u",
        )
        assert result["error"]["code"] == "TOOL_FAILED"
        assert "denied" in result["error"]["message"]
        # gate.check was called and raised, so commit_findings was never reached
        mock_gate.commit_findings.assert_not_called()

    def test_tool_fn_raises_returns_error_envelope(self):
        """When the wrapped tool function crashes, wrapper catches it."""
        @gated_tool("test_tool", "target")
        def tool_fn(*, gate, params, authz_token, caller_id):
            raise ValueError("adapter crashed")

        mock_gate = _mock_gate()
        result = tool_fn(
            gate=mock_gate,
            params={"target": "example.com"},
            authz_token="tok",
            caller_id="u",
        )
        assert result["error"]["code"] == "TOOL_FAILED"
        assert "adapter crashed" in result["error"]["message"]

    def test_commit_findings_failure_still_returns_findings(self):
        """When commit_findings fails, findings are still returned to client."""
        @gated_tool("test_tool", "target")
        def tool_fn(*, gate, params, authz_token, caller_id):
            return [_ok_finding()]

        mock_gate = _mock_gate(raise_on_commit=True)
        result = tool_fn(
            gate=mock_gate,
            params={"target": "example.com"},
            authz_token="tok",
            caller_id="u",
        )
        # Should NOT have error — the wrapper catches commit failure
        assert "error" not in result or "commit" not in result.get("error", "").lower()
        assert len(result["findings"]) == 1
        assert result["findings"][0]["id"] == "test-001"
        assert result["findings"][0]["confidence"] == "validated"
        assert result["engagement_id"].startswith("eng_")

    def test_normal_flow_still_works(self):
        """Happy path: no exceptions, returns expected envelope."""
        @gated_tool("test_tool", "target")
        def tool_fn(*, gate, params, authz_token, caller_id):
            return [_ok_finding()]

        result = tool_fn(
            gate=_mock_gate(),
            params={"target": "example.com"},
            authz_token="tok",
            caller_id="u",
        )
        assert result["tool"] == "test_tool"
        assert result["engagement_id"].startswith("eng_")
        assert len(result["findings"]) == 1
        assert result["findings"][0]["confidence"] == "validated"


# ── standard_adapter_tool error paths ───────────────────────────────────

class TestStandardAdapterToolErrorHandling:
    """standard_adapter_tool must also handle errors gracefully."""

    def test_pre_flight_fn_raises(self):
        """When the mutation fn raises, wrapper catches it."""
        @standard_adapter_tool("test_tool", "target", MagicMock)
        def pre_fn(*, gate, params, authz_token, caller_id):
            raise RuntimeError("pre-flight mutation failed")

        result = pre_fn(
            gate=_mock_gate(),
            params={"target": "example.com"},
            authz_token="tok",
            caller_id="u",
        )
        assert result["error"]["code"] == "TOOL_FAILED"
        assert "mutation" in result["error"]["message"]

    def test_adapter_run_raises(self):
        """When adapter.run() raises, wrapper catches it."""
        mock_adapter_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.run.side_effect = OSError("disk full")
        mock_adapter_cls.return_value = mock_instance

        @standard_adapter_tool("test_tool", "target", mock_adapter_cls)
        def pre_fn(*, gate, params, authz_token, caller_id):
            pass  # no mutation

        result = pre_fn(
            gate=_mock_gate(),
            params={"target": "example.com"},
            authz_token="tok",
            caller_id="u",
        )
        assert result["error"]["code"] == "TOOL_FAILED"
        assert "disk full" in result["error"]["message"]


# ── gate.commit_findings error handling ────────────────────────────────

class TestCommitFindingsErrorHandling:
    """commit_findings must wrap DB errors and re-raise as RuntimeError."""

    def test_commit_wraps_db_error(self, tmp_db):
        """When SQLite transaction fails, RuntimeError is raised with message."""
        from secagent.core.authz import AuthorizationScope, ScopeType
        from secagent.core.registry import AuthorizationRegistry
        from secagent.storage.sqlite_store import SQLiteStore
        from secagent.core.gate import ComplianceGate

        store = SQLiteStore(tmp_db)
        store.bootstrap()
        reg = AuthorizationRegistry(store, default_quota=5)
        token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, "example.com"))
        reg.mark_verified(token, method="dns_txt")
        gate = ComplianceGate(store, reg.quota, default_quota=5)

        # Force the transaction to fail
        with patch.object(store, "transaction") as mock_txn:
            mock_txn.side_effect = Exception("simulated DB lock")
            with pytest.raises(RuntimeError, match="commit_findings failed"):
                gate.commit_findings(
                    token=token, count=1, quota_used=1,
                    caller_id="u", tool="test", target="example.com",
                )

    def test_commit_success_normal_path(self, tmp_db):
        """Normal commit_findings still works without exception."""
        from secagent.core.authz import AuthorizationScope, ScopeType
        from secagent.core.registry import AuthorizationRegistry
        from secagent.storage.sqlite_store import SQLiteStore
        from secagent.core.gate import ComplianceGate

        store = SQLiteStore(tmp_db)
        store.bootstrap()
        reg = AuthorizationRegistry(store, default_quota=5)
        token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, "example.com"))
        reg.mark_verified(token, method="dns_txt")
        gate = ComplianceGate(store, reg.quota, default_quota=5)

        gate.commit_findings(
            token=token, count=1, quota_used=1,
            caller_id="u", tool="test", target="example.com",
            findings=[{"id": "f1", "engagement_id": "eng_x", "type": "test"}],
        )
        # No exception means success
