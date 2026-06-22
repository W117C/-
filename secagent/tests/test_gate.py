from __future__ import annotations

import pytest

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.gate import ComplianceGate
from secagent.core.errors import NotAuthorizedError, ComplianceBlockError, RateLimitedError
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore


def _setup(tmp_db, scope_domain="acme.com"):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=5)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain))
    reg.mark_verified(token, method="dns_txt")
    return ComplianceGate(store, reg.quota, default_quota=5), token


def test_gate_passes_for_authorized_clean_target(tmp_db: str):
    gate, token = _setup(tmp_db)
    gate.check(token=token, tool="enumerate_subdomains", target="acme.com", caller_id="u")
    gate.commit_findings(token=token, count=3, quota_used=1)


def test_gate_rejects_target_out_of_scope(tmp_db: str):
    gate, token = _setup(tmp_db, scope_domain="acme.com")
    with pytest.raises(NotAuthorizedError):
        gate.check(token=token, tool="x", target="evil.com", caller_id="u")


def test_gate_rejects_blocked_target_even_if_in_scope(tmp_db: str):
    # authorize a .gov domain — it's "in scope" but blocklist refuses it
    gate, token = _setup(tmp_db, scope_domain="agency.gov")
    with pytest.raises(ComplianceBlockError):
        gate.check(token=token, tool="x", target="agency.gov", caller_id="u")


def test_gate_requires_verified_token(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=5)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, "acme.com"))  # NOT verified
    gate = ComplianceGate(store, reg.quota, default_quota=5)
    with pytest.raises(NotAuthorizedError):
        gate.check(token=token, tool="x", target="acme.com", caller_id="u")


def test_gate_logs_every_outcome(tmp_db: str):
    gate, token = _setup(tmp_db)
    gate.check(token=token, tool="x", target="acme.com", caller_id="u")
    gate.commit_findings(token=token, count=1, quota_used=1)
    # rejected attempt should also be logged
    with pytest.raises(NotAuthorizedError):
        gate.check(token=token, tool="x", target="evil.com", caller_id="u")
    count = gate._conn_count_audit()
    assert count >= 2


def test_gate_refuses_when_quota_exhausted(tmp_db: str):
    gate, token = _setup(tmp_db)
    # default quota is 5; spend it
    for _ in range(5):
        gate.check(token=token, tool="x", target="acme.com", caller_id="u")
        gate.commit_findings(token=token, count=0, quota_used=1)
    with pytest.raises(RateLimitedError):
        gate.check(token=token, tool="x", target="acme.com", caller_id="u")
        gate.commit_findings(token=token, count=0, quota_used=1)


def test_gate_quota_precheck_refuses_before_tool_runs(tmp_db: str):
    """With quota exhausted, check() must raise RateLimitedError itself —
    not wait until commit — so the tool never runs against the target."""
    gate, token = _setup(tmp_db)
    for _ in range(5):
        gate.check(token=token, tool="x", target="acme.com", caller_id="u")
        gate.commit_findings(token=token, count=0, quota_used=1)
    # check() itself must now raise, without needing commit_findings to run.
    with pytest.raises(RateLimitedError):
        gate.check(token=token, tool="x", target="acme.com", caller_id="u")


def test_commit_atomicity_rolls_back_quota_when_audit_fails(tmp_db: str, monkeypatch):
    """If the audit write fails after the quota decrement, the quota decrement
    must roll back — quota must NOT be consumed without an audit trail."""
    gate, token = _setup(tmp_db)
    remaining_before = gate.quota.remaining(token)

    # Force the audit row insert to fail inside the transaction.
    def boom(conn, **kwargs):
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr(gate.audit, "log_in_tx", boom)

    with pytest.raises(RuntimeError):
        gate.commit_findings(token=token, count=1, quota_used=1)

    # Transaction rolled back → quota unchanged, no audit row added.
    assert gate.quota.remaining(token) == remaining_before
    assert gate._conn_count_audit() == 0
