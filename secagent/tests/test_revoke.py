"""Tests for token revocation (003_revoke.sql + registry.revoke + gate check)."""
from __future__ import annotations

import pytest

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.errors import NotAuthorizedError
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore


def _setup(tmp_db: str) -> tuple[ComplianceGate, AuthorizationRegistry, str]:
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, "example.com"))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=100)
    return gate, reg, token


def test_revoke_prevents_check(tmp_db):
    """A revoked token should raise NotAuthorizedError on gate.check()."""
    gate, reg, token = _setup(tmp_db)

    # Before revoke — should pass
    scope = gate.check(token=token, tool="test", target="example.com", caller_id="test")
    assert scope is not None

    # Revoke
    reg.revoke(token)

    # After revoke — should raise
    with pytest.raises(NotAuthorizedError):
        gate.check(token=token, tool="test", target="example.com", caller_id="test")


def test_revoke_record_reflects_revoked(tmp_db):
    """The AuthorizationRecord returned by get() should show revoked=True."""
    _, reg, token = _setup(tmp_db)

    record = reg.get(token)
    assert record.revoked is False

    reg.revoke(token)
    record = reg.get(token)
    assert record.revoked is True


def test_revoke_list_shows_revoked(tmp_db):
    """The list() output should include the revoked flag."""
    _, reg, token = _setup(tmp_db)

    reg.revoke(token)
    records = reg.list()
    matching = [r for r in records if r.token == token]
    assert len(matching) == 1
    assert matching[0].revoked is True


def test_revoke_nonexistent_token_succeeds(tmp_db):
    """Revoking a token that doesn't exist should not raise (idempotent UPDATE)."""
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    # Should not raise
    reg.revoke("nonexistent_token")


def test_revoked_token_still_in_list(tmp_db):
    """A revoked token should still appear in list() — not deleted."""
    _, reg, token = _setup(tmp_db)
    reg.revoke(token)
    assert reg.get(token) is not None


def test_revoke_is_idempotent(tmp_db):
    """Calling revoke() twice should not raise."""
    _, reg, token = _setup(tmp_db)
    reg.revoke(token)
    reg.revoke(token)  # second call should be a no-op
    record = reg.get(token)
    assert record.revoked is True
