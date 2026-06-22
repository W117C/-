"""Shared test helpers for SecAgent tests."""
from __future__ import annotations

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore


def setup_gate_and_token(
    tmp_db: str,
    scope_type: ScopeType = ScopeType.DOMAIN,
    scope_value: str = "acme.com",
) -> tuple[ComplianceGate, str]:
    """Bootstrap a ComplianceGate + verified auth token for the given scope.

    Returns (gate, token) tuple.
    """
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(scope_type, scope_value))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=100)
    return gate, token
