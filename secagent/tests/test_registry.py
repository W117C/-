from __future__ import annotations

import pytest

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore


def test_issue_token_creates_authorization_and_quota(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(
        scope=AuthorizationScope(ScopeType.DOMAIN, "acme.com"),
        note="customer onboarding",
    )
    assert token.startswith("auth_")
    record = reg.get(token)
    assert record is not None
    assert record.scope.type is ScopeType.DOMAIN
    assert record.verified is False


def test_verify_marks_record_verified(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, "acme.com"))
    reg.mark_verified(token, method="dns_txt")
    record = reg.get(token)
    assert record.verified is True


def test_list_returns_all_records(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, "acme.com"))
    reg.issue(scope=AuthorizationScope(ScopeType.IP, "203.0.113.10"))
    records = reg.list()
    assert len(records) == 2


def test_get_unknown_token_returns_none(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    assert reg.get("auth_doesnotexist") is None
