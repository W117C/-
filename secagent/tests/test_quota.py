from __future__ import annotations

import pytest

from secagent.core.quota import QuotaManager
from secagent.core.errors import RateLimitedError
from secagent.storage.sqlite_store import SQLiteStore


def test_quota_initialized_for_token(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    qm = QuotaManager(store, default_total=100)
    qm.ensure("auth_xxx")
    assert qm.remaining("auth_xxx") == 100


def test_decrement_reduces_remaining(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    qm = QuotaManager(store, default_total=100)
    qm.decrement("auth_xxx", amount=3)
    assert qm.remaining("auth_xxx") == 97


def test_decrement_raises_when_exhausted(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    qm = QuotaManager(store, default_total=2)
    qm.decrement("auth_xxx", amount=2)
    with pytest.raises(RateLimitedError):
        qm.decrement("auth_xxx", amount=1)


def test_decrement_is_atomic_and_checks_first(tmp_db: str):
    store = SQLiteStore(tmp_db); store.bootstrap()
    qm = QuotaManager(store, default_total=1)
    # spend the last unit, then a second decrement must fail without going negative
    qm.decrement("auth_xxx", amount=1)
    with pytest.raises(RateLimitedError):
        qm.decrement("auth_xxx", amount=1)
    assert qm.remaining("auth_xxx") >= 0
