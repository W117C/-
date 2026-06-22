from __future__ import annotations

import sqlite3

from secagent.storage.sqlite_store import SQLiteStore


def test_store_bootstraps_schema(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    # tables exist
    conn = sqlite3.connect(tmp_db)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert {"authorizations", "audit_log", "quota", "findings"}.issubset(names)


def test_store_records_schema_version(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    assert store.schema_version() >= 1


def test_bootstrap_is_idempotent(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    store.bootstrap()  # second call must not error
    assert store.schema_version() >= 1
