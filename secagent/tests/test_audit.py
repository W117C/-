from __future__ import annotations

from secagent.core.audit import AuditLogger
from secagent.storage.sqlite_store import SQLiteStore


def test_audit_appends_a_row(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)
    logger.log(
        caller_id="user_1",
        authz_token="auth_xxx",
        tool="enumerate_subdomains",
        target="acme.com",
        scope_at_call="acme.com",
        outcome="executed",
        findings_count=12,
        quota_used=1,
        duration_ms=340,
    )
    rows = store._connect().execute("SELECT COUNT(*) FROM audit_log").fetchone()
    assert rows[0] == 1


def test_audit_hash_chain_links_rows(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)
    logger.log(caller_id="u", authz_token="t", tool="x", target="a", scope_at_call="a", outcome="executed", findings_count=0, quota_used=1, duration_ms=1)
    logger.log(caller_id="u", authz_token="t", tool="x", target="b", scope_at_call="a", outcome="not_authorized", findings_count=0, quota_used=0, duration_ms=1)

    import sqlite3
    conn = sqlite3.connect(tmp_db)
    r1, r2 = conn.execute("SELECT prev_hash, row_hash FROM audit_log ORDER BY id").fetchall()
    conn.close()
    # First row has no previous hash; second row references the first row's hash.
    assert r1[0] is None or r1[0] == ""
    assert r2[0] == r1[1]


def test_audit_hash_chain_detects_tamper(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)
    logger.log(caller_id="u", authz_token="t", tool="x", target="a", scope_at_call="a", outcome="executed", findings_count=0, quota_used=1, duration_ms=1)
    logger.log(caller_id="u", authz_token="t", tool="x", target="b", scope_at_call="a", outcome="executed", findings_count=0, quota_used=1, duration_ms=1)

    # Tamper: change the first row's target.
    import sqlite3
    conn = sqlite3.connect(tmp_db)
    conn.execute("UPDATE audit_log SET target='HACKED' WHERE id=1")
    conn.commit()
    conn.close()

    assert logger.verify_chain() is False


def test_audit_verify_chain_passes_when_intact(tmp_db: str):
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)
    logger.log(caller_id="u", authz_token="t", tool="x", target="a", scope_at_call="a", outcome="executed", findings_count=0, quota_used=1, duration_ms=1)
    assert logger.verify_chain() is True
