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


def test_audit_does_not_store_plaintext_token(tmp_db: str):
    """Long-lived authz tokens must be fingerprinted, never stored plaintext,
    so the credential cannot be recovered from the audit table."""
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)
    secret_token = "auth_super_secret_long_lived_token_xyz"
    logger.log(
        caller_id="u", authz_token=secret_token, tool="x", target="a",
        scope_at_call="a", outcome="executed", findings_count=0, quota_used=1,
    )
    conn = store._connect()
    try:
        stored = conn.execute("SELECT authz_token FROM audit_log").fetchone()[0]
    finally:
        conn.close()
    # The plaintext must not be recoverable.
    assert secret_token not in stored
    # A non-empty fingerprint is stored instead (deterministic, 16 hex chars).
    assert len(stored) == 16
    assert all(c in "0123456789abcdef" for c in stored)


def test_audit_token_fingerprint_is_deterministic(tmp_db: str):
    """The same token always yields the same fingerprint, enabling correlation."""
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)
    logger.log(caller_id="u", authz_token="tok", tool="x", target="a",
               scope_at_call="a", outcome="executed", findings_count=0, quota_used=1)
    logger.log(caller_id="u", authz_token="tok", tool="x", target="b",
               scope_at_call="a", outcome="executed", findings_count=0, quota_used=1)
    conn = store._connect()
    try:
        fps = [r[0] for r in conn.execute("SELECT authz_token FROM audit_log").fetchall()]
    finally:
        conn.close()
    assert fps[0] == fps[1]
    assert len(fps[0]) == 16
