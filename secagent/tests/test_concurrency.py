"""Concurrency tests for the data layer (spec §4.4, §2.1).

WAL mode + busy_timeout + BEGIN IMMEDIATE transactions should keep the quota
counter correct and the audit hash chain unforked under contention. These use
threads (not processes) so all writers share one SQLite file; on macOS that
exercises the same locking paths the MCP server hits with multiple clients.
"""
from __future__ import annotations

import threading

from secagent.core.audit import AuditLogger
from secagent.core.quota import QuotaManager
from secagent.storage.sqlite_store import SQLiteStore


def test_concurrent_quota_decrements_are_lossless(tmp_db: str):
    """N threads each decrement once from a quota of N: final remaining 0, with
    no lost updates (which would leave remaining > 0)."""
    n = 20
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    qm = QuotaManager(store, default_total=n)
    token = "tok_concurrent"
    qm.ensure(token)
    assert qm.remaining(token) == n

    errors: list[Exception] = []

    def worker():
        try:
            qm.decrement(token, amount=1)
        except Exception as exc:  # noqa: BLE001 — surface any failure
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    # Every decrement landed; none was lost.
    assert qm.remaining(token) == 0


def test_concurrent_audit_writes_keep_chain_unforked(tmp_db: str):
    """N threads each append an audit row concurrently. The hash chain must
    stay linear (every row's prev_hash equals the previous row's row_hash) and
    verify_chain() must pass — the prev_hash read+insert must be atomic."""
    n = 20
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)

    errors: list[Exception] = []

    def worker(i: int):
        try:
            logger.log(
                caller_id=f"u{i}", authz_token=f"t{i}", tool="x",
                target=f"target{i}", scope_at_call="scope", outcome="executed",
                findings_count=i, quota_used=1,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    # All rows landed.
    conn = store._connect()
    try:
        count = int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
    finally:
        conn.close()
    assert count == n
    # Chain is intact (no fork, no tamper).
    assert logger.verify_chain() is True


def test_concurrent_chain_has_no_duplicate_prev_hash(tmp_db: str):
    """A direct structural check: no two rows may share the same prev_hash
    (the signature of a forked chain caused by a non-atomic read+insert)."""
    n = 15
    store = SQLiteStore(tmp_db)
    store.bootstrap()
    logger = AuditLogger(store)

    threads = [
        threading.Thread(
            target=logger.log,
            kwargs=dict(
                caller_id="u", authz_token="t", tool="x", target="a",
                scope_at_call="a", outcome="executed", findings_count=0, quota_used=1,
            ),
        )
        for _ in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    conn = store._connect()
    try:
        prev_hashes = [r[0] for r in conn.execute("SELECT prev_hash FROM audit_log").fetchall()]
    finally:
        conn.close()
    # The empty-string prev_hash (genesis row) may appear at most once; all
    # other prev_hashes must be unique.
    non_empty = [h for h in prev_hashes if h]
    assert len(non_empty) == len(set(non_empty)), "audit chain forked: duplicate prev_hash"
