"""Defense line 4 — append-only, tamper-evident audit log (spec §4.4).

Each row's row_hash = sha256(prev_hash || canonical_fields). Verifying the chain
recomputes hashes top-to-bottom; any in-place edit of an older row breaks it.

The authz token is stored as a truncated SHA-256 fingerprint (not plaintext) so
a long-lived credential cannot be recovered from the audit table, while still
allowing correlation between log rows and a token. The fingerprint participates
in the row hash just like the plaintext did before.
"""
from __future__ import annotations

import datetime as dt
import hashlib

from secagent.storage.sqlite_store import SQLiteStore


def _fingerprint(token: str | None) -> str:
    """One-way fingerprint of an authz token for storage in the audit log.

    We keep 16 hex chars (64 bits) of the SHA-256: enough to distinguish and
    correlate tokens, far too little to brute-force the original even for
    moderately short tokens.
    """
    if not token:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def _hash_row(prev_hash: str, fields: tuple) -> str:
    payload = prev_hash + "|" + "|".join(str(f) for f in fields)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, store: SQLiteStore):
        self.store = store

    def _write_row(
        self, conn, *, caller_id: str, token_fp: str, tool: str, target: str,
        scope_at_call: str | None, outcome: str, findings_count: int = 0,
        quota_used: int = 0, duration_ms: int | None = None,
    ) -> None:
        """Compute the prev-hash-linked row_hash and INSERT on the given conn.

        Shared by log() (own transaction) and log_in_tx() (caller's transaction).
        Reads the latest row_hash for chain linking — the caller is responsible
        for holding a write lock (BEGIN IMMEDIATE) so this read+insert is atomic.
        """
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        prev = conn.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = prev[0] if prev else ""
        body = (ts, caller_id, token_fp, tool, target, scope_at_call or "", outcome,
                findings_count, quota_used, duration_ms if duration_ms is not None else "")
        row_hash = _hash_row(prev_hash, body)
        conn.execute(
            """INSERT INTO audit_log
               (ts, caller_id, authz_token, tool, target, scope_at_call,
                outcome, findings_count, quota_used, duration_ms, prev_hash, row_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ts, caller_id, token_fp, tool, target, scope_at_call or "",
             outcome, findings_count, quota_used, duration_ms, prev_hash, row_hash),
        )

    def log_in_tx(
        self, conn, *, caller_id: str, authz_token: str | None, tool: str,
        target: str, scope_at_call: str | None, outcome: str,
        findings_count: int = 0, quota_used: int = 0,
        duration_ms: int | None = None,
    ) -> None:
        """Append an audit row on a caller-supplied (already locked) connection.

        For composing the audit write with other writes (e.g. quota decrement)
        into one atomic transaction via store.transaction(). The caller owns the
        BEGIN IMMEDIATE / COMMIT; this method only reads+inserts.
        """
        self._write_row(
            conn, caller_id=caller_id, token_fp=_fingerprint(authz_token),
            tool=tool, target=target, scope_at_call=scope_at_call, outcome=outcome,
            findings_count=findings_count, quota_used=quota_used, duration_ms=duration_ms,
        )

    def log(
        self,
        *,
        caller_id: str,
        authz_token: str | None,
        tool: str,
        target: str,
        scope_at_call: str | None,
        outcome: str,
        findings_count: int = 0,
        quota_used: int = 0,
        duration_ms: int | None = None,
    ) -> None:
        token_fp = _fingerprint(authz_token)
        conn = self.store._connect()
        try:
            # BEGIN IMMEDIATE acquires a write lock up front so the prev_hash
            # read and the INSERT happen atomically. Without it two concurrent
            # writers can both read the same prev_hash and each insert a row
            # referencing it, forking the chain.
            conn.execute("BEGIN IMMEDIATE")
            try:
                self._write_row(
                    conn, caller_id=caller_id, token_fp=token_fp, tool=tool, target=target,
                    scope_at_call=scope_at_call, outcome=outcome,
                    findings_count=findings_count, quota_used=quota_used,
                    duration_ms=duration_ms,
                )
                conn.execute("COMMIT")
            except Exception:
                # ROLLBACK may itself fail if the connection broke; never let
                # it mask the original error.
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        finally:
            conn.close()

    def verify_chain(self) -> bool:
        conn = self.store._connect()
        try:
            rows = conn.execute(
                "SELECT id, ts, caller_id, authz_token, tool, target, scope_at_call, outcome, findings_count, quota_used, duration_ms, prev_hash, row_hash FROM audit_log ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
        expected_prev = ""
        for r in rows:
            (_id, ts, caller_id, authz_token, tool, target, scope_at_call, outcome, findings_count, quota_used, duration_ms, prev_hash, row_hash) = r
            if prev_hash != expected_prev:
                return False
            # authz_token column already holds the fingerprint; reuse it.
            body = (ts, caller_id, authz_token, tool, target, scope_at_call, outcome, findings_count, quota_used, duration_ms if duration_ms is not None else "")
            if _hash_row(prev_hash, body) != row_hash:
                return False
            expected_prev = row_hash
        return True
