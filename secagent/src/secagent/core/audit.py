"""Defense line 4 — append-only, tamper-evident audit log (spec §4.4).

Each row's row_hash = sha256(prev_hash || canonical_fields). Verifying the chain
recomputes hashes top-to-bottom; any in-place edit of an older row breaks it.
"""
from __future__ import annotations

import datetime as dt
import hashlib

from secagent.storage.sqlite_store import SQLiteStore


def _hash_row(prev_hash: str, fields: tuple) -> str:
    payload = prev_hash + "|" + "|".join(str(f) for f in fields)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, store: SQLiteStore):
        self.store = store

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
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        conn = self.store._connect()
        try:
            prev = conn.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = prev[0] if prev else ""
            body = (ts, caller_id, authz_token or "", tool, target, scope_at_call or "", outcome, findings_count, quota_used, duration_ms if duration_ms is not None else "")
            row_hash = _hash_row(prev_hash, body)
            conn.execute(
                """INSERT INTO audit_log
                   (ts, caller_id, authz_token, tool, target, scope_at_call,
                    outcome, findings_count, quota_used, duration_ms, prev_hash, row_hash)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, caller_id, authz_token, tool, target, scope_at_call or "",
                 outcome, findings_count, quota_used, duration_ms, prev_hash, row_hash),
            )
            conn.commit()
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
            body = (ts, caller_id, authz_token, tool, target, scope_at_call, outcome, findings_count, quota_used, duration_ms if duration_ms is not None else "")
            if _hash_row(prev_hash, body) != row_hash:
                return False
            expected_prev = row_hash
        return True
