"""Quota decrement (spec §2.1, M1: naive per-token counter).

M1 keeps quota simple: a counter per token, atomically checked-and-decremented
inside a transaction. Billing tiers arrive in a later milestone.
"""
from __future__ import annotations

from secagent.core.errors import RateLimitedError
from secagent.storage.sqlite_store import SQLiteStore


class QuotaManager:
    def __init__(self, store: SQLiteStore, default_total: int):
        self.store = store
        self.default_total = default_total

    def ensure(self, token: str) -> None:
        """Create a quota row for the token if it doesn't exist."""
        conn = self.store._connect()
        try:
            row = conn.execute("SELECT 1 FROM quota WHERE token=?", (token,)).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO quota(token, remaining, total) VALUES (?,?,?)",
                    (token, self.default_total, self.default_total),
                )
                conn.commit()
        finally:
            conn.close()

    def remaining(self, token: str) -> int:
        self.ensure(token)
        conn = self.store._connect()
        try:
            row = conn.execute("SELECT remaining FROM quota WHERE token=?", (token,)).fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    def decrement(self, token: str, amount: int = 1) -> None:
        """Atomically decrement; raise RateLimitedError if insufficient."""
        self.ensure(token)
        conn = self.store._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT remaining FROM quota WHERE token=?", (token,)).fetchone()
            current = int(row[0]) if row else 0
            if current < amount:
                conn.execute("ROLLBACK")
                raise RateLimitedError(f"quota exhausted for token {token} (need {amount}, have {current})")
            conn.execute("UPDATE quota SET remaining = remaining - ? WHERE token=?", (amount, token))
            conn.commit()
        except RateLimitedError:
            raise
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
