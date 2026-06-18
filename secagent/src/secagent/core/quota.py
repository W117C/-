"""Quota decrement (spec §2.1, M1: naive per-token counter).

M1 keeps quota simple: a counter per token, atomically checked-and-decremented
inside a transaction. Billing tiers arrive in a later milestone.
"""
from __future__ import annotations

import sqlite3

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

    def ensure_in_tx(self, conn: sqlite3.Connection, token: str) -> None:
        """Like ensure() but on a caller-supplied (already-open) connection."""
        row = conn.execute("SELECT 1 FROM quota WHERE token=?", (token,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO quota(token, remaining, total) VALUES (?,?,?)",
                (token, self.default_total, self.default_total),
            )

    def decrement_in_tx(self, conn: sqlite3.Connection, token: str, amount: int = 1) -> None:
        """Decrement on a caller-supplied connection (no own BEGIN/COMMIT).

        For composing quota + other writes (e.g. audit) into one atomic
        transaction via store.transaction(). Raises RateLimitedError if the
        token has insufficient quota.
        """
        self.ensure_in_tx(conn, token)
        row = conn.execute("SELECT remaining FROM quota WHERE token=?", (token,)).fetchone()
        current = int(row[0]) if row else 0
        if current < amount:
            raise RateLimitedError(f"quota exhausted for token {token} (need {amount}, have {current})")
        conn.execute("UPDATE quota SET remaining = remaining - ? WHERE token=?", (amount, token))

    def decrement(self, token: str, amount: int = 1) -> None:
        """Atomically decrement; raise RateLimitedError if insufficient."""
        self.ensure(token)
        conn = self.store._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT remaining FROM quota WHERE token=?", (token,)).fetchone()
                current = int(row[0]) if row else 0
                if current < amount:
                    raise RateLimitedError(f"quota exhausted for token {token} (need {amount}, have {current})")
                conn.execute("UPDATE quota SET remaining = remaining - ? WHERE token=?", (amount, token))
                conn.execute("COMMIT")
            except Exception:
                # ROLLBACK may itself fail if the connection broke mid-statement;
                # never let it mask the original error.
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise
        finally:
            conn.close()
