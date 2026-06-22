"""Authorization registry — token issuance + records (spec §4.1).

Ownership verification (DNS TXT / file / cert) is orchestrated by the CLI in
Task 10. The registry just stores scope + verified flag + token. Real network
probing of DNS/HTTP is intentionally out of M1's unit-testable core; the CLI
performs it and calls mark_verified() on success.
"""
from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.quota import QuotaManager
from secagent.storage.sqlite_store import SQLiteStore


@dataclass
class AuthorizationRecord:
    token: str
    scope: AuthorizationScope
    verified: bool
    revoked: bool
    created_at: str
    note: str | None


def _row_to_record(row) -> AuthorizationRecord:
    token, scope_type, scope_value, verified, created_at, note = row[:6]
    revoked = bool(row[6]) if len(row) > 6 else False
    return AuthorizationRecord(
        token=token,
        scope=AuthorizationScope(ScopeType(scope_type), scope_value),
        verified=bool(verified),
        revoked=revoked,
        created_at=created_at,
        note=note,
    )


class AuthorizationRegistry:
    def __init__(self, store: SQLiteStore, default_quota: int):
        self.store = store
        self.quota = QuotaManager(store, default_total=default_quota)

    def issue(self, scope: AuthorizationScope, note: str | None = None) -> str:
        token = "auth_" + secrets.token_urlsafe(16)
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        conn = self.store._connect()
        try:
            conn.execute(
                "INSERT INTO authorizations(token, scope_type, scope_value, verified, created_at, note) VALUES (?,?,?,?,?,?)",
                (token, scope.type.value, scope.value, 0, ts, note),
            )
            conn.commit()
        finally:
            conn.close()
        self.quota.ensure(token)
        return token

    def revoke(self, token: str) -> None:
        """Revoke an authorization token, preventing future use."""
        conn = self.store._connect()
        try:
            conn.execute("UPDATE authorizations SET revoked=1 WHERE token=?", (token,))
            conn.commit()
        finally:
            conn.close()

    def mark_verified(self, token: str, method: str) -> None:
        conn = self.store._connect()
        try:
            conn.execute("UPDATE authorizations SET verified=1 WHERE token=?", (token,))
            conn.commit()
        finally:
            conn.close()

    def get(self, token: str) -> AuthorizationRecord | None:
        conn = self.store._connect()
        try:
            row = conn.execute(
                "SELECT token, scope_type, scope_value, verified, created_at, note, revoked FROM authorizations WHERE token=?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        return _row_to_record(row) if row is not None else None

    def list(self) -> list[AuthorizationRecord]:
        conn = self.store._connect()
        try:
            rows = conn.execute(
                "SELECT token, scope_type, scope_value, verified, created_at, note, revoked FROM authorizations ORDER BY created_at"
            ).fetchall()
        finally:
            conn.close()
        return [_row_to_record(r) for r in rows]
