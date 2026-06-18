"""Integrated compliance gate — the single choke point every tool calls (spec §4).

Order of checks (fail fast):
  1. token known + verified
  2. target within scope        -> else NotAuthorizedError
  3. target not on blocklist    -> else ComplianceBlockError
  4. quota available            -> else RateLimitedError (checked at commit time)
All outcomes (pass or refuse) are written to the audit log.
"""
from __future__ import annotations

from secagent.core.audit import AuditLogger
from secagent.core.authz import AuthorizationScope, ScopeType, check_target_in_scope
from secagent.core.blocklist import Blocklist
from secagent.core.errors import ComplianceBlockError, NotAuthorizedError
from secagent.core.quota import QuotaManager
from secagent.storage.sqlite_store import SQLiteStore


class ComplianceGate:
    def __init__(self, store: SQLiteStore, quota: QuotaManager, default_quota: int, blocklist: Blocklist | None = None):
        self.store = store
        self.quota = quota
        self.default_quota = default_quota
        self.blocklist = blocklist or Blocklist()
        self.audit = AuditLogger(store)

    def check(self, *, token: str, tool: str, target: str, caller_id: str) -> AuthorizationScope:
        """Pre-flight: scope + blocklist + verification. Raises on refusal.
        Quota is decremented in commit_findings() after the tool actually runs,
        so a refused call does not consume quota. Returns the matched scope."""
        # token must exist and be verified
        conn = self.store._connect()
        try:
            row = conn.execute(
                "SELECT scope_type, scope_value, verified FROM authorizations WHERE token=?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or not row[2]:
            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                           scope_at_call=None, outcome="not_authorized", findings_count=0, quota_used=0)
            raise NotAuthorizedError(target=target, scope_domain=None)

        scope = AuthorizationScope(ScopeType(row[0]), row[1])

        # scope check
        if not check_target_in_scope(target, scope):
            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                           scope_at_call=scope.value, outcome="not_authorized", findings_count=0, quota_used=0)
            raise NotAuthorizedError(target=target, scope_domain=scope.value)

        # blocklist check (even in-scope targets can be refused). Only catch
        # ComplianceBlockError here — a broad `except Exception` would mask
        # unrelated bugs as a compliance block and re-raise the wrong cause.
        try:
            self.blocklist.check(target)
        except ComplianceBlockError:
            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                           scope_at_call=scope.value, outcome="compliance_block", findings_count=0, quota_used=0)
            raise

        return scope

    def commit_findings(self, *, token: str, count: int, quota_used: int, caller_id: str = "system",
                        tool: str = "", target: str = "", scope_value: str | None = None) -> None:
        """Post-run: decrement quota and log an executed outcome."""
        self.quota.decrement(token, amount=quota_used)
        self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                       scope_at_call=scope_value, outcome="executed", findings_count=count, quota_used=quota_used)

    def _conn_count_audit(self) -> int:
        conn = self.store._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
        finally:
            conn.close()
