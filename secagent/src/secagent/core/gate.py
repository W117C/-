"""Integrated compliance gate — the single choke point every tool calls (spec §4).

Order of checks (fail fast):
  1. token known + verified
  2. target within scope        -> else NotAuthorizedError
  3. target not on blocklist    -> else ComplianceBlockError
  4. resolved IPs not blocked   -> else ComplianceBlockError (DNS-based defense)
  5. quota available            -> else RateLimitedError (checked at commit time)
All outcomes (pass or refuse) are written to the audit log.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading

from secagent.core.audit import AuditLogger
from secagent.core.authz import AuthorizationScope, ScopeType, check_target_in_scope
from secagent.core.blocklist import Blocklist
from secagent.core.errors import ComplianceBlockError, NotAuthorizedError
from secagent.core.proxy import ProxyManager
from secagent.core.quota import QuotaManager
from secagent.storage.sqlite_store import SQLiteStore

log = logging.getLogger(__name__)
def _resolve_with_timeout(target: str, timeout: float = 5.0,
                         proxy_manager = None) -> list:
    """Resolve hostname to addresses with a thread-based timeout.

    When a SOCKS5 proxy is active, uses PySocks so the DNS query is
    sent through the proxy (remote-DNS mode), preventing local DNS
    leakage of the target hostname.
    """
    result: list = []
    exception: BaseException | None = None

    def _resolve() -> None:
        nonlocal result, exception
        try:
            if (proxy_manager is not None and proxy_manager.is_enabled()
                    and proxy_manager._is_socks5(proxy_manager.get_proxy())):
                # SOCKS5 with remote DNS: resolve through the proxy
                with proxy_manager.socks_context():
                    result.extend(socket.getaddrinfo(target, None))
            else:
                result.extend(socket.getaddrinfo(target, None))
        except BaseException as exc:
            exception = exc

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise socket.gaierror(f"DNS resolution timed out after {timeout}s")
    if exception:
        raise exception  # type: ignore[misc]
    return result


class ComplianceGate:
    def __init__(self, store: SQLiteStore, quota: QuotaManager, default_quota: int,
                 blocklist: Blocklist | None = None,
                 proxy_manager: ProxyManager | None = None):
        self.store = store
        self.quota = quota
        self.default_quota = default_quota
        self.blocklist = blocklist or Blocklist()
        self.audit = AuditLogger(store)
        self.proxy_manager = proxy_manager or ProxyManager.from_env()

    def check(self, *, token: str, tool: str, target: str, caller_id: str) -> AuthorizationScope:
        """Pre-flight: scope + blocklist + verification. Raises on refusal.
        Quota is decremented in commit_findings() after the tool actually runs,
        so a refused call does not consume quota. Returns the matched scope."""
        # token must exist and be verified
        conn = self.store._connect()
        try:
            row = conn.execute(
                "SELECT scope_type, scope_value, verified, revoked FROM authorizations WHERE token=?",
                (token,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or not row[2]:
            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                           scope_at_call=None, outcome="not_authorized", findings_count=0, quota_used=0)
            raise NotAuthorizedError(target=target, scope_domain=None)

        # token must not be revoked
        if row[3]:  # revoked column
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
        # ComplianceBlockError — a broad `except Exception` would mask
        # unrelated bugs as a compliance block and re-raise the wrong cause.
        try:
            self.blocklist.check(target)
        except ComplianceBlockError:
            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                           scope_at_call=scope.value, outcome="compliance_block", findings_count=0, quota_used=0)
            raise

        # DNS-based defense: resolve hostname and check each resolved IP
        # against the blocklist. This catches hostnames that resolve to
        # private/restricted IPs (e.g. internal.corp.example.com -> 10.x.x.x).
        # Skip DNS resolution for targets that are already IP addresses —
        # the blocklist directly checks IP ranges later and the DNS call
        # would be redundant.
        if scope.type in (ScopeType.DOMAIN, ScopeType.IP, ScopeType.CIDR):
            try:
                ipaddress.ip_address(target)
                is_ip = True
            except ValueError:
                is_ip = False

            if not is_ip:
                try:
                    addrinfo = _resolve_with_timeout(target, timeout=5.0,
                                                     proxy_manager=self.proxy_manager)
                    for family, _, _, _, sockaddr in addrinfo:
                        ip = sockaddr[0]
                        blocked, reason = self.blocklist.is_blocked(ip)
                        if blocked:
                            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool,
                                           target=target, scope_at_call=scope.value,
                                           outcome="compliance_block", findings_count=0, quota_used=0)
                            raise ComplianceBlockError(
                                target=ip,
                                reason=reason or f"resolved IP {ip} blocked",
                            )
                except socket.gaierror:
                    log.warning("DNS resolution failed for %s — skipping IP blocklist check", target)

        # quota precheck: refuse BEFORE running the tool rather than after, so
        # an exhausted quota does not waste target resources and wall-clock.
        # The authoritative decrement still happens in commit_findings(); this
        # is a best-effort guard against the common race.
        if self.quota.remaining(token) <= 0:
            self.audit.log(caller_id=caller_id, authz_token=token, tool=tool, target=target,
                           scope_at_call=scope.value, outcome="rate_limited", findings_count=0, quota_used=0)
            from secagent.core.errors import RateLimitedError
            raise RateLimitedError("quota exhausted")

        return scope

    def commit_findings(self, *, token: str, count: int, quota_used: int,
                        caller_id: str = "system", tool: str = "", target: str = "",
                        scope_value: str | None = None,
                        findings: list[dict] | None = None) -> None:
        """Post-run: decrement quota, persist findings, and log audit, atomically.

        All three operations (quota decrement → findings INSERT → audit INSERT)
        run inside a single BEGIN IMMEDIATE transaction.  If any fails, the
        entire group rolls back — never quota consumed without audit trail.

        *findings* is an optional list of Finding dicts. When provided, each
        finding is written to the ``findings`` table (defense line 3).

        **Error handling**: If the transaction fails (DB locked, disk full,
        constraint violation), the exception is caught, logged, and re-raised
        as a ``RuntimeError`` with a clear message. The caller (decorator)
        catches this and still returns findings to the client.
        """
        import datetime as dt
        import json

        try:
            with self.store.transaction() as conn:
                self.quota.decrement_in_tx(conn, token, amount=quota_used)

                # Persist findings to the existing findings table
                if findings:
                    now = dt.datetime.now(dt.timezone.utc).isoformat()
                    for f in findings:
                        conn.execute(
                            """INSERT OR IGNORE INTO findings
                               (id, engagement_id, tool, type, severity, target,
                                title, evidence_json, source_tool, created_at)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                f.get("id", ""),
                                f.get("engagement_id", ""),
                                tool,
                                f.get("type", ""),
                                f.get("severity", "info"),
                                f.get("target", ""),
                                f.get("title", ""),
                                json.dumps(f.get("evidence", {}), ensure_ascii=False),
                                f.get("source_tool", tool),
                                now,
                            ),
                        )

                self.audit.log_in_tx(
                    conn, caller_id=caller_id, authz_token=token, tool=tool, target=target,
                    scope_at_call=scope_value, outcome="executed", findings_count=count,
                    quota_used=quota_used,
                )
        except Exception as e:
            log.error("commit_findings[token=%s tool=%s] transaction failed: %s", token, tool, e)
            raise RuntimeError(f"commit_findings failed: {e}") from e

    def _conn_count_audit(self) -> int:
        conn = self.store._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])
        finally:
            conn.close()
