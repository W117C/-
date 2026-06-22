"""JobManager — async job queue for slow tools (spec §OPTIMIZATION P0).

Spawns a background thread for each job so the MCP handler can return
immediately. The thread runs the full tool function (adapter → subprocess →
findings), then persists the result to the `jobs` table.

Thread safety: each background thread opens its own SQLite connection
(required because sqlite3 connections are not thread-safe). WAL mode
+ busy_timeout prevent lock contention between the reader and writers.
"""
from __future__ import annotations

import datetime as dt
import json
import threading
import uuid
from collections import Counter
from typing import Any, Callable

from secagent.config import Config
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore

# ---------------------------------------------------------------------------
# Tool dispatch map — kept here so the scheduler does not import all tools
# eagerly. Each entry is (name, import_path, handler_function_name).
# ---------------------------------------------------------------------------
_TOOL_DISPATCH: dict[str, tuple[str, str]] = {
    "attack_surface_scan": ("secagent.tools.attack_surface_scan", "attack_surface_scan"),
    "probe_services": ("secagent.tools.probe_services", "probe_services"),
    "gather_osint": ("secagent.tools.gather_osint", "gather_osint"),
    "scan_vulnerabilities": ("secagent.tools.scan_vulnerabilities", "scan_vulnerabilities"),
    "scan_ports": ("secagent.tools.scan_ports", "scan_ports"),
    "discover_paths": ("secagent.tools.discover_paths", "discover_paths"),
    "passive_recon": ("secagent.tools.passive_recon", "passive_recon"),
}


def _import_tool_fn(name: str) -> Callable[..., dict[str, Any]]:
    """Lazy-import and return the tool function for *name*."""
    mod_name, fn_name = _TOOL_DISPATCH[name]
    import importlib
    mod = importlib.import_module(mod_name)
    return getattr(mod, fn_name)


class JobManager:
    """Manages async scan jobs. One instance per SecAgentServer."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self._store = SQLiteStore(self.config.db_path)
        self._store.bootstrap()
        self._registry: AuthorizationRegistry | None = None  # lazy init in thread

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit_scan(
        self,
        tool: str,
        params: dict[str, Any],
        authz_token: str,
        caller_id: str = "mcp-client",
    ) -> dict[str, Any]:
        """Submit a slow scan for async execution.

        Validates the tool name, creates a job record, spawns a background
        thread, and returns immediately with a job_id.

        Returns::
            {"job_id": "job_abc123", "status": "running", "tool": tool}
        """
        if tool not in _TOOL_DISPATCH:
            return {
                "error": {
                    "code": "INVALID_INPUT",
                    "message": (
                        f"Unknown tool '{tool}' for async execution. "
                        f"Supported: {sorted(_TOOL_DISPATCH.keys())}"
                    ),
                    "retryable": False,
                }
            }

        job_id = f"job_{uuid.uuid4().hex[:12]}"
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        # Persist job record before spawning (so poll_result can see it)
        conn = self._store._connect()
        try:
            conn.execute(
                """INSERT INTO jobs (id, tool, params_json, authz_token, caller_id,
                                     status, created_at)
                   VALUES (?, ?, ?, ?, ?, 'running', ?)""",
                (job_id, tool, json.dumps(params, ensure_ascii=False),
                 authz_token, caller_id, now),
            )
            conn.commit()
        finally:
            conn.close()

        # Spawn background execution
        thread = threading.Thread(
            target=self._run_job,
            args=(job_id, tool, params, authz_token, caller_id),
            daemon=True,
        )
        thread.start()

        return {"job_id": job_id, "status": "running", "tool": tool}

    def poll_result(self, job_id: str) -> dict[str, Any]:
        """Poll the current state of a job.

        Returns the job record with findings if complete, or just status if
        still running/pending.
        """
        conn = self._store._connect()
        try:
            row = conn.execute(
                """SELECT id, tool, status, findings_json, error_message,
                          engagement_id, quota_used, output_buffer,
                          created_at, started_at, finished_at
                   FROM jobs WHERE id=?""",
                (job_id,),
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return {
                "error": {
                    "code": "INVALID_INPUT",
                    "message": f"Unknown job_id '{job_id}'.",
                    "retryable": False,
                }
            }

        result: dict[str, Any] = {
            "job_id": row[0],
            "tool": row[1],
            "status": row[2],
        }

        if row[2] == "done":
            # Parse stored findings
            findings_json = row[3]
            if findings_json:
                result["findings"] = json.loads(findings_json)
                result["summary"] = _summary_from_findings(result["findings"])
            else:
                result["findings"] = []
                result["summary"] = _summary_from_findings([])
            result["engagement_id"] = row[5] or ""
            result["quota_used"] = row[6] or 0
        elif row[2] == "failed":
            result["error_message"] = row[4] or "unknown error"
        else:
            # running / pending — include partial output buffer
            result["output_buffer"] = row[7] or ""
            result["started_at"] = row[9] or ""
            if row[8]:
                result["created_at"] = row[8]

        return result

    def list_jobs(self, tool: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """List recent jobs, newest first."""
        conn = self._store._connect()
        try:
            if tool:
                rows = conn.execute(
                    "SELECT id, tool, status, created_at FROM jobs WHERE tool=? ORDER BY created_at DESC LIMIT ?",
                    (tool, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, tool, status, created_at FROM jobs ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        finally:
            conn.close()

        return [
            {"job_id": r[0], "tool": r[1], "status": r[2], "created_at": r[3]}
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_job(
        self,
        job_id: str,
        tool: str,
        params: dict[str, Any],
        authz_token: str,
        caller_id: str,
    ) -> None:
        """Execute the tool function in a background thread.

        Everything is self-contained: creates its own store + gate so we
        don't share SQLite connections across threads.
        """
        store = SQLiteStore(self.config.db_path)
        store.bootstrap()
        registry = AuthorizationRegistry(
            store, default_quota=self.config.default_quota_per_token,
        )
        gate = ComplianceGate(
            store,
            registry.quota,
            default_quota=self.config.default_quota_per_token,
        )

        now = dt.datetime.now(dt.timezone.utc).isoformat()

        # Mark started
        conn = store._connect()
        try:
            conn.execute(
                "UPDATE jobs SET started_at=? WHERE id=?",
                (now, job_id),
            )
            conn.commit()
        finally:
            conn.close()

        try:
            fn = _import_tool_fn(tool)
            result = fn(
                gate=gate,
                params=params,
                authz_token=authz_token,
                caller_id=caller_id,
            )

            # Findings are persisted inside the tool function via
            # gate.commit_findings(findings=...), so no need to insert them
            # here again. Just read the result for the job record.
            findings_list = result.get("findings", [])
            engagement_id = result.get("engagement_id", "")

            # Mark job done
            finish_ts = dt.datetime.now(dt.timezone.utc).isoformat()
            conn = store._connect()
            try:
                conn.execute(
                    """UPDATE jobs SET status='done', findings_json=?,
                                      engagement_id=?, quota_used=?, finished_at=?
                       WHERE id=?""",
                    (
                        json.dumps(findings_list, ensure_ascii=False),
                        engagement_id,
                        result.get("quota_used", 0),
                        finish_ts,
                        job_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        except Exception as exc:
            # Mark failed
            finish_ts = dt.datetime.now(dt.timezone.utc).isoformat()
            conn = store._connect()
            try:
                conn.execute(
                    """UPDATE jobs SET status='failed', error_message=?,
                                      finished_at=? WHERE id=?""",
                    (str(exc), finish_ts, job_id),
                )
                conn.commit()
            finally:
                conn.close()


def _summary_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.get("severity", "info") for f in findings)),
        "by_type": dict(Counter(f.get("type", "") for f in findings)),
    }
