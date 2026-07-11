"""Continuous monitoring — scheduled re-scans with change detection (spec §M7).

This module provides the *scheduling* layer on top of the existing
``web_vuln_scan`` tool. A monitor task stores a target, an authorization
token, a re-scan interval, and the last-run timestamp. ``tick()`` finds
tasks whose interval has elapsed and re-runs the scan, then diffs the new
findings against the previous run to surface *new* vulnerabilities.

Design notes (KISS, no external deps):
  * Persistence is a single SQLite table in the main store.
  * ``tick()`` is a pure function over the store — it can be driven by a
    real cron job (``secagent monitor tick``) or by an in-process loop.
  * We reuse ``web_vuln_scan`` exactly as a client call would, so the
    compliance gate + authorization path is identical to manual scans.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from secagent.config import Config
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _fingerprint(f: dict[str, Any]) -> str:
    """Stable identity for a finding, used to detect NEW vs recurring."""
    return f"{f.get('type','')}|{f.get('target','')}|{f.get('title','')}"


class MonitorStore:
    """CRUD + tick for monitor tasks."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self._store = SQLiteStore(self.config.db_path)
        self._store.bootstrap()
        self._ensure_table()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _ensure_table(self) -> None:
        conn = self._store._connect()
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS monitor_tasks (
                    id              TEXT PRIMARY KEY,
                    name            TEXT UNIQUE NOT NULL,
                    target          TEXT NOT NULL,
                    token           TEXT NOT NULL,
                    interval_hours  INTEGER NOT NULL,
                    modules         TEXT NOT NULL DEFAULT '["sqli","xss","ssrf","lfi"]',
                    last_run_at     TEXT,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL
                )"""
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------
    def add_task(
        self,
        name: str,
        target: str,
        token: str,
        interval_hours: int,
        modules: list[str] | None = None,
        enabled: bool = True,
    ) -> str:
        task_id = f"mon_{uuid.uuid4().hex[:12]}"
        mods = modules or ["sqli", "xss", "ssrf", "lfi"]
        conn = self._store._connect()
        try:
            conn.execute(
                """INSERT INTO monitor_tasks
                   (id, name, target, token, interval_hours, modules, enabled, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    task_id, name, target, token, interval_hours,
                    _json_dumps(mods), 1 if enabled else 0, _now(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return task_id

    def list_tasks(self) -> list[dict[str, Any]]:
        conn = self._store._connect()
        try:
            rows = conn.execute(
                "SELECT id, name, target, interval_hours, modules, "
                "last_run_at, enabled FROM monitor_tasks ORDER BY name"
            ).fetchall()
        finally:
            conn.close()
        return [
            {
                "id": r[0], "name": r[1], "target": r[2],
                "interval_hours": r[3], "modules": _json_loads(r[4]),
                "last_run_at": r[5], "enabled": bool(r[6]),
            }
            for r in rows
        ]

    def get_task(self, name: str) -> dict[str, Any] | None:
        conn = self._store._connect()
        try:
            row = conn.execute(
                "SELECT id, name, target, token, interval_hours, modules, "
                "last_run_at, enabled FROM monitor_tasks WHERE name=?",
                (name,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return {
            "id": row[0], "name": row[1], "target": row[2], "token": row[3],
            "interval_hours": row[4], "modules": _json_loads(row[5]),
            "last_run_at": row[6], "enabled": bool(row[7]),
        }

    def set_last_run(self, name: str, ts: str) -> None:
        conn = self._store._connect()
        try:
            conn.execute(
                "UPDATE monitor_tasks SET last_run_at=? WHERE name=?",
                (ts, name),
            )
            conn.commit()
        finally:
            conn.close()

    def delete_task(self, name: str) -> bool:
        conn = self._store._connect()
        try:
            cur = conn.execute("DELETE FROM monitor_tasks WHERE name=?", (name,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Tick — find due tasks and re-scan
    # ------------------------------------------------------------------
    def tick(self, now: dt.datetime | None = None) -> list[dict[str, Any]]:
        """Run all enabled tasks whose interval has elapsed.

        Returns a list of run summaries, each containing the new findings
        detected since the previous run (per-target diff).
        """
        now = now or dt.datetime.now(dt.timezone.utc)
        due = self._due_tasks(now)
        summaries: list[dict[str, Any]] = []
        for task in due:
            # list_tasks() omits the token for safety; fetch the full record
            # (which includes the auth token) before running.
            full = self.get_task(task["name"])
            if full is None:
                continue
            summary = self._run_task(full, now)
            summaries.append(summary)
        return summaries

    def _due_tasks(self, now: dt.datetime) -> list[dict[str, Any]]:
        tasks = [t for t in self.list_tasks() if t["enabled"]]
        due = []
        for t in tasks:
            last = t["last_run_at"]
            if last is None:
                due.append(t)
                continue
            last_dt = dt.datetime.fromisoformat(last)
            if (now - last_dt).total_seconds() >= t["interval_hours"] * 3600:
                due.append(t)
        return due

    def _run_task(self, task: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
        """Execute one monitor task: re-scan + diff against prior findings."""
        from secagent.tools.web_vuln_scan import web_vuln_scan

        store = SQLiteStore(self.config.db_path)
        store.bootstrap()
        registry = AuthorizationRegistry(store, default_quota=self.config.default_quota_per_token)
        gate = ComplianceGate(store, registry.quota, default_quota=self.config.default_quota_per_token)

        prior = _fetch_target_findings(store, task["target"])

        result = web_vuln_scan(
            gate=gate,
            params={
                "target": task["target"],
                "modules": task["modules"],
            },
            authz_token=task["token"],
            caller_id=f"monitor:{task['name']}",
        )

        new_findings = result.get("findings", [])
        prior_fps = {_fingerprint(f) for f in prior}
        truly_new = [f for f in new_findings if _fingerprint(f) not in prior_fps]

        self.set_last_run(task["name"], now.isoformat())

        return {
            "task": task["name"],
            "target": task["target"],
            "total_findings": len(new_findings),
            "new_findings": len(truly_new),
            "new": truly_new,
            "status": "ok" if "error" not in result else "error",
            "error": result.get("error"),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _fetch_target_findings(store: SQLiteStore, target: str) -> list[dict[str, Any]]:
    """Fetch the most recent findings for a target (prior-run baseline)."""
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT id, tool, type, severity, target, title, created_at "
            "FROM findings WHERE target=? ORDER BY created_at DESC LIMIT 500",
            (target,),
        ).fetchall()
        return [
            {"id": r[0], "tool": r[1], "type": r[2], "severity": r[3],
             "target": r[4], "title": r[5], "created_at": r[6]}
            for r in rows
        ]
    finally:
        conn.close()


def _json_dumps(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False)


def _json_loads(s: str) -> list:
    import json
    return json.loads(s)
