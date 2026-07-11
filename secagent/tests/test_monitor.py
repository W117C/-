"""Tests for core/monitor.py — scheduled re-scan + change detection (spec §M7)."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

# Allow importing scripts/ helpers and the package when run standalone.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_ROOT / "scripts"))

from helper import setup_gate_and_token  # noqa: E402

from secagent.core.monitor import MonitorStore, _fingerprint  # noqa: E402


def _make_task(db_path, name="t1", target="http://acme.com", interval=24):
    """Create a fresh store + a task bound to a real issued token."""
    gate, token = setup_gate_and_token(db_path, scope_value="acme.com")
    store = MonitorStore.__new__(MonitorStore)
    # Bypass __init__ bootstrap on the shared db so the task token is valid.
    from secagent.config import Config
    from secagent.storage.sqlite_store import SQLiteStore
    store.config = Config(db_path=db_path)
    store._store = SQLiteStore(db_path)
    store._store.bootstrap()
    store._ensure_table()
    store.add_task(name=name, target=target, token=token, interval_hours=interval)
    return store, token


def test_add_and_list(tmp_path):
    db = str(tmp_path / "m.db")
    store, tok = _make_task(db)
    tasks = store.list_tasks()
    assert len(tasks) == 1
    assert tasks[0]["name"] == "t1"
    assert tasks[0]["interval_hours"] == 24
    assert tasks[0]["enabled"] is True


def test_get_and_delete(tmp_path):
    db = str(tmp_path / "m.db")
    store, tok = _make_task(db)
    assert store.get_task("t1")["target"] == "http://acme.com"
    assert store.delete_task("t1") is True
    assert store.get_task("t1") is None


def test_due_logic_first_run(tmp_path):
    db = str(tmp_path / "m.db")
    store, tok = _make_task(db)
    # Never run -> due immediately.
    due = store._due_tasks(dt.datetime.now(dt.timezone.utc))
    assert any(t["name"] == "t1" for t in due)


def test_due_logic_respects_interval(tmp_path):
    db = str(tmp_path / "m.db")
    store, tok = _make_task(db, interval=24)
    now = dt.datetime.now(dt.timezone.utc)
    # Mark last run as 1h ago -> not due yet.
    store.set_last_run("t1", (now - dt.timedelta(hours=1)).isoformat())
    assert not store._due_tasks(now)
    # Mark last run as 25h ago -> due.
    store.set_last_run("t1", (now - dt.timedelta(hours=25)).isoformat())
    assert any(t["name"] == "t1" for t in store._due_tasks(now))


def test_fingerprint_stable():
    a = {"type": "vulnerability", "target": "http://x", "title": "SQLi"}
    b = {"type": "vulnerability", "target": "http://x", "title": "SQLi"}
    c = {"type": "vulnerability", "target": "http://x", "title": "XSS"}
    assert _fingerprint(a) == _fingerprint(b)
    assert _fingerprint(a) != _fingerprint(c)


def test_tick_detects_new_findings(tmp_path):
    """A re-scan that returns a finding not present in the prior baseline
    must be reported as NEW in the tick summary."""
    db = str(tmp_path / "m.db")
    store, tok = _make_task(db)

    fake_finding = {
        "id": "fnd_new1", "type": "vulnerability", "severity": "high",
        "target": "http://acme.com", "title": "SQL Injection (MySQL) via 'id'",
        "evidence": {"parameter": "id"},
    }
    # Prior baseline is empty -> any returned finding is NEW.
    with patch("secagent.tools.web_vuln_scan.web_vuln_scan",
               return_value={"findings": [fake_finding], "engagement_id": "e1",
                             "quota_used": 1, "summary": {"total": 1}}):
        summaries = store.tick()
    assert len(summaries) == 1
    assert summaries[0]["new_findings"] == 1
    assert summaries[0]["new"][0]["title"].startswith("SQL Injection")


def test_tick_skips_when_not_due(tmp_path):
    db = str(tmp_path / "m.db")
    store, tok = _make_task(db, interval=24)
    now = dt.datetime.now(dt.timezone.utc)
    store.set_last_run("t1", (now - dt.timedelta(hours=1)).isoformat())
    summaries = store.tick(now)
    assert summaries == []  # not due -> nothing runs
