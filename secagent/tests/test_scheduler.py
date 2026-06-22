from __future__ import annotations

import datetime as dt
import json
from unittest.mock import patch

from secagent.config import Config
from secagent.core.scheduler import JobManager
from secagent.storage.sqlite_store import SQLiteStore


def test_poll_result_summarizes_done_findings(tmp_db):
    manager = JobManager(config=Config(db_path=tmp_db))
    store = SQLiteStore(tmp_db)
    store.bootstrap()

    findings = [
        {"id": "fnd_1", "type": "service", "severity": "info"},
        {"id": "fnd_2", "type": "service", "severity": "high"},
        {"id": "fnd_3", "type": "vulnerability", "severity": "high"},
    ]
    now = dt.datetime.now(dt.timezone.utc).isoformat()

    conn = store._connect()
    try:
        conn.execute(
            """INSERT INTO jobs
               (id, tool, params_json, authz_token, caller_id, status,
                findings_json, engagement_id, quota_used, created_at, finished_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "job_done",
                "probe_services",
                "{}",
                "auth_x",
                "tester",
                "done",
                json.dumps(findings),
                "eng_123",
                1,
                now,
                now,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    result = manager.poll_result("job_done")

    assert result["summary"] == {
        "total": 3,
        "by_severity": {"info": 1, "high": 2},
        "by_type": {"service": 2, "vulnerability": 1},
    }


def test_submit_scan_accepts_attack_surface_scan(tmp_db):
    manager = JobManager(config=Config(db_path=tmp_db))

    with patch("secagent.core.scheduler.threading.Thread") as MockThread:
        result = manager.submit_scan(
            tool="attack_surface_scan",
            params={"target_domain": "acme.com"},
            authz_token="auth_x",
            caller_id="tester",
        )

    assert result["status"] == "running"
    assert result["tool"] == "attack_surface_scan"
    MockThread.return_value.start.assert_called_once()
