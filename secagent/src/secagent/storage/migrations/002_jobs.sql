-- 002_jobs.sql: async job queue for slow tools (probe_services, gather_osint, scan_vulnerabilities)
-- Jobs are created by submit_scan, polled by poll_result, and cleaned up by TTL later.
CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    tool            TEXT NOT NULL,             -- probe_services | gather_osint | scan_vulnerabilities
    params_json     TEXT NOT NULL,             -- JSON blob of the original params dict
    authz_token     TEXT NOT NULL,
    caller_id       TEXT DEFAULT 'unknown',
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | running | done | failed
    findings_json   TEXT,                      -- JSON array of findings (set on done)
    error_message   TEXT,                      -- set on failed
    output_buffer   TEXT,                      -- incremental stdout from subprocess
    engagement_id   TEXT,                      -- set on done
    quota_used      INTEGER DEFAULT 0,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
