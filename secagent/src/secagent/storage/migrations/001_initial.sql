-- SecAgent initial schema (M1).
-- authorizations: defense line 1 — registered authorization scopes + tokens
CREATE TABLE IF NOT EXISTS authorizations (
    token           TEXT PRIMARY KEY,
    scope_type      TEXT NOT NULL,            -- domain | ip | cidr | repo | email
    scope_value     TEXT NOT NULL,            -- e.g. "example.com"
    verified        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    note            TEXT
);

-- audit_log: defense line 4 — append-only, tamper-evident (prev_hash chain)
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    caller_id       TEXT,
    authz_token     TEXT,
    tool            TEXT,
    target          TEXT,
    scope_at_call   TEXT,
    outcome         TEXT NOT NULL,            -- executed | not_authorized | compliance_block | error
    findings_count  INTEGER NOT NULL DEFAULT 0,
    quota_used      INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER,
    prev_hash       TEXT,
    row_hash        TEXT NOT NULL
);

-- quota: per-token counter
CREATE TABLE IF NOT EXISTS quota (
    token           TEXT PRIMARY KEY,
    remaining       INTEGER NOT NULL,
    total           INTEGER NOT NULL,
    FOREIGN KEY (token) REFERENCES authorizations(token)
);

-- findings: discovered results (defense line 3 retention applies here later)
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    engagement_id   TEXT,
    tool            TEXT NOT NULL,
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    target          TEXT NOT NULL,
    title           TEXT,
    evidence_json   TEXT,
    source_tool     TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
