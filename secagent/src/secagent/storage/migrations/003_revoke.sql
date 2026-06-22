-- 003_revoke.sql: token revocation support.
-- Adds a revoked flag to authorizations so tokens can be invalidated
-- without deleting the record.
ALTER TABLE authorizations ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
