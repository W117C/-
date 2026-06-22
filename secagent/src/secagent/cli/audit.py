"""`secagent audit verify` — audit log verification (defense line 4).

Verifies the hash-chain integrity of every audit log entry — that no row has
been tampered with and that the chain is linear (no forks).  The underlying
verify_chain() method recomputes the SHA-256 hash of each row using its
stored prev_hash and compares it to the stored row_hash.
"""
from __future__ import annotations

import click

from secagent.config import Config
from secagent.core.audit import AuditLogger
from secagent.storage.sqlite_store import SQLiteStore


def _audit_logger() -> AuditLogger:
    cfg = Config.load()
    store = SQLiteStore(cfg.db_path)
    store.bootstrap()
    return AuditLogger(store)


@click.group()
def audit() -> None:
    """Query and verify the audit log."""


@audit.command("verify")
def audit_verify():
    """Verify the hash-chain integrity of the audit log."""
    logger = _audit_logger()
    if logger.verify_chain():
        click.echo("audit log: integrity OK (hash chain verified)")
    else:
        click.echo("audit log: INTEGRITY FAILURE — chain broken or tampered with")
        raise click.ClickException("audit chain verification failed")
