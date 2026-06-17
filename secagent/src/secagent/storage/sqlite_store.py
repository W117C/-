"""SQLite storage with a simple migration runner (spec §5.3, §4.4).

M1 uses the stdlib sqlite3 module directly — no ORM. Migrations are numbered
SQL files applied in order; a `schema_meta` table records the current version.
"""
from __future__ import annotations

import sqlite3
from importlib import resources
from pathlib import Path


class SQLiteStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def bootstrap(self) -> None:
        """Create schema_meta if missing and apply any pending migrations."""
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER PRIMARY KEY)"
            )
            current = self.schema_version(conn=conn)
            migrations = self._available_migrations()
            for version, sql_text in sorted(migrations.items()):
                if version <= current:
                    continue
                conn.executescript(sql_text)
                conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (version,))
                conn.commit()
        finally:
            conn.close()

    def schema_version(self, conn: sqlite3.Connection | None = None) -> int:
        own = conn is None
        if own:
            conn = self._connect()
        try:
            row = conn.execute("SELECT MAX(version) FROM schema_meta").fetchone()
            return int(row[0]) if row and row[0] is not None else 0
        finally:
            if own:
                conn.close()

    def _available_migrations(self) -> dict[int, str]:
        migrations: dict[int, str] = {}
        mig_dir = resources.files("secagent.storage.migrations")
        for entry in mig_dir.iterdir():
            name = entry.name
            if name.endswith(".sql") and name[:3].isdigit():
                version = int(name[:3])
                migrations[version] = entry.read_text(encoding="utf-8")
        return migrations
