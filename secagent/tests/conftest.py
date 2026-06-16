"""Shared pytest fixtures for SecAgent tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from secagent.config import Config


@pytest.fixture()
def tmp_db(tmp_path: Path) -> str:
    """Return a path to a temp SQLite DB file that does not yet exist."""
    return str(tmp_path / "test.db")


@pytest.fixture()
def cfg(tmp_db: str) -> Config:
    """Config pointing at a temp DB."""
    os.environ["SECAGENT_DB_PATH"] = tmp_db
    c = Config.load()
    del os.environ["SECAGENT_DB_PATH"]
    return c
