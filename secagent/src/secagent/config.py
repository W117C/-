"""Config loading from YAML file + environment variable overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    db_path: str = "./data/secagent.db"
    default_quota_per_token: int = 100
    blocklist_path: str = "./data/blocklist.json"
    max_concurrent_per_target: int = 5
    nuclei_rate_limit: int = 150
    finding_ttl_days: int = 90
    binaries_dir: str = "./bin"
    extra: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        data: dict = {}
        if path and Path(path).exists():
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        db_path = os.environ.get("SECAGENT_DB_PATH", data.get("database", {}).get("path", "./data/secagent.db"))
        quota_block = data.get("quota", {})
        comp_block = data.get("compliance", {})
        ret_block = data.get("retention", {})
        tools_block = data.get("tools", {})

        return cls(
            db_path=db_path,
            default_quota_per_token=int(os.environ.get(
                "SECAGENT_DEFAULT_QUOTA", quota_block.get("default_per_token", 100))),
            blocklist_path=comp_block.get("blocklist_path", "./data/blocklist.json"),
            max_concurrent_per_target=comp_block.get("max_concurrent_per_target", 5),
            nuclei_rate_limit=comp_block.get("nuclei_rate_limit", 150),
            finding_ttl_days=ret_block.get("finding_ttl_days", 90),
            binaries_dir=tools_block.get("binaries_dir", "./bin"),
        )
