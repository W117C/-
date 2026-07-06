"""Config loading from YAML file + environment variable overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from secagent.core.proxy import ProxyConfig


@dataclass
class Config:
    db_path: str = "./data/secagent.db"
    default_quota_per_token: int = 100
    blocklist_path: str = "./data/blocklist.json"
    max_concurrent_per_target: int = 5
    nuclei_rate_limit: int = 150
    finding_ttl_days: int = 90
    binaries_dir: str = "./bin"
    wordlists_dir: str = "./wordlists"
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
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
        proxy_block = data.get("proxy", {})

        # Build ProxyConfig from yaml proxy block
        proxy_cfg = ProxyConfig(
            enabled=proxy_block.get("enabled", False),
            proxy_url=proxy_block.get("proxy_url", ""),
            pool=proxy_block.get("pool", []) if isinstance(proxy_block.get("pool"), list) else [],
            strategy=proxy_block.get("strategy", "round_robin"),
            health_check_interval=int(proxy_block.get("health_check_interval", 0)),
        )
        # Override with env var if set (simple setups)
        env_proxy = os.environ.get("ALL_PROXY") or os.environ.get("HTTP_PROXY") or ""
        if env_proxy and not proxy_cfg.enabled:
            proxy_cfg.enabled = True
            proxy_cfg.proxy_url = env_proxy

        return cls(
            db_path=db_path,
            default_quota_per_token=int(os.environ.get(
                "SECAGENT_DEFAULT_QUOTA", quota_block.get("default_per_token", 100))),
            blocklist_path=comp_block.get("blocklist_path", "./data/blocklist.json"),
            max_concurrent_per_target=comp_block.get("max_concurrent_per_target", 5),
            nuclei_rate_limit=comp_block.get("nuclei_rate_limit", 150),
            finding_ttl_days=ret_block.get("finding_ttl_days", 90),
            binaries_dir=os.environ.get(
                "SECAGENT_BINARIES_DIR", tools_block.get("binaries_dir", "./bin")),
            wordlists_dir=os.environ.get(
                "SECAGENT_WORDLISTS_DIR", tools_block.get("wordlists_dir", "./wordlists")),
            proxy=proxy_cfg,
            extra=data.get("extra", {}) or {},
        )
