"""Tests for secagent.config.Config loading: defaults, YAML, env overrides, proxy."""

from __future__ import annotations

import os
import textwrap

import pytest

from secagent.config import Config
from secagent.core.proxy import ProxyConfig


# ─── helpers ────────────────────────────────────────────────

def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(p)


# Env vars that Config.load reads — clean before/after each test
_ENV_KEYS = [
    "SECAGENT_DB_PATH",
    "SECAGENT_DEFAULT_QUOTA",
    "SECAGENT_BINARIES_DIR",
    "SECAGENT_WORDLISTS_DIR",
    "ALL_PROXY",
    "HTTP_PROXY",
]


@pytest.fixture(autouse=True)
def _clean_env():
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


# ─── defaults ────────────────────────────────────────────────

class TestDefaults:
    def test_no_path_no_env_uses_defaults(self):
        c = Config.load(None)
        assert c.db_path == "./data/secagent.db"
        assert c.default_quota_per_token == 100
        assert c.blocklist_path == "./data/blocklist.json"
        assert c.max_concurrent_per_target == 5
        assert c.nuclei_rate_limit == 150
        assert c.finding_ttl_days == 90
        assert c.binaries_dir == "./bin"
        assert c.wordlists_dir == "./wordlists"
        assert c.extra == {}
        assert isinstance(c.proxy, ProxyConfig)
        assert c.proxy.enabled is False

    def test_nonexistent_path_falls_back_to_defaults(self, tmp_path):
        c = Config.load(str(tmp_path / "nonexistent.yaml"))
        assert c.db_path == "./data/secagent.db"
        assert c.default_quota_per_token == 100


# ─── YAML loading ─────────────────────────────────────────────

class TestYamlLoad:
    def test_full_yaml_overrides_all_fields(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            database:
              path: /custom/db.sqlite
            quota:
              default_per_token: 500
            compliance:
              blocklist_path: /custom/blocklist.json
              max_concurrent_per_target: 10
              nuclei_rate_limit: 50
            retention:
              finding_ttl_days: 365
            tools:
              binaries_dir: /opt/tools
              wordlists_dir: /opt/wordlists
            extra:
              custom_key: custom_value
              number: 42
        """)
        c = Config.load(path)
        assert c.db_path == "/custom/db.sqlite"
        assert c.default_quota_per_token == 500
        assert c.blocklist_path == "/custom/blocklist.json"
        assert c.max_concurrent_per_target == 10
        assert c.nuclei_rate_limit == 50
        assert c.finding_ttl_days == 365
        assert c.binaries_dir == "/opt/tools"
        assert c.wordlists_dir == "/opt/wordlists"
        assert c.extra["custom_key"] == "custom_value"
        assert c.extra["number"] == 42

    def test_partial_yaml_preserves_defaults(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            database:
              path: /partial/db.sqlite
        """)
        c = Config.load(path)
        assert c.db_path == "/partial/db.sqlite"
        # Everything else stays at default
        assert c.default_quota_per_token == 100
        assert c.finding_ttl_days == 90
        assert c.binaries_dir == "./bin"

    def test_empty_yaml_file(self, tmp_path):
        path = _write_yaml(tmp_path, "")
        c = Config.load(path)
        assert c.db_path == "./data/secagent.db"
        assert c.default_quota_per_token == 100

    def test_null_yaml_content(self, tmp_path):
        """yaml.safe_load('') returns None → `or {}` should handle."""
        path = _write_yaml(tmp_path, "---\n")
        c = Config.load(path)
        assert c.db_path == "./data/secagent.db"

    def test_extra_block_absent_gives_empty_dict(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            database:
              path: /x/db.sqlite
        """)
        c = Config.load(path)
        assert c.extra == {}


# ─── env var overrides ─────────────────────────────────────────

class TestEnvOverrides:
    def test_env_overrides_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            database:
              path: /yaml/db.sqlite
            tools:
              binaries_dir: /yaml/bin
              wordlists_dir: /yaml/wordlists
        """)
        os.environ["SECAGENT_DB_PATH"] = "/env/db.sqlite"
        os.environ["SECAGENT_BINARIES_DIR"] = "/env/bin"
        os.environ["SECAGENT_WORDLISTS_DIR"] = "/env/wordlists"
        os.environ["SECAGENT_DEFAULT_QUOTA"] = "999"
        c = Config.load(path)
        assert c.db_path == "/env/db.sqlite"
        assert c.binaries_dir == "/env/bin"
        assert c.wordlists_dir == "/env/wordlists"
        assert c.default_quota_per_token == 999

    def test_env_overrides_defaults_when_no_yaml(self):
        os.environ["SECAGENT_DB_PATH"] = "/env-only/db.sqlite"
        os.environ["SECAGENT_DEFAULT_QUOTA"] = "50"
        os.environ["SECAGENT_BINARIES_DIR"] = "/env-only/bin"
        os.environ["SECAGENT_WORDLISTS_DIR"] = "/env-only/wordlists"
        c = Config.load(None)
        assert c.db_path == "/env-only/db.sqlite"
        assert c.default_quota_per_token == 50
        assert c.binaries_dir == "/env-only/bin"
        assert c.wordlists_dir == "/env-only/wordlists"

    def test_env_quota_coerced_to_int(self):
        os.environ["SECAGENT_DEFAULT_QUOTA"] = "250"
        c = Config.load(None)
        assert c.default_quota_per_token == 250
        assert isinstance(c.default_quota_per_token, int)


# ─── proxy config ──────────────────────────────────────────────

class TestProxyConfig:
    def test_proxy_from_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            proxy:
              enabled: true
              proxy_url: socks5://127.0.0.1:1080
              strategy: random
              health_check_interval: 30
              pool:
                - socks5://proxy1:1080
                - socks5://proxy2:1080
        """)
        c = Config.load(path)
        assert c.proxy.enabled is True
        assert c.proxy.proxy_url == "socks5://127.0.0.1:1080"
        assert c.proxy.strategy == "random"
        assert c.proxy.health_check_interval == 30
        assert len(c.proxy.pool) == 2

    def test_proxy_pool_not_list_defaults_empty(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            proxy:
              pool: "not_a_list"
        """)
        c = Config.load(path)
        assert c.proxy.pool == []

    def test_env_proxy_enables_when_yaml_proxy_disabled(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            proxy:
              enabled: false
        """)
        os.environ["ALL_PROXY"] = "http://env-proxy:8080"
        c = Config.load(path)
        assert c.proxy.enabled is True
        assert c.proxy.proxy_url == "http://env-proxy:8080"

    def test_env_proxy_does_not_override_yaml_enabled_proxy(self, tmp_path):
        path = _write_yaml(tmp_path, """\
            proxy:
              enabled: true
              proxy_url: socks5://yaml-proxy:1080
        """)
        os.environ["ALL_PROXY"] = "http://env-proxy:8080"
        c = Config.load(path)
        # YAML proxy already enabled → env proxy should not override
        assert c.proxy.proxy_url == "socks5://yaml-proxy:1080"

    def test_http_proxy_env_used_as_fallback(self):
        os.environ["HTTP_PROXY"] = "http://fallback:8080"
        c = Config.load(None)
        assert c.proxy.enabled is True
        assert c.proxy.proxy_url == "http://fallback:8080"

    def test_all_proxy_takes_precedence_over_http_proxy(self):
        os.environ["ALL_PROXY"] = "socks5://all:1080"
        os.environ["HTTP_PROXY"] = "http://http:8080"
        c = Config.load(None)
        assert c.proxy.proxy_url == "socks5://all:1080"

    def test_no_env_proxy_keeps_disabled(self):
        c = Config.load(None)
        assert c.proxy.enabled is False
        assert c.proxy.proxy_url == ""
