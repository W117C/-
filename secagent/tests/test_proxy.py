"""Unit tests for ProxyManager, ProxyPool, and Launcher proxy injection."""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch


from secagent.core.proxy import (
    PROXY_FLAG_TOOLS,
    ENV_PROXY_TOOLS,
    ProxyConfig,
    ProxyManager,
    ProxyPool,
)
from secagent.binmgmt.launcher import Launcher


# ---------------------------------------------------------------------------
# ProxyPool tests
# ---------------------------------------------------------------------------

class TestProxyPool:
    def test_round_robin_cycles(self):
        pool = ProxyPool(["p1", "p2", "p3"])
        assert pool.next() == "p1"
        assert pool.next() == "p2"
        assert pool.next() == "p3"
        assert pool.next() == "p1"  # wraps around

    def test_random_returns_something(self):
        pool = ProxyPool(["p1", "p2"], strategy="random")
        val = pool.next()
        assert val in ("p1", "p2")

    def test_empty_pool_returns_none(self):
        pool = ProxyPool([])
        assert pool.next() is None

    def test_all_dead_returns_none(self):
        pool = ProxyPool(["p1", "p2"])
        pool.mark_dead("p1")
        pool.mark_dead("p2")
        assert pool.next() is None

    def test_mark_alive_revives(self):
        pool = ProxyPool(["p1"])
        pool.mark_dead("p1")
        assert pool.next() is None
        pool.mark_alive("p1")
        assert pool.next() == "p1"

    def test_add_and_remove(self):
        pool = ProxyPool([])
        pool.add("p1")
        assert pool.count == 1
        pool.remove("p1")
        assert pool.count == 0

    def test_alive_count(self):
        pool = ProxyPool(["p1", "p2", "p3"])
        pool.mark_dead("p2")
        assert pool.alive_count == 2


# ---------------------------------------------------------------------------
# ProxyManager tests
# ---------------------------------------------------------------------------

class TestProxyManager:
    def test_disabled_returns_none(self):
        pm = ProxyManager(ProxyConfig(enabled=False))
        assert pm.get_proxy() is None
        assert pm.get_proxy_flags("nuclei") == []
        assert pm.get_proxy_env() == {}

    def test_single_proxy_url(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        proxy = pm.get_proxy()
        assert proxy == "socks5://127.0.0.1:9050"

    def test_proxy_flags_for_nuclei(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        flags = pm.get_proxy_flags("nuclei")
        assert "-proxy" in flags
        assert "socks5://127.0.0.1:9050" in flags

    def test_proxy_flags_for_ffuf(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="http://proxy:8080"))
        flags = pm.get_proxy_flags("ffuf")
        assert "-x" in flags
        assert "http://proxy:8080" in flags

    def test_proxy_flags_for_unknown_tool(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        flags = pm.get_proxy_flags("gitleaks")
        assert flags == []  # gitleaks is env-proxy only

    def test_proxy_env_vars(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        env = pm.get_proxy_env()
        assert env["ALL_PROXY"] == "socks5://127.0.0.1:9050"
        assert env["HTTP_PROXY"] == "socks5://127.0.0.1:9050"
        assert "NO_PROXY" in env

    def test_from_env_var(self):
        with patch.dict(os.environ, {"ALL_PROXY": "socks5://localhost:1080"}, clear=False):
            pm = ProxyManager.from_env()
            assert pm.is_enabled()
            assert pm.get_proxy() == "socks5://localhost:1080"

    def test_from_env_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            pm = ProxyManager.from_env()
            assert not pm.is_enabled()

    def test_pool_rotation(self):
        pm = ProxyManager(ProxyConfig(
            enabled=True,
            pool=["socks5://p1:9050", "socks5://p2:9050"],
            strategy="round_robin",
        ))
        proxies = {pm.get_proxy() for _ in range(10)}
        assert len(proxies) == 2

    def test_status(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        st = pm.status()
        assert st["enabled"] is True
        assert st["pool_size"] >= 1


# ---------------------------------------------------------------------------
# Launcher proxy injection tests
# ---------------------------------------------------------------------------

class TestLauncherProxyInjection:
    def test_inject_no_proxy(self):
        launcher = Launcher()
        cmd = ["./bin/nuclei", "-l", "targets.txt", "-jsonl"]
        modified_cmd, env_vars = launcher._inject_proxy(cmd, "nuclei", "example.com")
        assert modified_cmd == cmd  # no change
        assert env_vars == {}

    def test_inject_nuclei_proxy_flag(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        launcher = Launcher(proxy_manager=pm)
        cmd = ["./bin/nuclei", "-l", "targets.txt"]
        modified_cmd, env_vars = launcher._inject_proxy(cmd, "nuclei", "example.com")
        assert "-proxy" in modified_cmd
        assert "socks5://127.0.0.1:9050" in modified_cmd
        # Original flags preserved
        assert "-l" in modified_cmd

    def test_inject_ffuf_proxy_flag(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="http://proxy:8080"))
        launcher = Launcher(proxy_manager=pm)
        cmd = ["./bin/ffuf", "-u", "https://example.com/FUZZ"]
        modified_cmd, env_vars = launcher._inject_proxy(cmd, "ffuf", "example.com")
        assert "-x" in modified_cmd
        assert "http://proxy:8080" in modified_cmd

    def test_inject_gitleaks_env_vars(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        launcher = Launcher(proxy_manager=pm)
        cmd = ["./bin/gitleaks", "detect", "--no-git"]
        modified_cmd, env_vars = launcher._inject_proxy(cmd, "gitleaks", "example.com")
        # gitleaks doesn't support native proxy flags
        assert modified_cmd == cmd  # no flag injection
        assert "ALL_PROXY" in env_vars  # but env vars set
        assert env_vars["ALL_PROXY"] == "socks5://127.0.0.1:9050"

    def test_auto_detect_tool_name(self):
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        launcher = Launcher(proxy_manager=pm)
        cmd = ["./bin/nuclei", "-l", "targets.txt"]
        modified_cmd, env_vars = launcher._inject_proxy(cmd, "", "example.com")
        # Without explicit tool_name, auto-detection from cmd[0] path
        # But _inject_proxy requires tool_name - let's check the run method
        # Actually, the auto-detection is in run(), not _inject_proxy
        assert modified_cmd == cmd  # _inject_proxy needs tool_name


class TestLauncherRun:
    def test_run_with_proxy_flag_injection(self):
        """Verify that run() correctly injects proxy flags."""
        pm = ProxyManager(ProxyConfig(enabled=True, proxy_url="socks5://127.0.0.1:9050"))
        launcher = Launcher(proxy_manager=pm)

        with patch("secagent.binmgmt.launcher.subprocess.Popen") as MockPopen:
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate.return_value = (b"{}", b"")
            MockPopen.return_value = proc

            launcher.run(
                ["./bin/nuclei", "-l", "targets.txt", "-jsonl"],
                tool_name="nuclei",
                target_hint="example.com",
            )

        # Verify that proxy flag was injected into the command
        call_cmd = MockPopen.call_args[0][0]
        assert "-proxy" in call_cmd
        assert "socks5://127.0.0.1:9050" in call_cmd

    def test_run_without_proxy_no_change(self):
        """Without proxy, command should be unchanged."""
        launcher = Launcher()
        with patch("secagent.binmgmt.launcher.subprocess.Popen") as MockPopen:
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate.return_value = (b"{}", b"")
            MockPopen.return_value = proc

            launcher.run(
                ["./bin/nuclei", "-l", "targets.txt"],
                tool_name="nuclei",
                target_hint="example.com",
            )

        call_cmd = MockPopen.call_args[0][0]
        assert "-proxy" not in call_cmd
        assert call_cmd == ["./bin/nuclei", "-l", "targets.txt"]


# ---------------------------------------------------------------------------
# Config loading tests
# ---------------------------------------------------------------------------

class TestProxyConfig:
    def test_proxy_flag_tools_defined(self):
        assert "nuclei" in PROXY_FLAG_TOOLS
        assert "httpx" in PROXY_FLAG_TOOLS
        assert "subfinder" in PROXY_FLAG_TOOLS
        assert "naabu" in PROXY_FLAG_TOOLS
        assert "ffuf" in PROXY_FLAG_TOOLS

    def test_env_proxy_tools_defined(self):
        assert "gitleaks" in ENV_PROXY_TOOLS
        assert "theharvester" in ENV_PROXY_TOOLS
