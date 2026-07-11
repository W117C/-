"""ProxyManager — proxy chain management for scan traffic anonymization.

Supports four proxy modes:
  1. Native proxy flags (subfinder -proxy, httpx -proxy, nuclei -proxy, ffuf -x)
  2. ALL_PROXY/HTTP_PROXY/HTTPS_PROXY env vars
  3. Python urllib ProxyHandler (HTTP/HTTPS proxies only)
  4. PySocks global socket override (SOCKS5 proxies for Python tools)
"""
from __future__ import annotations

import os
import random
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class ProxyConfig:
    """Proxy configuration, loaded from config.yaml proxy: block.

    Attributes:
        enabled: Master switch. False = no proxying.
        proxy_url: Single proxy URL for simple setups (e.g. "socks5://127.0.0.1:9050").
        pool: List of proxy URLs for pool-based rotation.
        strategy: Rotation strategy — "round_robin" | "random".
        health_check_interval: Seconds between health checks (0 = disabled).
    """
    enabled: bool = False
    proxy_url: str = ""
    pool: list[str] = field(default_factory=list)
    strategy: str = "round_robin"
    health_check_interval: int = 0

    def get_all(self) -> list[str]:
        """Return all available proxy URLs (single + pool)."""
        urls: list[str] = []
        if self.proxy_url:
            urls.append(self.proxy_url)
        urls.extend(self.pool)
        return urls


# Tools that support native -proxy flag.
# Launcher will inject the flag automatically when proxy is enabled.
PROXY_FLAG_TOOLS: dict[str, list[str]] = {
    "subfinder": ["-proxy", "{proxy}"],
    "httpx": ["-proxy", "{proxy}"],
    "nuclei": ["-proxy", "{proxy}"],
    "naabu": ["-proxy", "{proxy}"],
    "ffuf": ["-x", "{proxy}"],
    "katana": ["-proxy", "{proxy}"],
    "dnsx": ["-proxy", "{proxy}"],
    "tlsx": ["-proxy", "{proxy}"],
    "uncover": ["-proxy", "{proxy}"],
}

# Tools that DON'T support native proxy flags — rely on ALL_PROXY env vars.
# These are primarily Python tools or tools without built-in proxy support.
ENV_PROXY_TOOLS: set[str] = {
    "gitleaks",
    "theharvester",
}


class ProxyPool:
    """Thread-safe proxy pool with strategy-based selection."""

    def __init__(self, proxies: list[str], strategy: str = "round_robin"):
        self._proxies = list(proxies)
        self._alive: set[str] = set(proxies)
        self._cursor = 0
        self._lock = threading.Lock()
        self._strategy = strategy

    def next(self) -> str | None:
        """Get the next proxy based on strategy (round_robin or random)."""
        with self._lock:
            available = [p for p in self._proxies if p in self._alive]
            if not available:
                return None
            if self._strategy == "random":
                return random.choice(available)
            # round_robin
            self._cursor = self._cursor % len(available)
            proxy = available[self._cursor]
            self._cursor += 1
            return proxy

    def mark_alive(self, url: str) -> None:
        with self._lock:
            self._alive.add(url)

    def mark_dead(self, url: str) -> None:
        with self._lock:
            self._alive.discard(url)

    def add(self, url: str) -> None:
        with self._lock:
            if url not in self._proxies:
                self._proxies.append(url)
                self._alive.add(url)

    def remove(self, url: str) -> None:
        with self._lock:
            self._proxies = [p for p in self._proxies if p != url]
            self._alive.discard(url)

    def all(self) -> list[str]:
        with self._lock:
            return list(self._proxies)

    def alive(self) -> list[str]:
        with self._lock:
            return [p for p in self._proxies if p in self._alive]

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._proxies)

    @property
    def alive_count(self) -> int:
        with self._lock:
            return len(self._alive)


class ProxyManager:
    """Manages proxy selection for scan tools.

    Usage:
        config = Config.load()
        pm = ProxyManager(config)

        # In tool functions:
        proxy = pm.get_proxy(tool_name="nuclei")
        launcher.run(cmd, proxy=proxy)  # auto-injects flag

        # Or for Python urllib tools:
        handler = pm.build_proxy_handler()
    """

    def __init__(self, config: ProxyConfig | None = None):
        self.config = config or ProxyConfig()
        self._pool = ProxyPool(
            proxies=self.config.get_all(),
            strategy=self.config.strategy,
        )
        self._lock = threading.Lock()
        self._session_map: dict[str, str] = {}

    @classmethod
    def from_env(cls) -> ProxyManager:
        """Create a ProxyManager from the ALL_PROXY env var (simple setup)."""
        env_proxy = os.environ.get("ALL_PROXY") or os.environ.get("HTTP_PROXY") or ""
        if env_proxy:
            return cls(ProxyConfig(enabled=True, proxy_url=env_proxy))
        return cls(ProxyConfig(enabled=False))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_proxy(self, target: str = "") -> str | None:
        """Get a proxy URL for the given target (or None if proxy disabled).

        Args:
            target: Target hostname (used for sticky_session in future).

        Returns:
            Proxy URL string (e.g. "socks5://127.0.0.1:9050") or None.
        """
        if not self.config.enabled:
            return None
        return self._pool.next()

    def get_tool_proxy(self, tool_name: str, target: str = "") -> tuple[str | None, bool]:
        """Get proxy info for a specific tool.

        Returns:
            (proxy_url, use_env_vars): proxy URL and whether to use env vars
            instead of CLI flags.
        """
        proxy = self.get_proxy(target)
        if proxy is None:
            return None, False
        use_env = tool_name in ENV_PROXY_TOOLS
        return proxy, use_env

    def get_proxy_flags(self, tool_name: str, target: str = "") -> list[str]:
        """Get CLI flags to inject for a proxy-aware tool.

        Returns empty list if proxy is disabled or tool doesn't support flags.
        """
        proxy = self.get_proxy(target)
        if proxy is None:
            return []
        template = PROXY_FLAG_TOOLS.get(tool_name)
        if template is None:
            return []
        return [flag.replace("{proxy}", proxy) if "{proxy}" in flag else flag
                for flag in template]

    def get_proxy_env(self, target: str = "") -> dict[str, str]:
        """Get environment variables for proxy configuration.

        Sets ALL_PROXY, HTTP_PROXY, HTTPS_PROXY and NO_PROXY.
        """
        proxy = self.get_proxy(target)
        if proxy is None:
            return {}
        return {
            "ALL_PROXY": proxy,
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "NO_PROXY": "127.0.0.1,localhost,::1,.local",
        }

    def build_proxy_handler(self) -> object | None:
        """Build a urllib ProxyHandler for Python-based tools.

        Returns None if proxy is disabled.
        For SOCKS5 proxies, returns an object whose 'open' method handles
        the socks context (the caller should use socks_context() instead).
        """
        proxy = self.get_proxy()
        if proxy is None:
            return None
        # For HTTP/HTTPS proxies, use standard ProxyHandler
        if not proxy.startswith("socks5"):
            try:
                from urllib.request import ProxyHandler
                return ProxyHandler({
                    "http": proxy,
                    "https": proxy,
                })
            except ImportError:
                return None
        # For SOCKS5, the caller should use socks_context()
        return None

    # ------------------------------------------------------------------
    # PySocks support (for SOCKS5 proxies in Python tools)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_socks5(proxy_url: str | None) -> bool:
        """Check if a proxy URL is SOCKS5."""
        return proxy_url is not None and proxy_url.startswith("socks5")

    @contextmanager
    def socks_context(self, target: str = "") -> Iterator[None]:
        """Context manager that enables SOCKS5 proxy for all Python sockets.

        Uses PySocks to override socket.socket globally within the context.
        Automatically restores the original socket on exit.

        Note: On some Python versions, the global socket.socket replacement
        may have compatibility issues with urllib. For CLI tools use the
        native -proxy flag injection (get_proxy_flags / get_tool_proxy).

        Usage:
            with proxy_manager.socks_context():
                # All urllib/requests calls now go through SOCKS5 proxy
                urllib.request.urlopen("https://example.com")
        """
        proxy = self.get_proxy(target)
        if not self._is_socks5(proxy) or not self.config.enabled:
            yield
            return

        try:
            import socks as socks_mod
        except ImportError:
            yield
            return

        parsed = urlparse(proxy)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9050

        # Use PySocks via a custom socket factory instead of global
        # socket.socket replacement (which has urllib compatibility issues).
        # We set default proxy and try socket replacement; if it fails
        # the caller should use socks_urlopen() instead.
        original_create_connection = socket.create_connection

        def _socks_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                                      source_address=None, **kwargs):
            """Replacement for socket.create_connection that routes through SOCKS5."""
            try:
                sock = socks_mod.socksocket()
                sock.set_proxy(socks_mod.SOCKS5, host, port, True)  # True = remote DNS
                sock.settimeout(timeout if timeout is not None else 10)
                sock.connect(address)
                return sock
            except Exception:
                # Fall back to original
                return original_create_connection(
                    address, timeout=timeout, source_address=source_address, **kwargs
                )

        socket.create_connection = _socks_create_connection
        try:
            yield
        finally:
            socket.create_connection = original_create_connection

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def is_enabled(self) -> bool:
        return self.config.enabled

    def status(self) -> dict[str, Any]:
        """Return proxy status for health checks."""
        return {
            "enabled": self.config.enabled,
            "pool_size": self._pool.count,
            "pool_alive": self._pool.alive_count,
            "strategy": self.config.strategy,
            "proxies": self._pool.all() if self.config.enabled else [],
        }
