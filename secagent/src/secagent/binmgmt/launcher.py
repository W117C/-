"""Subprocess launcher with timeout, retry, and proxy injection.

Every adapter calls Launcher.run() instead of subprocess directly. This
centralizes timeout/retry/proxy/error-handling logic in one place.

Proxy injection:
  - Tools with native proxy flags (-proxy, -x) get flags auto-injected
  - Tools without native flags get ALL_PROXY env vars
  - Both mechanisms respect tool-specific proxy support matrix
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from secagent.core.proxy import PROXY_FLAG_TOOLS, ENV_PROXY_TOOLS, ProxyManager


@dataclass
class LaunchResult:
    returncode: int
    stdout: str
    stderr: str
    json_output: Optional[dict | list] = None

    def __post_init__(self) -> None:
        if self.json_output is None:
            try:
                self.json_output = json.loads(self.stdout)
            except (json.JSONDecodeError, ValueError):
                pass


class Launcher:
    def __init__(self, timeout_sec: int = 120, retries: int = 0,
                 proxy_manager: ProxyManager | None = None):
        self.timeout_sec = timeout_sec
        self.retries = retries
        self.proxy_manager = proxy_manager

    def _inject_proxy(self, cmd: list[str], tool_name: str,
                      target: str) -> tuple[list[str], dict[str, str]]:
        """Inject proxy configuration into a command.

        Args:
            cmd: Original command list.
            tool_name: Tool name (e.g. "nuclei", "subfinder").
            target: Scan target hostname (for sticky session).

        Returns:
            (modified_cmd, proxy_env_vars): The possibly-modified command
            and any proxy env vars to set.
        """
        if not self.proxy_manager or not self.proxy_manager.is_enabled():
            return cmd, {}

        proxy = self.proxy_manager.get_proxy(target)
        if proxy is None:
            return cmd, {}

        env_vars: dict[str, str] = {}

        # Strategy 1: Native proxy flag injection
        if tool_name in PROXY_FLAG_TOOLS:
            flags = self.proxy_manager.get_proxy_flags(tool_name, target)
            if flags:
                # Inject after the binary path, before other args
                cmd = [cmd[0]] + flags + cmd[1:]

        # Strategy 2: ALL_PROXY env vars
        if tool_name in ENV_PROXY_TOOLS or tool_name not in PROXY_FLAG_TOOLS:
            env_vars = self.proxy_manager.get_proxy_env(target)

        return cmd, env_vars

    def run(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        target_hint: str | None = None,
        tool_name: str = "",
    ) -> LaunchResult:
        """Execute a binary command with optional proxy injection.

        Args:
            cmd: Command to run (list of strings).
            env: Optional environment overrides.
            cwd: Optional working directory.
            target_hint: Logical scan target (for error messages and proxy routing).
            tool_name: Tool name for proxy injection (e.g. "nuclei", "gitleaks").

        Raises ToolTimeoutError or ToolFailedError.
        """
        # Auto-detect tool name from cmd if not provided
        if not tool_name and cmd:
            binary = Path(cmd[0]).name
            # Check if it's a known tool
            if binary in PROXY_FLAG_TOOLS:
                tool_name = binary
            elif binary in ENV_PROXY_TOOLS:
                tool_name = binary

        # Inject proxy if configured
        modified_cmd, proxy_env = self._inject_proxy(
            cmd, tool_name, target_hint or "",
        )

        # Merge env vars: proxy_env takes precedence, then caller's env
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        merged_env.update(proxy_env)

        last_error: str = ""
        for attempt in range(1 + self.retries):
            proc: subprocess.Popen | None = None
            try:
                proc = subprocess.Popen(
                    modified_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=merged_env,
                    cwd=cwd,
                )
                stdout_bytes, stderr_bytes = proc.communicate(timeout=self.timeout_sec)
                return LaunchResult(
                    returncode=proc.returncode,
                    stdout=stdout_bytes.decode("utf-8", errors="replace"),
                    stderr=stderr_bytes.decode("utf-8", errors="replace"),
                )
            except subprocess.TimeoutExpired:
                if proc is not None:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                from secagent.core.errors import ToolTimeoutError
                raise ToolTimeoutError(
                    tool=tool_name or (cmd[0] if cmd else "unknown"),
                    target=target_hint or "<unknown>",
                )
            except (OSError, FileNotFoundError) as exc:
                last_error = str(exc)
                if attempt == self.retries:
                    break
        from secagent.core.errors import ToolFailedError
        raise ToolFailedError(
            tool=tool_name or (cmd[0] if cmd else "unknown"),
            detail=last_error or "command not found",
        )
