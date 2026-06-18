"""Subprocess launcher with timeout, retry, and JSON output parsing.

Every adapter calls Launcher.run() instead of subprocess directly. This
centralizes timeout/retry/error-handling logic in one place.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional


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
    def __init__(self, timeout_sec: int = 120, retries: int = 0):
        self.timeout_sec = timeout_sec
        self.retries = retries

    def run(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        target_hint: str | None = None,
    ) -> LaunchResult:
        """Execute a binary command. Raises ToolTimeoutError or ToolFailedError.

        target_hint is the logical scan target (domain/URL/repo). It is used
        only in the timeout error message so the full command line — which may
        contain temp-file paths or other internals — is NOT leaked to callers.
        """
        last_error: str = ""
        for attempt in range(1 + self.retries):
            proc: subprocess.Popen | None = None
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    cwd=cwd,
                )
                stdout_bytes, stderr_bytes = proc.communicate(timeout=self.timeout_sec)
                return LaunchResult(
                    returncode=proc.returncode,
                    stdout=stdout_bytes.decode("utf-8", errors="replace"),
                    stderr=stderr_bytes.decode("utf-8", errors="replace"),
                )
            except subprocess.TimeoutExpired:
                # Kill the runaway subprocess so nuclei/subfinder do NOT keep
                # probing the target in the background after we report a timeout
                # (compliance + resource risk). Best-effort: ignore cleanup errors.
                if proc is not None:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                from secagent.core.errors import ToolTimeoutError
                raise ToolTimeoutError(
                    tool=cmd[0] if cmd else "unknown",
                    target=target_hint or "<unknown>",
                )
            except (OSError, FileNotFoundError) as exc:
                last_error = str(exc)
                if attempt == self.retries:
                    break
        # All retries exhausted or FileNotFoundError
        from secagent.core.errors import ToolFailedError
        raise ToolFailedError(
            tool=cmd[0] if cmd else "unknown",
            detail=last_error or "command not found",
        )
