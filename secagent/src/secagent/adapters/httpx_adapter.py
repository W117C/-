"""HttpxAdapter — wraps httpx binary into the BaseAdapter interface.

httpx (projectdiscovery/httpx) performs live probe + service identification.
It outputs one JSON object per line with host/port/scheme/title/tech fields.
This adapter parses that into Finding(type=service).

Spec: §3.2 ② probe_services, §5.2 (binary dependency strategy).
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
import datetime as dt
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.versions import get_tool_version
from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.waf_detect import detect_waf_from_raw


class HttpxAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "httpx"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        targets = params.get("targets")
        if not targets or not isinstance(targets, list):
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="targets", reason="must be a non-empty list")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info['binary_name'])

        # Write targets to a temp file so httpx reads them via -l (single
        # subprocess call regardless of target count).
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="httpx_targets_", suffix=".txt")
        try:
            with os.fdopen(tmp_fd, "w") as f:
                f.write("\n".join(targets))
            cmd: list[str] = [binary, "-l", tmp_path, "-json", "-silent"]

            ports = params.get("ports")
            if ports:
                cmd.extend(["-p", str(ports)])
            threads = params.get("threads")
            if threads:
                cmd.extend(["-threads", str(threads)])

            result = self._launch(cmd)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        if result.returncode != 0:
            from secagent.core.errors import ToolFailedError
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200]}",
            )

        return self._parse_output(result.stdout)

    def _parse_output(self, stdout: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host") or obj.get("input", "")
            if not host:
                continue
            port = str(obj.get("port", ""))
            scheme = obj.get("scheme", "")
            title = obj.get("title", "")
            status_code = obj.get("status_code")
            tech = obj.get("tech", []) or []
            webserver = obj.get("webserver", "")

            # Detect WAF/CDN from raw response headers
            waf_info = detect_waf_from_raw(obj)

            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.SERVICE,
                severity=Severity.INFO,
                target=host,
                title=f"Service: {host}:{port}" if port else f"Service: {host}",
                evidence={
                    "port": port,
                    "protocol": scheme,
                    "service": webserver,
                    "title": title,
                    "tech_stack": tech,
                    "status_code": status_code,
                    "input_host": obj.get("input", ""),
                    "waf": waf_info if waf_info else None,
                },
                source_tool=self.tool_name,
                raw=obj,
                timestamp=dt.datetime.now(dt.timezone.utc),
            ))
        return findings
