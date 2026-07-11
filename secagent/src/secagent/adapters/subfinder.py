"""SubfinderAdapter — wraps subfinder binary into the BaseAdapter interface.

Subfinder enumerates subdomains. It outputs one JSON object per line with at
minimum a "host" field. This adapter parses that into Finding(type=subdomain).

Spec: §3.2 ① enumerate_subdomains, §5.2 (binary dependency strategy).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import uuid
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.binmgmt.versions import get_tool_version
from secagent.core.finding import Finding, FindingType, Severity


class SubfinderAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "subfinder"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        domain = params.get("target_domain")
        if not domain:
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="target_domain", reason="must be a non-empty string")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info['binary_name'])

        cmd: list[str] = [binary, "-d", domain, "-json", "-silent"]

        sources = params.get("sources")
        if sources:
            cmd.extend(["-sources", ",".join(sources)])

        result = self._launch(cmd)

        if result.returncode != 0:
            from secagent.core.errors import ToolFailedError
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200]}",
            )

        return self._parse_output(result.stdout, domain)

    def _parse_output(self, stdout: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host", "")
            if not host:
                continue
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.SUBDOMAIN,
                severity=Severity.INFO,
                target=host,
                title=f"Subdomain: {host}",
                evidence={
                    "source": obj.get("source", ""),
                    "domain_queried": domain,
                },
                source_tool=self.tool_name,
                timestamp=dt.datetime.now(dt.timezone.utc),
            ))
        return findings
