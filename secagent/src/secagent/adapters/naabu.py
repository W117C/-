"""NaabuAdapter — wraps the naabu port scanner into the BaseAdapter interface.

Naabu is a ProjectDiscovery port scanner that outputs JSONL (one JSON object per
open port). This adapter follows the same pattern as SubfinderAdapter and
NucleiAdapter.

Naabu JSONL output:
  {"host":"example.com","port":443,"protocol":"tcp","service":"https"}
"""
from __future__ import annotations

import json
import os
import uuid
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.versions import get_tool_version
from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.errors import InvalidInputError, ToolFailedError


class NaabuAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "naabu"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        target = params.get("target", "")
        if not target:
            raise InvalidInputError(field="target", reason="must be a non-empty string")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info['binary_name'])

        ports = params.get("ports", "80,443,8080-8090,8443")
        scan_type = params.get("scan_type", "connect")
        rate = max(1, min(int(params.get("rate", 500)), 2000))

        cmd: list[str] = [
            binary,
            "-host", target,
            "-p", str(ports),
            "-scan-type", scan_type,
            "-rate", str(rate),
            "-json",
            "-silent",
        ]

        result = self._launch(cmd)

        if result.returncode != 0:
            # naabu returns exit code 0 even with no open ports;
            # a non-zero exit usually means a real failure.
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200] if result.stderr else '(no stderr)'}",
            )

        return self._parse_output(result.stdout)

    def _parse_output(self, stdout: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()  # dedup by (port, protocol) only
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = obj.get("host", obj.get("ip", ""))
            port = obj.get("port")
            protocol = obj.get("protocol", "tcp")
            service = obj.get("service", "")
            if not host or not port:
                continue
            # Deduplicate: same port/protocol from different IPs (IPv4/IPv6)
            key = (int(port), protocol)
            if key in seen:
                continue
            seen.add(key)
            title = f"Open port {port}/{protocol}"
            if service:
                title += f" ({service})"
            findings.append(
                Finding(
                    id=f"fnd_{uuid.uuid4().hex}",
                    type=FindingType.OPEN_PORT,
                    severity=Severity.INFO,
                    target=host,
                    title=title,
                    evidence={
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "scan_type": "connect",
                    },
                    source_tool=self.tool_name,
                )
            )
        return findings
