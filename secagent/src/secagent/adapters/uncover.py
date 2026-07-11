"""UncoverAdapter — wraps ProjectDiscovery uncover (search engine aggregation).

uncover queries Shodan/Censys/Fofa simultaneously for discovered hosts,
providing an alternative passive reconnaissance source to theHarvester.

Spec: uncover → passive_recon enhancement.
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


class UncoverAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "uncover"

    def _launch(self, cmd: list[str], target: str = "", **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, target_hint=target, tool_name="uncover", **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        query = params.get("query", "") or params.get("target", "")
        if not query:
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="query", reason="must be a non-empty string")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info["binary_name"])

        engines = params.get("engines", ["shodan", "censys", "fofa"])
        limit = int(params.get("limit", 100))
        limit = max(1, min(limit, 1000))

        cmd = [binary, "-json", "-silent",
               "-q", query,
               "-e", ",".join(engines),
               "-l", str(limit)]

        result = self._launch(cmd)
        if result.returncode != 0:
            from secagent.core.errors import ToolFailedError
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200]}",
            )
        return self._parse_output(result.stdout, query)

    def _parse_output(self, stdout: str, query: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = obj.get("host", "") or obj.get("ip", "")
            port = obj.get("port", "")
            engine = obj.get("source", "") or obj.get("engine", "")
            if not host:
                continue

            evidence = {"query": query, "engine": engine}
            if port:
                host = f"{host}:{port}"
                evidence["port"] = port

            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.INTEL,
                severity=Severity.INFO,
                target=host,
                title=f"Uncovered: {host} via {engine}" if engine else f"Uncovered: {host}",
                evidence=evidence,
                source_tool=self.tool_name,
                timestamp=dt.datetime.now(dt.timezone.utc),
            ))
        return findings
