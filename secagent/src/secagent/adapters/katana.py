"""KatanaAdapter — wraps ProjectDiscovery katana (next-gen web crawler).

Katana is a headless crawler that extracts URLs, endpoints, and JS sources
from target websites, replacing the built-in SimpleCrawlerAdapter for
production-grade crawling. Supports headless browser mode, depth control,
JS rendering, and automatic form/endpoint extraction.

Spec: katana → crawl_target enhancement.
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


class KatanaAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=300)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "katana"

    def _launch(self, cmd: list[str], target: str = "", **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, target_hint=target, tool_name="katana", **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        target = params.get("target", "")
        if not target:
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="target", reason="must be a non-empty URL")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info["binary_name"])

        depth = int(params.get("depth", 3))
        depth = max(1, min(depth, 10))
        headless = params.get("headless", False)
        js_render = params.get("js_render", False)

        cmd = [binary, "-u", target, "-json", "-silent", "-d", str(depth)]
        if headless:
            cmd.append("-headless")
        if js_render:
            cmd.append("-js-crawl")

        result = self._launch(cmd, target=target)
        if result.returncode != 0:
            from secagent.core.errors import ToolFailedError
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200]}",
            )
        return self._parse_output(result.stdout, target)

    def _parse_output(self, stdout: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("request", {}).get("endpoint", "") or obj.get("URL", "")
            if not url:
                continue
            source = obj.get("request", {}).get("source", "")
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.EXPOSURE,
                severity=Severity.INFO,
                target=url,
                title=f"Crawled: {url} (source: {source})" if source else f"Crawled: {url}",
                evidence={
                    "source": source,
                    "method": obj.get("request", {}).get("method", "GET"),
                    "status_code": obj.get("response", {}).get("status_code", 0),
                },
                source_tool=self.tool_name,
                timestamp=dt.datetime.now(dt.timezone.utc),
            ))
        return findings
