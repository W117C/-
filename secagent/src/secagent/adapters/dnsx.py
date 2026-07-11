"""DnsxAdapter — wraps ProjectDiscovery dnsx (multi-purpose DNS toolkit).

dnsx performs DNS resolution, wildcard detection, and service record queries.
Integrates with the subdomain+port pipeline for attack surface mapping.

Spec: dnsx → enumerate_subdomains DNS resolution phase.
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


class DnsxAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "dnsx"

    def _launch(self, cmd: list[str], target: str = "", **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, target_hint=target, tool_name="dnsx", **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        domains = params.get("targets", [])
        if isinstance(domains, str):
            domains = [domains]
        if not domains:
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="targets", reason="must be a non-empty list of domains")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info["binary_name"])

        # Write domains to temp file for dnsx stdin input
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            temp_path = f.name

        try:
            query_types = params.get("query_types", ["a", "cname"])
            cmd = [binary, "-json", "-silent",
                   "-l", temp_path,
                   "-q", ",".join(query_types)]
            if params.get("wildcard_detect", True):
                cmd.append("-wd")

            result = self._launch(cmd)
            if result.returncode != 0:
                from secagent.core.errors import ToolFailedError
                raise ToolFailedError(
                    tool=self.tool_name,
                    detail=f"exit code {result.returncode}: {result.stderr[:200]}",
                )
            return self._parse_output(result.stdout, ", ".join(domains))
        finally:
            os.unlink(temp_path)

    def _parse_output(self, stdout: str, target_hint: str) -> list[Finding]:
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
            a_records = obj.get("a", [])
            cname = obj.get("cname", [])
            wildcard = obj.get("wildcard", False)

            for ip in a_records:
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex}",
                    type=FindingType.SERVICE,
                    severity=Severity.INFO,
                    target=host,
                    title=f"DNS A record: {host} → {ip}",
                    evidence={"host": host, "a_record": ip, "wildcard": wildcard},
                    source_tool=self.tool_name,
                    timestamp=dt.datetime.now(dt.timezone.utc),
                ))
            for cn in cname:
                findings.append(Finding(
                    id=f"fnd_{uuid.uuid4().hex}",
                    type=FindingType.INTEL,
                    severity=Severity.INFO,
                    target=host,
                    title=f"DNS CNAME: {host} → {cn}",
                    evidence={"host": host, "cname": cn, "wildcard": wildcard},
                    source_tool=self.tool_name,
                    timestamp=dt.datetime.now(dt.timezone.utc),
                ))
        return findings
