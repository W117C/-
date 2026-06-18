"""TheHarvesterAdapter — wraps theHarvester binary into the BaseAdapter interface.

theHarvester gathers OSINT (emails, subdomains, hosts, usernames) from public
sources. This adapter parses its (simplified) JSON output into Finding(type=INTEL).

MVP JSON contract (we assume theHarvester emits this single JSON object):
  {
    "emails": ["admin@acme.com", ...],
    "subdomains": ["mail.acme.com", ...],
    "hosts": ["acme.com:1.2.3.4", ...],
    "usernames": []
  }

Spec: §3.2 ④ gather_osint, §5.2 (binary dependency strategy).
"""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.launcher import LaunchResult, Launcher
from secagent.binmgmt.versions import get_tool_version
from secagent.core.finding import Finding, FindingType, Severity


# All categories this adapter knows how to turn into findings.
_CATEGORIES: tuple[str, ...] = ("emails", "subdomains", "hosts", "usernames")

# Singular human-readable labels for titles, keyed by JSON category.
_SINGULAR: dict[str, str] = {
    "emails": "Email",
    "subdomains": "Subdomain",
    "hosts": "Host",
    "usernames": "Username",
    "breaches": "Breach",
}


class TheHarvesterAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "theharvester"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        target = params.get("target")
        if not target:
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="target", reason="must be a non-empty string")

        tool_info = get_tool_version(self.tool_name)
        binary = f"{self._binaries_dir}/{tool_info['binary_name']}"

        cmd: list[str] = [binary, "-d", target, "-b", "all", "-f", "json"]

        result = self._launch(cmd)

        if result.returncode != 0:
            from secagent.core.errors import ToolFailedError
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200]}",
            )

        return self._parse_output(result.stdout, target, params.get("data_types"))

    def _parse_output(
        self,
        stdout: str,
        target: str,
        data_types: list[str] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        stripped = stdout.strip()
        if not stripped:
            return findings
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            # Non-JSON stdout with returncode 0: treat as no findings.
            return findings
        if not isinstance(obj, dict):
            return findings

        # If the caller requested specific data_types, only emit those; otherwise emit all.
        categories = data_types if data_types else _CATEGORIES
        for category in categories:
            items = obj.get(category, [])
            if not isinstance(items, list):
                continue
            label = _SINGULAR.get(category, category.capitalize())
            for value in items:
                if not isinstance(value, str) or not value:
                    continue
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex[:8]}",
                        type=FindingType.INTEL,
                        severity=Severity.INFO,
                        target=value,
                        title=f"{label}: {value}",
                        evidence={
                            "category": category,
                            "source": "theHarvester",
                            "value": value,
                        },
                        source_tool=self.tool_name,
                        raw={"target": target},
                        timestamp=dt.datetime.now(dt.timezone.utc),
                    )
                )
        return findings
