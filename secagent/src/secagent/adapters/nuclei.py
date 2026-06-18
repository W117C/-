"""NucleiAdapter — wraps nuclei binary into the BaseAdapter interface (spec §3.2 ③).

Nuclei is an active vulnerability scanner: it sends probe packets to targets.
This adapter ONLY parses nuclei JSON output into Findings. The three-layer
compliance guard (authz → blocklist → rate limit) lives in the tool function,
NOT here — the adapter is a pure "run binary + parse output" unit, matching
every other adapter in this package.

Nuclei JSON output (one object per line, -jsonl):
  {"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical"},
   "host":"https://sub.acme.com","matched-at":"https://sub.acme.com/?cmd=${jndi:...}",
   "curl-command":"curl -X GET ...","type":"http"}
"""
from __future__ import annotations

import json
import uuid
import datetime as dt
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.versions import get_tool_version
from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.errors import InvalidInputError, ToolFailedError


# Map nuclei severity strings → our Severity enum. Nuclei uses lowercase.
_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


class NucleiAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=600)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "nuclei"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        targets: list[str] = params.get("targets", [])
        if not targets:
            raise InvalidInputError(
                field="targets", reason="must be a non-empty list"
            )

        tool_info = get_tool_version(self.tool_name)
        binary = f"{self._binaries_dir}/{tool_info['binary_name']}"

        # nuclei accepts targets via -u (single) or -l <file>. For a list we
        # write a temp file so a single subprocess run covers all targets.
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        try:
            tmp.write("\n".join(targets))
            tmp.close()
            cmd: list[str] = [
                binary,
                "-l", tmp.name,
                "-jsonl",
                "-silent",
                "-no-color",
                "-rate-limit", str(params.get("rate_limit", 150)),
            ]
            templates = params.get("templates")
            if templates:
                cmd.extend(["-t", ",".join(templates)])
            severity_filter = params.get("severity_filter")
            if severity_filter:
                cmd.extend(["-severity", severity_filter])

            result = self._launch(cmd)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        if result.returncode != 0:
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
            template_id = obj.get("template-id", obj.get("templateID", ""))
            info = obj.get("info", {}) or {}
            name = info.get("name", template_id)
            sev_str = str(info.get("severity", "info")).lower()
            severity = _NUCLEI_SEVERITY_MAP.get(sev_str, Severity.INFO)
            host = obj.get("host", obj.get("matched-at", ""))
            matched_at = obj.get("matched-at", host)
            if not host:
                continue
            findings.append(
                Finding(
                    id=f"fnd_{uuid.uuid4().hex[:8]}",
                    type=FindingType.VULNERABILITY,
                    severity=severity,
                    target=host,
                    title=f"{name} ({template_id})" if template_id else name,
                    evidence={
                        "template_id": template_id,
                        "matched_at": matched_at,
                        "cvss": info.get("classification", {}).get("cvss-score")
                        if isinstance(info.get("classification"), dict)
                        else None,
                        "curl_repro": obj.get("curl-command", ""),
                        "tags": info.get("tags", []),
                    },
                    source_tool=self.tool_name,
                    raw=obj,
                    timestamp=dt.datetime.now(dt.timezone.utc),
                )
            )
        return findings
