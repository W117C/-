"""TlsxAdapter — wraps ProjectDiscovery tlsx (TLS/SSL fingerprinting).

tlsx probes TLS services to extract certificate info, cipher suites,
JA3/JA4 hashes, and protocol versions — essential for TLS fingerprinting
and identifying services behind CDNs/WAFs.

Spec: tlsx → probe_services TLS enhancement.
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


class TlsxAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "tlsx"

    def _launch(self, cmd: list[str], target: str = "", **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, target_hint=target, tool_name="tlsx", **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        targets = params.get("targets", [])
        if isinstance(targets, str):
            targets = [targets]
        if not targets:
            from secagent.core.errors import InvalidInputError
            raise InvalidInputError(field="targets", reason="must be a non-empty list")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info["binary_name"])

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            temp_path = f.name

        try:
            ports = params.get("ports", ["443", "8443"])
            cmd = [binary, "-json", "-silent",
                   "-l", temp_path,
                   "-tp", ",".join(ports)]
            # JA3/JA4 fingerprint support
            if params.get("ja3", False):
                cmd.append("-ja3")
            if params.get("ja4", False):
                cmd.append("-ja4")
            # Certificate extraction
            if params.get("cert_info", True):
                cmd.extend(["-cert", "-cn", "-san"])
            # Protocol detection
            if params.get("probe_all", False):
                cmd.append("-all")

            result = self._launch(cmd)
            if result.returncode != 0:
                from secagent.core.errors import ToolFailedError
                raise ToolFailedError(
                    tool=self.tool_name,
                    detail=f"exit code {result.returncode}: {result.stderr[:200]}",
                )
            return self._parse_output(result.stdout, ", ".join(targets))
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
            host = obj.get("host", "") or obj.get("ip", "")
            port = obj.get("port", "")
            if not host:
                continue

            tls_ver = obj.get("tls_version", "")
            cipher = obj.get("cipher", "")
            ja3_hash = obj.get("ja3_hash", "") or obj.get("ja3", "")
            ja4_hash = obj.get("ja4", "")
            cn = obj.get("subject_cn", "") or obj.get("common_name", "")
            san = obj.get("subject_an", []) or obj.get("san", [])

            title_parts = [f"TLS {tls_ver}" if tls_ver else "TLS"]
            if cn:
                title_parts.append(f"(CN: {cn})")
            title = " ".join(title_parts)

            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.SERVICE,
                severity=Severity.INFO,
                target=f"{host}:{port}" if port else host,
                title=title,
                evidence={
                    "host": host, "port": port,
                    "tls_version": tls_ver, "cipher": cipher,
                    "ja3_hash": ja3_hash, "ja4_hash": ja4_hash,
                    "common_name": cn, "san": san,
                },
                source_tool=self.tool_name,
                timestamp=dt.datetime.now(dt.timezone.utc),
            ))
        return findings
