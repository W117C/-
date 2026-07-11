"""FfufAdapter — wraps the ffuf web fuzzer into the BaseAdapter interface.

Ffuf is a fast web fuzzer written in Go. With the -json flag, ffuf outputs one
JSON object per request (JSONL format), making it easy to parse.

Ffuf JSONL output:
  {"url":"https://example.com/admin","status":200,"content_length":3241,
   "content_type":"text/html","redirect":"","duration":125}

This adapter classifies findings by severity based on status code and path
patterns.
"""
from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.binmgmt.versions import get_tool_version
from secagent.core.errors import InvalidInputError, ToolFailedError
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.tech_paths import paths_for_tech

# Path patterns that indicate higher-severity findings.
_CRITICAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.git/config$", re.I),
    re.compile(r"\.env", re.I),
    re.compile(r"\.(sql|bak|old|orig|save|swp|swo)$", re.I),
    re.compile(r"~backup", re.I),
    re.compile(r"config\.php\.(bak|old|save)", re.I),
    re.compile(r"Dockerfile$", re.I),
    re.compile(r"credentials", re.I),
    re.compile(r"secrets", re.I),
]

_HIGH_PATTERNS: list[re.Pattern] = [
    re.compile(r"^/admin", re.I),
    re.compile(r"^/wp-admin", re.I),
    re.compile(r"^/api/", re.I),
    re.compile(r"^/debug", re.I),
    re.compile(r"^/\.git/", re.I),
    re.compile(r"^/actuator", re.I),
    re.compile(r"swagger", re.I),
    re.compile(r"graphi?ql", re.I),
]

_MEDIUM_PATTERNS: list[re.Pattern] = [
    re.compile(r"phpmyadmin", re.I),
    re.compile(r"^/uploads", re.I),
    re.compile(r"^/docs", re.I),
    re.compile(r"^/backup", re.I),
    re.compile(r"info\.php$", re.I),
    re.compile(r"phpinfo", re.I),
    re.compile(r"xmlrpc", re.I),
    re.compile(r"^/var/", re.I),
    re.compile(r"^/vendor/", re.I),
    re.compile(r"^/node_modules", re.I),
    re.compile(r"^/storage/", re.I),
]


def _classify_severity(status_code: int, url_path: str) -> Severity:
    """Classify a discovered path by severity based on status code and path.

    Priority:
      1. Critical path patterns (config, env, backup, credentials)
      2. High path patterns (admin, api, debug)
      3. Medium path patterns
      4. Status code based:
         - 200/301/302/307/308 on sensitive patterns
         - 401/403 -> low (access denied but path exists)
         - other non-404 -> info
    """
    path_lower = url_path.lower()

    # Extract path component from full URL for pattern matching
    # Support both full URLs ("https://acme.com/admin") and bare paths ("/admin")
    if "://" in path_lower:
        # Extract path from URL
        path_part = "/" + "/".join(path_lower.split("/")[3:])
    else:
        path_part = path_lower

    for pattern in _CRITICAL_PATTERNS:
        if pattern.search(path_part):
            # Only critical if actually accessible (2xx/3xx)
            if status_code in (200, 201, 301, 302, 307, 308):
                return Severity.CRITICAL
            if status_code in (401, 403):
                return Severity.HIGH

    for pattern in _HIGH_PATTERNS:
        if pattern.search(path_part):
            if status_code in (200, 201, 301, 302, 307, 308):
                return Severity.HIGH
            if status_code in (401, 403):
                return Severity.MEDIUM

    for pattern in _MEDIUM_PATTERNS:
        if pattern.search(path_part):
            if status_code in (200, 201, 301, 302, 307, 308):
                return Severity.MEDIUM

    # Default by status code
    if status_code in (200, 201):
        return Severity.LOW
    if status_code in (301, 302, 307, 308):
        return Severity.LOW
    if status_code in (401, 403, 405):
        return Severity.LOW
    if status_code in (500, 502, 503):
        return Severity.LOW
    return Severity.INFO


def _resolve_wordlist(wordlist_param: str | None, wordlists_dir: str = "./wordlists") -> str:
    """Resolve a wordlist parameter to an actual file path.

    Only two values are accepted: 'builtin' (default) and 'common'. Both
    resolve to files under *wordlists_dir* only — arbitrary filesystem paths
    are rejected to prevent path traversal / arbitrary file read (CVE-style).

    Falls back to the built-in wordlist on any resolution failure.
    """
    if wordlist_param in (None, "", "builtin"):
        # Use the built-in wordlist via importlib.resources
        import importlib.resources
        try:
            return str(
                importlib.resources.files("secagent.wordlists").joinpath("paths_builtin.txt")
            )
        except (ImportError, TypeError, OSError):
            # Fallback: try the filesystem path
            fallback = os.path.join(wordlists_dir, "paths_builtin.txt")
            if os.path.isfile(fallback):
                return fallback
            raise InvalidInputError(
                field="wordlist",
                reason="built-in wordlist not found — reinstall secagent or specify a custom wordlist path",
            )
    if wordlist_param == "common":
        common = os.path.join(wordlists_dir, "common.txt")
        if os.path.isfile(common):
            return common
        # Fall back to builtin
        return _resolve_wordlist("builtin", wordlists_dir)
    # Reject arbitrary file paths to prevent path traversal / file disclosure
    raise InvalidInputError(
        field="wordlist",
        reason=f"wordlist '{wordlist_param}' rejected. Only 'builtin' and 'common' are allowed. "
               "Arbitrary paths are not supported for security reasons.",
    )


class FfufAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin", wordlists_dir: str = "./wordlists"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir
        self._wordlists_dir = wordlists_dir

    @property
    def tool_name(self) -> str:
        return "ffuf"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        target = params.get("target", "")
        if not target:
            raise InvalidInputError(field="target", reason="must be a non-empty string")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info['binary_name'])

        # Resolve wordlist
        wordlist = _resolve_wordlist(
            params.get("wordlist"),
            params.get("wordlists_dir", self._wordlists_dir),
        )

        # Tech-stack-aware path extension
        tech_stack = params.get("tech_stack")
        tech_paths = paths_for_tech(tech_stack) if tech_stack else []
        if tech_paths:
            # Write a combined wordlist: base + tech-specific paths
            combined_path = wordlist + ".tech_combined"
            if not os.path.isfile(combined_path):
                with open(wordlist) as base_f:
                    base_content = base_f.read()
                with open(combined_path, "w") as cf:
                    cf.write(base_content)
                    if not base_content.endswith("\n"):
                        cf.write("\n")
                    for tp in tech_paths:
                        cf.write(tp.rstrip("/") + "\n")
            wordlist = combined_path

        # Safety clamps
        rate = max(1, min(int(params.get("rate", 100)), 500))
        threads = max(1, min(int(params.get("threads", 40)), 200))
        recursive_depth = min(int(params.get("recursive_depth", 1)), 3)
        max_time = min(int(params.get("max_time", 60)), 300)

        cmd: list[str] = [
            binary,
            "-u", target,
            "-w", wordlist,
            "-rate", str(rate),
            "-t", str(threads),
            "-recursion-depth", str(recursive_depth),
            "-maxtime", str(max_time),
            "-json",
        ]

        extensions = params.get("extensions")
        if extensions:
            cmd.extend(["-e", str(extensions)])

        match_status = params.get("match_status")
        if match_status:
            cmd.extend(["-mc", str(match_status)])

        recursive = params.get("recursive")
        if recursive:
            cmd.append("-recursion")

        result = self._launch(cmd)

        if result.returncode != 0:
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200] if result.stderr else '(no stderr)'}",
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

            url = obj.get("url", "")
            if not url:
                continue
            status_code = obj.get("status", 0)
            content_length = obj.get("content_length", obj.get("length", 0))
            content_type = obj.get("content_type", obj.get("type", ""))
            redirect = obj.get("redirect", "")
            duration = obj.get("duration", obj.get("time", 0))

            severity = _classify_severity(status_code, url)

            title = f"{url} ({status_code}"
            if content_length:
                title += f" - {content_length}B"
            if content_type:
                title += f" - {content_type}"
            title += ")"

            findings.append(
                Finding(
                    id=f"fnd_{uuid.uuid4().hex}",
                    type=FindingType.EXPOSED_PATH,
                    severity=severity,
                    target=url,
                    title=title,
                    evidence={
                        "url": url,
                        "status_code": status_code,
                        "content_length": content_length,
                        "content_type": content_type,
                        "redirect": redirect,
                        "duration_ms": duration,
                    },
                    source_tool=self.tool_name,
                )
            )
        return findings
