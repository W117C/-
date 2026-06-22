"""GitleaksAdapter — wraps gitleaks binary into the BaseAdapter interface.

Gitleaks scans a local git repository for secrets/credentials. It emits a JSON
array (one object per finding) when invoked with `--report-format json
--report-path -`. This adapter parses that into Finding(type=SECRET_LEAK).

Spec: §3.2 ⑤ scan_secret_leaks, §4.3 data minimization (secrets MUST be
redacted before they enter a Finding — never store raw plaintext).
"""
from __future__ import annotations

import json
import os
import uuid
import datetime as dt
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.binmgmt.versions import get_tool_version
from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.errors import InvalidInputError, ToolFailedError


# Rule IDs that map to CRITICAL severity. Everything else is HIGH.
_CRITICAL_RULE_KEYWORDS = ("aws", "private-key", "private_key", "rsa", "gcp", "github-token")


def _redact(secret: str) -> str:
    """Redact a secret: keep first 4 and last 4 chars, replace middle with ****.

    Spec §4.3 data minimization — secrets of length <= 8 are fully masked so
    short tokens don't leak via the prefix/suffix. The full plaintext MUST NOT
    be persisted anywhere in a Finding (evidence, raw, title).
    """
    if not secret:
        return "****"
    if len(secret) <= 8:
        return "****"
    return secret[:4] + "****" + secret[-4:]


def _severity_for_rule(rule_id: str) -> Severity:
    """Map a gitleaks RuleID to a Severity. Default HIGH; CRITICAL for
    cloud-provider / private-key rules."""
    rid = (rule_id or "").lower()
    for kw in _CRITICAL_RULE_KEYWORDS:
        if kw in rid:
            return Severity.CRITICAL
    return Severity.HIGH


class GitleaksAdapter(BaseAdapter):
    def __init__(self, launcher: Launcher | None = None, binaries_dir: str = "./bin"):
        self._launcher = launcher or Launcher(timeout_sec=120)
        self._binaries_dir = binaries_dir

    @property
    def tool_name(self) -> str:
        return "gitleaks"

    def _launch(self, cmd: list[str], **kwargs: Any) -> LaunchResult:
        return self._launcher.run(cmd, **kwargs)

    def run(self, params: dict[str, Any]) -> list[Finding]:
        repo_path = params.get("scope")
        if not repo_path or not isinstance(repo_path, str):
            raise InvalidInputError(field="scope", reason="must be a non-empty string (local repo path or repo URL)")

        mode = params.get("mode", "github")
        if mode != "github":
            raise InvalidInputError(field="mode", reason=f"unsupported mode '{mode}'; MVP supports only 'github'")

        tool_info = get_tool_version(self.tool_name)
        binary = os.path.join(self._binaries_dir, tool_info['binary_name'])

        cmd: list[str] = [
            binary,
            "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", "-",
            "--no-banner",
        ]

        result = self._launch(cmd, target_hint=repo_path)

        # gitleaks exit codes: 0 = no leaks, 1 = leaks found (a NORMAL result,
        # not a failure), 2+ = actual error. Treat only >1 as failure, otherwise
        # we'd raise ToolFailedError every time secrets are detected.
        if result.returncode not in (0, 1):
            raise ToolFailedError(
                tool=self.tool_name,
                detail=f"exit code {result.returncode}: {result.stderr[:200]}",
            )

        return self._parse_output(result.stdout, repo_path)

    def _parse_output(self, stdout: str, scope: str) -> list[Finding]:
        findings: list[Finding] = []
        text = (stdout or "").strip()
        if not text:
            return findings

        # gitleaks emits a JSON array when --report-format json is used.
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Defensive: tolerate a stream of JSON objects (one per line) too.
            data = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not isinstance(data, list):
            return findings

        for obj in data:
            if not isinstance(obj, dict):
                continue
            rule_id = obj.get("RuleID", "") or ""
            file_path = obj.get("File", "") or ""
            line_no = obj.get("StartLine", "") or ""
            repo = obj.get("Repo", "") or scope
            secret = obj.get("Secret", "") or ""
            match = obj.get("Match", "") or ""
            description = obj.get("Description", "") or ""
            tags = obj.get("Tags", []) or []

            redacted = _redact(secret)

            # Data minimization (spec §4.3): build raw/evidence WITHOUT the
            # plaintext secret. We also redact Match (which is usually the same
            # as Secret, but may include surrounding context).
            raw = {
                "description": description,
                "start_line": obj.get("StartLine"),
                "end_line": obj.get("EndLine"),
                "start_column": obj.get("StartColumn"),
                "end_column": obj.get("EndColumn"),
                "file": file_path,
                "repo": repo,
                "rule_id": rule_id,
                "tags": list(tags) if isinstance(tags, list) else [tags],
                "redacted_secret": redacted,
                "redacted_match": _redact(match) if match else "",
            }

            evidence = {
                "repo": repo,
                "file": file_path,
                "line": line_no,
                "rule_id": rule_id,
                "secret_type": description or rule_id,
                "redacted_secret": redacted,
            }

            title = f"Secret leak: {rule_id} in {file_path}:{line_no}"

            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.SECRET_LEAK,
                severity=_severity_for_rule(rule_id),
                target=scope,
                title=title,
                evidence=evidence,
                source_tool=self.tool_name,
                raw=raw,
                timestamp=dt.datetime.now(dt.timezone.utc),
            ))

        return findings
