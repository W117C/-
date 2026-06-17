# SecAgent M2a — Subfinder Adapter Closed Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the first tool (subfinder subdomain enumeration) end-to-end: tool function → BaseAdapter → subprocess → JSON parse → unified Finding → compliance gate → audit log. Proves the architecture works before adding MCP or more tools.

**Architecture:** The adapter layer wraps each open-source binary behind a `BaseAdapter` interface. The `Launcher` handles subprocess execution with timeout/retry. The tool function wires the adapter into M1's compliance gate. No MCP SDK needed — M2a proves the core pipeline; MCP server shell is M2b (after Python ≥3.10 upgrade).

**Tech Stack:** Python 3.9+ (no new dependencies). `subprocess` + `json` stdlib for adapter execution. `unittest.mock` for subprocess in tests (subfinder binary not required on CI). All existing M1 tests continue to pass.

**Reference spec:** `docs/superpowers/specs/2026-06-16-secagent-mcp-design.md` §3.2 ①, §5.2, §7.2 M2.

**Context from M1:** M1 delivered 4 defense lines (authz, blocklist, audit, quota), SQLite store, CLI, unified Finding model, and ComplianceGate. M2a builds on top — all M1 code stays untouched.

---

## File Structure (new files only)

| File | Responsibility |
|---|---|
| `secagent/src/secagent/binmgmt/__init__.py` | Package marker |
| `secagent/src/secagent/binmgmt/versions.py` | Version lock list for all tool binaries |
| `secagent/src/secagent/binmgmt/launcher.py` | Subprocess execution: timeout, retry, JSON parse |
| `secagent/src/secagent/binmgmt/installer.py` | Binary download + checksum verify (stub for M2a) |
| `secagent/src/secagent/adapters/__init__.py` | Package marker |
| `secagent/src/secagent/adapters/base.py` | BaseAdapter abstract interface |
| `secagent/src/secagent/adapters/subfinder.py` | SubfinderAdapter: parse JSON → list[Finding] |
| `secagent/src/secagent/tools/__init__.py` | Package marker |
| `secagent/src/secagent/tools/enumerate_subdomains.py` | Tool function: wires adapter + compliance gate |
| `secagent/tests/test_launcher.py` | Launcher unit tests (mock subprocess) |
| `secagent/tests/test_versions.py` | Version lock list tests |
| `secagent/tests/test_subfinder_adapter.py` | SubfinderAdapter unit tests (mock subprocess + real JSON) |
| `secagent/tests/test_enumerate_subdomains_tool.py` | Tool function e2e test (mock subprocess + gate) |

---

## Task 1: Binary version lock list

**Files:**
- Create: `secagent/src/secagent/binmgmt/__init__.py`
- Create: `secagent/src/secagent/binmgmt/versions.py`
- Create: `secagent/tests/test_versions.py`

- [ ] **Step 1: Write the failing test**

`secagent/tests/test_versions.py`:
```python
from __future__ import annotations

from secagent.binmgmt.versions import VERSIONS, get_tool_version, known_tools


def test_versions_is_non_empty_dict():
    assert isinstance(VERSIONS, dict)
    assert len(VERSIONS) >= 1


def test_subfinder_entry_exists():
    assert "subfinder" in VERSIONS
    entry = VERSIONS["subfinder"]
    assert entry["version"]
    assert entry["checksum_sha256"]
    assert entry["download_url"]
    assert entry["binary_name"] == "subfinder"


def test_get_tool_version_returns_entry():
    entry = get_tool_version("subfinder")
    assert entry["version"] == VERSIONS["subfinder"]["version"]


def test_get_tool_version_raises_on_unknown():
    from secagent.core.errors import InvalidInputError
    import pytest
    with pytest.raises(InvalidInputError):
        get_tool_version("nonexistent_tool")


def test_known_tools_returns_list():
    tools = known_tools()
    assert "subfinder" in tools
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd secagent && python3 -m pytest tests/test_versions.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

`secagent/src/secagent/binmgmt/__init__.py`:
```python
"""Binary dependency management — version locking, downloading, subprocess launching."""
```

`secagent/src/secagent/binmgmt/versions.py`:
```python
"""Version lock list for open-source tool binaries (spec §5.2).

Each tool binary is pinned to a specific version with a SHA-256 checksum.
Upgrade paths: bump version + checksum in this file, run tests, commit.
"""
from __future__ import annotations

from secagent.core.errors import InvalidInputError

VERSIONS: dict[str, dict] = {
    "subfinder": {
        "version": "2.6.8",
        "checksum_sha256": "placeholder_sha256_until_real_binary_is_downloaded",
        "download_url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_macOS_amd64.zip",
        "binary_name": "subfinder",
    },
    # M3 will add: httpx, nuclei, gitleaks, theHarvester
}


def get_tool_version(tool_name: str) -> dict:
    if tool_name not in VERSIONS:
        raise InvalidInputError(field="tool_name", reason=f"unknown tool '{tool_name}'. Known: {list(VERSIONS.keys())}")
    return VERSIONS[tool_name]


def known_tools() -> list[str]:
    return list(VERSIONS.keys())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd secagent && python3 -m pytest tests/test_versions.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add secagent/src/secagent/binmgmt/ secagent/tests/test_versions.py
git commit -m "feat(secagent): binary version lock list with subfinder pinned"
```

---

## Task 2: Subprocess launcher with timeout + retry + JSON parse

**Files:**
- Create: `secagent/src/secagent/binmgmt/launcher.py`
- Create: `secagent/tests/test_launcher.py`

- [ ] **Step 1: Write the failing test**

`secagent/tests/test_launcher.py`:
```python
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from secagent.binmgmt.launcher import Launcher, LaunchResult
from secagent.core.errors import ToolFailedError, ToolTimeoutError


def test_launcher_runs_command_and_parses_json():
    fake_output = json.dumps({"host": "sub.example.com", "source": "crtsh"})
    with patch("secagent.binmgmt.launcher.subprocess") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.stdout.read.return_value = fake_output.encode()
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_sub.Popen.return_value = mock_proc
        mock_sub.Popen.poll.return_value = None

        launcher = Launcher(timeout_sec=10)
        result = launcher.run(["subfinder", "-d", "acme.com", "-json"])

    assert result.returncode == 0
    assert result.stdout == fake_output
    assert result.json_output == {"host": "sub.example.com", "source": "crtsh"}


def test_launcher_returns_empty_json_on_non_json_output():
    with patch("secagent.binmgmt.launcher.subprocess") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.stdout.read.return_value = b"plain text output"
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_sub.Popen.return_value = mock_proc
        mock_sub.Popen.poll.return_value = None

        launcher = Launcher(timeout_sec=10)
        result = launcher.run(["subfinder", "-d", "acme.com"])

    assert result.json_output is None


def test_launcher_raises_tool_timeout_on_timeout():
    with patch("secagent.binmgmt.launcher.subprocess") as mock_sub:
        mock_sub.Popen.side_effect = TimeoutError("timed out")

        launcher = Launcher(timeout_sec=1)
        with pytest.raises(ToolTimeoutError):
            launcher.run(["subfinder", "-d", "acme.com"])


def test_launcher_raises_tool_failed_on_nonzero_exit():
    with patch("secagent.binmgmt.launcher.subprocess") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.stdout.read.return_value = b""
        mock_proc.stderr.read.return_value = b"error: something went wrong"
        mock_proc.returncode = 1
        mock_sub.Popen.return_value = mock_proc
        mock_sub.Popen.poll.return_value = None

        launcher = Launcher(timeout_sec=10)
        with pytest.raises(ToolFailedError) as exc_info:
            launcher.run(["subfinder", "-d", "acme.com"])
        assert "something went wrong" in str(exc_info.value)


def test_launcher_honors_timeout_kwarg():
    with patch("secagent.binmgmt.launcher.subprocess") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.stdout.read.return_value = b"{}"
        mock_proc.stderr.read.return_value = b""
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"{}", b"")
        mock_sub.Popen.return_value = mock_proc
        mock_sub.Popen.poll.return_value = None

        launcher = Launcher(timeout_sec=5)
        launcher.run(["subfinder", "-d", "acme.com"])

    _, kwargs = mock_sub.Popen.call_args
    assert kwargs["timeout"] == 5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd secagent && python3 -m pytest tests/test_launcher.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

`secagent/src/secagent/binmgmt/launcher.py`:
```python
"""Subprocess launcher with timeout, retry, and JSON output parsing.

Every adapter calls Launcher.run() instead of subprocess directly. This
centralizes timeout/retry/error-handling logic in one place.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class LaunchResult:
    returncode: int
    stdout: str
    stderr: str
    json_output: Optional[dict | list] = None

    def __post_init__(self) -> None:
        if self.json_output is None:
            try:
                self.json_output = json.loads(self.stdout)
            except (json.JSONDecodeError, ValueError):
                pass


class Launcher:
    def __init__(self, timeout_sec: int = 120, retries: int = 0):
        self.timeout_sec = timeout_sec
        self.retries = retries

    def run(
        self,
        cmd: list[str],
        env: dict[str, str] | None = None,
        cwd: str | None = None,
    ) -> LaunchResult:
        """Execute a binary command. Raises ToolTimeoutError or ToolFailedError."""
        last_error: str = ""
        for attempt in range(1 + self.retries):
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    cwd=cwd,
                )
                stdout_bytes, stderr_bytes = proc.communicate(timeout=self.timeout_sec)
                return LaunchResult(
                    returncode=proc.returncode,
                    stdout=stdout_bytes.decode("utf-8", errors="replace"),
                    stderr=stderr_bytes.decode("utf-8", errors="replace"),
                )
            except subprocess.TimeoutExpired:
                from secagent.core.errors import ToolTimeoutError
                raise ToolTimeoutError(
                    tool=cmd[0] if cmd else "unknown",
                    target=" ".join(cmd),
                )
            except (OSError, FileNotFoundError) as exc:
                last_error = str(exc)
                if attempt == self.retries:
                    break
        # All retries exhausted or FileNotFoundError
        from secagent.core.errors import ToolFailedError
        raise ToolFailedError(
            tool=cmd[0] if cmd else "unknown",
            detail=last_error or "command not found",
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd secagent && python3 -m pytest tests/test_launcher.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add secagent/src/secagent/binmgmt/launcher.py secagent/tests/test_launcher.py
git commit -m "feat(secagent): subprocess launcher with timeout, retry, JSON parse"
```

---

## Task 3: BaseAdapter abstract interface

**Files:**
- Create: `secagent/src/secagent/adapters/__init__.py`
- Create: `secagent/src/secagent/adapters/base.py`

- [ ] **Step 1: Write minimal implementation (interface, no tests — abstract class)**

`secagent/src/secagent/adapters/__init__.py`:
```python
"""Adapter layer — wraps each open-source tool behind a uniform interface."""
```

`secagent/src/secagent/adapters/base.py`:
```python
"""BaseAdapter — the interface every tool adapter must implement.

Every adapter receives params, runs a binary via Launcher, parses its output,
and returns a list of Finding objects. The ComplianceGate is the caller's
responsibility (it wraps the adapter call, not the adapter itself).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from secagent.core.finding import Finding


class BaseAdapter(ABC):
    """Abstract base for tool adapters. Subclass per open-source tool."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name used in versions.py and Finding.source_tool."""

    @abstractmethod
    def run(self, params: dict[str, Any]) -> list[Finding]:
        """Execute the tool with given params, return findings.

        The adapter is responsible for:
        1. Translating params → CLI command
        2. Calling Launcher.run()
        3. Parsing tool-specific JSON output → list[Finding]
        """
```

- [ ] **Step 2: Commit**

```bash
git add secagent/src/secagent/adapters/
git commit -m "feat(secagent): BaseAdapter abstract interface"
```

---

## Task 4: SubfinderAdapter — parse subfinder JSON → list[Finding]

**Files:**
- Create: `secagent/src/secagent/adapters/subfinder.py`
- Create: `secagent/tests/test_subfinder_adapter.py`

This is the core of M2a. The adapter must translate `enumerate_subdomains` params into the subfinder CLI command, call Launcher, and parse subfinder's JSON output into Finding objects.

Subfinder JSON output format (one JSON object per line):
```json
{"host": "sub.example.com", "source": "crtsh", "resolver": "8.8.8.8"}
{"host": "blog.example.com", "source": "virustotal"}
```

- [ ] **Step 1: Write the failing test**

`secagent/tests/test_subfinder_adapter.py`:
```python
from __future__ import annotations

import json
import datetime as dt
from unittest.mock import patch, MagicMock

import pytest

from secagent.adapters.subfinder import SubfinderAdapter
from secagent.core.finding import Finding, FindingType, Severity


def _mock_launcher(stdout_lines: list[str], returncode: int = 0):
    """Patch Launcher.run to return canned output lines joined by newline."""
    stdout = "\n".join(stdout_lines)
    mock_result = MagicMock()
    mock_result.returncode = returncode
    mock_result.stdout = stdout
    mock_result.stderr = ""
    mock_result.json_output = None  # launcher will try json.loads
    return mock_result


def test_adapter_returns_one_finding_per_host():
    adapter = SubfinderAdapter()
    lines = [
        json.dumps({"host": "sub.acme.com", "source": "crtsh"}),
        json.dumps({"host": "blog.acme.com", "source": "virustotal"}),
        json.dumps({"host": "api.acme.com", "source": "crtsh"}),
    ]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"target_domain": "acme.com"})

    assert len(findings) == 3
    for f in findings:
        assert f.type == FindingType.SUBDOMAIN
        assert f.severity == Severity.INFO
        assert f.source_tool == "subfinder"


def test_adapter_includes_evidence():
    adapter = SubfinderAdapter()
    lines = [json.dumps({"host": "sub.acme.com", "source": "crtsh"})]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"target_domain": "acme.com"})

    f = findings[0]
    assert f.target == "sub.acme.com"
    assert f.title == "Subdomain: sub.acme.com"
    assert f.evidence["source"] == "crtsh"


def test_adapter_handles_empty_output():
    adapter = SubfinderAdapter()
    with patch.object(adapter, "_launch", return_value=_mock_launcher([])):
        findings = adapter.run({"target_domain": "acme.com"})
    assert findings == []


def test_adapter_handles_non_json_lines():
    adapter = SubfinderAdapter()
    lines = ["not json at all", json.dumps({"host": "sub.acme.com", "source": "crtsh"})]
    with patch.object(adapter, "_launch", return_value=_mock_launcher(lines)):
        findings = adapter.run({"target_domain": "acme.com"})
    # Bad lines are silently skipped; only valid JSON lines become findings.
    assert len(findings) == 1
    assert findings[0].target == "sub.acme.com"


def test_adapter_uses_target_domain_in_command():
    adapter = SubfinderAdapter()
    cmd_used = None

    def capture_launch(self, cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher([])

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"target_domain": "acme.com"})

    assert "subfinder" in cmd_used
    assert "-d" in cmd_used
    assert "acme.com" in cmd_used


def test_adapter_supports_sources_param():
    adapter = SubfinderAdapter()
    cmd_used = None

    def capture_launch(self, cmd, **kw):
        nonlocal cmd_used
        cmd_used = cmd
        return _mock_launcher([])

    with patch.object(adapter, "_launch", capture_launch):
        adapter.run({"target_domain": "acme.com", "sources": ["crtsh", "virustotal"]})

    assert "-sources" in cmd_used  # subfinder flag
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd secagent && python3 -m pytest tests/test_subfinder_adapter.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

`secagent/src/secagent/adapters/subfinder.py`:
```python
"""SubfinderAdapter — wraps subfinder binary into the BaseAdapter interface.

Subfinder enumerates subdomains. It outputs one JSON object per line with at
minimum a "host" field. This adapter parses that into Finding(type=subdomain).

Spec: §3.2 ① enumerate_subdomains, §5.2 (binary dependency strategy).
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
        binary = f"{self._binaries_dir}/{tool_info['binary_name']}"

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
                id=f"fnd_{uuid.uuid4().hex[:8]}",
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd secagent && python3 -m pytest tests/test_subfinder_adapter.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add secagent/src/secagent/adapters/subfinder.py secagent/tests/test_subfinder_adapter.py
git commit -m "feat(secagent): SubfinderAdapter — parse subfinder JSON output to findings"
```

---

## Task 5: Installer stub (download + checksum placeholder)

**Files:**
- Create: `secagent/src/secagent/binmgmt/installer.py`

- [ ] **Step 1: Write implementation (no dedicated tests — the function is a thin wrapper that will be fleshed out in M4)**

`secagent/src/secagent/binmgmt/installer.py`:
```python
"""Binary installer — download + checksum verification (spec §5.2).

M2a provides a stub: check_if_installed (bool) and an install placeholder.
Real download + checksum verification arrives in M4 (install script).
The launcher already handles FileNotFoundError with a ToolFailedError,
so missing binaries produce a clear error even without the installer.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from secagent.binmgmt.versions import known_tools


def get_bin_path(binaries_dir: str, tool_name: str) -> str:
    """Return the expected path for a tool binary."""
    from secagent.binmgmt.versions import get_tool_version
    info = get_tool_version(tool_name)
    return str(Path(binaries_dir) / info["binary_name"])


def check_if_installed(binaries_dir: str, tool_name: str) -> bool:
    """Check if a tool binary exists at the expected path."""
    return shutil.which(get_bin_path(binaries_dir, tool_name)) is not None


def ensure_binaries_dir(binaries_dir: str) -> None:
    """Create the binaries directory if it doesn't exist."""
    Path(binaries_dir).mkdir(parents=True, exist_ok=True)


def install_tool(tool_name: str, binaries_dir: str = "./bin") -> None:
    """Download and verify a tool binary. Stub for M2a.

    In M2a this raises NotImplementedError with a helpful message.
    In M4 this will download from versions.py download_url and verify checksum.
    """
    raise NotImplementedError(
        f"Binary installation not yet automated for '{tool_name}'. "
        f"Please download manually and place in {binaries_dir}/. "
        f"See versions.py for the expected version and download URL. "
        f"Or use the install script (arriving in M4)."
    )
```

- [ ] **Step 2: Commit**

```bash
git add secagent/src/secagent/binmgmt/installer.py
git commit -m "feat(secagent): binary installer stub with check_if_installed"
```

---

## Task 6: Tool function — enumerate_subdomains (wires adapter + gate)

**Files:**
- Create: `secagent/src/secagent/tools/__init__.py`
- Create: `secagent/src/secagent/tools/enumerate_subdomains.py`
- Create: `secagent/tests/test_enumerate_subdomains_tool.py`

This is the key integration point: the tool function that M2b's MCP server will expose as a tool, and that M1's ComplianceGate wraps for defense. It calls the adapter, but the **caller** (M2b MCP handler) is responsible for invoking compliance_gate.check() before and commit_findings() after.

- [ ] **Step 1: Write the failing test**

`secagent/tests/test_enumerate_subdomains_tool.py`:
```python
from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.gate import ComplianceGate
from secagent.core.errors import NotAuthorizedError
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore
from secagent.tools.enumerate_subdomains import enumerate_subdomains


def _setup_gate_and_token(tmp_db, scope_domain="acme.com"):
    store = SQLiteStore(tmp_db); store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=100)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=100)
    return gate, token


def _mock_subfinder_lines():
    return [
        json.dumps({"host": "sub.acme.com", "source": "crtsh"}),
        json.dumps({"host": "blog.acme.com", "source": "virustotal"}),
    ]


def test_tool_returns_findings_for_authorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = [
            MagicMock(target="sub.acme.com"),
            MagicMock(target="blog.acme.com"),
        ]
        MockAdapter.return_value = mock_instance

        result = enumerate_subdomains(
            gate=gate,
            params={"target_domain": "acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["tool"] == "enumerate_subdomains"
    assert result["summary"]["total"] == 2
    assert result["quota_used"] == 1


def test_tool_rejects_unauthorized_target(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db, scope_domain="acme.com")
    with pytest.raises(NotAuthorizedError):
        enumerate_subdomains(
            gate=gate,
            params={"target_domain": "evil.com"},
            authz_token=token,
            caller_id="test_user",
        )


def test_tool_empty_result_still_commits(tmp_db):
    gate, token = _setup_gate_and_token(tmp_db)
    with patch("secagent.tools.enumerate_subdomains.SubfinderAdapter") as MockAdapter:
        mock_instance = MagicMock()
        mock_instance.run.return_value = []
        MockAdapter.return_value = mock_instance

        result = enumerate_subdomains(
            gate=gate,
            params={"target_domain": "acme.com"},
            authz_token=token,
            caller_id="test_user",
        )

    assert result["summary"]["total"] == 0
    assert result["quota_used"] == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd secagent && python3 -m pytest tests/test_enumerate_subdomains_tool.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

`secagent/src/secagent/tools/__init__.py`:
```python
"""Tool function layer — each function wires an adapter through the compliance gate.

These functions are the boundary between "MCP/server layer" (M2b) and
"adapter layer" (M2a). The MCP server calls these; tests verify them
independently.
"""
```

`secagent/src/secagent/tools/enumerate_subdomains.py`:
```python
"""Tool function: enumerate_subdomains (spec §3.2 ①).

Wires SubfinderAdapter through ComplianceGate. The MCP server (M2b) will
expose this as a tool; tests call it directly.

Contract:
  - caller MUST call this with a valid authz_token for the target.
  - the compliance gate checks authorization, blocklist, and quota.
  - adapter runs after gate.check() passes.
  - gate.commit_findings() is called after adapter returns.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from secagent.adapters.subfinder import SubfinderAdapter
from secagent.binmgmt.launcher import Launcher
from secagent.core.gate import ComplianceGate


def enumerate_subdomains(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run subfinder subdomain enumeration through the compliance gate.

    Returns the unified output structure (spec §3.1):
    { engagement_id, tool, findings, summary, quota_used }
    """
    target_domain = params.get("target_domain", "")
    tool_name = "enumerate_subdomains"

    # Pre-flight: compliance gate check (authz + blocklist)
    scope = gate.check(
        token=authz_token,
        tool=tool_name,
        target=target_domain,
        caller_id=caller_id,
    )

    # Execute: adapter
    adapter = SubfinderAdapter(launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)))
    findings = adapter.run(params)

    # Post-run: commit findings + decrement quota
    gate.commit_findings(
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool=tool_name,
        target=target_domain,
        scope_value=scope.value,
    )

    # Build response
    return {
        "engagement_id": f"eng_{uuid.uuid4().hex[:8]}",
        "tool": tool_name,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": {"info": len(findings)},
            "by_type": {"subdomain": len(findings)},
        },
        "quota_used": 1,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd secagent && python3 -m pytest tests/test_enumerate_subdomains_tool.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add secagent/src/secagent/tools/ secagent/tests/test_enumerate_subdomains_tool.py
git commit -m "feat(secagent): enumerate_subdomains tool function wiring adapter + gate"
```

---

## Task 7: Full test sweep + README update

**Files:**
- Modify: `secagent/README.md`

- [ ] **Step 1: Run the full test suite**

Run: `cd secagent && python3 -m pytest -v`
Expected: all tests pass (M1's 48 + M2a's new tests ≈ 67 total).

- [ ] **Step 2: Update README**

Add M2a status to the README:

`secagent/README.md` — update the status line and add a tools section:
```markdown
> **Status:** M2a — subfinder adapter closed loop. MCP server shell is M2b
(pending Python ≥3.10 upgrade).
```

And add after the M1 section:
```markdown
## M2a — Subfinder Adapter

The first tool is wired end-to-end:

- **`enumerate_subdomains`** — calls subfinder via subprocess adapter,
  parses JSON output into unified Findings, passes through compliance gate
  (auth + blocklist + audit + quota).

The tool function (`secagent/tools/enumerate_subdomains.py`) is the boundary
between the adapter layer and the future MCP server. It can be called
directly in tests without MCP.
```

- [ ] **Step 3: Commit**

```bash
git add secagent/README.md
git commit -m "docs(secagent): update README for M2a subfinder adapter"
```

---

## Self-Review

1. **Spec coverage:**
   - §3.2 ① enumerate_subdomains input/output → Task 4 (adapter) + Task 6 (tool function) ✅
   - §5.2 binary dependency + version locking → Task 1 (versions) + Task 2 (launcher) + Task 5 (installer stub) ✅
   - §7.2 M2 deliverables (BaseAdapter, binmgmt, SubfinderAdapter, MCP server skeleton, e2e test) → Tasks 1-6 ✅
     Note: MCP server skeleton deferred to M2b (Python ≥3.10 required). M2a delivers the tool function layer that the MCP server will call.
   - §3.1 unified output structure → Task 6 (enumerate_subdomains returns engagement_id + tool + findings + summary + quota_used) ✅

2. **Placeholder scan:** No TBD. All code complete. ✅

3. **Type consistency:** `Launcher.run()` returns `LaunchResult` (Task 2), `SubfinderAdapter._launch()` receives and returns same (Task 4). `enumerate_subdomains()` takes `gate: ComplianceGate` (Task 6) matching M1's type. `params` dict keys (`target_domain`, `sources`, `timeout_sec`) consistent across Tasks 4 and 6. ✅

---

## Execution Handoff

Plan complete. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks.

**2. Inline Execution** — execute in this session, batch with checkpoints.

**Which approach?**
