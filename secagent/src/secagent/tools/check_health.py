"""Tool function: check_health.

Diagnoses the SecAgent environment and reports system health.
No authz_token required — it's a diagnostic tool, not a scan.

Accepts the standard tool signature (gate, params, authz_token, caller_id)
for uniform MCP dispatch, but gate and authz_token are ignored because no
target resources are accessed.
"""
from __future__ import annotations

import os
import platform
import sys
from pathlib import Path
from typing import Any

from secagent.binmgmt.launcher import Launcher
from secagent.binmgmt.versions import known_tools
from secagent.config import Config
from secagent.core.gate import ComplianceGate
from secagent.core.proxy import ProxyManager
from secagent.storage.sqlite_store import SQLiteStore


def _version_for(tool_name: str, bin_dir: str) -> str:
    """Get the version string for a tool binary.

    Different tools use different flags:
      - projectdiscovery tools (subfinder, httpx, nuclei, naabu): -version
      - ffuf, gitleaks: --version
      - theHarvester: --version
    """
    tool_path = Path(bin_dir) / tool_name
    if not tool_path.is_file() or not os.access(tool_path, os.X_OK):
        return ""

    flags = ["--version", "-version", "-v"]
    launcher = Launcher(timeout_sec=10)
    for flag in flags:
        try:
            result = launcher.run([str(tool_path), flag])
            if result.returncode == 0:
                line = (result.stdout or result.stderr or "").strip().split("\n")[0]
                if line:
                    return line[:200]
            # naabu returns 0 but writes version to stderr
            stderr_line = (result.stderr or "").strip().split("\n")[0]
            if stderr_line and ("version" in stderr_line.lower() or "v" == stderr_line[0:1].lower()):
                return stderr_line[:200]
        except Exception:
            continue
    return ""


def _check_db(config: Config) -> dict[str, Any]:
    """Check database connectivity with proper connection cleanup."""
    try:
        store = SQLiteStore(config.db_path)
        store.bootstrap()
    except Exception as e:
        return {"status": "error", "path": config.db_path, "error": f"bootstrap: {e}"}

    conn = store._connect()
    try:
        token_count = conn.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0]
        findings_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        audit_count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        return {
            "status": "ok",
            "path": config.db_path,
            "tokens": token_count,
            "findings": findings_count,
            "audit_entries": audit_count,
        }
    except Exception as e:
        return {"status": "error", "path": config.db_path, "error": str(e)}
    finally:
        conn.close()


def check_health(
    *,
    gate: ComplianceGate | None = None,
    params: dict[str, Any] | None = None,
    authz_token: str | None = None,
    caller_id: str = "system",
) -> dict[str, Any]:
    """Run a comprehensive health check on the SecAgent environment.

    Args:
        gate: ComplianceGate (ignored — no target authorization needed).
        params: Parameters dict (ignored — health checks have no params).
        authz_token: Authorization token (ignored — health check is unauthenticated).
        caller_id: Caller identifier (default "system").

    Returns a dict with status, db, binaries, wordlists, etc.
    """
    cfg = Config.load()
    bin_dir = os.environ.get("SECAGENT_BINARIES_DIR", cfg.binaries_dir)
    wl_dir = os.environ.get("SECAGENT_WORDLISTS_DIR", cfg.wordlists_dir)

    # Database
    db_status = _check_db(cfg)

    # Binaries — check all known tools plus extras that may be installed
    all_tool_names = sorted(set(known_tools()) | {"naabu", "ffuf"})
    binaries: dict[str, Any] = {}
    for tool_name in all_tool_names:
        tool_path = Path(bin_dir) / tool_name
        if not tool_path.is_file():
            binaries[tool_name] = {"found": False, "error": "binary not found"}
            continue
        if not os.access(tool_path, os.X_OK):
            binaries[tool_name] = {"found": False, "error": "binary not executable"}
            continue
        version = _version_for(tool_name, bin_dir)
        binaries[tool_name] = {
            "found": True,
            "path": str(tool_path),
        }
        if version:
            binaries[tool_name]["version"] = version

    # Wordlists
    wordlist_builtin = Path(wl_dir) / "paths_builtin.txt"
    wordlist_common = Path(wl_dir) / "common.txt"
    wordlists = {
        "builtin": {
            "found": wordlist_builtin.is_file(),
            "path": str(wordlist_builtin),
        },
        "common": {
            "found": wordlist_common.is_file(),
            "path": str(wordlist_common),
        },
        "wordlists_dir": wl_dir,
    }

    # Check CAP_NET_RAW for naabu SYN mode
    naabu_path = Path(bin_dir) / "naabu"
    cap_net_raw: dict[str, Any] = {"status": "not_installed"}
    if naabu_path.is_file():
        try:
            import subprocess
            result = subprocess.run(
                ["getcap", str(naabu_path)],
                capture_output=True, text=True, timeout=5,
            )
            stdout = result.stdout.strip()
            if "cap_net_raw" in stdout:
                cap_net_raw = {"status": "ok", "detail": stdout}
            else:
                cap_net_raw = {"status": "missing", "detail": stdout or "no capabilities set"}
        except FileNotFoundError:
            cap_net_raw = {"status": "unknown", "detail": "getcap not available"}
        except Exception as e:
            cap_net_raw = {"status": "error", "detail": str(e)}

    # Proxy status
    proxy_mgr = ProxyManager(cfg.proxy)
    proxy_status = proxy_mgr.status() if proxy_mgr.is_enabled() else {"enabled": False}

    # System info
    system_info = {
        "python_version": sys.version.split()[0],
        "platform": platform.system(),
        "arch": platform.machine(),
    }

    # Overall status
    critical_tools = {"subfinder", "httpx", "nuclei"}
    critical_ok = any(
        info.get("found") for name, info in binaries.items()
        if name in critical_tools
    )
    all_ok = db_status.get("status") == "ok" and critical_ok

    return {
        "status": "ok" if all_ok else "degraded",
        "db": db_status,
        "binaries": binaries,
        "wordlists": wordlists,
        "capabilities": {"cap_net_raw": cap_net_raw},
        "system": system_info,
        "proxy": proxy_status,
        "config": {
            "db_path": cfg.db_path,
            "binaries_dir": bin_dir,
            "wordlists_dir": wl_dir,
        },
    }
