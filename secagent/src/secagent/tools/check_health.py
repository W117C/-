"""Health check tool — verify environment readiness before scanning."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

from secagent.binmgmt.versions import VERSIONS
from secagent.core.gate import ComplianceGate


def _check_binary(name: str, binaries_dir: str) -> dict[str, Any]:
    """Check if a binary exists and report its status."""
    info = VERSIONS.get(name, {"version": "?", "binary_name": name})
    binary_path = os.path.join(binaries_dir, info["binary_name"])
    resolved = shutil.which(binary_path) or (
        binary_path if os.path.isfile(binary_path) else None
    )
    if resolved:
        return {
            "name": name,
            "status": "ok",
            "path": resolved,
            "version": info.get("version", "?"),
        }
    return {
        "name": name,
        "status": "missing",
        "version": info.get("version", "?"),
        "hint": f"run 'make install' or place binary at {binary_path}",
    }


def check_health(
    *,
    gate: ComplianceGate | None = None,
    params: dict[str, Any] | None = None,
    authz_token: str | None = None,
    caller_id: str = "system",
) -> dict[str, Any]:
    """Comprehensive health check for the SecAgent environment.

    Checks:
      - All 6 tool binaries (subfinder, httpx, nuclei, gitleaks, naabu, ffuf)
      - Python version
      - Database connectivity
      - Wordlists availability
      - Nuclei templates

    No authz_token required — this is a diagnostic tool, not a scan.
    """
    binaries_dir = os.environ.get("SECAGENT_BINARIES_DIR", "./bin")
    results: dict[str, Any] = {
        "tool": "check_health",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }

    # --- Binaries ---
    binaries = []
    all_ok = True
    for name in ("subfinder", "httpx", "nuclei", "gitleaks", "naabu", "ffuf"):
        check = _check_binary(name, binaries_dir)
        binaries.append(check)
        if check["status"] != "ok":
            all_ok = False
    results["binaries"] = binaries
    results["binaries_all_ok"] = all_ok

    # --- Wordlists ---
    wordlists_dir = params.get("wordlists_dir", "./wordlists") if params else "./wordlists"
    wl_builtin = os.path.join(wordlists_dir, "paths_builtin.txt")
    wl_common = os.path.join(wordlists_dir, "common.txt")
    results["wordlists"] = {
        "paths_builtin": os.path.isfile(wl_builtin),
        "common": os.path.isfile(wl_common),
    }

    # --- Database ---
    if gate and hasattr(gate, "store"):
        try:
            conn = gate.store._connect()
            conn.execute("SELECT 1").fetchone()
            conn.close()
            results["database"] = "ok"
        except Exception as e:
            results["database"] = f"error: {e}"
    else:
        results["database"] = "not checked"

    # --- Nuclei templates ---
    nuclei_path = binaries_dir + "/nuclei"
    if os.path.isfile(nuclei_path):
        templates_dir = ""
        for candidate in ("~/nuclei-templates", "~/.local/nuclei-templates", "~/.local/share/nuclei-templates"):
            td = os.path.expanduser(candidate)
            if os.path.isdir(td):
                templates_dir = td
                break
        if templates_dir:
            count = len(list(Path(templates_dir).rglob("*.yaml")))
            results["nuclei_templates"] = f"{count} templates"
        else:
            results["nuclei_templates"] = "not installed (run 'make update-templates')"
    else:
        results["nuclei_templates"] = "nuclei binary not found"

    results["summary"] = (
        "✅ All checks passed" if all_ok and results.get("database") in ("ok", "not checked")
        else "⚠️ Some checks failed — review details"
    )
    return results
