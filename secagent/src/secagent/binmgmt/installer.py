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
