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
