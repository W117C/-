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
    "httpx": {
        "version": "1.6.8",
        "checksum_sha256": "placeholder_sha256_until_real_binary_is_downloaded",
        "download_url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_macOS_amd64.zip",
        "binary_name": "httpx",
    },
    "nuclei": {
        "version": "3.3.5",
        "checksum_sha256": "placeholder_sha256_until_real_binary_is_downloaded",
        "download_url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_macOS_amd64.zip",
        "binary_name": "nuclei",
    },
    "gitleaks": {
        "version": "8.21.2",
        "checksum_sha256": "placeholder_sha256_until_real_binary_is_downloaded",
        "download_url": "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_darwin_x64.tar.gz",
        "binary_name": "gitleaks",
    },
    "theharvester": {
        "version": "4.6.0",
        "checksum_sha256": "placeholder_sha256_until_real_binary_is_downloaded",
        "download_url": "https://github.com/laramies/theHarvester/releases/download/v4.6.0/theHarvester-4.6.0.tar.gz",
        "binary_name": "theHarvester",
    },
    # crawl_target uses a built-in Python HTTP crawler (no external binary),
    # so it is intentionally NOT registered here.
}


def get_tool_version(tool_name: str) -> dict:
    if tool_name not in VERSIONS:
        raise InvalidInputError(field="tool_name", reason=f"unknown tool '{tool_name}'. Known: {list(VERSIONS.keys())}")
    return VERSIONS[tool_name]


def known_tools() -> list[str]:
    return list(VERSIONS.keys())
