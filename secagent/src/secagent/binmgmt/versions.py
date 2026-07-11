"""Version lock list for open-source tool binaries (spec §5.2).

Each tool binary is pinned to a specific version with a SHA-256 checksum.
Upgrade paths: bump version + checksum in this file, run tests, commit.
"""
from __future__ import annotations

from secagent.core.errors import InvalidInputError

VERSIONS: dict[str, dict] = {
    "subfinder": {
        "version": "2.6.8",
        "checksum_sha256": "498d2f7ea16eaa352f1dad29b12c791802661e49502d5536f4f979cf5e602101",
        "download_url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.8/subfinder_2.6.8_macOS_amd64.zip",
        "binary_name": "subfinder",
    },
    "httpx": {
        "version": "1.6.8",
        "checksum_sha256": "d895559e4c76396db1750bfa7b0eb2028b47be00a40f1672ff6e9ddddc15470b",
        "download_url": "https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_macOS_amd64.zip",
        "binary_name": "httpx",
    },
    "nuclei": {
        "version": "3.3.5",
        "checksum_sha256": "7566277a7c1e246f8b3fd306888df37abf1e2d84d3b0855755e5b329d670cdbf",
        "download_url": "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_macOS_amd64.zip",
        "binary_name": "nuclei",
    },
    "gitleaks": {
        "version": "8.21.2",
        "checksum_sha256": "17c8eb3fc101eb7d0dcb8a7264b83758b5a906b91cd96eba1542db3c40d12e38",
        "download_url": "https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_darwin_x64.tar.gz",
        "binary_name": "gitleaks",
    },
    "theharvester": {
        "version": "4.6.0",
        "checksum_sha256": "c28d38043a48c1a022ac1abea9c386c855422bf32efe9ff5f083616d2d850f2c",
        "download_url": "https://github.com/laramies/theHarvester/releases/download/v4.6.0/theHarvester-4.6.0.tar.gz",
        "binary_name": "theHarvester",
    },
    "naabu": {
        "version": "2.3.1",
        "checksum_sha256": "72b5bffb192a4cb4d9c10f3f6f410203b5f7a6562445d96062fb4d501f4f13be",
        "download_url": "https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_macOS_amd64.zip",
        "binary_name": "naabu",
    },
    "ffuf": {
        "version": "2.1.0",
        "checksum_sha256": "3637c82ca2b4c37339c3f2cfc81669f10d19c6b5e34db8c59b93acfaf04246f9",
        "download_url": "https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_macos_amd64.tar.gz",
        "binary_name": "ffuf",
    },
    "katana": {
        "version": "1.1.2",
        "checksum_sha256": "placeholder-sha256-katana-1.1.2",
        "download_url": "https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_macOS_amd64.zip",
        "binary_name": "katana",
    },
    "dnsx": {
        "version": "1.2.2",
        "checksum_sha256": "placeholder-sha256-dnsx-1.2.2",
        "download_url": "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.2/dnsx_1.2.2_macOS_amd64.zip",
        "binary_name": "dnsx",
    },
    "tlsx": {
        "version": "1.1.8",
        "checksum_sha256": "placeholder-sha256-tlsx-1.1.8",
        "download_url": "https://github.com/projectdiscovery/tlsx/releases/download/v1.1.8/tlsx_1.1.8_macOS_amd64.zip",
        "binary_name": "tlsx",
    },
    "uncover": {
        "version": "1.0.9",
        "checksum_sha256": "placeholder-sha256-uncover-1.0.9",
        "download_url": "https://github.com/projectdiscovery/uncover/releases/download/v1.0.9/uncover_1.0.9_macOS_amd64.zip",
        "binary_name": "uncover",
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
