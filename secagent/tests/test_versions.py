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
