"""Unit tests for secagent.binmgmt.installer (M4)."""
from __future__ import annotations

import hashlib
import os
import stat
from unittest.mock import patch
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

from secagent.binmgmt import installer
from secagent.binmgmt.installer import (
    GO_BINARIES,
    build_download_url,
    detect_platform,
    download_file,
    extract_archive,
    install_all,
    install_tool,
    main,
    verify_checksum,
)
from secagent.core.errors import InvalidInputError, ToolFailedError


# ---------- detect_platform ----------

def test_detect_platform_returns_valid_combination():
    os_name, arch = detect_platform()
    assert os_name in {"macOS", "Linux"}
    assert arch in {"amd64", "arm64"}


# ---------- build_download_url ----------

@pytest.mark.parametrize("tool", sorted(GO_BINARIES))
def test_build_download_url_contains_version_and_platform(tool):
    os_name, arch = detect_platform()
    url = build_download_url(tool, os_name=os_name, arch=arch)
    # Contains the locked version
    from secagent.binmgmt.versions import get_tool_version
    ver = get_tool_version(tool)["version"]
    assert f"v{ver}" in url or f"_{ver}_" in url
    # Contains an arch token
    assert arch in url
    # Correct extension
    if tool in ("gitleaks", "ffuf"):
        assert url.endswith(".tar.gz")
    else:
        assert url.endswith(".zip")


def test_build_download_url_uses_os_token_per_vendor():
    # projectdiscovery tools use 'macOS'/'Linux'; gitleaks uses 'darwin'/'linux'
    sub_url = build_download_url("subfinder", os_name="macOS", arch="arm64")
    assert "macOS" in sub_url
    assert "arm64" in sub_url

    gitleaks_url = build_download_url("gitleaks", os_name="macOS", arch="arm64")
    assert "darwin" in gitleaks_url
    assert "arm64" in gitleaks_url

    gitleaks_linux = build_download_url("gitleaks", os_name="Linux", arch="amd64")
    assert "linux" in gitleaks_linux
    assert "amd64" in gitleaks_linux


def test_build_download_url_unknown_tool_raises():
    with pytest.raises(InvalidInputError):
        build_download_url("nonexistent_tool")


def test_build_download_url_defaults_to_detected_platform(monkeypatch):
    monkeypatch.setattr(installer, "detect_platform", lambda: ("macOS", "arm64"))
    url = build_download_url("subfinder")
    assert "macOS" in url
    assert "arm64" in url


# ---------- download_file ----------

def test_download_file_uses_injected_downloader(tmp_path):
    dest = tmp_path / "out.bin"
    seen = {}

    def fake_dl(url, d):
        seen["url"] = url
        seen["dest"] = d
        Path(d).write_bytes(b"hello")

    result = download_file("https://example.com/x", str(dest), downloader=fake_dl)
    assert result == str(dest)
    assert seen["url"] == "https://example.com/x"
    assert dest.read_bytes() == b"hello"


def test_download_file_raises_tool_failed_on_error(tmp_path):
    dest = tmp_path / "out.bin"

    def bad_dl(url, d):
        raise ConnectionError("boom")

    with pytest.raises(ToolFailedError):
        download_file("https://example.com/x", str(dest), downloader=bad_dl)


# ---------- verify_checksum ----------

def test_verify_checksum_correct_returns_true(tmp_path):
    f = tmp_path / "file.bin"
    data = b"hello world"
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert verify_checksum(str(f), expected) is True


def test_verify_checksum_incorrect_returns_false(tmp_path):
    f = tmp_path / "file.bin"
    f.write_bytes(b"hello world")
    wrong = "0" * 64
    assert verify_checksum(str(f), wrong) is False


def test_verify_checksum_case_insensitive(tmp_path):
    f = tmp_path / "file.bin"
    data = b"abc"
    f.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest().upper()
    assert verify_checksum(str(f), expected) is True


# ---------- extract_archive ----------

def _make_zip(path: Path, binary_name: str, payload: bytes = b"#!/bin/sh\nexit 0\n"):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(binary_name, payload)


def _make_targz(path: Path, binary_name: str, payload: bytes = b"#!/bin/sh\nexit 0\n"):
    with tarfile.open(path, "w:gz") as tf:
        ti = tarfile.TarInfo(name=binary_name)
        ti.size = len(payload)
        ti.mode = 0o755
        import io
        tf.addfile(ti, io.BytesIO(payload))


def test_extract_archive_zip_finds_and_chmods_binary(tmp_path):
    archive = tmp_path / "subfinder.zip"
    _make_zip(archive, "subfinder")
    dest_dir = tmp_path / "out"
    bin_path = extract_archive(str(archive), str(dest_dir), "subfinder")
    assert Path(bin_path).is_file()
    assert Path(bin_path).name == "subfinder"
    # executable bit set
    mode = Path(bin_path).stat().st_mode
    assert mode & stat.S_IXUSR


def test_extract_archive_tar_gz_finds_and_chmods_binary(tmp_path):
    archive = tmp_path / "gitleaks.tar.gz"
    _make_targz(archive, "gitleaks")
    dest_dir = tmp_path / "out"
    bin_path = extract_archive(str(archive), str(dest_dir), "gitleaks")
    assert Path(bin_path).is_file()
    assert Path(bin_path).name == "gitleaks"
    mode = Path(bin_path).stat().st_mode
    assert mode & stat.S_IXUSR


def test_extract_archive_missing_binary_raises(tmp_path):
    archive = tmp_path / "nuclei.zip"
    _make_zip(archive, "some_other_file")  # no 'nuclei' inside
    dest_dir = tmp_path / "out"
    with pytest.raises(ToolFailedError):
        extract_archive(str(archive), str(dest_dir), "nuclei")


def test_extract_archive_unsupported_format_raises(tmp_path):
    archive = tmp_path / "weird.rar"
    archive.write_bytes(b"junk")
    with pytest.raises(ToolFailedError):
        extract_archive(str(archive), str(tmp_path / "out"), "subfinder")


def test_extract_archive_finds_nested_binary(tmp_path):
    # Binary nested in a subdir inside the archive.
    archive = tmp_path / "httpx.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("subdir/httpx", b"#!/bin/sh\nexit 0\n")
    dest_dir = tmp_path / "out"
    bin_path = extract_archive(str(archive), str(dest_dir), "httpx")
    assert Path(bin_path).name == "httpx"
    assert Path(bin_path).is_file()


# ---------- install_tool ----------

def test_install_tool_with_mock_downloader(tmp_path):
    """install_tool end-to-end with a mocked downloader that drops a real zip."""
    binaries_dir = tmp_path / "bin"
    tool = "subfinder"

    # Build a real zip payload the mock downloader will "download".
    zip_bytes_path = tmp_path / "payload.zip"
    _make_zip(zip_bytes_path, "subfinder")
    payload = zip_bytes_path.read_bytes()

    def mock_dl(url, dest):
        Path(dest).write_bytes(payload)

    with patch("secagent.binmgmt.installer.verify_checksum", return_value=True):
        result_path = install_tool(tool, binaries_dir=str(binaries_dir), downloader=mock_dl)
    assert Path(result_path).is_file()
    assert Path(result_path).name == "subfinder"
    # Executable
    assert Path(result_path).stat().st_mode & stat.S_IXUSR


def test_install_tool_gitleaks_tar_gz(tmp_path):
    binaries_dir = tmp_path / "bin"
    tool = "gitleaks"

    archive_path = tmp_path / "payload.tar.gz"
    _make_targz(archive_path, "gitleaks")
    payload = archive_path.read_bytes()

    def mock_dl(url, dest):
        Path(dest).write_bytes(payload)

    with patch("secagent.binmgmt.installer.verify_checksum", return_value=True):
        result_path = install_tool(tool, binaries_dir=str(binaries_dir), downloader=mock_dl)
    assert Path(result_path).is_file()
    assert Path(result_path).name == "gitleaks"


def test_install_tool_unknown_tool_raises(tmp_path):
    with pytest.raises(InvalidInputError):
        install_tool("not_a_tool", binaries_dir=str(tmp_path / "bin"))


def test_install_tool_url_uses_correct_platform(monkeypatch, tmp_path):
    """The URL passed to the downloader should reflect the detected platform."""
    monkeypatch.setattr(installer, "detect_platform", lambda: ("Linux", "arm64"))

    captured = {}

    def mock_dl(url, dest):
        captured["url"] = url
        # Write a minimal zip so install_tool can proceed
        p = Path(tmp_path) / "payload.zip"
        _make_zip(p, "subfinder")
        Path(dest).write_bytes(p.read_bytes())

    with patch("secagent.binmgmt.installer.verify_checksum", return_value=True):
        install_tool("subfinder", binaries_dir=str(tmp_path / "bin"), downloader=mock_dl)
    assert "Linux" in captured["url"]
    assert "arm64" in captured["url"]


def test_install_tool_cleans_up_temp_file(tmp_path):
    """The temp archive should be deleted after install_tool completes."""
    binaries_dir = tmp_path / "bin"

    # Snapshot existing temp files
    before = set(Path("/tmp").iterdir()) if Path("/tmp").exists() else set()

    payload_path = tmp_path / "p.zip"
    _make_zip(payload_path, "subfinder")
    payload = payload_path.read_bytes()

    def mock_dl(url, dest):
        Path(dest).write_bytes(payload)

    with patch("secagent.binmgmt.installer.verify_checksum", return_value=True):
        install_tool("subfinder", binaries_dir=str(binaries_dir), downloader=mock_dl)
    # No leftover .zip files in /tmp that we created (best-effort check)
    after = set(Path("/tmp").iterdir()) if Path("/tmp").exists() else set()
    new_files = after - before
    leftovers = [f for f in new_files if f.name.endswith(".zip")]
    assert leftovers == []


# ---------- install_all ----------

def test_install_all_installs_all_four(tmp_path):
    binaries_dir = tmp_path / "bin"

    # Pre-build payloads for each tool
    payloads = {}
    for tool in GO_BINARIES:
        if tool in ("gitleaks", "ffuf"):
            p = tmp_path / f"{tool}.tar.gz"
            _make_targz(p, tool)
        else:
            p = tmp_path / f"{tool}.zip"
            _make_zip(p, tool)
        payloads[tool] = p.read_bytes()

    def mock_dl(url, dest):
        # Figure out which tool by URL
        for tool in GO_BINARIES:
            if tool in url:
                Path(dest).write_bytes(payloads[tool])
                return
        raise AssertionError(f"unexpected url: {url}")

    with patch("secagent.binmgmt.installer.verify_checksum", return_value=True):
        results = install_all(binaries_dir=str(binaries_dir), downloader=mock_dl)

    assert set(results.keys()) == GO_BINARIES
    for tool, r in results.items():
        assert r["ok"] is True, f"{tool} failed: {r['error']}"
        assert Path(r["path"]).is_file()
        assert Path(r["path"]).name == tool


def test_install_all_continues_when_one_fails(tmp_path):
    """One tool failing should not abort the others."""
    binaries_dir = tmp_path / "bin"

    payloads = {}
    for tool in GO_BINARIES:
        if tool in ("gitleaks", "ffuf"):
            p = tmp_path / f"{tool}.tar.gz"
            _make_targz(p, tool)
        else:
            p = tmp_path / f"{tool}.zip"
            _make_zip(p, tool)
        payloads[tool] = p.read_bytes()

    def mock_dl(url, dest):
        if "nuclei" in url:
            raise ConnectionError("simulated nuclei download failure")
        for tool in GO_BINARIES:
            if tool in url:
                Path(dest).write_bytes(payloads[tool])
                return

    with patch("secagent.binmgmt.installer.verify_checksum", return_value=True):
        results = install_all(binaries_dir=str(binaries_dir), downloader=mock_dl)

    assert results["nuclei"]["ok"] is False
    assert "nuclei" in results["nuclei"]["error"].lower() or "simulated" in results["nuclei"]["error"].lower()
    # Others should succeed
    for tool in ("subfinder", "httpx", "gitleaks"):
        assert results[tool]["ok"] is True, f"{tool} should have succeeded: {results[tool]['error']}"


# ---------- CLI main ----------

def test_main_with_tool_arg_uses_install_tool(monkeypatch, tmp_path, capsys):
    """--tool should route through install_tool with the given binaries-dir."""
    binaries_dir = tmp_path / "bin"

    payloads = {}
    for tool in ("subfinder",):
        p = tmp_path / f"{tool}.zip"
        _make_zip(p, tool)
        payloads[tool] = p.read_bytes()

    captured = {}

    def fake_install_tool(tool_name, binaries_dir="./bin", downloader=None):
        captured["tool"] = tool_name
        captured["binaries_dir"] = binaries_dir
        # Simulate success
        p = Path(binaries_dir) / tool_name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"#!/bin/sh\nexit 0\n")
        os.chmod(p, 0o755)
        return str(p)

    monkeypatch.setattr(installer, "install_tool", fake_install_tool)

    rc = main(["--tool", "subfinder", "--binaries-dir", str(binaries_dir)])
    assert rc == 0
    assert captured["tool"] == "subfinder"
    assert captured["binaries_dir"] == str(binaries_dir)

    out = capsys.readouterr().out
    assert "subfinder" in out
    assert "ok" in out.lower()


def test_main_no_tool_arg_installs_all(monkeypatch, tmp_path, capsys):
    """No --tool arg → calls install_all."""
    binaries_dir = tmp_path / "bin"
    monkeypatch.setattr(
        installer,
        "install_all",
        lambda binaries_dir="./bin", downloader=None: {
            t: {"ok": True, "path": str(Path(binaries_dir) / t), "error": ""}
            for t in sorted(GO_BINARIES)
        },
    )
    rc = main(["--binaries-dir", str(binaries_dir)])
    assert rc == 0
    out = capsys.readouterr().out
    for tool in GO_BINARIES:
        assert tool in out


def test_main_returns_nonzero_on_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(
        installer,
        "install_all",
        lambda binaries_dir="./bin", downloader=None: {
            "subfinder": {"ok": False, "path": "", "error": "boom"},
        },
    )
    rc = main([])
    assert rc == 1


def test_main_rejects_unknown_tool(capsys):
    with pytest.raises(SystemExit):
        main(["--tool", "definitely-not-a-tool"])
