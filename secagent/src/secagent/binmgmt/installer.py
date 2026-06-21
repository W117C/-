"""Binary installer — download + checksum verification + extraction (spec §5.2).

M4 implementation: dynamically build per-platform download URLs for the 4 Go
binaries (subfinder / httpx / nuclei / gitleaks), download, verify SHA256,
extract, and chmod +x. Provides a CLI entry point usable from install.sh.

The download URL is constructed from the locked version in versions.py plus
the running OS/arch, so we do NOT rely on the (macOS-amd64-only) download_url
field that versions.py currently hard-codes.
"""
from __future__ import annotations

import os
import platform
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from secagent.binmgmt.versions import get_tool_version
from secagent.core.errors import InvalidInputError, ToolFailedError

# The 4 Go binaries that this installer knows how to fetch.
GO_BINARIES = {"subfinder", "httpx", "nuclei", "gitleaks"}

# URL templates. projectdiscovery ships .zip; gitleaks ships .tar.gz.
# {os} is substituted as 'macOS' / 'Linux' (projectdiscovery style) for the
# pd tools; gitleaks uses 'darwin' / 'linux' — handled in build_download_url.
_URL_TEMPLATES = {
    "subfinder": "https://github.com/projectdiscovery/subfinder/releases/download/v{ver}/subfinder_{ver}_{os}_{arch}.zip",
    "httpx": "https://github.com/projectdiscovery/httpx/releases/download/v{ver}/httpx_{ver}_{os}_{arch}.zip",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{ver}/nuclei_{ver}_{os}_{arch}.zip",
    "gitleaks": "https://github.com/gitleaks/gitleaks/releases/download/v{ver}/gitleaks_{ver}_{os}_{arch}.tar.gz",
}

# Translate our internal os_name to the os token each vendor uses in URLs.
_OS_TOKEN = {
    "subfinder": {"macOS": "macOS", "Linux": "Linux"},
    "httpx": {"macOS": "macOS", "Linux": "Linux"},
    "nuclei": {"macOS": "macOS", "Linux": "Linux"},
    "gitleaks": {"macOS": "darwin", "Linux": "linux"},
}


def get_bin_path(binaries_dir: str, tool_name: str) -> str:
    """Return the expected path for a tool binary."""
    info = get_tool_version(tool_name)
    return str(Path(binaries_dir) / info["binary_name"])


def check_if_installed(binaries_dir: str, tool_name: str) -> bool:
    """Check if a tool binary exists at the expected path."""
    p = Path(get_bin_path(binaries_dir, tool_name))
    return p.is_file() and os.access(p, os.X_OK)


def ensure_binaries_dir(binaries_dir: str) -> None:
    """Create the binaries directory if it doesn't exist."""
    Path(binaries_dir).mkdir(parents=True, exist_ok=True)


def detect_platform() -> tuple[str, str]:
    """Return (os_name, arch).

    os_name in {'macOS','Linux'}; arch in {'amd64','arm64'}.
    macOS arm64 (Apple Silicon) → 'arm64'; x86_64 → 'amd64'.
    Unknown platforms raise InvalidInputError.
    """
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Darwin":
        os_name = "macOS"
    elif system == "Linux":
        os_name = "Linux"
    else:
        raise InvalidInputError(
            field="platform",
            reason=f"unsupported OS '{system}'. Only macOS and Linux are supported.",
        )

    if machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("x86_64", "amd64", "x64"):
        arch = "amd64"
    else:
        raise InvalidInputError(
            field="platform",
            reason=f"unsupported architecture '{machine}'. Only amd64 and arm64 are supported.",
        )

    return os_name, arch


def build_download_url(tool_name: str, os_name: str | None = None, arch: str | None = None) -> str:
    """Build the download URL for a tool on a given platform.

    Defaults to detect_platform(). Unknown tool_name raises InvalidInputError.
    """
    if tool_name not in _URL_TEMPLATES:
        raise InvalidInputError(
            field="tool_name",
            reason=f"unknown tool '{tool_name}'. Known: {sorted(_URL_TEMPLATES.keys())}",
        )
    if os_name is None or arch is None:
        detected_os, detected_arch = detect_platform()
        os_name = os_name or detected_os
        arch = arch or detected_arch

    info = get_tool_version(tool_name)
    ver = info["version"]
    os_token = _OS_TOKEN[tool_name][os_name]
    return _URL_TEMPLATES[tool_name].format(ver=ver, os=os_token, arch=arch)


def _default_downloader(url: str, dest: str) -> None:
    """Download url → dest with a 120s timeout (prevents indefinite hangs).

    Uses urllib with an explicit socket timeout so a stalled connection
    (common behind restrictive networks) fails fast instead of hanging
    the installer forever.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "SecAgent-installer/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
        # urlretrieve follows redirects automatically; urlopen does too.
        shutil.copyfileobj(resp, f, length=64 * 1024)


def download_file(url: str, dest_path: str, downloader=None) -> str:
    """Download a file to dest_path. Returns dest_path.

    `downloader` is an optional callable (url, dest) -> None used for test mocks.
    Default uses urllib.request.urlretrieve. Failures raise ToolFailedError.
    """
    dl = downloader or _default_downloader
    try:
        dl(url, dest_path)
    except Exception as e:  # noqa: BLE001 — surface any download error uniformly
        raise ToolFailedError(
            tool="installer",
            detail=f"download failed for {url}: {e}",
        ) from e
    return dest_path


def verify_checksum(file_path: str, expected_sha256: str) -> bool:
    """Verify SHA256 of a file.

    If `expected` starts with 'placeholder', print a warning to stderr and
    skip verification (MVP pragmatic mode). Otherwise compute the file's
    SHA256 and return True on match, False on mismatch.
    """
    if expected_sha256.startswith("placeholder"):
        print(
            f"warning: checksum for {file_path} is a placeholder; skipping verification",
            file=sys.stderr,
        )
        return True

    import hashlib

    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    actual = h.hexdigest()
    return actual.lower() == expected_sha256.lower()


def extract_archive(archive_path: str, dest_dir: str, tool_name: str) -> str:
    """Extract a .zip or .tar.gz archive into dest_dir and return the binary path.

    After extraction, locates a file named exactly `tool_name` (the binary),
    chmod +x it, and returns its full path. Raises ToolFailedError if the
    binary is not found in the archive.
    """
    Path(dest_dir).mkdir(parents=True, exist_ok=True)

    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest_dir)
    elif archive_path.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive_path, "r:gz") as tf:
            # filter="data" sanitizes metadata on extract (Python ≥3.12 default
            # behavior; passing it explicitly silences the 3.14 deprecation
            # warning and is safe for our trusted release archives).
            try:
                tf.extractall(dest_dir, filter="data")
            except TypeError:
                tf.extractall(dest_dir)
    else:
        raise ToolFailedError(
            tool="installer",
            detail=f"unsupported archive format: {archive_path}",
        )

    # Find the binary by walking the extracted tree. Prefer an exact-name match
    # at the top of dest_dir; fall back to any nested match.
    dest = Path(dest_dir)
    candidates = [dest / tool_name]
    candidates.extend(sorted(dest.rglob(tool_name)))

    for cand in candidates:
        if cand.is_file() and not cand.name.endswith((".txt", ".md", ".yaml", ".yml")):
            # chmod +x for owner/group/other
            current = cand.stat().st_mode
            os.chmod(cand, current | 0o111)
            return str(cand)

    raise ToolFailedError(
        tool="installer",
        detail=f"binary '{tool_name}' not found in archive {archive_path}",
    )


def install_tool(tool_name: str, binaries_dir: str = "./bin", downloader=None) -> str:
    """Download + verify + extract a single tool. Returns the binary path."""
    if tool_name not in _URL_TEMPLATES:
        raise InvalidInputError(
            field="tool_name",
            reason=f"installer cannot install '{tool_name}'. Installable: {sorted(GO_BINARIES)}",
        )

    info = get_tool_version(tool_name)
    url = build_download_url(tool_name)
    ensure_binaries_dir(binaries_dir)

    # Download to a temp file, then verify + extract.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=_suffix_for(tool_name))
    os.close(tmp_fd)
    try:
        download_file(url, tmp_path, downloader=downloader)
        if not verify_checksum(tmp_path, info["checksum_sha256"]):
            raise ToolFailedError(
                tool=tool_name,
                detail="checksum verification failed — file may be corrupted or tampered with",
            )
        bin_path = extract_archive(tmp_path, binaries_dir, tool_name)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return bin_path


def install_all(binaries_dir: str = "./bin", downloader=None) -> dict:
    """Install all 4 Go binaries. Returns {tool: {"ok": bool, "path": str, "error": str}}.

    A single tool failing does NOT abort the others; the error is recorded and
    the loop continues.
    """
    results: dict[str, dict] = {}
    for tool in sorted(GO_BINARIES):
        try:
            path = install_tool(tool, binaries_dir=binaries_dir, downloader=downloader)
            results[tool] = {"ok": True, "path": path, "error": ""}
        except Exception as e:  # noqa: BLE001 — record error, continue
            results[tool] = {"ok": False, "path": "", "error": str(e)}
    return results


def _suffix_for(tool_name: str) -> str:
    return ".zip" if tool_name != "gitleaks" else ".tar.gz"


def _print_results_table(results: dict) -> None:
    width_tool = max([len("tool")] + [len(t) for t in results])
    width_status = len("status")
    width_path = max([len("path")] + [len(r.get("path", "")) for r in results.values()])
    header = f"{'tool':<{width_tool}}  {'status':<{width_status}}  {'path':<{width_path}}  error"
    print(header)
    print("-" * len(header))
    for tool, r in results.items():
        status = "ok" if r["ok"] else "FAIL"
        print(
            f"{tool:<{width_tool}}  {status:<{width_status}}  {r['path']:<{width_path}}  {r['error']}"
        )


def main(argv: list[str] | None = None) -> int:
    """CLI entry: python -m secagent.binmgmt.installer [--tool NAME] [--binaries-dir DIR]."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="secagent.installer",
        description="Download and install SecAgent's Go binary dependencies.",
    )
    parser.add_argument(
        "--tool",
        choices=sorted(GO_BINARIES),
        help="Install only this tool. If omitted, install all 4.",
    )
    parser.add_argument(
        "--binaries-dir",
        default="./bin",
        help="Directory to install binaries into (default: ./bin)",
    )
    args = parser.parse_args(argv)

    if args.tool:
        try:
            path = install_tool(args.tool, binaries_dir=args.binaries_dir)
            results = {args.tool: {"ok": True, "path": path, "error": ""}}
        except Exception as e:  # noqa: BLE001
            results = {args.tool: {"ok": False, "path": "", "error": str(e)}}
    else:
        results = install_all(binaries_dir=args.binaries_dir)

    _print_results_table(results)

    if all(r["ok"] for r in results.values()):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
