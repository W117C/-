"""Tool function: passive_recon (设计文档 §4).

Gathers OSINT data from multiple public sources to enrich the attack surface.

Unlike the other tool functions, this does NOT use a subprocess-based adapter.
Instead, it directly calls HTTP APIs (crt.sh, SecurityTrails, Shodan) using
urllib. This is purely passive — no packets are sent to the target.

Sources (all optional, degrade gracefully on failure):
  - crt.sh:        Certificate Transparency logs (no API key needed)
  - SecurityTrails Passive DNS (requires SECAGENT_SECURITYTRAILS_KEY env var)
  - Shodan:        Internet census data (requires SECAGENT_SHODAN_KEY env var)
  - theHarvester:  Reuses the existing gather_osint tool logic when available

API keys are read from environment variables ONLY to prevent leakage.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
import uuid
from typing import Any
from urllib.parse import urlencode

from secagent.core.decorators import gated_tool
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.gate import ComplianceGate
from secagent.core.headers import random_ua
from secagent.core.proxy import ProxyManager

# Timeout for external API calls (seconds)
_API_TIMEOUT = 15


def _build_opener(proxy_manager=None):
    """Build a urllib opener that respects proxy configuration."""
    if proxy_manager and proxy_manager.is_enabled():
        proxy = proxy_manager.get_proxy()
        if proxy and not proxy_manager._is_socks5(proxy):
            # HTTP/HTTPS proxy → use standard ProxyHandler
            handler = proxy_manager.build_proxy_handler()
            if handler:
                # Use default SSL context (certificate verification ENABLED)
                # Do NOT disable check_hostname/verify_mode — that would enable MITM on API calls
                https_handler = urllib.request.HTTPSHandler(context=ssl.create_default_context())
                return urllib.request.build_opener(handler, https_handler)
        # SOCKS5 → return None (caller should use socks_context)
    return urllib.request.build_opener()


def _crt_sh_query(domain: str, proxy_manager=None) -> list[dict[str, Any]]:
    """Query crt.sh certificate transparency logs for subdomains.

    Returns a list of dicts with 'name_value' field containing discovered
    hostnames (one per certificate, may include wildcards).
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": random_ua("chrome_mac")})
    try:
        opener = _build_opener(proxy_manager)
        with opener.open(req, timeout=_API_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return []


def _securitytrails_query(domain: str, proxy_manager=None) -> list[str]:
    """Query SecurityTrails Passive DNS API for subdomains.

    Requires SECAGENT_SECURITYTRAILS_KEY env var. Returns a list of subdomain
    hostnames, or empty list on any failure (including missing API key).
    """
    api_key = os.environ.get("SECAGENT_SECURITYTRAILS_KEY")
    if not api_key:
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    req = urllib.request.Request(url)
    req.add_header("APIKEY", api_key)
    req.add_header("User-Agent", random_ua("chrome_mac"))
    try:
        opener = _build_opener(proxy_manager)
        with opener.open(req, timeout=_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            subdomains = data.get("subdomains", [])
            return [f"{sd}.{domain}" for sd in subdomains]
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return []


def _shodan_query(domain: str, proxy_manager=None) -> list[dict[str, Any]]:
    """Query Shodan for host information about a domain.

    Requires SECAGENT_SHODAN_KEY env var. Returns a list of service dicts,
    or empty list on any failure.
    """
    api_key = os.environ.get("SECAGENT_SHODAN_KEY")
    if not api_key:
        return []
    query = urlencode({"q": domain, "key": api_key})
    url = f"https://api.shodan.io/shodan/host/search?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": random_ua("chrome_mac")})
    try:
        opener = _build_opener(proxy_manager)
        with opener.open(req, timeout=_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("matches", [])
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return []


# Unique subdomain extraction helpers
def _extract_subdomains_from_crt(domain: str, entries: list[dict[str, Any]]) -> set[str]:
    """Extract unique subdomains from crt.sh JSON response."""
    subdomains: set[str] = set()
    for entry in entries:
        name = entry.get("name_value", "")
        for raw in name.split("\n"):
            raw = raw.strip().lower()
            if raw.startswith("*."):
                raw = raw[2:]  # strip wildcard
            if raw.endswith(f".{domain}") or raw == domain:
                # Only include subdomains (not the apex itself)
                if raw != domain:
                    subdomains.add(raw)
    return subdomains


@gated_tool(tool_name="passive_recon", target_field="target")
def passive_recon(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> list[Finding]:
    """Gather passive intelligence on an authorized domain.

    Required param:
      - target: domain to investigate (e.g. 'example.com')

    Optional params:
      - sources: list of sources to use ['crtsh', 'securitytrails', 'shodan']
                 (default: all available)

    Returns list[Finding] — envelope built by @gated_tool decorator.
    """
    target = params.get("target", "")
    if not target or not isinstance(target, str):
        raise InvalidInputError(field="target", reason="must be a non-empty string")

    allowed_sources = params.get("sources")
    if allowed_sources is None:
        allowed_sources = ["crtsh", "securitytrails", "shodan"]
    elif not isinstance(allowed_sources, list):
        allowed_sources = ["crtsh", "securitytrails", "shodan"]

    findings: list[Finding] = []

    proxy_mgr = ProxyManager.from_env() if gate.proxy_manager is None else gate.proxy_manager

    # If SOCKS5 proxy is active, use PySocks context for all API calls
    with proxy_mgr.socks_context(target):
        # --- crt.sh ---
        if "crtsh" in allowed_sources:
            crt_entries = _crt_sh_query(target, proxy_mgr)
            subdomains = _extract_subdomains_from_crt(target, crt_entries)
            for sub in sorted(subdomains):
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex}",
                        type=FindingType.INTEL,
                        severity=Severity.INFO,
                        target=sub,
                        title=f"Subdomain discovered via crt.sh: {sub}",
                        evidence={
                            "source": "crtsh",
                            "domain": target,
                        },
                        source_tool="passive_recon",
                    )
                )

        # --- SecurityTrails ---
        if "securitytrails" in allowed_sources:
            st_subdomains = _securitytrails_query(target, proxy_mgr)
            for sub in sorted(st_subdomains):
                findings.append(
                    Finding(
                        id=f"fnd_{uuid.uuid4().hex}",
                        type=FindingType.INTEL,
                        severity=Severity.INFO,
                        target=sub,
                        title=f"Subdomain discovered via SecurityTrails: {sub}",
                        evidence={
                            "source": "securitytrails",
                            "domain": target,
                        },
                        source_tool="passive_recon",
                    )
                )

        # --- Shodan ---
        if "shodan" in allowed_sources:
            shodan_matches = _shodan_query(target, proxy_mgr)
            for match in shodan_matches:
                ip_str = match.get("ip_str", "")
                port = match.get("port", 0)
                data = match.get("data", "")
                if ip_str and port:
                    findings.append(
                        Finding(
                            id=f"fnd_{uuid.uuid4().hex}",
                            type=FindingType.INTEL,
                            severity=Severity.INFO,
                            target=ip_str,
                            title=f"Service on {ip_str}:{port} ({data[:80]}...)" if data else f"Service on {ip_str}:{port}",
                            evidence={
                                "source": "shodan",
                                "ip": ip_str,
                                "port": port,
                                "domain": target,
                                "service_preview": data[:200] if data else "",
                            },
                            source_tool="passive_recon",
                        )
                    )

    # Deduplicate findings by target
    seen_targets: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = f"{f.type.value}:{f.target}"
        if key not in seen_targets:
            seen_targets.add(key)
            deduped.append(f)

    return deduped
