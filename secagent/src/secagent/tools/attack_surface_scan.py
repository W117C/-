"""Tool function: attack_surface_scan — complete attack surface mapping.

Orchestrates a multi-phase pipeline:
  Phase 1  — enumerate_subdomains (subfinder)
  Phase 2  — scan_ports (naabu, parallel per host)
  Phase 2.5 — resolve_dns (dnsx, A/CNAME/wildcard detection)
  Phase 3  — probe_services (httpx, live service detection)
  Phase 4  — discover_paths (ffuf, optional directory fuzzing)
  Phase 4.5 — fingerprint_tls (tlsx, TLS/JA3/JA4 fingerprints)
  Phase 5  — scan_vulnerabilities (nuclei, capped by max_scan_targets)

All phases automatically route through proxy when configured.
"""
from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from secagent.core.errors import ComplianceBlockError, InvalidInputError, NotAuthorizedError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate
from secagent.tools.enumerate_subdomains import enumerate_subdomains
from secagent.tools.probe_services import probe_services
from secagent.tools.scan_vulnerabilities import scan_vulnerabilities

log = logging.getLogger(__name__)

# ---- helpers ----

def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result

def _service_scan_target(finding: dict[str, Any]) -> str:
    host = str(finding.get("target", ""))
    evidence = finding.get("evidence", {}) or {}
    protocol = str(evidence.get("protocol") or "")
    port = str(evidence.get("port") or "")
    input_host = str(evidence.get("input_host", "") or "")
    if input_host and "://" not in input_host:
        host = input_host
    if not host or not protocol:
        return host
    default_port = (protocol == "https" and port == "443") or (
        protocol == "http" and port == "80"
    )
    if port and not default_port and ":" not in host:
        host = f"{host}:{port}"
    return f"{protocol}://{host}"

def _summary_from_dicts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    typed = [Finding.from_dict(f) for f in findings]
    return Finding.summary(typed)

def _dedup_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by (type, target, title) across phases."""
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for f in findings:
        key = (f.get("type", ""), f.get("target", ""), f.get("title", ""))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _empty_phase(tool: str, skipped: str) -> dict[str, Any]:
    return {
        "engagement_id": "", "tool": tool,
        "findings": [], "summary": {"total": 0, "by_severity": {}, "by_type": {}},
        "quota_used": 0, "skipped": skipped,
    }


# ---- main ----

def attack_surface_scan(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    target_domain = params.get("target_domain", "")
    if not isinstance(target_domain, str) or not target_domain:
        raise InvalidInputError("target_domain", "must be a non-empty string")

    max_scan_targets = params.get("max_scan_targets", 25)
    if not isinstance(max_scan_targets, int) or isinstance(max_scan_targets, bool):
        raise InvalidInputError("max_scan_targets", "must be an integer")
    if max_scan_targets < 1:
        raise InvalidInputError("max_scan_targets", "must be >= 1")

    skip_port_scan = bool(params.get("skip_port_scan", False))
    skip_dns_resolve = bool(params.get("skip_dns_resolve", False))
    skip_path_fuzz = bool(params.get("skip_path_fuzz", True))
    skip_tls_fingerprint = bool(params.get("skip_tls_fingerprint", True))

    # Phase 1: enumerate_subdomains
    enum_params: dict[str, Any] = {
        "target_domain": target_domain,
        "timeout_sec": params.get("enumerate_timeout_sec", params.get("timeout_sec", 120)),
    }
    if params.get("sources"):
        enum_params["sources"] = params["sources"]
    enum_result = enumerate_subdomains(
        gate=gate, params=enum_params, authz_token=authz_token, caller_id=caller_id,
    )

    subdomain_targets = [
        str(f.get("target", ""))
        for f in enum_result.get("findings", [])
        if f.get("target")
    ]
    all_hosts = _dedupe_keep_order([target_domain] + subdomain_targets)

    # Phase 2: scan_ports (parallel per host)
    port_result = _empty_phase("scan_ports",
        "port scanning disabled" if skip_port_scan else "no hosts to scan")
    collected_ports: set[str] = set()

    if not skip_port_scan and all_hosts:
        from secagent.tools.scan_ports import scan_ports as _scan_ports

        port_scan_ports = str(params.get("ports", "80,443,8080-8090,8443"))
        port_timeout = params.get("port_timeout_sec", params.get("timeout_sec", 120))
        max_workers = min(int(params.get("port_parallel", 5)), 20)

        all_port_findings: list[dict[str, Any]] = []
        total_quota = 0

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for host in all_hosts:
                f = pool.submit(
                    _scan_ports,
                    gate=gate,
                    params={"target": host, "ports": port_scan_ports, "timeout_sec": port_timeout},
                    authz_token=authz_token, caller_id=caller_id,
                )
                futures[f] = host
            for future in as_completed(futures):
                host = futures[future]
                try:
                    pr = future.result()
                    all_port_findings.extend(pr.get("findings", []))
                    total_quota += pr.get("quota_used", 0)
                except Exception as exc:
                    log.warning("Port scan failed for %s: %s", host, exc)

        port_result = {
            "engagement_id": f"eng_{uuid.uuid4().hex}",
            "tool": "scan_ports",
            "findings": all_port_findings,
            "summary": _summary_from_dicts(all_port_findings),
            "quota_used": total_quota,
        }
        for f in all_port_findings:
            evidence = f.get("evidence", {}) or {}
            port = evidence.get("port")
            if port:
                collected_ports.add(str(port))

    # Phase 2.5: DNS resolution (wildcard detection, A/CNAME records)
    dns_result = _empty_phase("resolve_dns",
        "DNS resolution disabled" if skip_dns_resolve else "no hosts to resolve")

    if not skip_dns_resolve and all_hosts:
        from secagent.tools.resolve_dns import resolve_dns as _resolve_dns
        try:
            dns_result = _resolve_dns(
                gate=gate,
                params={"targets": all_hosts},
                authz_token=authz_token, caller_id=caller_id,
            )
        except Exception as exc:
            log.warning("DNS resolution failed: %s", exc)

    # Phase 3: probe_services
    probe_params: dict[str, Any] = {
        "targets": all_hosts,
        "timeout_sec": params.get("probe_timeout_sec", params.get("timeout_sec", 120)),
    }
    if collected_ports:
        probe_params["ports"] = ",".join(sorted(collected_ports, key=int))
    else:
        for opt in ("ports", "threads"):
            if params.get(opt) is not None:
                probe_params[opt] = params[opt]

    probe_result = probe_services(
        gate=gate, params=probe_params, authz_token=authz_token, caller_id=caller_id,
    )

    # Phase 4: discover_paths (optional)
    path_result = _empty_phase("discover_paths",
        "path fuzzing disabled" if skip_path_fuzz else "no live services")

    if not skip_path_fuzz:
        live_urls = _dedupe_keep_order([
            _service_scan_target(f)
            for f in probe_result.get("findings", [])
            if _service_scan_target(f)
        ])
        if live_urls:
            from secagent.tools.discover_paths import discover_paths as _discover_paths
            path_timeout = params.get("path_timeout_sec", params.get("timeout_sec", 120))
            path_wordlist = params.get("wordlist", "builtin")
            path_extensions = params.get("path_extensions", "")
            tech_stacks: list[str] = []
            for f in probe_result.get("findings", []):
                ev = f.get("evidence", {}) or {}
                stack = ev.get("tech_stack", []) or []
                tech_stacks.extend(stack)

            all_path_findings: list[dict[str, Any]] = []
            total_path_quota = 0
            fuzz_targets = live_urls[:max_scan_targets]
            for url in fuzz_targets:
                try:
                    pr = _discover_paths(
                        gate=gate,
                        params={
                            "target": url, "wordlist": path_wordlist,
                            "extensions": path_extensions,
                            "tech_stack": tech_stacks if tech_stacks else None,
                            "timeout_sec": path_timeout,
                        },
                        authz_token=authz_token, caller_id=caller_id,
                    )
                    all_path_findings.extend(pr.get("findings", []))
                    total_path_quota += pr.get("quota_used", 0)
                except Exception as exc:
                    log.warning("Path discovery failed for %s: %s", url, exc)
            path_result = {
                "engagement_id": f"eng_{uuid.uuid4().hex}",
                "tool": "discover_paths",
                "findings": all_path_findings,
                "summary": _summary_from_dicts(all_path_findings),
                "quota_used": total_path_quota,
            }

    # Phase 4.5: TLS fingerprinting
    tls_result = _empty_phase("fingerprint_tls",
        "TLS fingerprint disabled" if skip_tls_fingerprint else "no HTTPS services")

    if not skip_tls_fingerprint:
        live_https = _dedupe_keep_order([
            str(f.get("target", ""))
            for f in probe_result.get("findings", [])
            if (f.get("evidence", {}) or {}).get("protocol", "") == "https"
            and f.get("target")
        ])
        if live_https:
            from secagent.tools.fingerprint_tls import fingerprint_tls as _tls
            try:
                tls_result = _tls(
                    gate=gate,
                    params={"targets": live_https[:max_scan_targets],
                            "cert_info": True, "ja3": True},
                    authz_token=authz_token, caller_id=caller_id,
                )
            except Exception as exc:
                log.warning("TLS fingerprinting failed: %s", exc)

    # Phase 5: scan_vulnerabilities
    live_targets = _dedupe_keep_order([
        _service_scan_target(f) for f in probe_result.get("findings", [])
    ])
    scan_targets = live_targets[:max_scan_targets]
    scan_result = _empty_phase("scan_vulnerabilities", "no live services discovered")

    if scan_targets:
        scan_params: dict[str, Any] = {
            "targets": scan_targets,
            "timeout_sec": params.get("scan_timeout_sec", params.get("timeout_sec", 600)),
        }
        for opt in ("templates", "severity_filter", "rate_limit"):
            if params.get(opt) is not None:
                scan_params[opt] = params[opt]
        try:
            scan_result = scan_vulnerabilities(
                gate=gate, params=scan_params,
                authz_token=authz_token, caller_id=caller_id,
            )
        except Exception as exc:
            if isinstance(exc, (ComplianceBlockError, NotAuthorizedError)):
                raise
            log.warning("Vulnerability scan failed: %s", exc)
            scan_result = {
                "engagement_id": "", "tool": "scan_vulnerabilities",
                "findings": [], "summary": {"total": 0, "by_severity": {}, "by_type": {}},
                "quota_used": 0, "error": f"scan_vulnerabilities failed: {type(exc).__name__}",
            }

    # Combine + deduplicate across all phases
    raw_findings = (
        enum_result.get("findings", [])
        + port_result.get("findings", [])
        + dns_result.get("findings", [])
        + probe_result.get("findings", [])
        + path_result.get("findings", [])
        + tls_result.get("findings", [])
        + scan_result.get("findings", [])
    )
    findings = _dedup_findings(raw_findings)

    return {
        "engagement_id": f"eng_{uuid.uuid4().hex}",
        "tool": "attack_surface_scan",
        "findings": findings,
        "summary": _summary_from_dicts(findings),
        "quota_used": (
            enum_result.get("quota_used", 0)
            + port_result.get("quota_used", 0)
            + dns_result.get("quota_used", 0)
            + probe_result.get("quota_used", 0)
            + path_result.get("quota_used", 0)
            + tls_result.get("quota_used", 0)
            + scan_result.get("quota_used", 0)
        ),
        "phases": {
            "enumerate_subdomains": enum_result,
            "scan_ports": port_result,
            "resolve_dns": dns_result,
            "probe_services": probe_result,
            "discover_paths": path_result,
            "fingerprint_tls": tls_result,
            "scan_vulnerabilities": scan_result,
        },
        "scan_targets": scan_targets,
        "scan_targets_omitted": max(0, len(live_targets) - len(scan_targets)),
    }
