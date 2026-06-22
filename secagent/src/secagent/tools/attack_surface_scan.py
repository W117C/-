"""Tool function: attack_surface_scan.

Chains passive enum, port scan, live probing, path fuzzing, and nuclei scan into
a single attack-surface workflow:

  1. enumerate_subdomains(target_domain)
  2. scan_ports(apex + discovered subdomains)        [NEW, optional]
  3. probe_services(discovered hosts on scanned ports)
  4. discover_paths(live HTTP services)               [NEW, optional]
  5. scan_vulnerabilities(live HTTP services)

Each phase still goes through its own ComplianceGate checks and audit/quota
commit. This orchestrator does not bypass the per-tool legal/safety controls.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from secagent.core.errors import ComplianceBlockError, InvalidInputError, NotAuthorizedError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate
from secagent.tools.enumerate_subdomains import enumerate_subdomains
from secagent.tools.probe_services import probe_services
from secagent.tools.scan_vulnerabilities import scan_vulnerabilities

log = logging.getLogger(__name__)


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

    # Prefer the original input hostname over the resolved IP for scope chaining
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


def attack_surface_scan(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Discover live attack surface, then scan it with nuclei.

    Required param:
      - target_domain: apex domain covered by authz_token

    Optional params are forwarded to the matching phase when present:
      - sources -> enumerate_subdomains
      - ports, threads -> probe_services
      - templates, severity_filter, rate_limit -> scan_vulnerabilities
      - max_scan_targets -> active scan cap, default 25
      - skip_port_scan  -> skip port scanning phase (default: False)
      - skip_path_fuzz  -> skip directory fuzzing phase (default: True)
      - wordlist        -> wordlist for path fuzzing (default: builtin)
    """
    target_domain = params.get("target_domain", "")
    if not isinstance(target_domain, str) or not target_domain:
        raise InvalidInputError("target_domain", "must be a non-empty string")

    max_scan_targets = params.get("max_scan_targets", 25)
    if not isinstance(max_scan_targets, int) or isinstance(max_scan_targets, bool):
        raise InvalidInputError("max_scan_targets", "must be an integer")
    if max_scan_targets < 1:
        raise InvalidInputError("max_scan_targets", "must be >= 1")

    skip_port_scan = bool(params.get("skip_port_scan", False))
    skip_path_fuzz = bool(params.get("skip_path_fuzz", True))

    # ----------------------------------------------------------------
    # Phase 1: enumerate_subdomains
    # ----------------------------------------------------------------
    enum_params: dict[str, Any] = {
        "target_domain": target_domain,
        "timeout_sec": params.get("enumerate_timeout_sec", params.get("timeout_sec", 120)),
    }
    if params.get("sources"):
        enum_params["sources"] = params["sources"]
    enum_result = enumerate_subdomains(
        gate=gate,
        params=enum_params,
        authz_token=authz_token,
        caller_id=caller_id,
    )

    subdomain_targets = [
        str(f.get("target", ""))
        for f in enum_result.get("findings", [])
        if f.get("target")
    ]
    all_hosts = _dedupe_keep_order([target_domain] + subdomain_targets)

    # ----------------------------------------------------------------
    # Phase 2: scan_ports (optional)
    # ----------------------------------------------------------------
    port_result: dict[str, Any] = {
        "engagement_id": "",
        "tool": "scan_ports",
        "findings": [],
        "summary": {"total": 0, "by_severity": {}, "by_type": {}},
        "quota_used": 0,
        "skipped": "port scanning disabled" if skip_port_scan else "no hosts to scan",
    }
    collected_ports: set[str] = set()

    if not skip_port_scan and all_hosts:
        from secagent.tools.scan_ports import scan_ports as _scan_ports

        port_scan_ports = str(params.get("ports", "80,443,8080-8090,8443"))
        port_timeout = params.get("port_timeout_sec", params.get("timeout_sec", 120))

        all_port_findings: list[dict[str, Any]] = []
        total_quota = 0

        for host in all_hosts:
            try:
                pr = _scan_ports(
                    gate=gate,
                    params={
                        "target": host,
                        "ports": port_scan_ports,
                        "timeout_sec": port_timeout,
                    },
                    authz_token=authz_token,
                    caller_id=caller_id,
                )
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

        # Collect unique ports from findings
        for f in all_port_findings:
            evidence = f.get("evidence", {}) or {}
            port = evidence.get("port")
            if port:
                collected_ports.add(str(port))

    # ----------------------------------------------------------------
    # Phase 3: probe_services
    # ----------------------------------------------------------------
    probe_params: dict[str, Any] = {
        "targets": all_hosts,
        "timeout_sec": params.get("probe_timeout_sec", params.get("timeout_sec", 120)),
    }

    # If port scan found ports, restrict probe to those ports
    if collected_ports:
        probe_params["ports"] = ",".join(sorted(collected_ports, key=int))
    else:
        for opt in ("ports", "threads"):
            if params.get(opt) is not None:
                probe_params[opt] = params[opt]

    probe_result = probe_services(
        gate=gate,
        params=probe_params,
        authz_token=authz_token,
        caller_id=caller_id,
    )

    # ----------------------------------------------------------------
    # Phase 4: discover_paths (optional)
    # ----------------------------------------------------------------
    path_result: dict[str, Any] = {
        "engagement_id": "",
        "tool": "discover_paths",
        "findings": [],
        "summary": {"total": 0, "by_severity": {}, "by_type": {}},
        "quota_used": 0,
        "skipped": "path fuzzing disabled" if skip_path_fuzz else "no live services",
    }

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

            # Collect tech stack from probe findings for tech-aware fuzzing
            tech_stacks: list[str] = []
            for f in probe_result.get("findings", []):
                ev = f.get("evidence", {}) or {}
                stack = ev.get("tech_stack", []) or []
                tech_stacks.extend(stack)

            all_path_findings: list[dict[str, Any]] = []
            total_path_quota = 0

            # Limit to max_scan_targets to avoid excessive fuzzing
            fuzz_targets = live_urls[:max_scan_targets]

            for url in fuzz_targets:
                try:
                    pr = _discover_paths(
                        gate=gate,
                        params={
                            "target": url,
                            "wordlist": path_wordlist,
                            "extensions": path_extensions,
                            "tech_stack": tech_stacks if tech_stacks else None,
                            "timeout_sec": path_timeout,
                        },
                        authz_token=authz_token,
                        caller_id=caller_id,
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

    # ----------------------------------------------------------------
    # Phase 5: scan_vulnerabilities (nuclei)
    # ----------------------------------------------------------------
    live_targets = _dedupe_keep_order([
        _service_scan_target(f) for f in probe_result.get("findings", [])
    ])
    scan_targets = live_targets[:max_scan_targets]

    scan_result: dict[str, Any] = {
        "engagement_id": "",
        "tool": "scan_vulnerabilities",
        "findings": [],
        "summary": {"total": 0, "by_severity": {}, "by_type": {}},
        "quota_used": 0,
        "skipped": "no live services discovered",
    }
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
                gate=gate,
                params=scan_params,
                authz_token=authz_token,
                caller_id=caller_id,
            )
        except Exception as exc:
            log.warning("Vulnerability scan failed: %s", exc)
            # Re-raise compliance blocks so the caller knows the scan was refused
            if isinstance(exc, (ComplianceBlockError, NotAuthorizedError)):
                raise
            scan_result = {
                "engagement_id": "",
                "tool": "scan_vulnerabilities",
                "findings": [],
                "summary": {"total": 0, "by_severity": {}, "by_type": {}},
                "quota_used": 0,
                "error": "scan_vulnerabilities failed",
                "skipped": f"scan_vulnerabilities failed: {type(exc).__name__}",
            }

    # ----------------------------------------------------------------
    # Combine results
    # ----------------------------------------------------------------
    findings = (
        enum_result.get("findings", [])
        + port_result.get("findings", [])
        + probe_result.get("findings", [])
        + path_result.get("findings", [])
        + scan_result.get("findings", [])
    )

    return {
        "engagement_id": f"eng_{uuid.uuid4().hex}",
        "tool": "attack_surface_scan",
        "findings": findings,
        "summary": _summary_from_dicts(findings),
        "quota_used": (
            enum_result.get("quota_used", 0)
            + port_result.get("quota_used", 0)
            + probe_result.get("quota_used", 0)
            + path_result.get("quota_used", 0)
            + scan_result.get("quota_used", 0)
        ),
        "phases": {
            "enumerate_subdomains": enum_result,
            "scan_ports": port_result,
            "probe_services": probe_result,
            "discover_paths": path_result,
            "scan_vulnerabilities": scan_result,
        },
        "scan_targets": scan_targets,
        "scan_targets_omitted": max(0, len(live_targets) - len(scan_targets)),
    }
